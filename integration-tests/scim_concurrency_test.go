package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// scimTryDo is scimDo without test assertions, so it is safe to call from
// spawned goroutines (require.FailNow must only run on the test goroutine).
func scimTryDo(ctx context.Context, method, rawURL string, fromUserId uuid.UUID, body interface{}) (int, []byte, error) {
	var br io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		br = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, br)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("From", fromUserId.String())
	resp, err := testHttpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

type scimRaceResult struct {
	status int
	body   []byte
	err    error
}

// fireConcurrently runs fn n times in parallel, releasing all goroutines at
// once to maximize the overlap.
func fireConcurrently(n int, fn func(i int) scimRaceResult) []scimRaceResult {
	results := make([]scimRaceResult, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
	return results
}

// countMembershipsByEmail counts the individual membership rows the members
// API reports for the given primary email. Unlike rolesHeldByEmail this does
// not collapse duplicates, so a double-created membership shows up.
func countMembershipsByEmail(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId string, asUser uuid.UUID, email string) int {
	t.Helper()
	r, err := client.ListMembersWithResponse(t.Context(), orgId, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(asUser))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode(), "list members: %s", string(r.Body))
	count := 0
	for _, m := range r.JSON200.Items {
		if m.UserPrimaryEmailAddress != nil && *m.UserPrimaryEmailAddress == email {
			count++
		}
	}
	return count
}

// TestScimConcurrentProvisioning simulates an IDP with two provisioning cycles
// in flight: identical requests race each other and the end state must be
// consistent. Exactly one resource wins, losers get a clean SCIM 409
// uniqueness error, and nothing 5xxes or leaves duplicates behind.
func TestScimConcurrentProvisioning(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	const n = 8

	t.Run("concurrent identical POST /Users leaves exactly one user", func(t *testing.T) {
		userName := "scim-race-" + uuid.New().String()[:8] + "@test.example"
		userBody := testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
			Emails:   []testScimEmail{{Value: userName, Primary: true, Type: "work"}},
		}
		results := fireConcurrently(n, func(int) scimRaceResult {
			status, body, err := scimTryDo(t.Context(), http.MethodPost, baseURL+"/Users", caller, userBody)
			return scimRaceResult{status: status, body: body, err: err}
		})

		created, conflicted := 0, 0
		for i, r := range results {
			require.NoError(t, r.err, "request %d failed on the wire", i)
			require.Less(t, r.status, 500, "request %d must not 5xx: %s", i, string(r.body))
			switch r.status {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflicted++
				var envelope struct {
					ScimType string `json:"scimType"`
				}
				require.NoError(t, json.Unmarshal(r.body, &envelope), "decode conflict body: %s", string(r.body))
				assert.Equal(t, "uniqueness", envelope.ScimType, "loser must report a SCIM uniqueness error: %s", string(r.body))
			default:
				t.Fatalf("request %d: unexpected status %d: %s", i, r.status, string(r.body))
			}
		}
		assert.Equal(t, 1, created, "exactly one POST must win")
		assert.Equal(t, n-1, conflicted, "every other POST must lose with 409")

		// The database agrees: one SCIM user, one org membership.
		params := url.Values{"filter": {fmt.Sprintf(`userName eq "%s"`, userName)}}
		status, body := scimDo(t, http.MethodGet, baseURL+"/Users?"+params.Encode(), &caller, nil)
		require.Equal(t, http.StatusOK, status, "filter users: %s", string(body))
		var list struct {
			TotalResults int `json:"totalResults"`
		}
		require.NoError(t, json.Unmarshal(body, &list))
		assert.Equal(t, 1, list.TotalResults, "exactly one SCIM user must exist")
		assert.Equal(t, 1, countMembershipsByEmail(t, client, orgId, adminId, userName), "exactly one membership must exist")
	})

	t.Run("concurrent PATCHes adding different members keep every add", func(t *testing.T) {
		// The lost-update case: each PATCH read-modify-writes the member set, so
		// without a row lock two concurrent adds of DIFFERENT members would each
		// compute from the same baseline and the second write would drop the
		// first member. Every add must survive.
		groupName := "Race Distinct " + uuid.New().String()[:8]
		status, body := scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: groupName,
		})
		require.Equal(t, http.StatusCreated, status, "create group: %s", string(body))
		groupId := uuid.MustParse(mustDecodeScimGroup(t, body).Id)
		groupURL := fmt.Sprintf("%s/Groups/%s", baseURL, groupId)

		distinct := n
		memberIds := make([]uuid.UUID, 0, distinct)
		for i := 0; i < distinct; i++ {
			email := fmt.Sprintf("scim-distinct-%d-%s@test.example", i, uuid.New().String()[:8])
			status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
				Schemas:  []string{testScimUserSchema},
				UserName: email,
				Active:   true,
				Emails:   []testScimEmail{{Value: email, Primary: true, Type: "work"}},
			})
			require.Equal(t, http.StatusCreated, status, "provision member %d: %s", i, string(body))
			memberIds = append(memberIds, uuid.MustParse(mustDecodeScimUser(t, body).Id))
		}

		results := fireConcurrently(distinct, func(i int) scimRaceResult {
			patch := testScimPatch{
				Schemas: []string{testScimPatchSchema},
				Operations: []testScimPatchOp{
					{Op: "add", Path: "members", Value: []map[string]string{{"value": memberIds[i].String()}}},
				},
			}
			status, body, err := scimTryDo(t.Context(), http.MethodPatch, groupURL, caller, patch)
			return scimRaceResult{status: status, body: body, err: err}
		})
		for i, r := range results {
			require.NoError(t, r.err, "request %d failed on the wire", i)
			require.Equal(t, http.StatusOK, r.status, "request %d: %s", i, string(r.body))
		}

		status, body = scimDo(t, http.MethodGet, groupURL, &caller, nil)
		require.Equal(t, http.StatusOK, status, "get group: %s", string(body))
		got := make([]string, 0, distinct)
		for _, m := range mustDecodeScimGroup(t, body).Members {
			got = append(got, m["value"])
		}
		want := make([]string, 0, distinct)
		for _, id := range memberIds {
			want = append(want, id.String())
		}
		assert.ElementsMatch(t, want, got, "every concurrently added member must survive")
	})

	t.Run("concurrent identical group member PATCHes stay consistent", func(t *testing.T) {
		// A mapped group makes the race meaningful: each PATCH also runs role
		// reconciliation (Viewer -> mapped role) inside its transaction.
		mappedRole, err := client.CreateRoleWithResponse(t.Context(), orgId, serverclient.CreateRoleJSONRequestBody{
			DisplayName: "Race Mapped Role",
			Permissions: []string{authz.PermissionRoleRead},
		}, WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, mappedRole.StatusCode(), "create mapped role: %s", string(mappedRole.Body))
		mappedRoleId := mappedRole.JSON201.Id

		groupName := "Race Group " + uuid.New().String()[:8]
		m, err := client.UpsertScimGroupMappingWithResponse(t.Context(), orgId, groupName,
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRoleId},
			WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, m.StatusCode(), "upsert mapping: %s", string(m.Body))

		memberEmail := "scim-race-member-" + uuid.New().String()[:8] + "@test.example"
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: memberEmail,
			Active:   true,
			Emails:   []testScimEmail{{Value: memberEmail, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision member: %s", string(body))
		memberId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

		status, body = scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: groupName,
		})
		require.Equal(t, http.StatusCreated, status, "create group: %s", string(body))
		groupId := uuid.MustParse(mustDecodeScimGroup(t, body).Id)

		patchBody := testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "add", Path: "members", Value: []map[string]string{{"value": memberId.String()}}},
			},
		}
		groupURL := fmt.Sprintf("%s/Groups/%s", baseURL, groupId)
		results := fireConcurrently(n, func(int) scimRaceResult {
			status, body, err := scimTryDo(t.Context(), http.MethodPatch, groupURL, caller, patchBody)
			return scimRaceResult{status: status, body: body, err: err}
		})
		for i, r := range results {
			require.NoError(t, r.err, "request %d failed on the wire", i)
			require.Less(t, r.status, 500, "request %d must not 5xx: %s", i, string(r.body))
			assert.Equal(t, http.StatusOK, r.status, "request %d: identical member adds are idempotent: %s", i, string(r.body))
		}

		// End state: the member appears exactly once, holds exactly the mapped
		// role, and reconciliation created no duplicate membership rows.
		status, body = scimDo(t, http.MethodGet, groupURL, &caller, nil)
		require.Equal(t, http.StatusOK, status, "get group: %s", string(body))
		g := mustDecodeScimGroup(t, body)
		require.Len(t, g.Members, 1, "the member must appear exactly once")
		assert.Equal(t, memberId.String(), g.Members[0]["value"])

		_, roles := rolesHeldByEmail(t, client, orgId, adminId, memberEmail)
		assert.Equal(t, map[string]bool{mappedRoleId.String(): true}, roles, "member must hold exactly the mapped role")
		assert.Equal(t, 1, countMembershipsByEmail(t, client, orgId, adminId, memberEmail), "exactly one membership row must exist")
	})

	t.Run("deactivation serializes with group role reconciliation", func(t *testing.T) {
		mappedRole, err := client.CreateRoleWithResponse(t.Context(), orgId, serverclient.CreateRoleJSONRequestBody{
			DisplayName: "Deactivation Race Role", Permissions: []string{authz.PermissionRoleRead},
		}, WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, mappedRole.StatusCode(), "create mapped role: %s", string(mappedRole.Body))

		groupName := "Deactivation Race " + uuid.New().String()[:8]
		mapping, err := client.UpsertScimGroupMappingWithResponse(t.Context(), orgId, groupName,
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRole.JSON201.Id},
			WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, mapping.StatusCode(), "upsert mapping: %s", string(mapping.Body))

		memberEmail := "scim-deactivate-race-" + uuid.New().String()[:8] + "@test.example"
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: memberEmail, Active: true,
			Emails: []testScimEmail{{Value: memberEmail, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision member: %s", string(body))
		memberId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

		status, body = scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas: []string{testScimGroupSchema}, DisplayName: groupName,
		})
		require.Equal(t, http.StatusCreated, status, "create group: %s", string(body))
		groupId := uuid.MustParse(mustDecodeScimGroup(t, body).Id)
		groupURL := fmt.Sprintf("%s/Groups/%s", baseURL, groupId)
		userURL := fmt.Sprintf("%s/Users/%s", baseURL, memberId)

		const groupWriters = 12
		results := fireConcurrently(groupWriters+1, func(i int) scimRaceResult {
			if i == groupWriters {
				patch := testScimPatch{Schemas: []string{testScimPatchSchema}, Operations: []testScimPatchOp{{Op: "replace", Path: "active", Value: false}}}
				status, body, err := scimTryDo(t.Context(), http.MethodPatch, userURL, caller, patch)
				return scimRaceResult{status: status, body: body, err: err}
			}
			patch := testScimPatch{Schemas: []string{testScimPatchSchema}, Operations: []testScimPatchOp{{
				Op: "add", Path: "members", Value: []map[string]string{{"value": memberId.String()}},
			}}}
			status, body, err := scimTryDo(t.Context(), http.MethodPatch, groupURL, caller, patch)
			return scimRaceResult{status: status, body: body, err: err}
		})
		for i, result := range results {
			require.NoError(t, result.err, "request %d failed on the wire", i)
			require.Equal(t, http.StatusOK, result.status, "request %d: %s", i, string(result.body))
		}

		status, body = scimDo(t, http.MethodGet, userURL, &caller, nil)
		require.Equal(t, http.StatusOK, status, "get deactivated user: %s", string(body))
		user := mustDecodeScimUser(t, body)
		require.False(t, user.Active, "the SCIM resource must remain inactive")
		require.Equal(t, 0, countMembershipsByEmail(t, client, orgId, adminId, memberEmail),
			"group reconciliation must never grant a role after deactivation")
	})
}
