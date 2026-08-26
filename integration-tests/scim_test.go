package integrationtests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// Local SCIM wire types for the integration tests. The real types live in
// internal/api (package-private to the server), so we define minimal mirrors here.

type testScimUserBody struct {
	Schemas     []string        `json:"schemas"`
	UserName    string          `json:"userName"`
	DisplayName string          `json:"displayName,omitempty"`
	ExternalId  string          `json:"externalId,omitempty"`
	Active      interface{}     `json:"active,omitempty"` // bool or "True"/"False" string
	Emails      []testScimEmail `json:"emails,omitempty"`
}

type testScimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// testScimUserResp decodes the SCIM User response from the server.
// active is always serialized as a JSON boolean by the server.
type testScimUserResp struct {
	Id          string `json:"id"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName,omitempty"`
	Active      bool   `json:"active"`
}

type testScimGroupBody struct {
	Schemas     []string            `json:"schemas"`
	DisplayName string              `json:"displayName"`
	Members     []map[string]string `json:"members,omitempty"`
}

type testScimGroupResp struct {
	Id          string              `json:"id"`
	DisplayName string              `json:"displayName"`
	Members     []map[string]string `json:"members,omitempty"`
}

type testScimPatch struct {
	Schemas    []string          `json:"schemas"`
	Operations []testScimPatchOp `json:"Operations"` // capital O — that's the SCIM wire format
}

type testScimPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

const (
	testScimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	testScimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	testScimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// scimDo makes a raw HTTP request to a SCIM endpoint.
// Set fromUserId to nil to omit the From header entirely (→ 401).
// Set body to nil for requests that carry no payload (GET, DELETE).
func scimDo(t *testing.T, method, rawURL string, fromUserId *uuid.UUID, body interface{}) (int, []byte) {
	t.Helper()
	var br io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		br = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, br)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if fromUserId != nil {
		req.Header.Set("From", fromUserId.String())
	}
	resp, err := testHttpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

func mustDecodeScimUser(t *testing.T, body []byte) testScimUserResp {
	t.Helper()
	var u testScimUserResp
	require.NoError(t, json.Unmarshal(body, &u), "decode SCIM user from: %s", string(body))
	return u
}

func mustDecodeScimGroup(t *testing.T, body []byte) testScimGroupResp {
	t.Helper()
	var g testScimGroupResp
	require.NoError(t, json.Unmarshal(body, &g), "decode SCIM group from: %s", string(body))
	return g
}

// countOrgMembers lists members visible to the admin and returns the count.
// Each unscoped role-based membership appears as one item.
func countOrgMembers(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId string, asUser uuid.UUID) int {
	t.Helper()
	r, err := client.ListMembersWithResponse(t.Context(), orgId, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(asUser))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode(), "list members: %s", string(r.Body))
	return len(r.JSON200.Items)
}

func TestScimProvisioning(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	cpInternalClient := MustInternalControlPlaneClient(t)

	org := MustCreateTestOrg(cpInternalClient, t)
	admin := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, admin.Id, adminRoleId)

	// Custom role carrying only provisioning permissions — this mirrors what an IDP
	// service user would be granted in production.
	provRole, err := client.CreateRoleWithResponse(t.Context(), org.Id, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Provisioner",
		Permissions: []string{authz.PermissionProvisioningRead, authz.PermissionProvisioningWrite},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, provRole.StatusCode(), "create provisioner role: %s", string(provRole.Body))
	provisionerRoleId := provRole.JSON201.Id

	// A dedicated SCIM caller bound to the provisioner role.
	scimCaller := MustRegisterTestUser(client, t)
	callerMembership, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id,
		serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      scimCaller.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     provisionerRoleId.String(),
		})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, callerMembership.StatusCode(), "add scimCaller membership: %s", string(callerMembership.Body))

	// Wait for Casbin to pick up the provisioning permissions.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
			authz.OrgCheck(org.Id, authz.PermissionProvisioningRead),
			authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite),
		}, WithAuthenticatedUserId(scimCaller.Id))
		require.NoError(t, err)
		if !assert.Equal(c, http.StatusOK, resp.StatusCode(), "check perms: %s", string(resp.Body)) {
			return
		}
		assert.Equal(c, []serverclient.ResourcePermissionCheckResultItem{
			{Allowed: true, PermissionCheck: authz.OrgCheck(org.Id, authz.PermissionProvisioningRead)},
			{Allowed: true, PermissionCheck: authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite)},
		}, resp.JSON200.Items)
	}, 30*time.Second, 500*time.Millisecond, "scimCaller did not get provisioning permissions in time")

	// This test hits the IAM container directly via INTERNAL_SERVER_URL. The
	// proxied /scim/v2 path (SERVER_URL) is exercised by the tests in
	// scim_auth_test.go.
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), org.Id)
	callerID := scimCaller.Id

	// ------------------------------------------------------------------ authorization

	t.Run("missing From header yields 401", func(t *testing.T) {
		// nil fromUserId → scimDo omits the From header entirely.
		status, body := scimDo(t, http.MethodGet, baseURL+"/Users", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, status, "body: %s", string(body))
	})

	t.Run("unknown principal yields 403", func(t *testing.T) {
		// A random UUID that has no org membership and no permissions.
		stranger := uuid.New()
		status, body := scimDo(t, http.MethodGet, baseURL+"/Users", &stranger, nil)
		assert.Equal(t, http.StatusForbidden, status, "body: %s", string(body))
	})

	t.Run("registered user without provisioning permissions yields 403", func(t *testing.T) {
		// Freshly registered, no org membership at all.
		outsider := MustRegisterTestUser(client, t)
		status, body := scimDo(t, http.MethodGet, baseURL+"/Users", &outsider.Id, nil)
		assert.Equal(t, http.StatusForbidden, status, "body: %s", string(body))
	})

	t.Run("write-only caller gets 403 on GET /Users", func(t *testing.T) {
		// A user with only provisioning_write (but not read) should be rejected on reads.
		writeRole, err := client.CreateRoleWithResponse(t.Context(), org.Id, serverclient.CreateRoleJSONRequestBody{
			DisplayName: "WriteOnlyProvisioner",
			Permissions: []string{authz.PermissionProvisioningWrite},
		}, WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, writeRole.StatusCode())

		writeOnlyCaller := MustRegisterTestUser(client, t)
		wm, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id,
			serverclient.InternalCreateOrgMembershipJSONRequestBody{
				UserId:      writeOnlyCaller.Id,
				SubjectType: serverclient.SubjectTypeRole,
				Subject:     writeRole.JSON201.Id.String(),
			})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, wm.StatusCode())

		// Wait for policy propagation before checking.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
				authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite),
			}, WithAuthenticatedUserId(writeOnlyCaller.Id))
			require.NoError(t, err)
			if !assert.Equal(c, http.StatusOK, resp.StatusCode()) {
				return
			}
			assert.Equal(c, []serverclient.ResourcePermissionCheckResultItem{
				{Allowed: true, PermissionCheck: authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite)},
			}, resp.JSON200.Items)
		}, 30*time.Second, 500*time.Millisecond, "write-only caller permissions did not propagate")

		status, body := scimDo(t, http.MethodGet, baseURL+"/Users", &writeOnlyCaller.Id, nil)
		assert.Equal(t, http.StatusForbidden, status, "write-only should not read; body: %s", string(body))
	})

	// ------------------------------------------------------------------ User lifecycle

	// Snapshot the member count before any SCIM provisioning. Each subsequent
	// assertion tracks the delta, not the absolute count.
	initialCount := countOrgMembers(t, client, org.Id, admin.Id)

	userName := "scim-user-" + uuid.New().String()[:8]
	var scimUserId uuid.UUID

	t.Run("POST /Users returns 201 with active user", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &callerID, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
			Emails:   []testScimEmail{{Value: userName + "@test.example", Primary: true, Type: "work"}},
		})
		if assert.Equal(t, http.StatusCreated, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.Equal(t, userName, u.UserName)
			assert.True(t, u.Active)
			assert.NotEmpty(t, u.Id)
			parsed, parseErr := uuid.Parse(u.Id)
			require.NoError(t, parseErr)
			scimUserId = parsed
		}
	})

	t.Run("duplicate POST /Users returns 409", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &callerID, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
		})
		assert.Equal(t, http.StatusConflict, status, "body: %s", string(body))
	})

	t.Run("provisioned user gets Viewer membership in org", func(t *testing.T) {
		// ensureOrgMembership runs inside the provision transaction so it should be
		// immediately reflected in the memberships API.
		assert.Equal(t, initialCount+1, countOrgMembers(t, client, org.Id, admin.Id))
	})

	t.Run("GET /Users/:id returns 200", func(t *testing.T) {
		require.NotEmpty(t, scimUserId, "scimUserId not set — POST /Users must pass first")
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &callerID, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.Equal(t, scimUserId.String(), u.Id)
			assert.Equal(t, userName, u.UserName)
			assert.True(t, u.Active)
		}
	})

	t.Run("GET /Users?filter=userName eq finds the user", func(t *testing.T) {
		params := url.Values{"filter": {fmt.Sprintf(`userName eq "%s"`, userName)}}
		filterURL := baseURL + "/Users?" + params.Encode()
		status, body := scimDo(t, http.MethodGet, filterURL, &callerID, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			var list struct {
				TotalResults int             `json:"totalResults"`
				Resources    json.RawMessage `json:"Resources"`
			}
			require.NoError(t, json.Unmarshal(body, &list))
			assert.Equal(t, 1, list.TotalResults)
		}
	})

	t.Run("GET /Users?filter=userName eq for non-existent user returns empty list", func(t *testing.T) {
		params := url.Values{"filter": {`userName eq "nobody@nowhere.example"`}}
		filterURL := baseURL + "/Users?" + params.Encode()
		status, body := scimDo(t, http.MethodGet, filterURL, &callerID, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			var list struct {
				TotalResults int `json:"totalResults"`
			}
			require.NoError(t, json.Unmarshal(body, &list))
			assert.Equal(t, 0, list.TotalResults)
		}
	})

	t.Run("PATCH deactivate with Entra-style capitalized op and string boolean active=False", func(t *testing.T) {
		require.NotEmpty(t, scimUserId)
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &callerID, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				// Entra sends capitalized "Replace" and the string "False" instead of false.
				{Op: "Replace", Path: "active", Value: "False"},
			},
		})
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.False(t, u.Active, "user should be deactivated")
		}
	})

	t.Run("org membership removed after deactivation", func(t *testing.T) {
		// scimDeactivateUser calls BulkDeleteMemberships then commits synchronously,
		// so the membership list should reflect the change immediately.
		assert.Equal(t, initialCount, countOrgMembers(t, client, org.Id, admin.Id))
	})

	t.Run("PATCH reactivate restores Viewer membership", func(t *testing.T) {
		require.NotEmpty(t, scimUserId)
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &callerID, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "Replace", Path: "active", Value: true},
			},
		})
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.True(t, u.Active)
		}
		// Membership should be restored by scimReactivateUser.
		assert.Equal(t, initialCount+1, countOrgMembers(t, client, org.Id, admin.Id))
	})

	t.Run("DELETE /Users/:id returns 204", func(t *testing.T) {
		require.NotEmpty(t, scimUserId)
		status, body := scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &callerID, nil)
		assert.Equal(t, http.StatusNoContent, status, "body: %s", string(body))
	})

	t.Run("GET /Users/:id after DELETE returns 404", func(t *testing.T) {
		require.NotEmpty(t, scimUserId)
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &callerID, nil)
		assert.Equal(t, http.StatusNotFound, status, "body: %s", string(body))
	})

	t.Run("org membership gone after DELETE", func(t *testing.T) {
		assert.Equal(t, initialCount, countOrgMembers(t, client, org.Id, admin.Id))
	})

	// ------------------------------------------------------------------ Groups

	groupName := "scim-group-" + uuid.New().String()[:8]
	var scimGroupId uuid.UUID

	// We need a live SCIM user to use as a group member.
	memberName := "scim-member-" + uuid.New().String()[:8]
	var scimMemberId uuid.UUID

	t.Run("POST /Users for group member setup", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &callerID, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: memberName,
			Active:   true,
		})
		if assert.Equal(t, http.StatusCreated, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			parsed, parseErr := uuid.Parse(u.Id)
			require.NoError(t, parseErr)
			scimMemberId = parsed
		}
	})

	t.Run("POST /Groups returns 201", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, baseURL+"/Groups", &callerID, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: groupName,
		})
		if assert.Equal(t, http.StatusCreated, status, "body: %s", string(body)) {
			g := mustDecodeScimGroup(t, body)
			assert.Equal(t, groupName, g.DisplayName)
			assert.Empty(t, g.Members)
			parsed, parseErr := uuid.Parse(g.Id)
			require.NoError(t, parseErr)
			scimGroupId = parsed
		}
	})

	t.Run("PATCH /Groups add member (standard path form)", func(t *testing.T) {
		require.NotEmpty(t, scimGroupId)
		require.NotEmpty(t, scimMemberId)
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "add", Path: "members", Value: []map[string]string{{"value": scimMemberId.String()}}},
			},
		})
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			g := mustDecodeScimGroup(t, body)
			require.Len(t, g.Members, 1)
			assert.Equal(t, scimMemberId.String(), g.Members[0]["value"])
		}
	})

	t.Run("PATCH /Groups remove member via Entra bracket filter form", func(t *testing.T) {
		require.NotEmpty(t, scimGroupId)
		require.NotEmpty(t, scimMemberId)
		// Entra sends path: `members[value eq "<id>"]` with no value payload.
		bracketPath := fmt.Sprintf(`members[value eq "%s"]`, scimMemberId.String())
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "Remove", Path: bracketPath},
			},
		})
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			g := mustDecodeScimGroup(t, body)
			assert.Empty(t, g.Members)
		}
	})

	// Tenant isolation: membership is pinned to one org by composite foreign
	// keys, so a member id that is not a SCIM user of this org must be refused
	// rather than stored. A stale id from the IDP takes the same path.
	t.Run("PATCH /Groups rejects a member that is not a SCIM user of this org", func(t *testing.T) {
		require.NotEmpty(t, scimGroupId)
		foreignMemberId := uuid.New()
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "add", Path: "members", Value: []map[string]string{{"value": foreignMemberId.String()}}},
			},
		})
		assert.Equal(t, http.StatusBadRequest, status, "body: %s", string(body))

		status, body = scimDo(t, http.MethodGet, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			g := mustDecodeScimGroup(t, body)
			assert.Empty(t, g.Members, "foreign member must not have been stored")
		}
	})

	t.Run("DELETE /Groups returns 204", func(t *testing.T) {
		require.NotEmpty(t, scimGroupId)
		status, body := scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, nil)
		assert.Equal(t, http.StatusNoContent, status, "body: %s", string(body))
	})

	t.Run("GET /Groups/:id after DELETE returns 404", func(t *testing.T) {
		require.NotEmpty(t, scimGroupId)
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Groups/%s", baseURL, scimGroupId), &callerID, nil)
		assert.Equal(t, http.StatusNotFound, status, "body: %s", string(body))
	})
}
