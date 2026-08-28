package integrationtests

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// TestKeycloakScimDeprovisionGate proves end to end — against the real
// database, through a real Keycloak login — that SCIM deprovisioning cannot be
// undone by the user simply logging in again via SSO. This was the audit
// finding: DELETE /Users/{id} used to hard-delete the scim_users row, the SSO
// gate then saw a never-provisioned user, and the membership integrity
// fallback handed out a fresh Viewer membership.
//
// The dedicated Keycloak users (scimgateuser, jitonlyuser) exist only for this
// test, so it shares no state with TestKeycloakSso's testuser.
func TestKeycloakScimDeprovisionGate(t *testing.T) {
	if os.Getenv("SELF_HOSTED_IAM_URL") == "" {
		t.Skip("SELF_HOSTED_IAM_URL not set, skipping Keycloak SCIM deprovision gate tests")
	}
	selfHostedIamUrl := mustSelfHostedIamURL(t)

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	shClient, err := serverclient.NewClientWithResponses(selfHostedIamUrl, serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	// The SCIM and SSO traffic below hits the self-hosted instance, which keeps
	// its own Casbin policy; wait until it has picked up the caller's grant too.
	waitForProvisioningPerms(t, shClient, orgId, caller)

	scimBaseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", selfHostedIamUrl, orgId)

	// Direct database access: the guarantee under test is about persisted state
	// (memberships, sessions, tombstones), not HTTP status codes.
	rawDb, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDb.Close() })

	globalUserIdByEmail := func(t *testing.T, email string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		require.NoError(t, rawDb.QueryRowContext(t.Context(),
			`SELECT id FROM users WHERE primary_email_address = $1`, email).Scan(&id))
		return id
	}
	countMemberships := func(t *testing.T, userId uuid.UUID) int {
		t.Helper()
		var n int
		require.NoError(t, rawDb.QueryRowContext(t.Context(),
			`SELECT COUNT(*) FROM memberships WHERE org_id = $1 AND user_id = $2`, orgId, userId).Scan(&n))
		return n
	}
	countSessions := func(t *testing.T, userId uuid.UUID) int {
		t.Helper()
		var n int
		require.NoError(t, rawDb.QueryRowContext(t.Context(),
			`SELECT COUNT(*) FROM session_tokens WHERE user_id = $1`, userId).Scan(&n))
		return n
	}

	// ssoLoginAs runs the full SSO round trip (init → Keycloak form login →
	// callback) for a Keycloak user and returns the callback response.
	ssoLoginAs := func(t *testing.T, username string) *serverclient.GetSsoCallbackResponse {
		t.Helper()
		r, err := shClient.RequestSsoLoginWithResponse(t.Context(), serverclient.RequestSsoLoginJSONRequestBody{OrgId: orgId})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "init sso login: %s", string(r.Body))
		parsedUrl, err := url.Parse(r.JSON200.RedirectUrl)
		require.NoError(t, err)
		state := parsedUrl.Query().Get("state")
		require.NotEmpty(t, state, "state should be present in redirect URL")
		code := keycloakLogin(t, r.JSON200.RedirectUrl, username, "testpassword")
		cb, err := shClient.GetSsoCallbackWithResponse(t.Context(), &serverclient.GetSsoCallbackParams{Code: &code, State: &state})
		require.NoError(t, err)
		return cb
	}

	const victimEmail = "scimgateuser@example.com"

	provisionVictim := func(t *testing.T) uuid.UUID {
		t.Helper()
		status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Users", &caller, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: victimEmail,
			Active:   true,
			Emails:   []testScimEmail{{Value: victimEmail, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision victim: %s", string(body))
		return uuid.MustParse(mustDecodeScimUser(t, body).Id)
	}

	scimUserId := provisionVictim(t)
	globalUserId := globalUserIdByEmail(t, victimEmail)

	t.Run("provisioned user can log in via SSO", func(t *testing.T) {
		cb := ssoLoginAs(t, "scimgateuser")
		require.Equal(t, http.StatusOK, cb.StatusCode(), "body: %s", string(cb.Body))
		assert.Equal(t, globalUserId, cb.JSON200.Id, "SSO must land on the SCIM-provisioned user")
		assert.NotEmpty(t, cb.HTTPResponse.Header.Get("Set-Cookie"))
		assert.Equal(t, 1, countMemberships(t, globalUserId), "Viewer membership from provisioning")
		assert.GreaterOrEqual(t, countSessions(t, globalUserId), 1, "login must have created a session")
	})

	t.Run("deactivated user cannot log in and holds nothing", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", scimBaseURL, scimUserId), &caller, testScimPatch{
			Schemas:    []string{testScimPatchSchema},
			Operations: []testScimPatchOp{{Op: "Replace", Path: "active", Value: "False"}},
		})
		require.Equal(t, http.StatusOK, status, "deactivate: %s", string(body))
		assert.Equal(t, 0, countMemberships(t, globalUserId), "deactivation must strip the org membership")
		assert.Equal(t, 0, countSessions(t, globalUserId), "deactivation must revoke sessions")

		cb := ssoLoginAs(t, "scimgateuser")
		require.Equal(t, http.StatusUnauthorized, cb.StatusCode(), "deactivated user must be rejected; body: %s", string(cb.Body))
		assert.Equal(t, 0, countMemberships(t, globalUserId), "the rejected login must not create a membership")
		assert.Equal(t, 0, countSessions(t, globalUserId), "the rejected login must not create a session")
	})

	t.Run("reactivated user can log in again", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", scimBaseURL, scimUserId), &caller, testScimPatch{
			Schemas:    []string{testScimPatchSchema},
			Operations: []testScimPatchOp{{Op: "Replace", Path: "active", Value: true}},
		})
		require.Equal(t, http.StatusOK, status, "reactivate: %s", string(body))

		cb := ssoLoginAs(t, "scimgateuser")
		require.Equal(t, http.StatusOK, cb.StatusCode(), "body: %s", string(cb.Body))
		assert.Equal(t, 1, countMemberships(t, globalUserId), "reactivation restores the Viewer membership")
	})

	t.Run("DELETE tombstones the row and strips access", func(t *testing.T) {
		status, body := scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", scimBaseURL, scimUserId), &caller, nil)
		require.Equal(t, http.StatusNoContent, status, "delete: %s", string(body))

		var deletedAt *time.Time
		var active bool
		require.NoError(t, rawDb.QueryRowContext(t.Context(),
			`SELECT deleted_at, active FROM scim_users WHERE org_id = $1 AND id = $2`, orgId, scimUserId).
			Scan(&deletedAt, &active))
		assert.NotNil(t, deletedAt, "the row must survive as a tombstone")
		assert.False(t, active, "a tombstone is never active")
		assert.Equal(t, 0, countMemberships(t, globalUserId), "delete must strip the org membership")
		assert.Equal(t, 0, countSessions(t, globalUserId), "delete must revoke sessions")
	})

	t.Run("deleted user cannot resurrect access via SSO", func(t *testing.T) {
		// The audit finding: this login used to succeed and mint a fresh Viewer
		// membership through the membership integrity fallback.
		cb := ssoLoginAs(t, "scimgateuser")
		require.Equal(t, http.StatusUnauthorized, cb.StatusCode(), "deleted user must be rejected; body: %s", string(cb.Body))
		assert.Empty(t, cb.HTTPResponse.Header.Get("Set-Cookie"), "no session cookie for a rejected login")
		assert.Equal(t, 0, countMemberships(t, globalUserId), "the rejected login must not create a membership")
		assert.Equal(t, 0, countSessions(t, globalUserId), "the rejected login must not create a session")
	})

	t.Run("deleted user stays gone from SCIM reads", func(t *testing.T) {
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Users/%s", scimBaseURL, scimUserId), &caller, nil)
		assert.Equal(t, http.StatusNotFound, status, "GET after DELETE: %s", string(body))

		params := url.Values{"filter": {fmt.Sprintf(`userName eq "%s"`, victimEmail)}}
		status, body = scimDo(t, http.MethodGet, scimBaseURL+"/Users?"+params.Encode(), &caller, nil)
		require.Equal(t, http.StatusOK, status, "filter after DELETE: %s", string(body))
		var list struct {
			TotalResults int `json:"totalResults"`
		}
		require.NoError(t, json.Unmarshal(body, &list))
		assert.Equal(t, 0, list.TotalResults, "the tombstone must not appear in filter results")
	})

	t.Run("a tombstoned id is not a valid group member", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Groups", &caller, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: "Deprovision Gate Crew",
			Members:     []map[string]string{{"value": scimUserId.String()}},
		})
		assert.Equal(t, http.StatusBadRequest, status, "a tombstoned member id must be refused: %s", string(body))
	})

	var reprovisionedScimUserId uuid.UUID
	t.Run("re-provisioning after DELETE creates a fresh row and restores access", func(t *testing.T) {
		reprovisionedScimUserId = provisionVictim(t)
		assert.NotEqual(t, scimUserId, reprovisionedScimUserId, "re-provisioning must mint a new SCIM id; the tombstone stays for history")
		assert.Equal(t, 1, countMemberships(t, globalUserId), "re-provisioning restores the Viewer membership")

		cb := ssoLoginAs(t, "scimgateuser")
		require.Equal(t, http.StatusOK, cb.StatusCode(), "re-provisioned user must log in again; body: %s", string(cb.Body))
		assert.Equal(t, globalUserId, cb.JSON200.Id, "same person, same global user")
	})

	t.Run("filter finds only the live row after re-provisioning", func(t *testing.T) {
		params := url.Values{"filter": {fmt.Sprintf(`userName eq "%s"`, victimEmail)}}
		status, body := scimDo(t, http.MethodGet, scimBaseURL+"/Users?"+params.Encode(), &caller, nil)
		require.Equal(t, http.StatusOK, status, "filter after re-provision: %s", string(body))
		var list struct {
			TotalResults int `json:"totalResults"`
			Resources    []testScimUserResp
		}
		require.NoError(t, json.Unmarshal(body, &list))
		require.Equal(t, 1, list.TotalResults)
		assert.Equal(t, reprovisionedScimUserId.String(), list.Resources[0].Id)
	})

	t.Run("a user this org never provisioned still gets normal JIT", func(t *testing.T) {
		cb := ssoLoginAs(t, "jitonlyuser")
		require.Equal(t, http.StatusOK, cb.StatusCode(), "body: %s", string(cb.Body))
		jitUserId := cb.JSON200.Id
		assert.NotEqual(t, globalUserId, jitUserId)
		assert.Equal(t, 1, countMemberships(t, jitUserId), "JIT must grant the Viewer membership as before")
		assert.GreaterOrEqual(t, countSessions(t, jitUserId), 1)
	})
}
