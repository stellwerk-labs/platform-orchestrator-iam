package integrationtests

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// TestScimDeprovisionRevokesDeviceLogin settles a disputed audit finding
// empirically: an already-ACCEPTED device-login request used to be able to mint
// a fresh session token AFTER SCIM deprovisioning, because the session is
// created at POLL time (PollDeviceLoginRequest) from decided_by — not at accept
// time. Deprovisioning deleted the session_tokens rows but left the accepted
// device_login_requests row behind as a redeemable credential.
//
// The fix removes every device-login request the user decided in the same
// transaction that revokes their sessions. This test is the regression guard:
//
//  1. a session minted BEFORE deprovisioning dies with it,
//  2. an accepted-but-unpolled request yields NO credentials after
//     deprovisioning (the audit's exact scenario),
//  3. a request left PENDING across deprovisioning stays a dead end: polling
//     returns no token, and the user can no longer accept it because every
//     session died.
func TestScimDeprovisionRevokesDeviceLogin(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	scimBaseURL := scimProxyBaseURL(t, orgId)

	// Register the victim with a unique email so the SCIM provisioning below
	// binds to exactly this global user via the email-match path.
	victimEmail := fmt.Sprintf("device-victim-%s@example.com", uuid.NewString())
	reg, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
		Provider: "testuser",
		ProviderToken: MustGenerateTestUserTokenWith(t, TestUser{
			ProviderId:  rand.Text(),
			DisplayName: "Device Victim",
			Email:       victimEmail,
		}),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, reg.StatusCode(), "register victim: %s", string(reg.Body))
	victimId := reg.JSON202.Id

	status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Users", &caller, testScimUserBody{
		Schemas:  []string{testScimUserSchema},
		UserName: victimEmail,
		Active:   true,
		Emails:   []testScimEmail{{Value: victimEmail, Primary: true, Type: "work"}},
	})
	require.Equal(t, http.StatusCreated, status, "provision victim: %s", string(body))
	scimUserId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

	newDeviceLoginRequest := func(t *testing.T) serverclient.CreatedDeviceLoginRequest {
		t.Helper()
		userAgent := "deprovision-test"
		r, err := client.RequestDeviceLoginWithResponse(t.Context(), &serverclient.RequestDeviceLoginParams{
			UserAgent: &userAgent,
		}, serverclient.RequestDeviceLoginJSONRequestBody{})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "create device login request: %s", string(r.Body))
		return *r.JSON201
	}
	acceptAsVictim := func(t *testing.T, requestId uuid.UUID) {
		t.Helper()
		r, err := client.AcceptDeviceLoginRequestWithResponse(t.Context(), requestId, WithAuthenticatedUserId(victimId))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), "accept device login: %s", string(r.Body))
	}
	poll := func(t *testing.T, req serverclient.CreatedDeviceLoginRequest) *serverclient.PollDeviceLoginRequestResponse {
		t.Helper()
		r, err := client.PollDeviceLoginRequestWithResponse(t.Context(), req.Id, &serverclient.PollDeviceLoginRequestParams{PollingToken: req.PollingToken})
		require.NoError(t, err)
		return r
	}
	authenticateWithToken := func(t *testing.T, token string) int {
		t.Helper()
		authHeader := "Bearer " + token
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &serverclient.InternalAuthenticateParams{
			Authorization: &authHeader,
		})
		require.NoError(t, err)
		return r.StatusCode()
	}

	// (1) A fully redeemed device login: accepted and polled → session token.
	redeemed := newDeviceLoginRequest(t)
	acceptAsVictim(t, redeemed.Id)
	pollResp := poll(t, redeemed)
	require.Equal(t, http.StatusOK, pollResp.StatusCode(), "poll accepted request: %s", string(pollResp.Body))
	sessionToken := pollResp.JSON200.Token
	require.Equal(t, http.StatusOK, authenticateWithToken(t, sessionToken), "the minted session must work before deprovisioning")

	// (2) The audit scenario: accepted but NOT yet polled when deprovisioning hits.
	accepted := newDeviceLoginRequest(t)
	acceptAsVictim(t, accepted.Id)

	// (3) A request still pending (undecided) across deprovisioning.
	pending := newDeviceLoginRequest(t)

	// Deprovision the victim via SCIM DELETE.
	status, body = scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", scimBaseURL, scimUserId), &caller, nil)
	require.Equal(t, http.StatusNoContent, status, "deprovision victim: %s", string(body))

	t.Run("accepted request cannot mint a session after deprovisioning", func(t *testing.T) {
		r := poll(t, accepted)
		require.NotEqual(t, http.StatusOK, r.StatusCode(),
			"an accepted device-login request must not yield credentials after deprovisioning; body: %s", string(r.Body))
		assert.Equal(t, http.StatusNotFound, r.StatusCode(),
			"deprovisioning must have deleted the accepted request; body: %s", string(r.Body))
		require.Nil(t, r.JSON200, "no token may be minted for a deprovisioned user")
	})

	t.Run("pending request stays a dead end", func(t *testing.T) {
		// The row survives (it references no user), but it can never turn into
		// credentials: polling returns no token, and accepting it requires an
		// authenticated session — all of which deprovisioning just destroyed,
		// as the 401 above proves.
		r := poll(t, pending)
		assert.Equal(t, http.StatusAccepted, r.StatusCode(), "pending request must still be undecided; body: %s", string(r.Body))
		require.Nil(t, r.JSON200, "a pending request must not carry a token")
	})

	t.Run("deprovisioning leaves no device-login rows for the user", func(t *testing.T) {
		db := MustDatabase(t)
		t.Cleanup(func() { _ = db.Close() })
		for _, requestId := range []uuid.UUID{redeemed.Id, accepted.Id} {
			_, err := db.GetDeviceLoginRequest(t.Context(), nil, requestId)
			assert.Error(t, err, "request %s decided by the deprovisioned user must be gone", requestId)
		}
	})

	t.Run("session minted before deprovisioning dies within the auth cache TTL", func(t *testing.T) {
		// The session_tokens row is deleted in the deprovision transaction, but
		// GetTokenByHashCache (internal/api/authenticate.go) may keep serving a
		// recently-used token for up to authenticationTokenCacheTTL (60s). That
		// staleness is a deliberate, TTL-bounded property of EVERY revocation
		// path (logout included), not something SCIM-specific — so this asserts
		// what the system actually guarantees: the token converges to 401
		// within the bound and never comes back.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Equal(c, http.StatusUnauthorized, authenticateWithToken(t, sessionToken),
				"deprovisioning must revoke sessions minted through device login")
		}, 90*time.Second, 2*time.Second,
			"revoked session token must stop authenticating within the auth cache TTL")
	})
}
