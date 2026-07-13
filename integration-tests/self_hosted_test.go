// This file contains specific tests that run against a self-hosted IAM instance (SELF_HOSTED_IAM_URL).
package integrationtests

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// keycloakLogin programmatically authenticates with Keycloak by simulating a browser login.
// It rewrites Docker-internal URLs to localhost, fetches the login page, submits credentials,
// and captures the authorization code from the redirect.
func keycloakLogin(t *testing.T, authURL string) string {
	t.Helper()

	// Rewrite keycloak:8080 (Docker internal) to localhost:8180 (host-accessible)
	hostAuthURL := strings.Replace(authURL, "keycloak:8080", "localhost:8180", 1)
	t.Logf("Auth URL: %s", hostAuthURL)

	// HTTP client that does NOT follow redirects — we need to capture the 302 Location
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET the Keycloak login page
	resp, err := noRedirectClient.Get(hostAuthURL) //nolint:gosec
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	// Keycloak may redirect auth → login page; follow manually to collect cookies
	var cookies []*http.Cookie
	cookies = append(cookies, resp.Cookies()...)
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected Keycloak login page")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Parse the form action URL from the HTML login page
	actionRe := regexp.MustCompile(`action="([^"]+)"`)
	matches := actionRe.FindSubmatch(body)
	require.NotEmpty(t, matches, "could not find form action in Keycloak login page")

	formAction := strings.ReplaceAll(string(matches[1]), "&amp;", "&")
	// Form action URL uses Docker-internal hostname, rewrite to host-accessible
	formAction = strings.Replace(formAction, "keycloak:8080", "localhost:8180", 1)

	// POST username/password to the form action, forwarding all collected cookies
	formData := url.Values{
		"username": {"testuser"},
		"password": {"testpassword"},
	}
	postReq, err := http.NewRequest("POST", formAction, strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		postReq.AddCookie(c)
	}
	resp, err = noRedirectClient.Do(postReq)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	require.Equal(t, http.StatusFound, resp.StatusCode, "expected 302 redirect after login")

	// Extract the authorization code from the redirect Location header
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "missing Location header in redirect")

	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "missing code in redirect URL query params")

	return code
}

func TestKeycloakSso(t *testing.T) {
	selfHostedIamUrl := os.Getenv("SELF_HOSTED_IAM_URL")
	if selfHostedIamUrl == "" {
		t.Skip("SELF_HOSTED_IAM_URL not set, skipping Keycloak SSO tests")
	}

	cpClient := MustInternalControlPlaneClient(t)
	org := MustCreateTestOrg(cpClient, t)

	client, err := serverclient.NewClientWithResponses(selfHostedIamUrl, serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	var redirectUrl string
	var state string
	var firstUserId uuid.UUID

	t.Run("init sso login", func(t *testing.T) {
		r, err := client.RequestSsoLoginWithResponse(t.Context(), serverclient.RequestSsoLoginJSONRequestBody{OrgId: org.Id})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d: %s", r.StatusCode(), string(r.Body))

		redirectUrl = r.JSON200.RedirectUrl
		assert.Contains(t, redirectUrl, "openid-connect/auth")

		parsedUrl, err := url.Parse(redirectUrl)
		require.NoError(t, err)
		state = parsedUrl.Query().Get("state")
		require.NotEmpty(t, state, "state should be present in redirect URL")
	})

	t.Run("full sso login success (new user)", func(t *testing.T) {
		code := keycloakLogin(t, redirectUrl)

		r, err := client.GetSsoCallbackWithResponse(t.Context(), &serverclient.GetSsoCallbackParams{Code: &code, State: &state})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d: %s", r.StatusCode(), string(r.Body))

		user := r.JSON200
		assert.Equal(t, "testuser@example.com", *user.PrimaryEmailAddress)
		assert.Equal(t, "Test User", user.DisplayName)
		assert.Contains(t, user.LoginProviders, "sso")
		assert.NotNil(t, user.LastLoggedInAt)

		// Verify session cookie is set
		setCookie := r.HTTPResponse.Header.Get("Set-Cookie")
		assert.NotEmpty(t, setCookie, "expected session cookie to be set")

		firstUserId = user.Id
	})

	t.Run("sso login again (existing user)", func(t *testing.T) {
		// Init a new SSO flow to get a fresh state and redirect URL
		r, err := client.RequestSsoLoginWithResponse(t.Context(), serverclient.RequestSsoLoginJSONRequestBody{OrgId: org.Id})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d: %s", r.StatusCode(), string(r.Body))

		newRedirectUrl := r.JSON200.RedirectUrl
		parsedUrl, err := url.Parse(newRedirectUrl)
		require.NoError(t, err)
		newState := parsedUrl.Query().Get("state")

		code := keycloakLogin(t, newRedirectUrl)

		cbResp, err := client.GetSsoCallbackWithResponse(t.Context(), &serverclient.GetSsoCallbackParams{Code: &code, State: &newState})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, cbResp.StatusCode(), "unexpected status %d: %s", cbResp.StatusCode(), string(cbResp.Body))

		user := cbResp.JSON200
		assert.Equal(t, firstUserId, user.Id, "should be the same user on second login")
		assert.NotNil(t, user.LastLoggedInAt, "LastLoggedInAt should be set")
	})

	t.Run("callback with invalid code", func(t *testing.T) {
		r, err := client.GetSsoCallbackWithResponse(t.Context(), &serverclient.GetSsoCallbackParams{Code: opt.Of("INVALIDCODE").Ref(), State: &state})
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, r.StatusCode(), "unexpected status %d: %s", r.StatusCode(), string(r.Body))
	})

	t.Run("callback with error description", func(t *testing.T) {
		r, err := client.GetSsoCallbackWithResponse(t.Context(), &serverclient.GetSsoCallbackParams{ErrorDescription: opt.Of("Unauthorized").Ref()})
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, r.StatusCode(), "unexpected status %d: %s", r.StatusCode(), string(r.Body))
	})
}
