package integrationtests

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

func TestUserRegister(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	tu := TestUser{
		ProviderId:  rand.Text(),
		DisplayName: "bob.smith",
	}
	tut := MustGenerateTestUserTokenWith(t, tu)

	t.Run("google provider exists", func(t *testing.T) {
		// unfortunately can't really test this provider in integration tests :(
		r, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
			Provider:      "google",
			ProviderToken: "definitely-not-a-jwt",
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, "invalid provider token", r.JSON400.Message)
	})

	var userId uuid.UUID
	var sessionToken string
	t.Run("can register a user", func(t *testing.T) {
		r, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{
			XClientIP:     opt.Of("1.1.1.1").Ref(),
			XClientRegion: opt.Of("GB").Ref(),
			XClientCity:   opt.Of("London").Ref(),
		}, serverclient.RegisterUserBody{
			Provider:      "testuser",
			ProviderToken: tut,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, "bob.smith", r.JSON202.DisplayName)
		assert.Empty(t, r.JSON202.PrimaryEmailAddress)
		assert.NotEmpty(t, r.JSON202.LastLoggedInAt)
		assert.False(t, r.JSON202.IdentityAlreadyExists)
		userId = r.JSON202.Id

		cookies, err := http.ParseCookie(strings.Split(r.HTTPResponse.Header.Get("Set-Cookie"), ";")[0])
		require.NoError(t, err)
		if assert.Len(t, cookies, 1) {
			sessionToken = cookies[0].Value
		}
	})

	t.Run("should have a session", func(t *testing.T) {
		r, err := client.ListUserSessionTokensWithResponse(t.Context(), userId, &serverclient.ListUserSessionTokensParams{}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, "testuser", r.JSON200.Items[0].Provider)
				assert.Equal(t, "1.1.1.1", *r.JSON200.Items[0].ClientIp)
				assert.Equal(t, "GB", *r.JSON200.Items[0].ClientRegion)
				assert.Equal(t, "London", *r.JSON200.Items[0].ClientCity)
				assert.NotEmpty(t, r.JSON200.Items[0].CreatedAt)
				assert.NotEmpty(t, r.JSON200.Items[0].ExpiresAt)
				assert.NotEmpty(t, r.JSON200.Items[0].Hash)
			}
		}
	})

	t.Run("can register the same user again", func(t *testing.T) {
		r, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
			Provider:      "testuser",
			ProviderToken: tut,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, "bob.smith", r.JSON202.DisplayName)
		assert.True(t, r.JSON202.IdentityAlreadyExists)
		assert.Equal(t, userId, r.JSON202.Id)

		cookies, err := http.ParseCookie(strings.Split(r.HTTPResponse.Header.Get("Set-Cookie"), ";")[0])
		require.NoError(t, err)
		if assert.Len(t, cookies, 1) {
			assert.NotEqual(t, sessionToken, cookies[0].Value)
		}
	})

	var revokeHash string
	t.Run("should have two sessions", func(t *testing.T) {
		r, err := client.ListUserSessionTokensWithResponse(t.Context(), userId, &serverclient.ListUserSessionTokensParams{}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 2) {
				revokeHash = r.JSON200.Items[0].Hash
				assert.NotEqual(t, r.JSON200.Items[0].Hash, r.JSON200.Items[1].Hash)
			}
		}
	})

	t.Run("can revoke a session", func(t *testing.T) {
		{
			r, err := client.RevokeUserSessionTokenWithResponse(t.Context(), userId, revokeHash, WithAuthenticatedUserId(userId))
			require.NoError(t, err)
			require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}
		{
			r, err := client.ListUserSessionTokensWithResponse(t.Context(), userId, &serverclient.ListUserSessionTokensParams{}, WithAuthenticatedUserId(userId))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
				assert.Len(t, r.JSON200.Items, 1)
			}
		}
	})

	t.Run("different token is different user", func(t *testing.T) {
		r, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
			Provider:      "testuser",
			ProviderToken: MustGenerateTestUserToken(t),
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.False(t, r.JSON202.IdentityAlreadyExists)
		assert.NotEqual(t, userId, r.JSON202.Id)
	})

	t.Run("cannot list sessions of other users", func(t *testing.T) {
		r, err := client.ListUserSessionTokensWithResponse(t.Context(), uuid.New(), &serverclient.ListUserSessionTokensParams{}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can logout even without session token", func(t *testing.T) {
		r, err := client.LogoutSessionWithResponse(t.Context(), &serverclient.LogoutSessionParams{}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can login again - should be the same user with a new session", func(t *testing.T) {
		tu.Email = "bob.smith@example.com"
		tut = MustGenerateTestUserTokenWith(t, tu)

		r, err := client.LoginSessionWithResponse(t.Context(), &serverclient.LoginSessionParams{}, serverclient.LoginUserBody{
			Provider:      "testuser",
			ProviderToken: tut,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, "bob.smith", r.JSON200.DisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON200.PrimaryEmailAddress)
		assert.Equal(t, userId, r.JSON200.Id)

		cookies, err := http.ParseCookie(strings.Split(r.HTTPResponse.Header.Get("Set-Cookie"), ";")[0])
		require.NoError(t, err)
		if assert.Len(t, cookies, 1) {
			assert.NotEqual(t, sessionToken, cookies[0].Value)
			sessionToken = cookies[0].Value
		}
	})

	t.Run("can authenticate with the new session token", func(t *testing.T) {
		hv := "Bearer " + sessionToken
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &serverclient.InternalAuthenticateParams{
			Authorization: &hv,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, userId.String(), r.HTTPResponse.Header.Get("From"))
	})

	t.Run("cannot authenticate with the bad session token", func(t *testing.T) {
		hv := "Bearer " + base64.URLEncoding.EncodeToString([]byte("bad"))
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &serverclient.InternalAuthenticateParams{
			Authorization: &hv,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot authenticate with garbage", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), "GET", mustInternalServerURL(t)+"/internal/authenticate/some/path", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() {
			_ = resp.Body.Close()
		}()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("can request current user", func(t *testing.T) {
		{
			r, err := client.GetCurrentUserWithResponse(t.Context(), WithAuthenticatedUserId(userId))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			assert.Equal(t, "bob.smith", r.JSON200.DisplayName)
			assert.Equal(t, "bob.smith@example.com", *r.JSON200.PrimaryEmailAddress)
			assert.Equal(t, userId, r.JSON200.Id)
			assert.Equal(t, []string{"testuser"}, r.JSON200.LoginProviders)
			assert.Empty(t, r.JSON200.OrganizationMemberships)
		}
	})

	t.Run("login should accept empty header params", func(t *testing.T) {
		tu.Email = "bob.smith@example.com"
		tut = MustGenerateTestUserTokenWith(t, tu)

		r, err := client.LoginSessionWithResponse(t.Context(), &serverclient.LoginSessionParams{
			XClientIP:     opt.Of("").Ref(),
			XClientRegion: opt.Of("").Ref(),
			XClientCity:   opt.Of("").Ref(),
		}, serverclient.LoginUserBody{
			Provider:      "testuser",
			ProviderToken: tut,
		})

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can logout and revoke session", func(t *testing.T) {
		raw, err := base64.URLEncoding.DecodeString(sessionToken)
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		h := base64.URLEncoding.EncodeToString(sum[:])

		getTokenHashes := func() []string {
			r, err := client.ListUserSessionTokensWithResponse(t.Context(), userId, &serverclient.ListUserSessionTokensParams{}, WithAuthenticatedUserId(userId))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			return slices.Collect(func(yield func(string) bool) {
				for _, item := range r.JSON200.Items {
					yield(item.Hash)
				}
			})
		}

		assert.Contains(t, getTokenHashes(), h)
		{
			r, err := client.LogoutSessionWithResponse(t.Context(), &serverclient.LogoutSessionParams{
				XTokenHash: &h,
			}, WithAuthenticatedUserId(userId))
			require.NoError(t, err)
			require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}
		assert.NotContains(t, getTokenHashes(), h)

	})

}
