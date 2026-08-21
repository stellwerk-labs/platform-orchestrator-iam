package integrationtests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestDeviceLoginRequests(t *testing.T) {
	t.Parallel()

	client, err := genclient.NewClientWithResponses(mustServerURL(t), genclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := genclient.NewClientWithResponses(mustInternalServerURL(t), genclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	user := MustRegisterTestUser(client, t)

	t.Run("cannot get device login request that doesn't exist", func(t *testing.T) {
		r, err := client.GetDeviceLoginRequestWithResponse(t.Context(), "blah", WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot poll device login request that doesn't exist", func(t *testing.T) {
		r, err := client.PollDeviceLoginRequestWithResponse(t.Context(), uuid.New(), &genclient.PollDeviceLoginRequestParams{PollingToken: "blah"})
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot accept device login request that doesn't exist", func(t *testing.T) {
		r, err := client.AcceptDeviceLoginRequestWithResponse(t.Context(), uuid.New(), WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot reject device login request that doesn't exist", func(t *testing.T) {
		r, err := client.RejectDeviceLoginRequestWithResponse(t.Context(), uuid.New(), WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("authentication skipped for CLI device login requests", func(t *testing.T) {
		for _, path := range []string{
			"/auth/device",
			"/devicelogins/" + uuid.New().String() + "/actions/poll",
		} {
			r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &genclient.InternalAuthenticateParams{}, func(ctx context.Context, req *http.Request) error {
				req.URL.Path = "/internal/authenticate" + path
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status for %s %d %s", r.HTTPResponse.Request.URL, r.StatusCode(), string(r.Body))
		}
	})

	var deviceLoginRequest genclient.CreatedDeviceLoginRequest
	t.Run("can create device login request", func(t *testing.T) {
		userAgent := "my agent"
		r, err := client.RequestDeviceLoginWithResponse(t.Context(), &genclient.RequestDeviceLoginParams{
			UserAgent:     &userAgent,
			XClientIP:     opt.Of("1.1.1.1").Ref(),
			XClientRegion: opt.Of("GB").Ref(),
			XClientCity:   opt.Of("London").Ref(),
		}, genclient.RequestDeviceLoginJSONRequestBody{})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		deviceLoginRequest = *r.JSON201
	})

	t.Run("cannot poll device login request with incorrect code", func(t *testing.T) {
		r, err := client.PollDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, &genclient.PollDeviceLoginRequestParams{PollingToken: "bananas"})
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can poll device login request with correct code", func(t *testing.T) {
		r, err := client.PollDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, &genclient.PollDeviceLoginRequestParams{PollingToken: deviceLoginRequest.PollingToken})
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can get device login request", func(t *testing.T) {
		r, err := client.GetDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Code, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, deviceLoginRequest.Id, r.JSON200.Id)
		assert.Equal(t, "my agent", r.JSON200.UserAgent)
		assert.Equal(t, "1.1.1.1", *r.JSON200.ClientIp)
		assert.Equal(t, "London", *r.JSON200.ClientCity)
		assert.Equal(t, "GB", *r.JSON200.ClientRegion)
	})

	t.Run("cannot accept device login with service user", func(t *testing.T) {
		r, err := client.AcceptDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, WithAuthenticatedUserId(userid.NewServiceUserTokenId()))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can accept device login as human user", func(t *testing.T) {
		r, err := client.AcceptDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot reject accepted device login", func(t *testing.T) {
		r, err := client.RejectDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	var token string
	t.Run("can poll accepted device login", func(t *testing.T) {
		r, err := client.PollDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Id, &genclient.PollDeviceLoginRequestParams{PollingToken: deviceLoginRequest.PollingToken})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, deviceLoginRequest.Id, r.JSON200.Id)
		assert.NotEmpty(t, r.JSON200.Token)
		assert.Greater(t, r.JSON200.ExpiresAt, time.Now().UTC())
		token = r.JSON200.Token
	})

	t.Run("cannot get accepted device login", func(t *testing.T) {
		r, err := client.GetDeviceLoginRequestWithResponse(t.Context(), deviceLoginRequest.Code, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can use new session token", func(t *testing.T) {
		authheader := "Bearer " + token
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &genclient.InternalAuthenticateParams{
			Authorization: &authheader,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, user.Id.String(), r.HTTPResponse.Header.Get("From"))
	})

}
