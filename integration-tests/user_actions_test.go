package integrationtests

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

func TestUserActions(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	t.Run("dismiss prompt", func(t *testing.T) {
		t.Parallel()
		user := MustRegisterTestUser(client, t)

		t.Run("current user should not have any dismissed prompts", func(t *testing.T) {
			r, err := client.GetCurrentUserWithResponse(t.Context(), WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			require.Empty(t, r.JSON200.DismissedPrompts)
		})

		t.Run("current user should dismiss a prompt", func(t *testing.T) {
			r, err := client.DismissPromptWithResponse(t.Context(), user.Id, &serverclient.DismissPromptParams{Id: "test"}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		})

		t.Run("current user should have one dismissed prompt", func(t *testing.T) {
			r, err := client.GetCurrentUserWithResponse(t.Context(), WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			require.Len(t, r.JSON200.DismissedPrompts, 1)
			require.Equal(t, "test", r.JSON200.DismissedPrompts[0])
		})
	})
}
