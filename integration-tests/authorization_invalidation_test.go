package integrationtests

import (
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

func TestNATSAuthorizationInvalidation(t *testing.T) {
	selfHostedURL, err := url.Parse(os.Getenv("SELF_HOSTED_IAM_URL"))
	require.NoError(t, err)
	if selfHostedURL.Host == "" {
		t.Skip("SELF_HOSTED_IAM_URL not set")
	}

	primary, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	peer, err := serverclient.NewClientWithResponses(selfHostedURL.String(), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	org := MustCreateTestOrg(MustInternalControlPlaneClient(t), t)
	user := MustRegisterTestUser(primary, t)
	adminRoleID := MustObtainRoleIdByName(t, primary, org.Id, DefaultAdminRoleName)
	check := authz.CanReadOrgCheck(org.Id)

	denied, err := peer.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
		UserId: user.Id,
		Checks: []serverclient.ResourcePermissionCheck{check},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, denied.StatusCode(), "the peer must cache the initial denial")

	started := time.Now()
	created, err := primary.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
		UserId:      user.Id,
		SubjectType: serverclient.SubjectTypeRole,
		Subject:     adminRoleID.String(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, created.StatusCode(), "unexpected status %d %s", created.StatusCode(), string(created.Body))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		allowed, err := peer.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: user.Id,
			Checks: []serverclient.ResourcePermissionCheck{check},
		})
		assert.NoError(collect, err)
		if allowed != nil {
			assert.Equal(collect, http.StatusNoContent, allowed.StatusCode())
		}
	}, 2*time.Second, 10*time.Millisecond, "the peer did not process the NATS invalidation")

	t.Logf("cross-instance authorization invalidation completed in %s", time.Since(started))
}
