package integrationtests

import (
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
)

func TestScopedRoles(t *testing.T) {
	t.Parallel()
	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)
	adminRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	otherUser := MustRegisterTestUser(client, t)
	deployerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultDeployerRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, otherUser.Id, deployerRoleId)

	cpClient := MustControlPlaneClient(t)
	project := MustCreateProject(t, cpClient, org.Id, "pg-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "env-"+strings.ToLower(rand.Text()))

	viewerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultViewerRoleName)

	t.Run("deployer user has write permission at every scope", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanWriteOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, 10*time.Second, 1*time.Second, "deployer user should have read org permission")
	})

	t.Run("can update the deployer role to be a viewer", func(t *testing.T) {
		res, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), "unexpected status %d %s", res.StatusCode(), string(res.Body))
	})

	t.Run("user shouldn't have write permission anymore", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanWriteOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			if assert.Equal(collect, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
				failedChecks, ok := (*r.JSON403.Details)["failed_checks"].([]interface{})
				assert.True(t, ok)
				assert.Len(collect, failedChecks, 3, "expected all 3 checks to fail")

			}
		}, 30*time.Second, 3*time.Second, "user should not have write permissions anymore")
	})

	t.Run("can add a scoped role to the viewer user", func(t *testing.T) {
		res, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     deployerRoleId.String(),
					Scope:       ref.Ref("project:" + project.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), "unexpected status %d %s", res.StatusCode(), string(res.Body))
	})

	t.Run("viewer user with scoped permissions has now write permission on the scope", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, 30*time.Second, 1*time.Second, "viewer user should have the expected permissions on the scope")
	})

	t.Run("can remove the scoped role from the viewer user", func(t *testing.T) {
		res, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), "unexpected status %d %s", res.StatusCode(), string(res.Body))
	})

	t.Run("user shouldn't have write permission anymore", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanWriteOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			if assert.Equal(collect, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
				failedChecks, ok := (*r.JSON403.Details)["failed_checks"].([]interface{})
				assert.True(t, ok)
				assert.Len(collect, failedChecks, 3, "expected all 3 checks to fail")

			}
		}, 30*time.Second, 3*time.Second, "user should not have write permissions anymore")
	})

}
