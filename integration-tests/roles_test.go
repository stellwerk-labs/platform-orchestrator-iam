package integrationtests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoles(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	org := MustCreateTestOrg(cpInternalClient, t)
	user := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)
	var viewerRoleId uuid.UUID

	t.Run("list roles", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, 200, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			for _, role := range r.JSON200.Items {
				if role.DisplayName == api.RoleAdmin {
					assert.Equal(t, adminRoleId, role.Id)
					assert.Equal(t, []string{api.PermissionsManageAll}, role.Permissions)
				}
				if role.DisplayName == api.RoleDeployer {
					assert.Equal(t, []string{api.PermissionsWriteAll}, role.Permissions)
				}
				if role.DisplayName == api.RoleViewer {
					viewerRoleId = role.Id
					assert.Equal(t, []string{api.PermissionsReadAll}, role.Permissions)
				}
			}
			assert.NotEmpty(t, adminRoleId, "admin role not found")
			assert.NotEmpty(t, viewerRoleId, "viewer role not found")
		}
	})

	t.Run("get admin role", func(t *testing.T) {
		r, err := client.GetRoleWithResponse(t.Context(), org.Id, adminRoleId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, 200, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, api.RoleAdmin, r.JSON200.DisplayName)
			assert.Equal(t, []string{api.PermissionsManageAll}, r.JSON200.Permissions)
		}
	})

	t.Run("get viewer role", func(t *testing.T) {
		r, err := client.GetRoleWithResponse(t.Context(), org.Id, viewerRoleId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, 200, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, api.RoleViewer, r.JSON200.DisplayName)
			assert.Equal(t, []string{api.PermissionsReadAll}, r.JSON200.Permissions)
		}
	})

	t.Run("list roles again to verify data integrity", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, 200, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			for _, role := range r.JSON200.Items {
				if role.DisplayName == api.RoleAdmin {
					assert.Equal(t, adminRoleId, role.Id)
					assert.Equal(t, []string{api.PermissionsManageAll}, role.Permissions)
				}
				if role.DisplayName == api.RoleViewer {
					assert.Equal(t, viewerRoleId, role.Id)
					assert.Equal(t, []string{api.PermissionsReadAll}, role.Permissions)
				}
			}
		}
	})
}
