package integrationtests

import (
	"crypto/rand"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
)

func TestOrgActions(t *testing.T) {
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

	t.Run("list roles", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, 200, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.True(t, slices.ContainsFunc(r.JSON200.Items, func(role serverclient.Role) bool {
				return role.DisplayName == api.RoleAdmin && role.Id == adminRoleId && slices.Equal(role.Permissions, []string{api.PermissionsManageAll})
			}), "admin role not found or does not match expected values")
		}
	})

	var serviceUserId uuid.UUID

	t.Run("create new service user with admin role", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.CreateServiceUserJSONRequestBody{
			DisplayName:  "service-user-1",
			Roles:        &[]serverclient.ServiceUserRole{{Id: adminRoleId}},
			ExpiryInDays: 180,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			serviceUser := r.JSON201
			serviceUserId = serviceUser.Id
		}
	})

	t.Run("sync org to spicedb", func(t *testing.T) {
		// First sync may add relationships from service user creation, retry until stable
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalSyncOrgToSpiceDBWithResponse(t.Context(), org.Id, WithAuthenticatedUserId(user.Id))

			assert.NoError(collect, err)
			assert.Equal(collect, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			assert.Zero(collect, *r.JSON200.Removed, "expected 0 relationships to be removed, got %d", *r.JSON200.Removed)

		}, time.Second*30, time.Second*1, "sync should stabilize with 0 additions")

		// prove user has proper permissions via SpiceDB
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{authz.CanReadOrgCheck(org.Id), authz.CanManageOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id)}, WithAuthenticatedUserId(serviceUserId))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				assert.Equal(collect, []serverclient.ResourcePermissionCheckResultItem{{
					Allowed:         true,
					PermissionCheck: authz.CanReadOrgCheck(org.Id),
				}, {Allowed: true, PermissionCheck: authz.CanManageOrgCheck(org.Id)}, {Allowed: true, PermissionCheck: authz.CanWriteOrgCheck(org.Id)}}, resp.JSON200.Items)
			}
		}, time.Second*30, time.Second*3, "service user did not get proper permissions in time")
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{authz.CanReadOrgCheck(org.Id), authz.CanManageOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id)}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				assert.Equal(collect, []serverclient.ResourcePermissionCheckResultItem{{
					Allowed:         true,
					PermissionCheck: authz.CanReadOrgCheck(org.Id),
				}, {Allowed: true, PermissionCheck: authz.CanManageOrgCheck(org.Id)}, {Allowed: true, PermissionCheck: authz.CanWriteOrgCheck(org.Id)}}, resp.JSON200.Items)
			}
		}, time.Second*30, time.Second*3, "user did not get proper permissions in time")
	})

	t.Run("sync org with delete and recreate to spicedb", func(t *testing.T) {
		r, err := internalClient.InternalSyncOrgToSpiceDBWithResponse(t.Context(), org.Id, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Zero(t, *r.JSON200.Removed, "expected 0 relationships to be removed, got %d", *r.JSON200.Removed)
		}
	})

	t.Run("sync org scopes", func(t *testing.T) {
		_ = MustCreateProject(t, MustControlPlaneClient(t), org.Id, "test-pj-"+strings.ToLower(rand.Text()))

		r, err := internalClient.InternalSyncOrgScopesWithResponse(t.Context(), org.Id, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, 1, r.JSON200.ProjectsSynced, "expected 1 project to be synced, got %d", r.JSON200.ProjectsSynced)
			assert.Zero(t, r.JSON200.EnvironmentsSynced, "expected 0 envs to be synced, got %d", r.JSON200.EnvironmentsSynced)
			// project -> org (1), scoped roles -> project (3), scoped roles -> org (3)
			assert.Equal(t, 7, r.JSON200.RelationshipsAdded, "expected 5 relationships to be added, got %d", r.JSON200.RelationshipsAdded)
		}
	})
}
