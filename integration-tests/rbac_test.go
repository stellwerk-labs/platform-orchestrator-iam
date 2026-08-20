package integrationtests

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

func TestConfigurableRBAC(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	org := MustCreateTestOrg(MustInternalControlPlaneClient(t), t)
	admin := MustRegisterTestUser(client, t)
	adminRoleID := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, admin.Id, adminRoleID)

	member := MustRegisterTestUser(client, t)

	created, err := client.CreateRoleWithResponse(t.Context(), org.Id, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Auditor",
		Permissions: []string{"read_all"},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, created.StatusCode(), "unexpected status %d %s", created.StatusCode(), string(created.Body))
	require.NotNil(t, created.JSON201)
	assert.False(t, created.JSON201.IsSystem)
	roleID := created.JSON201.Id

	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, member.Id, roleID)

	checks := []serverclient.ResourcePermissionCheck{
		authz.CanReadOrgCheck(org.Id),
		authz.CanWriteOrgCheck(org.Id),
	}
	permissions, err := client.CheckPermissionsWithResponse(t.Context(), checks, WithAuthenticatedUserId(member.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, permissions.StatusCode(), "unexpected status %d %s", permissions.StatusCode(), string(permissions.Body))
	require.Equal(t, []serverclient.ResourcePermissionCheckResultItem{
		{Allowed: true, PermissionCheck: checks[0]},
		{Allowed: false, PermissionCheck: checks[1]},
	}, permissions.JSON200.Items)

	updated, err := client.UpdateRoleWithResponse(t.Context(), org.Id, roleID, serverclient.UpdateRoleJSONRequestBody{
		DisplayName: "Operator",
		Permissions: []string{"write_all"},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, updated.StatusCode(), "unexpected status %d %s", updated.StatusCode(), string(updated.Body))

	permissions, err = client.CheckPermissionsWithResponse(t.Context(), checks, WithAuthenticatedUserId(member.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, permissions.StatusCode(), "unexpected status %d %s", permissions.StatusCode(), string(permissions.Body))
	require.Equal(t, []serverclient.ResourcePermissionCheckResultItem{
		{Allowed: true, PermissionCheck: checks[0]},
		{Allowed: true, PermissionCheck: checks[1]},
	}, permissions.JSON200.Items)

	inUse, err := client.DeleteRoleWithResponse(t.Context(), org.Id, roleID, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, inUse.StatusCode(), "assigned roles must not be deleted")

	viewerRoleID := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultViewerRoleName)
	replaced, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, member.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
		Memberships: []serverclient.UserMembershipRequest{{SubjectType: serverclient.SubjectTypeRole, Subject: viewerRoleID.String()}},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, replaced.StatusCode(), "unexpected status %d %s", replaced.StatusCode(), string(replaced.Body))

	deleted, err := client.DeleteRoleWithResponse(t.Context(), org.Id, roleID, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, deleted.StatusCode(), "unexpected status %d %s", deleted.StatusCode(), string(deleted.Body))
}
