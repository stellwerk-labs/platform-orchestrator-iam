package integrationtests

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

func TestServiceUserTokens(t *testing.T) {
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
	org2 := MustCreateTestOrg(cpInternalClient, t)
	adminRoleId2 := MustObtainRoleIdByName(t, client, org2.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org2.Id, user.Id, adminRoleId2)
	cpClient := MustControlPlaneClient(t)
	project := MustCreateProject(t, cpClient, org.Id, "test-pj-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "test-env-"+strings.ToLower(rand.Text()))

	t.Run("no service users exist", func(t *testing.T) {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s user %s/%s", r.StatusCode(), string(r.Body), org.Id, user.Id) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	var viewerRoleId uuid.UUID

	t.Run("can list roles", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 3)
			var adminRoleFound bool
			for _, role := range r.JSON200.Items {
				switch role.DisplayName {
				case DefaultAdminRoleName:
					assert.Equal(t, adminRoleId, role.Id)
					adminRoleFound = true
				case DefaultViewerRoleName:
					viewerRoleId = role.Id
				}
			}
			assert.True(t, adminRoleFound, "admin role not found")
			assert.NotEmpty(t, adminRoleId)
		}
	})

	var su serverclient.ServiceUserWithToken
	t.Run("create service user", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
			Roles: &[]serverclient.ServiceUserRole{
				// the second entry here is to test that multiple roles can be assigned
				{Id: adminRoleId}, {Id: viewerRoleId, Scope: ptr("project:" + project.Uuid.String())},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			su = *r.JSON201
			assert.NotEmpty(t, su.Token)
			assert.Regexp(t, "^SU-.+", su.Token)
			assert.NotEmpty(t, su.Id)
			assert.Equal(t, "my-service-user", su.DisplayName)
			assert.NotEmpty(t, su.GeneratedAt)
			assert.NotEmpty(t, su.GeneratedBy)
			assert.Greater(t, su.CurrentTokenExpiresAt, su.GeneratedAt)
			if assert.GreaterOrEqual(t, len(su.Roles), 1) {
				assert.Equal(t, adminRoleId, su.Roles[0].Id)
			}
		}
	})

	t.Run("service user should now have all permissions on the org", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{authz.CanReadOrgCheck(org.Id), authz.CanManageOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id)}, WithAuthenticatedUserId(su.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				assert.Equal(collect, []serverclient.ResourcePermissionCheckResultItem{{
					Allowed:         true,
					PermissionCheck: authz.CanReadOrgCheck(org.Id),
				}, {Allowed: true, PermissionCheck: authz.CanManageOrgCheck(org.Id)}, {Allowed: true, PermissionCheck: authz.CanWriteOrgCheck(org.Id)}}, resp.JSON200.Items)
			}
		}, time.Second*30, time.Second*3, "service user did not get proper permissions in time")
	})

	t.Run("service user should be in the list of users with permissions on a project", func(t *testing.T) {
		r, err := client.ListProjectUsersWithResponse(t.Context(), org.Id, project.Id, &serverclient.ListProjectUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 2)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == su.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == adminRoleId && item.Type == serverclient.UserWithRoleTypeServiceUser
			}), -1)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == user.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == adminRoleId && item.Type == serverclient.UserWithRoleTypeUser
			}), -1)
		}
	})

	t.Run("service user should be in the list of users with permissions on a project and it should be possible to filter only service users", func(t *testing.T) {
		r, err := client.ListProjectUsersWithResponse(t.Context(), org.Id, project.Id, &serverclient.ListProjectUsersParams{
			Type: ref.Ref(serverclient.ListProjectUsersParamsTypeServiceUser),
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 1)
			assert.Equal(t, serverclient.UserWithRole{Id: su.Id, SubjectType: serverclient.SubjectTypeRole, SubjectId: adminRoleId, Type: serverclient.UserWithRoleTypeServiceUser}, r.JSON200.Items[0])
		}
	})

	t.Run("service user should be in the list of users with permissions on an environment", func(t *testing.T) {
		r, err := client.ListEnvironmentUsersWithResponse(t.Context(), org.Id, project.Id, env.Id, &serverclient.ListEnvironmentUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 2)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == su.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == adminRoleId && item.Type == serverclient.UserWithRoleTypeServiceUser
			}), -1)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == user.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == adminRoleId && item.Type == serverclient.UserWithRoleTypeUser
			}), -1)
		}
	})

	t.Run("service user should be in the list of users with permissions on an environment and it should be possible to filter only service users", func(t *testing.T) {
		r, err := client.ListEnvironmentUsersWithResponse(t.Context(), org.Id, project.Id, env.Id, &serverclient.ListEnvironmentUsersParams{
			Type: ref.Ref(serverclient.ListEnvironmentUsersParamsTypeServiceUser),
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 1)
			assert.Equal(t, serverclient.UserWithRole{Id: su.Id, SubjectType: serverclient.SubjectTypeRole, SubjectId: adminRoleId, Type: serverclient.UserWithRoleTypeServiceUser}, r.JSON200.Items[0])
		}
	})

	t.Run("cannot authenticate with bad token", func(t *testing.T) {
		auth := "Bearer " + su.Token + su.Token
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &serverclient.InternalAuthenticateParams{
			Authorization: &auth,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can authenticate", func(t *testing.T) {
		auth := "Bearer " + su.Token
		r, err := internalClient.InternalAuthenticateWithResponse(t.Context(), &serverclient.InternalAuthenticateParams{
			Authorization: &auth,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, su.Id.String(), r.HTTPResponse.Header.Get("From"))
	})

	t.Run("is authorized on org", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: su.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanReadOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("but cannot create other service users", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
		}, WithAuthenticatedUserId(su.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Contains(t, r.JSON400.Message, "service users may not create service users")
		}
	})

	t.Run("list is not empty", func(t *testing.T) {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			require.Len(t, r.JSON200.Items, 1)
			if assert.GreaterOrEqual(t, len(r.JSON200.Items[0].Roles), 1) {
				assert.NotEmpty(t, r.JSON200.Items[0].Roles[0].Id)
			}
		}
	})

	t.Run("regenerate", func(t *testing.T) {
		r, err := client.RegenerateServiceUserWithResponse(t.Context(), org.Id, su.Id, serverclient.RegenerateServiceUserJSONRequestBody{
			ExpiryInDays: 30,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.NotEmpty(t, su.Token)
			assert.NotEqual(t, su.Token, r.JSON200.Token)
			assert.Equal(t, su.Id, r.JSON200.Id)
			assert.Equal(t, su.DisplayName, r.JSON200.DisplayName)
			assert.Greater(t, r.JSON200.GeneratedAt, su.GeneratedAt)
			assert.NotEmpty(t, r.JSON200.GeneratedBy)
			assert.Greater(t, r.JSON200.CurrentTokenExpiresAt, su.CurrentTokenExpiresAt)
			su = *r.JSON200
		}
	})

	t.Run("delete", func(t *testing.T) {
		r, err := client.DeleteServiceUserWithResponse(t.Context(), org.Id, su.Id, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("service user should not have permissions on the org anymore", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{authz.CanReadOrgCheck(org.Id), authz.CanManageOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id)}, WithAuthenticatedUserId(su.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				assert.Equal(collect, []serverclient.ResourcePermissionCheckResultItem{{
					Allowed:         false,
					PermissionCheck: authz.CanReadOrgCheck(org.Id),
				}, {Allowed: false, PermissionCheck: authz.CanManageOrgCheck(org.Id)}, {Allowed: false, PermissionCheck: authz.CanWriteOrgCheck(org.Id)}}, resp.JSON200.Items)
			}
		}, time.Second*30, time.Second*3, "service user did not get proper permissions revoked in time")
	})

	t.Run("no service users exist", func(t *testing.T) {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	t.Run("create service user with viewer role and scoped roles", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
			Roles: &[]serverclient.ServiceUserRole{
				{
					Id: viewerRoleId,
				},
				{
					Id:    adminRoleId,
					Scope: ptr("project:" + project.Uuid.String()),
				},
				{
					Id:    adminRoleId,
					Scope: ptr("env:" + env.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			su = *r.JSON201
			assert.NotEmpty(t, su.Token)
			assert.Regexp(t, "^SU-.+", su.Token)
			assert.NotEmpty(t, su.Id)
			assert.Equal(t, "my-service-user", su.DisplayName)
			assert.NotEmpty(t, su.GeneratedAt)
			assert.NotEmpty(t, su.GeneratedBy)
			assert.Greater(t, su.CurrentTokenExpiresAt, su.GeneratedAt)
			assert.Len(t, su.Roles, 3)
			assert.Equal(t, viewerRoleId, su.Roles[0].Id)
			assert.Empty(t, su.Roles[0].Scope)
			assert.Equal(t, adminRoleId, su.Roles[1].Id)
			assert.Equal(t, "project:"+project.Uuid.String(), *su.Roles[1].Scope)
			assert.Equal(t, adminRoleId, su.Roles[2].Id)
			assert.Equal(t, "env:"+env.Uuid.String(), *su.Roles[2].Scope)
		}
	})

	t.Run("listing service user shows scoped roles", func(t *testing.T) {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 1) && assert.Len(t, r.JSON200.Items[0].Roles, 3) {
				assert.Equal(t, viewerRoleId, r.JSON200.Items[0].Roles[0].Id)
				assert.Empty(t, r.JSON200.Items[0].Roles[0].Scope)
				assert.Equal(t, adminRoleId, r.JSON200.Items[0].Roles[1].Id)
				assert.NotNil(t, r.JSON200.Items[0].Roles[1].Scope)
				assert.Equal(t, "project:"+project.Uuid.String(), *r.JSON200.Items[0].Roles[1].Scope)
				assert.Equal(t, adminRoleId, r.JSON200.Items[0].Roles[2].Id)
				assert.NotNil(t, r.JSON200.Items[0].Roles[2].Scope)
				assert.Equal(t, "env:"+env.Uuid.String(), *r.JSON200.Items[0].Roles[2].Scope)
			}
		}
	})

	t.Run("service user is not an admin of the org anyway", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: su.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanManageOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("service user is a viewer of the org but has admin privileges on project and env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: su.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanManageProjectCheck(project.Uuid),
					authz.CanManageEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, time.Second*30, time.Second*3, "service user %s did not get proper permissions in time", su.Id)
	})

	deployerRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultDeployerRoleName)
	t.Run("update service user with viewer role and deployer role instead of admin", func(t *testing.T) {
		r, err := client.ReplaceServiceUserRolesWithResponse(t.Context(), org.Id, su.Id, serverclient.ReplaceServiceUserRolesJSONRequestBody{
			Roles: []serverclient.ServiceUserRole{
				{
					Id: viewerRoleId,
				},
				{
					Id:    deployerRoleId,
					Scope: ptr("project:" + project.Uuid.String()),
				},
				{
					Id:    deployerRoleId,
					Scope: ptr("env:" + env.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			require.Len(t, r.JSON200.Roles, 3)
			assert.Equal(t, serverclient.ServiceUserRole{Id: viewerRoleId, Scope: ref.Ref("")}, r.JSON200.Roles[0])
			assert.Equal(t, serverclient.ServiceUserRole{Id: deployerRoleId, Scope: ref.Ref("env:" + env.Uuid.String())}, r.JSON200.Roles[1])
			assert.Equal(t, serverclient.ServiceUserRole{Id: deployerRoleId, Scope: ref.Ref("project:" + project.Uuid.String())}, r.JSON200.Roles[2])
		}
	})

	t.Run("replacing service user roles with duplicate roles returns 409", func(t *testing.T) {
		r, err := client.ReplaceServiceUserRolesWithResponse(t.Context(), org.Id, su.Id, serverclient.ReplaceServiceUserRolesJSONRequestBody{
			Roles: []serverclient.ServiceUserRole{
				{
					Id: viewerRoleId,
				},
				{
					Id: viewerRoleId,
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("service user has no more admin privileges on project and env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: su.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanManageProjectCheck(project.Uuid),
					authz.CanManageEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, time.Second*30, time.Second*3, "service user %s did not lose permissions in time", su.Id)
	})

	t.Run("service user role should now be updated in the project users", func(t *testing.T) {
		r, err := client.ListProjectUsersWithResponse(t.Context(), org.Id, project.Id, &serverclient.ListProjectUsersParams{
			Type: ref.Ref(serverclient.ListProjectUsersParamsTypeServiceUser),
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 1)
			assert.Equal(t, serverclient.UserWithRole{Id: su.Id, SubjectType: serverclient.SubjectTypeRole, SubjectId: deployerRoleId, Type: serverclient.UserWithRoleTypeServiceUser}, r.JSON200.Items[0])
		}
	})

	t.Run("service user should be in the list of users with permissions on a project", func(t *testing.T) {
		r, err := client.ListProjectUsersWithResponse(t.Context(), org.Id, project.Id, &serverclient.ListProjectUsersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 2)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == su.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == deployerRoleId && item.Type == serverclient.UserWithRoleTypeServiceUser
			}), -1)
			assert.Greater(t, slices.IndexFunc(r.JSON200.Items, func(item serverclient.UserWithRole) bool {
				return item.Id == user.Id && item.SubjectType == serverclient.SubjectTypeRole && item.SubjectId == adminRoleId && item.Type == serverclient.UserWithRoleTypeUser
			}), -1)
		}
	})

	t.Run("service user is a viewer of the org but has deployer privileges on project and env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: su.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, time.Second*30, time.Second*3, "service user %s did not get proper permissions in time", su.Id)
	})

	t.Run("can create another service user with the same role", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-other-service-user",
			ExpiryInDays: 14,
			Roles: &[]serverclient.ServiceUserRole{
				{
					Id: viewerRoleId,
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			su = *r.JSON201
			assert.NotEmpty(t, su.Token)
			assert.Regexp(t, "^SU-.+", su.Token)
			assert.NotEmpty(t, su.Id)
			assert.Equal(t, "my-other-service-user", su.DisplayName)
			assert.NotEmpty(t, su.GeneratedAt)
			assert.NotEmpty(t, su.GeneratedBy)
			assert.Greater(t, su.CurrentTokenExpiresAt, su.GeneratedAt)
			assert.Len(t, su.Roles, 1)
			assert.Equal(t, viewerRoleId, su.Roles[0].Id)
		}
	})

	t.Run("cannot create service user with invalid role", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
			Roles: &[]serverclient.ServiceUserRole{
				{
					Id: uuid.New(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Contains(t, r.JSON409.Message, "role not found in the organization")
		}
	})

	t.Run("cannot use service user token in other org", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org2.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
			Roles: &[]serverclient.ServiceUserRole{
				{
					Id: uuid.New(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Contains(t, r.JSON409.Message, "role not found in the organization")
		}
	})

}

func TestServiceUserPagination(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	org := MustCreateTestOrg(MustInternalControlPlaneClient(t), t)
	user := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	created := make(map[uuid.UUID]struct{}, 5)
	for i := range 5 {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  fmt.Sprintf("pagination-service-user-%d", i),
			ExpiryInDays: 1,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		require.NotNil(t, r.JSON201)
		created[r.JSON201.Id] = struct{}{}
	}

	perPage := 2
	var page *string
	seen := make(map[uuid.UUID]int, len(created))
	for {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{
			Page:    page,
			PerPage: &perPage,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		require.NotNil(t, r.JSON200)
		for _, serviceUser := range r.JSON200.Items {
			seen[serviceUser.Id]++
		}
		page = r.JSON200.NextPageToken
		if page == nil {
			break
		}
	}

	require.Len(t, seen, len(created))
	for id := range created {
		require.Equal(t, 1, seen[id], "service user %s was skipped or repeated", id)
	}

	invalidPage := "not-a-uuid"
	r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{
		Page: &invalidPage,
	}, WithAuthenticatedUserId(user.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
}

func TestListUsersWithInvalidCursor(t *testing.T) {
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

	cpClient := MustControlPlaneClient(t)
	project := MustCreateProject(t, cpClient, org.Id, "test-project-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "test-env-"+strings.ToLower(rand.Text()))

	t.Run("list project users with invalid cursor returns 400", func(t *testing.T) {
		invalidCursor := "this-is-not-a-valid-cursor"
		r, err := client.ListProjectUsersWithResponse(t.Context(), org.Id, project.Id, &serverclient.ListProjectUsersParams{
			Page: &invalidCursor,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode(), "expected 400 for invalid cursor, got %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("list environment users with invalid cursor returns 400", func(t *testing.T) {
		invalidCursor := "this-is-not-a-valid-cursor"
		r, err := client.ListEnvironmentUsersWithResponse(t.Context(), org.Id, project.Id, env.Id, &serverclient.ListEnvironmentUsersParams{
			Page: &invalidCursor,
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode(), "expected 400 for invalid cursor, got %d %s", r.StatusCode(), string(r.Body))
	})
}
