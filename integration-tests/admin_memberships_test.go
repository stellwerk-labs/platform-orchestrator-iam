package integrationtests

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestAdminMemberships_DuplicateMembershipConflict(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	// Create test user and org
	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)

	// Get admin role ID
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)

	// Add user to org with admin role
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	t.Run("creating duplicate membership via internal endpoint returns 409", func(t *testing.T) {
		// Try to create the same membership again - should return 409
		r, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, "membership conflict", r.JSON409.Message)
		}
	})

	t.Run("replacing memberships with duplicates returns 409", func(t *testing.T) {
		// Create another user to be managed
		targetUser := MustRegisterTestUser(client, t)

		// Add target user to org first
		viewerRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultViewerRoleName)
		_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, targetUser.Id, viewerRoleId)

		// Try to replace memberships with duplicate entries (same role twice)
		r, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(), // duplicate
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, "membership conflict", r.JSON409.Message)
		}
	})

}

func TestAdminMemberships_crud(t *testing.T) {
	t.Parallel()
	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)
	cpClient := MustControlPlaneClient(t)
	project := MustCreateProject(t, cpClient, org.Id, "pg-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "env-"+strings.ToLower(rand.Text()))

	t.Run("empty org has no memberships", func(t *testing.T) {
		r, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{}, WithInternalUserId)
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	t.Run("new user has no memberships", func(t *testing.T) {
		r, err := client.ListUserMembershipsWithResponse(t.Context(), user.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	var adminRoleId, viewerRoleId, deployerRoleId uuid.UUID
	t.Run("list roles in the org", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 3) {
				assert.Equal(t, DefaultAdminRoleName, r.JSON200.Items[0].DisplayName)
				adminRoleId = r.JSON200.Items[0].Id
				assert.Equal(t, "Deployer", r.JSON200.Items[1].DisplayName)
				deployerRoleId = r.JSON200.Items[1].Id
				assert.Equal(t, "Viewer", r.JSON200.Items[2].DisplayName)
				viewerRoleId = r.JSON200.Items[2].Id
			}
		}
	})

	t.Run("cannot add membership to unknown user", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      uuid.New(),
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, "user not found", f.JSON409.Message)
		}
	})

	var membershipId uuid.UUID
	t.Run("set user as admin", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.NotEmpty(t, f.JSON201.Id)
			assert.Equal(t, adminRoleId.String(), f.JSON201.Subject)
			assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
			assert.Equal(t, user.Id, f.JSON201.UserId)
			assert.NotEmpty(t, f.JSON201.CreatedAt)
			membershipId = f.JSON201.Id
		}
	})

	t.Run("user should now have all permissions on the org due to the spicedb snapshot", func(t *testing.T) {
		// prove user has proper permissions via SpiceDB
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
				authz.CanManageOrgCheck(org.Id), authz.CanReadOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id),
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(collect, err)
			if assert.Equal(collect, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				if assert.Len(t, resp.JSON200.Items, 3) {
					permMap := make(map[string]bool)
					for _, permResult := range resp.JSON200.Items {
						permMap[permResult.PermissionCheck.Permission] = permResult.Allowed
					}
					assert.True(collect, permMap["manage"], "expected manage permission", fmt.Sprintf("user %s should have manage permission on org %s", user.Id, org.Id))
					assert.True(collect, permMap["write"], "expected write permission", fmt.Sprintf("user %s should have write permission on org %s", user.Id, org.Id))
					assert.True(collect, permMap["read"], "expected read permission", fmt.Sprintf("user %s should have read permission on org %s", user.Id, org.Id))
				}
			}
		}, time.Second*30, time.Second*3, "user did not get proper permissions in time")
	})

	t.Run("request non existing permissions should receive an error", func(t *testing.T) {
		resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
			authz.CanManageOrgCheck(org.Id), {Permission: "dumb", Resource: "organization:" + org.Id},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body))
		assert.Equal(t, "permission request not valid: dumb on organization:"+org.Id, resp.JSON400.Message)
	})

	t.Run("should be visible in lists now", func(t *testing.T) {
		{
			r, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, user.Id, r.JSON200.Items[0].UserId)
				assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
			}
		}
		{
			r, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{UserId: &user.Id}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, user.Id, r.JSON200.Items[0].UserId)
				assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
			}
		}
		{
			r, err := client.ListUserMembershipsWithResponse(t.Context(), user.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, org.Id, r.JSON200.Items[0].OrgId)
				assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
			}
		}
		{
			r, err := client.ListUserMembershipsWithResponse(t.Context(), user.Id, &serverclient.ListUserMembershipsParams{OrgId: &org.Id}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, org.Id, r.JSON200.Items[0].OrgId)
				assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
			}
		}
	})

	t.Run("cannot list user if not authorized", func(t *testing.T) {
		r, err := client.ListUserMembershipsWithResponse(t.Context(), user.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(userid.NewHumanUserId()))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			require.JSONEq(t, `{"error":"HTTP-403","message":"Forbidden","details":{"failed_checks":[{"resource":"user:`+user.Id.String()+`","permission":"self"}]}}`, string(r.Body))
		}
	})

	t.Run("cannot delete if i'm not authorized", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), "other-org", membershipId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.JSONEq(t, `{"error":"HTTP-403","message":"Forbidden","details":{"failed_checks":[{"resource":"organization:other-org","permission":"manage"}]}}`, string(r.Body))
		}
	})

	t.Run("cannot delete last admin", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), org.Id, membershipId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, "cannot delete the only remaining admin membership", r.JSON409.Message)
		}
	})

	t.Run("cannot delete if not exists", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), "unknown org", membershipId, WithInternalUserId)
		require.NoError(t, err)
		if assert.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, "membership not found", r.JSON404.Message)
		}
		r, err = client.DeleteOrgMembershipWithResponse(t.Context(), org.Id, uuid.New(), WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, "membership not found", r.JSON404.Message)
		}
	})

	t.Run("user should be authorized on this org", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: user.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanReadOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("user should not be authorized on another org", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: user.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanReadOrgCheck("unknown-org"),
			},
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, &serverclient.Error{
				Error:   "HTTP-403",
				Message: "one or more authorization checks failed",
				Details: &map[string]interface{}{
					"failed_checks": []interface{}{
						map[string]interface{}{
							"resource":   "organization:unknown-org",
							"permission": "read",
						},
					},
				},
			}, r.JSON403)
		}

	})

	org2 := MustCreateTestOrg(cpInternalClient, t)
	var adminRoleIdOrg2 uuid.UUID
	t.Run("list roles in the new org", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org2.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 3) {
				assert.Equal(t, DefaultAdminRoleName, r.JSON200.Items[0].DisplayName)
				adminRoleIdOrg2 = r.JSON200.Items[0].Id
				assert.Equal(t, "Deployer", r.JSON200.Items[1].DisplayName)
				assert.NotEqual(t, deployerRoleId, r.JSON200.Items[1].Id)
				assert.Equal(t, "Viewer", r.JSON200.Items[2].DisplayName)
			}
		}
	})

	t.Run("cannot add admin membership with role id of another org", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleIdOrg2.String(), // role from org2
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, "role not found in the organization", f.JSON409.Message)
		}
	})

	t.Run("can add admin membership to orgs with roles already defined", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org2.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleIdOrg2.String(),
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			if assert.NotEmpty(t, f.JSON201.Id) {
				assert.Equal(t, adminRoleIdOrg2.String(), f.JSON201.Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
				assert.Equal(t, user.Id, f.JSON201.UserId)
				assert.NotEmpty(t, f.JSON201.CreatedAt)
			}
		}
	})

	otherUser := MustRegisterTestUser(client, t)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, otherUser.Id, deployerRoleId)

	t.Run("can write any project / env", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: otherUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanWriteOrgCheck(org.Id),
				authz.CanWriteProjectCheck(project.Uuid),
				authz.CanWriteEnvironmentCheck(env.Uuid),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot manage anything", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: otherUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanManageOrgCheck(org.Id),
				authz.CanManageProjectCheck(project.Uuid),
				authz.CanManageEnvironmentCheck(env.Uuid),
			},
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Equal(t, &serverclient.Error{
				Error:   "HTTP-403",
				Message: "one or more authorization checks failed",
				Details: &map[string]interface{}{
					"failed_checks": []interface{}{
						map[string]interface{}{
							"resource":   "organization:" + org.Id,
							"permission": "manage",
						},
						map[string]interface{}{
							"resource":   "project:" + project.Uuid.String(),
							"permission": "manage",
						},
						map[string]interface{}{
							"resource":   "env:" + env.Uuid.String(),
							"permission": "manage",
						},
					},
				},
			}, r.JSON403)
		}
	})

	var otherUserMembershipId uuid.UUID
	t.Run("can make the other user a admin", func(t *testing.T) {
		r, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     adminRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode()) && assert.Len(t, r.JSON200.Items, 1) {
			otherUserMembershipId = r.JSON200.Items[0].Id
		}
	})

	t.Run("user has now only one membership in the org", func(t *testing.T) {
		r, err := client.ListUserMembershipsWithResponse(t.Context(), otherUser.Id, &serverclient.ListUserMembershipsParams{OrgId: &org.Id}, WithAuthenticatedUserId(otherUser.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
			assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
			assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
		}
	})

	t.Run("can delete admin membership when there's another admin", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), org.Id, otherUserMembershipId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("user has now no memberships in the org", func(t *testing.T) {
		r, err := client.ListUserMembershipsWithResponse(t.Context(), otherUser.Id, &serverclient.ListUserMembershipsParams{OrgId: &org.Id}, WithAuthenticatedUserId(otherUser.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	t.Run("user has no more perms", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(),
				[]serverclient.ResourcePermissionCheck{
					authz.CanManageOrgCheck(org.Id), authz.CanReadOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id),
				}, WithAuthenticatedUserId(otherUser.Id))
			require.NoError(t, err)
			if assert.Equal(collect, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				if assert.Len(collect, resp.JSON200.Items, 3) {
					permMap := make(map[string]bool)
					for _, permResult := range resp.JSON200.Items {
						permMap[permResult.PermissionCheck.Permission] = permResult.Allowed
					}
					assert.False(collect, permMap["manage"], "not expected manage permission")
					assert.False(collect, permMap["write"], "not expected write permission")
					assert.False(collect, permMap["read"], "not expected read permission")
				}
			}
		}, time.Second*30, time.Second*3, "user did not get permissions revoked in time")
	})

	targetUser := MustRegisterTestUser(client, t)
	t.Run("cannot replace memberships without admin authorization", func(t *testing.T) {
		// Create a user without permissions to org
		unauthorizedUser := MustRegisterTestUser(client, t)

		// Try to replace memberships without being an admin
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     adminRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(unauthorizedUser.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body))
	})

	t.Run("cannot replace memberships for non org member", func(t *testing.T) {
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     adminRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		assert.Equal(t, http.StatusNotFound, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body))
	})

	t.Run("set target user as viewer", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      targetUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     viewerRoleId.String(),
		})
		require.NoError(t, err)

		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, targetUser.Id, f.JSON201.UserId)
			assert.Equal(t, viewerRoleId.String(), f.JSON201.Subject)
			assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
		}
	})

	var scopedRoleMembershipId uuid.UUID
	t.Run("can add scoped role memberships as admin via internal endpoint", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      targetUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
			Scope:       ptr("project:" + project.Uuid.String()),
		})
		require.NoError(t, err)

		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, targetUser.Id, f.JSON201.UserId)
			assert.Equal(t, adminRoleId.String(), f.JSON201.Subject)
			assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
			assert.Equal(t, "project:"+project.Uuid.String(), *f.JSON201.Scope)
			scopedRoleMembershipId = f.JSON201.Id
		}
	})

	t.Run("all the memberships of the target user are visible", func(t *testing.T) {
		membershipsResp, err := client.ListUserMembershipsWithResponse(t.Context(), targetUser.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(targetUser.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, membershipsResp.StatusCode(), "unexpected status %d %s", membershipsResp.StatusCode(), string(membershipsResp.Body)) {
			memberships := membershipsResp.JSON200.Items
			if assert.Len(t, memberships, 2) {
				assert.Equal(t, org.Id, memberships[0].OrgId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)

				assert.Equal(t, org.Id, memberships[1].OrgId)
				assert.Equal(t, adminRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})

	t.Run("cannot replace memberships with malformed scopes", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      targetUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
			Scope:       ptr("project/" + project.Uuid.String()),
		})
		require.NoError(t, err)

		if assert.Equal(t, http.StatusBadRequest, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, fmt.Sprintf("invalid scope format 'project/%s', expected <resource_kind>:<resource_uuid>", project.Uuid.String()), f.JSON400.Message)
		}
	})

	t.Run("cannot replace memberships with non existing resource in the scope", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      targetUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
			Scope:       ptr("env:" + project.Uuid.String()),
		})
		require.NoError(t, err)

		if assert.Equal(t, http.StatusBadRequest, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, fmt.Sprintf("environment in the scope 'env:%s' does not exist", project.Uuid.String()), f.JSON400.Message)
		}
	})

	t.Run("cannot replace memberships as viewer", func(t *testing.T) {
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, user.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
			},
		}, WithAuthenticatedUserId(targetUser.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body))
	})

	t.Run("can delete the scoped role membership", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), org.Id, scopedRoleMembershipId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("delete all the relationships with project resource in SpiceDB to prove scoped roles work anyway", func(t *testing.T) {
		// manually delete project from spicedb to prove scoped roles work anyway
		spicedbClient := MustSpiceDBClient(t)
		deleteRes, err := spicedbClient.DeleteRelationships(t.Context(), &v1.DeleteRelationshipsRequest{
			RelationshipFilter: &v1.RelationshipFilter{
				OptionalResourceId: project.Uuid.String(),
				ResourceType:       "project",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(4), deleteRes.RelationshipsDeletedCount)

		dbConn := MustDatabaseConn(t)
		_, err = dbConn.ExecContext(t.Context(), "DELETE FROM scoped_roles WHERE scope = $1", "project:"+project.Uuid.String())
		require.NoError(t, err)
	})

	t.Run("can replace memberships as admin and set scoped role", func(t *testing.T) {
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     deployerRoleId.String(),
					Scope:       ptr("project:" + project.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		if assert.Equal(t, http.StatusOK, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body)) {
			memberships := replaceResp.JSON200.Items
			if assert.Len(t, memberships, 2) {
				assert.Equal(t, org.Id, memberships[0].OrgId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)

				assert.Equal(t, org.Id, memberships[1].OrgId)
				assert.Equal(t, deployerRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})

	t.Run("target user should have correct scoped roles", func(t *testing.T) {
		membershipsResp, err := client.ListUserMembershipsWithResponse(t.Context(), targetUser.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(targetUser.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, membershipsResp.StatusCode(), "unexpected status %d %s", membershipsResp.StatusCode(), string(membershipsResp.Body)) {
			memberships := membershipsResp.JSON200.Items
			if assert.Len(t, memberships, 2) {

				assert.Equal(t, org.Id, memberships[0].OrgId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)
				assert.Equal(t, org.Id, memberships[1].OrgId)
				assert.Equal(t, deployerRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})

	t.Run("org memberships have correct scoped roles", func(t *testing.T) {
		orgMembershipsResp, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{UserId: &targetUser.Id}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, orgMembershipsResp.StatusCode(), "unexpected status %d %s", orgMembershipsResp.StatusCode(), string(orgMembershipsResp.Body)) {
			memberships := orgMembershipsResp.JSON200.Items
			if assert.Len(t, memberships, 2) {

				assert.Equal(t, targetUser.Id, memberships[0].UserId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)
				assert.Equal(t, targetUser.Id, memberships[1].UserId)
				assert.Equal(t, deployerRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})

	t.Run("viewer member with scoped role can read org and write project / env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: targetUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(collect, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)+fmt.Sprintf("for user %s", targetUser.Id))
		}, time.Second*30, time.Second*3, "user %s did not get proper permissions in time", user.Id)
	})

	t.Run("viewer member with scoped deployer role can't manage organization", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: targetUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanWriteOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("viewer member with scoped deployer role can't manage project", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: targetUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanManageProjectCheck(project.Uuid),
			},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can replace memberships as admin and set admin scoped role", func(t *testing.T) {
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     adminRoleId.String(),
					Scope:       ptr("project:" + project.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		if assert.Equal(t, http.StatusOK, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body)) {
			memberships := replaceResp.JSON200.Items
			if assert.Len(t, memberships, 2) {
				assert.Equal(t, org.Id, memberships[0].OrgId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)

				assert.Equal(t, org.Id, memberships[1].OrgId)
				assert.Equal(t, adminRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})
	t.Run("viewer member with scoped role can read org and manage project / env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: targetUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanManageProjectCheck(project.Uuid),
					authz.CanManageEnvironmentCheck(env.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(collect, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)+fmt.Sprintf("for user %s", targetUser.Id))
		}, time.Second*30, time.Second*3, "user %s did not get proper permissions in time", user.Id)
	})

	t.Run("admin member without scoped role can manage org, project and env", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: user.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanManageProjectCheck(project.Uuid),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanManageEnvironmentCheck(env.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(collect, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, time.Second*30, time.Second*3, "user did not have expected permissions in time")
	})

	t.Run("can replace scoped memberships as admin", func(t *testing.T) {
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
					Scope:       ptr("project:" + project.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		if assert.Equal(t, http.StatusOK, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body)) {
			memberships := replaceResp.JSON200.Items
			assert.Len(t, memberships, 2)
		}
	})

	t.Run("org memberships have correct updated scoped roles", func(t *testing.T) {
		orgMembershipsResp, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{UserId: &targetUser.Id}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, orgMembershipsResp.StatusCode(), "unexpected status %d %s", orgMembershipsResp.StatusCode(), string(orgMembershipsResp.Body)) {
			memberships := orgMembershipsResp.JSON200.Items
			if assert.Len(t, memberships, 2) {

				assert.Equal(t, targetUser.Id, memberships[0].UserId)
				assert.Equal(t, viewerRoleId.String(), memberships[0].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[0].SubjectType)

				assert.Equal(t, targetUser.Id, memberships[1].UserId)
				assert.Equal(t, viewerRoleId.String(), memberships[1].Subject)
				assert.Equal(t, serverclient.SubjectTypeRole, memberships[1].SubjectType)
				assert.Equal(t, "project:"+project.Uuid.String(), *memberships[1].Scope)
			}
		}
	})

	t.Run("viewer member cannot manage project / env anymore", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: targetUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanManageProjectCheck(project.Uuid),
					authz.CanManageEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), fmt.Sprintf("user %s - project %s", targetUser.Id, project.Uuid))
		}, time.Second*30, time.Second*3, "user did not get permissions revoked in time for project %s/%s", org.Id, project.Uuid)
	})

	t.Run("cannot replace own memberships", func(t *testing.T) {
		// Try to replace the current user's own memberships
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, user.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{{
				SubjectType: serverclient.SubjectTypeRole,
				Subject:     viewerRoleId.String(),
			}},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		if assert.Equal(t, http.StatusConflict, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body)) {
			assert.Equal(t, "cannot modify your own memberships", replaceResp.JSON409.Message)
		}
	})

	t.Run("cannot replace memberships to empty list", func(t *testing.T) {
		// Try to replace with empty memberships array
		replaceResp, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, targetUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)

		// Should return 400 Bad Request due to minItems: 1 validation
		assert.Equal(t, http.StatusBadRequest, replaceResp.StatusCode(), "unexpected status %d %s", replaceResp.StatusCode(), string(replaceResp.Body))
	})
}
