package integrationtests

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestOwnerMemberships_crud(t *testing.T) {
	t.Parallel()
	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)

	user2 := MustRegisterTestUser(client, t)
	org2 := MustCreateTestOrg(cpInternalClient, t)
	var adminRoleIdOrg2 uuid.UUID
	t.Run("list roles of the org2", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org2.Id, &serverclient.ListRolesParams{}, WithInternalUserId)
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 3)
			for _, role := range r.JSON200.Items {
				if role.DisplayName == DefaultAdminRoleName {
					adminRoleIdOrg2 = role.Id
				}
			}
			assert.NotEmpty(t, adminRoleIdOrg2)
		}
	})

	t.Run("set user as owner - admin has the expected id", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org2.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user2.Id,
			SubjectType: "virtual-group",
			Subject:     "owners",
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.NotEmpty(t, f.JSON201.Id)
			assert.Equal(t, adminRoleIdOrg2.String(), f.JSON201.Subject)
			assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
			assert.Equal(t, user2.Id, f.JSON201.UserId)
			assert.NotEmpty(t, f.JSON201.CreatedAt)
		}
	})

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

	t.Run("cannot add membership to unknown user", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      uuid.New(),
			SubjectType: "virtual-group",
			Subject:     "owners",
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusConflict, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.Equal(t, "user not found", f.JSON409.Message)
		}
	})

	var membershipId, adminRoleId uuid.UUID
	t.Run("set user as owner", func(t *testing.T) {
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      user.Id,
			SubjectType: "virtual-group",
			Subject:     "owners",
		})
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body)) {
			assert.NotEmpty(t, f.JSON201.Id)
			adminRoleId, err = uuid.Parse(f.JSON201.Subject)
			require.NoError(t, err)
			assert.Equal(t, serverclient.SubjectTypeRole, f.JSON201.SubjectType)
			assert.Equal(t, user.Id, f.JSON201.UserId)
			assert.NotEmpty(t, f.JSON201.CreatedAt)
			membershipId = f.JSON201.Id
		}
	})

	t.Run("should be visible in lists now", func(t *testing.T) {
		{
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				r, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{}, WithAuthenticatedUserId(user.Id))
				require.NoError(t, err)
				if assert.Equal(collect, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) && assert.Len(t, r.JSON200.Items, 1) {
					assert.Equal(t, user.Id, r.JSON200.Items[0].UserId)
					assert.Equal(t, adminRoleId.String(), r.JSON200.Items[0].Subject)
					assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.Items[0].SubjectType)
				}
			}, time.Second*1, time.Millisecond*500, "membership did not appear in list in time")
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
	})

	t.Run("cannot list user if not authorized", func(t *testing.T) {
		r, err := client.ListUserMembershipsWithResponse(t.Context(), user.Id, &serverclient.ListUserMembershipsParams{}, WithAuthenticatedUserId(userid.NewHumanUserId()))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.JSONEq(t, `{"error":"HTTP-403","message":"Forbidden","details":{"failed_checks":[{"resource":"user:`+user.Id.String()+`","permission":"self"}]}}`, string(r.Body))
		}
	})

	t.Run("cannot delete if i'm not authorized", func(t *testing.T) {
		r, err := client.DeleteOrgMembershipWithResponse(t.Context(), "other-org", membershipId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.JSONEq(t, `{"error":"HTTP-403","message":"Forbidden","details":{"failed_checks":[{"resource":"organization:other-org","permission":"membership_write"}]}}`, string(r.Body))
		}
	})

	t.Run("cannot delete last owner", func(t *testing.T) {
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

	for _, badOrg := range []string{"unknown-org", "unknown-org-123", "x", "bad_characters"} {
		t.Run(fmt.Sprintf("user should not be authorized on another org (%s)", badOrg), func(t *testing.T) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: user.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(badOrg),
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
								"resource":   "organization:" + badOrg,
								"permission": "read",
							},
						},
					},
				}, r.JSON403)
			}
		})
	}

	for _, badOrg := range []string{"", ":awdoai32ta", "..."} {
		t.Run(fmt.Sprintf("user should not be authorized on another org (%s)", badOrg), func(t *testing.T) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: user.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(badOrg),
				},
			})
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		})
	}

}
