package integrationtests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func findLastEmailParamsForAddress(t *testing.T, address string) map[string]interface{} {
	entries, err := os.ReadDir("./mock-emails")
	require.NoError(t, err)
	emailMatch := base64.RawURLEncoding.EncodeToString([]byte(address))
	var lastParams map[string]interface{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-"+emailMatch+".json") {
			raw, err := os.ReadFile("./mock-emails/" + entry.Name())
			require.NoError(t, err, "failed to read dir entry")
			var data struct {
				Params map[string]interface{} `json:"params"`
			}
			require.NoError(t, json.Unmarshal(raw, &data), "failed to unmarshal params")
			lastParams = data.Params
		}
	}
	return lastParams
}

func TestInvitations_VirtualGroupsOwner(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternlClient := MustInternalControlPlaneClient(t)
	org := MustCreateTestOrg(cpInternlClient, t)

	user := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	t.Run("start with no invitations", func(t *testing.T) {
		p, err := client.ListInvitationsWithResponse(t.Context(), org.Id, &serverclient.ListInvitationsParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, p.StatusCode(), "unexpected status %d %s", p.StatusCode(), string(p.Body))
		require.Empty(t, p.JSON200.Items)
	})

	t.Run("cannot get invitation that doesn't exist", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, uuid.New(), &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot revoke invitation that doesn't exist", func(t *testing.T) {
		r, err := client.RevokeInvitationWithResponse(t.Context(), org.Id, uuid.New(), WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("cannot redeem invitation that doesn't exist", func(t *testing.T) {
		r, err := client.RedeemInvitationWithResponse(t.Context(), org.Id, uuid.New(), &serverclient.RedeemInvitationParams{RedemptionToken: "foo"}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	var createdInvitationId uuid.UUID
	t.Run("create invitation", func(t *testing.T) {
		r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
			EmailAddress:          "bob@email.com",
			MembershipSubjectType: "virtual-group",
			MembershipSubject:     "owners",
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.NotEmpty(t, r.JSON201.Id)
		assert.Equal(t, "bob@email.com", r.JSON201.EmailAddress)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON201.MembershipSubjectType)
		assert.Equal(t, adminRoleId.String(), r.JSON201.MembershipSubject)
		require.NoError(t, err)
		assert.Equal(t, "bob.smith", r.JSON201.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON201.CreatedByPrimaryEmailAddress)
		assert.NotEmpty(t, r.JSON201.CreatedAt)
		assert.Greater(t, r.JSON201.ExpiresAt, r.JSON201.CreatedAt)
		createdInvitationId = r.JSON201.Id
	})

	t.Run("should have seeded roles", func(t *testing.T) {
		r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			require.GreaterOrEqual(t, len(r.JSON200.Items), 2)
			var adminRoleFound, viewerRoleFound bool
			for _, r := range r.JSON200.Items {
				switch r.DisplayName {
				case api.RoleAdmin:
					adminRoleFound = true
					assert.Equal(t, adminRoleId, r.Id)
				case api.RoleViewer:
					viewerRoleFound = true
				}
			}
			assert.True(t, adminRoleFound, "admin role not found")
			assert.True(t, viewerRoleFound, "viewer role not found")
		}
	})

	var createdRedemptionToken string
	t.Run("should have sent an email", func(t *testing.T) {
		params := findLastEmailParamsForAddress(t, "bob@email.com")
		if assert.NotNil(t, params) {
			assert.Equal(t, org.Id, params["OrgId"])
			if assert.NotEmpty(t, params["EncodedRedemptionToken"]) {
				createdRedemptionToken = params["EncodedRedemptionToken"].(string)
			}
		}
	})

	t.Run("list should contain invitation", func(t *testing.T) {
		p, err := client.ListInvitationsWithResponse(t.Context(), org.Id, &serverclient.ListInvitationsParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, p.StatusCode(), "unexpected status %d %s", p.StatusCode(), string(p.Body))
		require.Len(t, p.JSON200.Items, 1)
		assert.Equal(t, createdInvitationId, p.JSON200.Items[0].Id)
		assert.Equal(t, "bob.smith", p.JSON200.Items[0].CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *p.JSON200.Items[0].CreatedByPrimaryEmailAddress)
	})

	t.Run("can get invitation authorized", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, createdInvitationId, r.JSON200.Id)
		assert.Equal(t, "bob.smith", r.JSON200.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON200.CreatedByPrimaryEmailAddress)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.MembershipSubjectType)
		assert.Equal(t, adminRoleId.String(), r.JSON200.MembershipSubject)
	})

	anotherUserId := MustRegisterTestUser(client, t)

	t.Run("cannot get invitation unauthorized", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can get invitation via token", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{RedemptionToken: &createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, createdInvitationId, r.JSON200.Id)
		assert.Equal(t, "bob.smith", r.JSON200.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON200.CreatedByPrimaryEmailAddress)
	})

	t.Run("can redeem invitation via token", func(t *testing.T) {
		r, err := client.RedeemInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.RedeemInvitationParams{RedemptionToken: createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, org.Id, r.JSON200.OrgId)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.SubjectType)
		assert.Equal(t, adminRoleId.String(), r.JSON200.Subject)
	})

	t.Run("user should now have all permissions on the org due to the spicedb snapshot", func(t *testing.T) {
		// prove user has proper permissions via SpiceDB
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
				authz.CanManageOrgCheck(org.Id), authz.CanReadOrgCheck(org.Id), authz.CanWriteOrgCheck(org.Id),
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			if assert.Equal(collect, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body)) {
				require.Len(collect, resp.JSON200.Items, 3)
				permMap := make(map[string]bool)
				for _, permResult := range resp.JSON200.Items {
					permMap[permResult.PermissionCheck.Permission] = permResult.Allowed
				}
				assert.True(collect, permMap["manage"], "expected manage permission")
				assert.True(collect, permMap["write"], "expected write permission")
				assert.True(collect, permMap["read"], "expected read permission")
			}
		}, time.Second*30, time.Second*3, "user did not get proper permissions in time")
	})

	t.Run("invitation should be deleted", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can revoke invitations", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "bob@email.com",
				MembershipSubjectType: "virtual-group",
				MembershipSubject:     "owners",
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}

		r, err := client.RevokeInvitationWithResponse(t.Context(), org.Id, createdInvitationId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("invitation should be deleted", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("invitations can resolve conflict", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "bob@email.com",
				MembershipSubjectType: "virtual-group",
				MembershipSubject:     "owners",
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}
		{
			params := findLastEmailParamsForAddress(t, "bob@email.com")
			if assert.NotNil(t, params) {
				assert.Equal(t, org.Id, params["OrgId"])
				if assert.NotEmpty(t, params["EncodedRedemptionToken"]) {
					createdRedemptionToken = params["EncodedRedemptionToken"].(string)
				}
			}
		}
		r, err := client.RedeemInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.RedeemInvitationParams{RedemptionToken: createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, org.Id, r.JSON200.OrgId)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.SubjectType)
		_, err = uuid.Parse(r.JSON200.Subject)
		require.NoError(t, err)
		{
			r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}
	})

	t.Run("system invitation has useful display name", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "bob@email.com",
				MembershipSubjectType: "virtual-group",
				MembershipSubject:     "owners",
			}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}
		t.Run("can get", func(t *testing.T) {
			r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			assert.Equal(t, "System", r.JSON200.CreatedByDisplayName)
			assert.Empty(t, r.JSON200.CreatedByPrimaryEmailAddress)
		})
		t.Run("can list", func(t *testing.T) {
			r, err := client.ListInvitationsWithResponse(t.Context(), org.Id, &serverclient.ListInvitationsParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			i := slices.IndexFunc(r.JSON200.Items, func(summary serverclient.InvitationSummary) bool {
				return summary.Id == createdInvitationId
			})
			require.GreaterOrEqual(t, i, 0, "invitation not found in list")
			assert.Equal(t, "System", r.JSON200.Items[i].CreatedByDisplayName)
			assert.Empty(t, r.JSON200.Items[i].CreatedByPrimaryEmailAddress)
		})
	})

	// Admin
	t.Run("create invitation - admin", func(t *testing.T) {
		r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
			EmailAddress:          "ted@email.com",
			MembershipSubjectType: serverclient.SubjectTypeRole,
			MembershipSubject:     adminRoleId.String(),
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.NotEmpty(t, r.JSON201.Id)
		assert.Equal(t, "ted@email.com", r.JSON201.EmailAddress)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON201.MembershipSubjectType)
		require.Equal(t, adminRoleId.String(), r.JSON201.MembershipSubject)
		assert.Equal(t, "bob.smith", r.JSON201.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON201.CreatedByPrimaryEmailAddress)
		assert.NotEmpty(t, r.JSON201.CreatedAt)
		assert.Greater(t, r.JSON201.ExpiresAt, r.JSON201.CreatedAt)
		createdInvitationId = r.JSON201.Id
	})

	t.Run("should have sent an email - admin", func(t *testing.T) {
		params := findLastEmailParamsForAddress(t, "ted@email.com")
		if assert.NotNil(t, params) {
			assert.Equal(t, org.Id, params["OrgId"])
			if assert.NotEmpty(t, params["EncodedRedemptionToken"]) {
				createdRedemptionToken = params["EncodedRedemptionToken"].(string)
			}
		}
	})

	t.Run("list should contain invitation - admin", func(t *testing.T) {
		p, err := client.ListInvitationsWithResponse(t.Context(), org.Id, &serverclient.ListInvitationsParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, p.StatusCode(), "unexpected status %d %s", p.StatusCode(), string(p.Body))
		require.Len(t, p.JSON200.Items, 2)
		var invitationFound bool
		for _, item := range p.JSON200.Items {
			if item.Id == createdInvitationId {
				assert.Equal(t, "ted@email.com", item.EmailAddress)
				assert.Equal(t, "bob.smith", item.CreatedByDisplayName)
				assert.Equal(t, "bob.smith@example.com", *item.CreatedByPrimaryEmailAddress)
				invitationFound = true
			}
		}
		require.True(t, invitationFound, "created invitation not found in list")
	})

	t.Run("can get invitation authorized - admin", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, createdInvitationId, r.JSON200.Id)
		assert.Equal(t, "ted@email.com", r.JSON200.EmailAddress)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.MembershipSubjectType)
		assert.Equal(t, adminRoleId.String(), r.JSON200.MembershipSubject)
		assert.Equal(t, "bob.smith", r.JSON200.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON200.CreatedByPrimaryEmailAddress)
	})

	anotherUserId = MustRegisterTestUser(client, t)
	t.Run("cannot get invitation unauthorized - admin", func(t *testing.T) {

		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))

	})

	t.Run("can get invitation via token", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{RedemptionToken: &createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, createdInvitationId, r.JSON200.Id)
		assert.Equal(t, "bob.smith", r.JSON200.CreatedByDisplayName)
		assert.Equal(t, "bob.smith@example.com", *r.JSON200.CreatedByPrimaryEmailAddress)
	})

	t.Run("can redeem invitation via token", func(t *testing.T) {
		r, err := client.RedeemInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.RedeemInvitationParams{RedemptionToken: createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, org.Id, r.JSON200.OrgId)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.SubjectType)
		assert.Equal(t, adminRoleId.String(), r.JSON200.Subject)
	})

	t.Run("invitation should be deleted", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("can revoke invitations", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "ted@email.com",
				MembershipSubjectType: serverclient.SubjectTypeRole,
				MembershipSubject:     adminRoleId.String(),
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}

		r, err := client.RevokeInvitationWithResponse(t.Context(), org.Id, createdInvitationId, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("invitation should be deleted", func(t *testing.T) {
		r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("invitations can resolve conflict", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "ted@email.com",
				MembershipSubjectType: serverclient.SubjectTypeRole,
				MembershipSubject:     adminRoleId.String(),
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}
		{
			params := findLastEmailParamsForAddress(t, "ted@email.com")
			if assert.NotNil(t, params) {
				assert.Equal(t, org.Id, params["OrgId"])
				if assert.NotEmpty(t, params["EncodedRedemptionToken"]) {
					createdRedemptionToken = params["EncodedRedemptionToken"].(string)
				}
			}
		}
		r, err := client.RedeemInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.RedeemInvitationParams{RedemptionToken: createdRedemptionToken}, WithAuthenticatedUserId(anotherUserId.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		assert.Equal(t, org.Id, r.JSON200.OrgId)
		assert.Equal(t, serverclient.SubjectTypeRole, r.JSON200.SubjectType)
		_, err = uuid.Parse(r.JSON200.Subject)
		require.NoError(t, err)
		{
			r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}
	})

	t.Run("system invitation has useful display name", func(t *testing.T) {
		{
			r, err := client.CreateInvitationWithResponse(t.Context(), org.Id, serverclient.InvitationCreateBody{
				EmailAddress:          "ted@email.com",
				MembershipSubjectType: serverclient.SubjectTypeRole,
				MembershipSubject:     adminRoleId.String(),
			}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			createdInvitationId = r.JSON201.Id
		}
		t.Run("can get", func(t *testing.T) {
			r, err := client.GetInvitationWithResponse(t.Context(), org.Id, createdInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			assert.Equal(t, "System", r.JSON200.CreatedByDisplayName)
			assert.Empty(t, r.JSON200.CreatedByPrimaryEmailAddress)
		})
		t.Run("can list", func(t *testing.T) {
			r, err := client.ListInvitationsWithResponse(t.Context(), org.Id, &serverclient.ListInvitationsParams{}, WithAuthenticatedUserId(userid.InternalSystemUuid))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			i := slices.IndexFunc(r.JSON200.Items, func(summary serverclient.InvitationSummary) bool {
				return summary.Id == createdInvitationId
			})
			require.GreaterOrEqual(t, i, 0, "invitation not found in list")
			assert.Equal(t, "System", r.JSON200.Items[i].CreatedByDisplayName)
			assert.Empty(t, r.JSON200.Items[i].CreatedByPrimaryEmailAddress)
		})
	})

}
