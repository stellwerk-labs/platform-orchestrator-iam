package integrationtests

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestListMembers(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)

	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	viewerRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultViewerRoleName)

	t.Run("empty org has no members", func(t *testing.T) {
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{}, WithInternalUserId)
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Empty(t, r.JSON200.Items)
		}
	})

	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	t.Run("user appears as member with testuser identity", func(t *testing.T) {
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, user.Id, r.JSON200.Items[0].UserId)
				assert.Contains(t, r.JSON200.Items[0].IdentityProviders, "testuser")
			}
		}
	})

	t.Run("can filter by userId", func(t *testing.T) {
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{UserId: &user.Id}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 1) {
				assert.Equal(t, user.Id, r.JSON200.Items[0].UserId)
			}
		}
	})

	t.Run("non-member cannot list members", func(t *testing.T) {
		outsider := MustRegisterTestUser(client, t)
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(outsider.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	t.Run("unauthenticated request is rejected", func(t *testing.T) {
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(userid.NewHumanUserId()))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})

	secondUser := MustRegisterTestUser(client, t)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, secondUser.Id, viewerRoleId)

	t.Run("pagination returns every member exactly once", func(t *testing.T) {
		perPage := 1
		var page *string
		seen := make(map[uuid.UUID]int)
		for {
			r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{
				Page:    page,
				PerPage: &perPage,
			}, WithAuthenticatedUserId(user.Id))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			require.NotNil(t, r.JSON200)
			for _, member := range r.JSON200.Items {
				seen[member.UserId]++
			}
			page = r.JSON200.NextPageToken
			if page == nil {
				break
			}
		}

		require.Equal(t, map[uuid.UUID]int{
			user.Id:       1,
			secondUser.Id: 1,
		}, seen)
	})

	cpClient := MustControlPlaneClient(t)
	project := MustCreateProject(t, cpClient, org.Id, "proj-members-test")

	t.Run("user with 2 identities and 2 memberships appears correctly", func(t *testing.T) {
		multiUser := MustRegisterTestUser(client, t)
		multiOrg := MustCreateTestOrg(cpInternalClient, t)
		multiAdminRoleId := MustObtainRoleIdByName(t, client, multiOrg.Id, DefaultAdminRoleName)
		multiViewerRoleId := MustObtainRoleIdByName(t, client, multiOrg.Id, DefaultViewerRoleName)

		db := MustDatabase(t)
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)

		// Create user's Google identity
		_, err = tx.ExecContext(t.Context(),
			`INSERT INTO identities (provider, provider_user_id, user_id) VALUES ($1, $2, $3)`,
			model.UserIdentityProviderGoogle, "google-id-"+multiUser.Id.String(), multiUser.Id,
		)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		// Create Admin org membership
		_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, multiOrg.Id, multiUser.Id, multiAdminRoleId)

		// Create Viewer org membership
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), multiOrg.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      multiUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     multiViewerRoleId.String(),
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body))

		r, err := client.ListMembersWithResponse(t.Context(), multiOrg.Id, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(multiUser.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			if assert.Len(t, r.JSON200.Items, 2, "expected one member entry per membership") {
				for _, m := range r.JSON200.Items {
					assert.Equal(t, multiUser.Id, m.UserId)
					assert.ElementsMatch(t, []string{"testuser", "google"}, m.IdentityProviders)
					assert.NotEmpty(t, m.UserDisplayName)
					assert.Equal(t, serverclient.SubjectTypeRole, m.SubjectType)
					assert.NotEmpty(t, m.Subject)
				}
			}
		}
	})

	t.Run("scoped membership does not appear in members list", func(t *testing.T) {
		// Add a scoped (project-level) membership for secondUser
		f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      secondUser.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     adminRoleId.String(),
			Scope:       ptr("project:" + project.Uuid.String()),
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body))

		// Members endpoint should still show only unscoped memberships: user + secondUser (viewer)
		r, err := client.ListMembersWithResponse(t.Context(), org.Id, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			assert.Len(t, r.JSON200.Items, 2, "scoped membership should not appear in members list")
		}
	})
}
