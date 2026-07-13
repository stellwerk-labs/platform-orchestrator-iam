package integrationtests

import (
	"context"
	"crypto/rand"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestScheduleExpiredDataCleanup_IntegrationTest(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)
	org := MustCreateTestOrg(cpInternalClient, t)

	now := time.Now().UTC()

	user1 := MustRegisterTestUser(client, t)
	user2 := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user1.Id, adminRoleId)

	var expiredTokenHash, validTokenHash []byte
	var expiredInvitationId uuid.UUID

	t.Run("setup test data with expired and valid data", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()

		expiredToken := &model.SessionToken{
			Sha256Hash: randomBytes(32),
			Provider:   model.UserIdentityProviderTestUser,
			UserId:     user1.Id,
			CreatedAt:  now.Add(-2 * time.Hour),
			ExpiresAt:  now.Add(-1 * time.Hour),
		}
		_, err = db.CreateSessionToken(ctx, tx, expiredToken)
		require.NoError(t, err)
		expiredTokenHash = expiredToken.Sha256Hash

		validToken := &model.SessionToken{
			Sha256Hash: randomBytes(32),
			Provider:   model.UserIdentityProviderTestUser,
			UserId:     user2.Id,
			CreatedAt:  now,
			ExpiresAt:  now.Add(1 * time.Hour),
		}
		_, err = db.CreateSessionToken(ctx, tx, validToken)
		require.NoError(t, err)
		validTokenHash = validToken.Sha256Hash

		expiredInvitation := &model.Invitation{
			OrgId:                     org.Id,
			Id:                        uuid.New(),
			CreatedAt:                 now.Add(-3 * time.Hour),
			ExpiresAt:                 now.Add(-30 * time.Minute),
			CreatedBy:                 user1.Id,
			RedemptionTokenSha256Hash: randomBytes(32),
			EmailAddress:              gofakeit.Email(),
			MembershipSubjectType:     model.MembershipSubjectTypeRole,
			MembershipSubject:         uuid.New().String(),
		}
		_, err = db.CreateInvitation(ctx, tx, expiredInvitation)
		require.NoError(t, err)
		expiredInvitationId = expiredInvitation.Id

		err = tx.Commit()
		require.NoError(t, err)
	})

	var validInvitationId uuid.UUID
	t.Run("create valid invitation via API", func(t *testing.T) {
		r, err := client.CreateInvitationWithResponse(ctx, org.Id, serverclient.InvitationCreateBody{
			EmailAddress:          gofakeit.Email(),
			MembershipSubjectType: "virtual-group",
			MembershipSubject:     "owners",
		}, WithAuthenticatedUserId(user1.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		validInvitationId = r.JSON201.Id
	})

	t.Run("verify data exists before cleanup", func(t *testing.T) {
		testCases := []struct {
			name          string
			verifyFunc    func(t *testing.T)
			expectedError bool
		}{
			{
				name: "expired token exists",
				verifyFunc: func(t *testing.T) {
					retrievedToken, err := db.GetSessionTokenByHash(ctx, nil, expiredTokenHash)
					require.NoError(t, err)
					assert.Equal(t, expiredTokenHash, retrievedToken.Sha256Hash)
				},
			},
			{
				name: "valid token exists",
				verifyFunc: func(t *testing.T) {
					retrievedToken, err := db.GetSessionTokenByHash(ctx, nil, validTokenHash)
					require.NoError(t, err)
					assert.Equal(t, validTokenHash, retrievedToken.Sha256Hash)
				},
			},
			{
				name: "expired invitation exists",
				verifyFunc: func(t *testing.T) {
					retrievedInvitation, err := db.GetInvitation(ctx, nil, expiredInvitationId)
					require.NoError(t, err)
					assert.Equal(t, expiredInvitationId, retrievedInvitation.Id)
				},
			},
			{
				name: "valid invitation exists",
				verifyFunc: func(t *testing.T) {
					r, err := client.GetInvitationWithResponse(ctx, org.Id, validInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user1.Id))
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, r.StatusCode())
					assert.Equal(t, validInvitationId, r.JSON200.Id)
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, tc.verifyFunc)
		}
	})

	t.Run("trigger cleanup", func(t *testing.T) {
		deletedTokens, err := db.DeleteExpiredSessionTokens(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, deletedTokens, int64(1))

		deletedInvitations, err := db.DeleteExpiredInvitations(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, deletedInvitations, int64(1))
	})

	t.Run("verify expired data deleted and valid data remains", func(t *testing.T) {
		testCases := []struct {
			name       string
			verifyFunc func(t *testing.T)
		}{
			{
				name: "expired token deleted",
				verifyFunc: func(t *testing.T) {
					_, err := db.GetSessionTokenByHash(ctx, nil, expiredTokenHash)
					require.Error(t, err)
					_, isNotFound := model.IsErrNotFound(err)
					assert.True(t, isNotFound)
				},
			},
			{
				name: "valid token still exists",
				verifyFunc: func(t *testing.T) {
					retrievedToken, err := db.GetSessionTokenByHash(ctx, nil, validTokenHash)
					require.NoError(t, err)
					assert.Equal(t, validTokenHash, retrievedToken.Sha256Hash)
				},
			},
			{
				name: "expired invitation deleted",
				verifyFunc: func(t *testing.T) {
					_, err := db.GetInvitation(ctx, nil, expiredInvitationId)
					require.Error(t, err)
					_, isNotFound := model.IsErrNotFound(err)
					assert.True(t, isNotFound)
				},
			},
			{
				name: "valid invitation still exists",
				verifyFunc: func(t *testing.T) {
					r, err := client.GetInvitationWithResponse(ctx, org.Id, validInvitationId, &serverclient.GetInvitationParams{}, WithAuthenticatedUserId(user1.Id))
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, r.StatusCode())
					assert.Equal(t, validInvitationId, r.JSON200.Id)
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, tc.verifyFunc)
		}
	})
}

func TestScheduleExpiredDataCleanup_WithScheduler(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	logger := zaptest.NewLogger(t)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)
	org := MustCreateTestOrg(cpInternalClient, t)

	now := time.Now().UTC()
	user := MustRegisterTestUser(client, t)

	tokenTestCases := []struct {
		name      string
		createdAt time.Duration
		expiresAt time.Duration
	}{
		{
			name:      "token1",
			createdAt: -2 * time.Hour,
			expiresAt: -1 * time.Hour,
		},
		{
			name:      "token2",
			createdAt: -3 * time.Hour,
			expiresAt: -30 * time.Minute,
		},
	}

	invitationTestCases := []struct {
		name      string
		createdAt time.Duration
		expiresAt time.Duration
	}{
		{
			name:      "invitation1",
			createdAt: -3 * time.Hour,
			expiresAt: -1 * time.Hour,
		},
		{
			name:      "invitation2",
			createdAt: -4 * time.Hour,
			expiresAt: -45 * time.Minute,
		},
	}

	var tokenHashes [][]byte
	var invitationIds []uuid.UUID

	t.Run("setup expired resources via DB", func(t *testing.T) {
		for _, tc := range tokenTestCases {
			token := &model.SessionToken{
				Sha256Hash: randomBytes(32),
				Provider:   model.UserIdentityProviderTestUser,
				UserId:     user.Id,
				CreatedAt:  now.Add(tc.createdAt),
				ExpiresAt:  now.Add(tc.expiresAt),
			}
			_, err = db.CreateSessionToken(ctx, nil, token)
			require.NoError(t, err, "failed to create %s", tc.name)
			tokenHashes = append(tokenHashes, token.Sha256Hash)
		}

		for _, tc := range invitationTestCases {
			invitation := &model.Invitation{
				OrgId:                     org.Id,
				Id:                        uuid.New(),
				CreatedAt:                 now.Add(tc.createdAt),
				ExpiresAt:                 now.Add(tc.expiresAt),
				CreatedBy:                 user.Id,
				RedemptionTokenSha256Hash: randomBytes(32),
				EmailAddress:              gofakeit.Email(),
				MembershipSubjectType:     model.MembershipSubjectTypeRole,
				MembershipSubject:         uuid.New().String(),
			}
			_, err = db.CreateInvitation(ctx, nil, invitation)
			require.NoError(t, err, "failed to create %s", tc.name)
			invitationIds = append(invitationIds, invitation.Id)
		}
	})

	t.Run("verify resources exist before cleanup", func(t *testing.T) {
		for i, hash := range tokenHashes {
			_, err = db.GetSessionTokenByHash(ctx, nil, hash)
			require.NoError(t, err, "token %d should exist before cleanup", i+1)
		}

		for i, id := range invitationIds {
			_, err = db.GetInvitation(ctx, nil, id)
			require.NoError(t, err, "invitation %d should exist before cleanup", i+1)
		}
	})

	interval := 100 * time.Millisecond

	errChan := make(chan error, 1)
	go func() {
		errChan <- api.ScheduleExpiredDataCleanup(ctx, interval, logger, db)
	}()

	time.Sleep(interval * 3)
	cancel()

	err = <-errChan
	require.NoError(t, err)

	t.Run("verify resources deleted after cleanup", func(t *testing.T) {
		for i, hash := range tokenHashes {
			_, err = db.GetSessionTokenByHash(t.Context(), nil, hash)
			require.Error(t, err, "token %d should be deleted after cleanup", i+1)
			_, isNotFound := model.IsErrNotFound(err)
			assert.True(t, isNotFound, "should return not found error for token %d", i+1)
		}

		for i, id := range invitationIds {
			_, err = db.GetInvitation(t.Context(), nil, id)
			require.Error(t, err, "invitation %d should be deleted after cleanup", i+1)
			_, isNotFound := model.IsErrNotFound(err)
			assert.True(t, isNotFound, "should return not found error for invitation %d", i+1)
		}
	})
}

func TestRemoveAccessFromOrg(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpClient := MustInternalControlPlaneClient(t)

	var userId uuid.UUID
	t.Run("can register a user", func(t *testing.T) {
		r, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
			Provider: "testuser",
			ProviderToken: MustGenerateTestUserTokenWith(t, TestUser{
				ProviderId:  rand.Text(),
				DisplayName: "bob.smith",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		userId = r.JSON202.Id
	})

	org := MustCreateTestOrg(cpClient, t)

	t.Run("add user as org admin", func(t *testing.T) {
		var adminRoleId uuid.UUID
		{
			r, err := client.ListRolesWithResponse(t.Context(), org.Id, &serverclient.ListRolesParams{}, WithInternalUserId)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
			if i := slices.IndexFunc(r.JSON200.Items, func(role serverclient.Role) bool {
				return role.DisplayName == DefaultAdminRoleName
			}); assert.GreaterOrEqual(t, i, 0) {
				adminRoleId = r.JSON200.Items[i].Id
			}
		}
		{
			f, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id, serverclient.InternalCreateOrgMembershipJSONRequestBody{
				UserId:      userId,
				SubjectType: "role",
				Subject:     adminRoleId.String(),
			}, WithInternalUserId)
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, f.StatusCode(), "unexpected status %d %s", f.StatusCode(), string(f.Body))
		}
		time.Sleep(time.Second * 5)
	})

	var su serverclient.ServiceUserWithToken
	t.Run("create service user", func(t *testing.T) {
		r, err := client.CreateServiceUserWithResponse(t.Context(), org.Id, serverclient.ServiceUserCreateBody{
			DisplayName:  "my-service-user",
			ExpiryInDays: 14,
		}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		if assert.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body)) {
			su = *r.JSON201
			assert.NotEmpty(t, su.Token)
			assert.Greater(t, su.CurrentTokenExpiresAt, su.GeneratedAt)
			assert.Len(t, su.Roles, 1)
		}
	})

	t.Run("can remove access", func(t *testing.T) {
		r, err := internalClient.InternalRemoveAccessFromOrgWithResponse(t.Context(), org.Id, WithInternalUserId)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, r.StatusCode(), string(r.Body))
	})

	t.Run("cleaned up service users", func(t *testing.T) {
		r, err := client.ListServiceUsersWithResponse(t.Context(), org.Id, &serverclient.ListServiceUsersParams{}, WithInternalUserId)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), string(r.Body))
		require.Len(t, r.JSON200.Items, 1)
		assert.True(t, r.JSON200.Items[0].CurrentTokenExpiresAt.Before(time.Now()))
	})

	t.Run("cleaned up memberships", func(t *testing.T) {
		r, err := client.ListOrgMembershipsWithResponse(t.Context(), org.Id, &serverclient.ListOrgMembershipsParams{}, WithInternalUserId)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), string(r.Body))
		assert.Empty(t, r.JSON200.Items)
	})
}
