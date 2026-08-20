package api

import (
	"context"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/identity"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestRegister_unknown_provider(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	r, err := s.RegisterUser(t.Context(), RegisterUserRequestObject{Body: &RegisterUserBody{
		Provider:      "fizz",
		ProviderToken: "buzz",
	}})
	require.NoError(t, err)
	assert.Equal(t, RegisterUser400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invalid provider"}}, r)
}

func TestRegister_new_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	k, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	tup, _ := identity.NewTestUserProvider(k.String())
	s.UserIdentityProviders = map[model.UserIdentityProvider]identity.Provider{model.UserIdentityProviderTestUser: tup}

	userId := userid.NewHumanUserId()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), gomock.Eq(model.UserIdentityProviderTestUser), gomock.Eq("my-user-id")).
		Return(nil, model.NewErrNotFound("not found"))

	now := time.Now().UTC()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, optionalTx model.Tx, request *model.User) (*model.User, error) {
			assert.Equal(t, "bob.smith", request.DisplayName)
			assert.NotEmpty(t, request.CreatedAt)
			assert.Equal(t, map[model.UserIdentityProvider]string{
				model.UserIdentityProviderTestUser: "my-user-id",
			}, request.UserIdentities)
			request.Id = userId
			request.CreatedAt = now
			request.LastLoggedInAt = &now
			return request, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateSessionToken(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, optionalTx model.Tx, request *model.SessionToken) (*model.SessionToken, error) {
			assert.Equal(t, userId, request.UserId)
			assert.NotEmpty(t, request.CreatedAt)
			assert.NotEmpty(t, request.ExpiresAt)
			return request, nil
		})

	displayName := "bob.smith"
	r, err := s.RegisterUser(t.Context(), RegisterUserRequestObject{Body: &RegisterUserBody{
		Provider:      string(model.UserIdentityProviderTestUser),
		ProviderToken: identity.EncryptForTestUserProvider(identity.IdentifiedUser{ProviderId: "my-user-id", DisplayName: &displayName, PrimaryEmailAddress: opt.Of("bob.smith@example.com").Ref()}, k),
	}})
	require.NoError(t, err)
	if assert.IsType(t, RegisterUser202JSONResponse{}, r) {
		r := r.(RegisterUser202JSONResponse)
		assert.NotEmpty(t, r.Headers.SetCookie)
		assert.Equal(t, RegisteredUser{
			Id:                    userId,
			DisplayName:           displayName,
			CreatedAt:             now,
			LastLoggedInAt:        &now,
			LoginProviders:        []string{string(model.UserIdentityProviderTestUser)},
			IdentityAlreadyExists: false,
			PrimaryEmailAddress:   opt.Of("bob.smith@example.com").Ref(),
		}, r.Body)
	}

}

func TestRegister_existing_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	k, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	tup, _ := identity.NewTestUserProvider(k.String())
	s.UserIdentityProviders = map[model.UserIdentityProvider]identity.Provider{model.UserIdentityProviderTestUser: tup}

	userId := userid.NewHumanUserId()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), gomock.Eq(model.UserIdentityProviderTestUser), gomock.Eq("my-user-id")).
		Return(&userId, nil)

	now := time.Now().UTC()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), gomock.Eq(userId)).
		Return(&model.User{
			Id:          userId,
			DisplayName: "bob.smith",
			CreatedAt:   now,
			UserIdentities: map[model.UserIdentityProvider]string{
				model.UserIdentityProviderTestUser: "my-user-id",
			},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		Return(&model.User{
			Id:             userId,
			DisplayName:    "bob.smith",
			CreatedAt:      now,
			LastLoggedInAt: &now,
			UserIdentities: map[model.UserIdentityProvider]string{
				model.UserIdentityProviderTestUser: "my-user-id",
			},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateSessionToken(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, optionalTx model.Tx, request *model.SessionToken) (*model.SessionToken, error) {
			assert.Equal(t, userId, request.UserId)
			assert.NotEmpty(t, request.CreatedAt)
			assert.NotEmpty(t, request.ExpiresAt)
			return request, nil
		})

	displayName := "bob.smith"
	r, err := s.RegisterUser(t.Context(), RegisterUserRequestObject{Body: &RegisterUserBody{
		Provider:      string(model.UserIdentityProviderTestUser),
		ProviderToken: identity.EncryptForTestUserProvider(identity.IdentifiedUser{ProviderId: "my-user-id", DisplayName: &displayName}, k),
	}})
	require.NoError(t, err)
	if assert.IsType(t, RegisterUser202JSONResponse{}, r) {
		r := r.(RegisterUser202JSONResponse)
		assert.NotEmpty(t, r.Headers.SetCookie)
		assert.Equal(t, RegisteredUser{
			Id:                    userId,
			DisplayName:           displayName,
			CreatedAt:             now,
			LastLoggedInAt:        &now,
			LoginProviders:        []string{string(model.UserIdentityProviderTestUser)},
			IdentityAlreadyExists: true,
		}, r.Body)
	}

}

func TestRegister_unidentifiable_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	k, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	tup, _ := identity.NewTestUserProvider(k.String())
	s.UserIdentityProviders = map[model.UserIdentityProvider]identity.Provider{model.UserIdentityProviderTestUser: tup}

	r, err := s.RegisterUser(t.Context(), RegisterUserRequestObject{Body: &RegisterUserBody{
		Provider:      string(model.UserIdentityProviderTestUser),
		ProviderToken: "buzz",
	}})
	require.NoError(t, err)
	assert.Equal(t, RegisterUser400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invalid provider token"}}, r)
}
