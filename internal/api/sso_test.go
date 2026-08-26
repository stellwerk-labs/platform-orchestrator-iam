package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider"
	mocksso "github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider/mocks"
)

const (
	TestSsoProviderOrgId = "org-12345"
	TestSsoAuthCode      = "AUTHCODE"
	TestSsoStateSecret   = "test-secret-key-for-hmac-signing"
)

func testSsoState(t *testing.T) string {
	t.Helper()
	state, err := encodeState(map[string]string{SsoStateOrgIdParamName: orgId}, TestSsoStateSecret)
	require.NoError(t, err)
	return state
}

func TestRequestSsoLogin_NotConfigured(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	// When SSO is not configured for org, the DB returns not found
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Nil(), orgId).
		Return(nil, model.NewErrNotFound("sso configuration not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RequestSsoLogin(ctx, RequestSsoLoginRequestObject{Body: &RequestSsoLoginJSONRequestBody{OrgId: orgId}})
	require.NoError(t, err)

	require.IsType(t, RequestSsoLogin404JSONResponse{}, r)
	resp := r.(RequestSsoLogin404JSONResponse)
	assert.Equal(t, "SSO is not configured or organization doesn't exist", resp.Message)
}

func TestRequestSsoLogin_ProviderError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetAuthorizationURL(TestSsoProviderOrgId, gomock.Any()).
		Return("", errors.New("sso provider error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	_, err := s.RequestSsoLogin(ctx, RequestSsoLoginRequestObject{Body: &RequestSsoLoginJSONRequestBody{OrgId: orgId}})
	require.ErrorContains(t, err, "sso provider error")
}

func TestRequestSsoLogin_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetAuthorizationURL(TestSsoProviderOrgId, gomock.Any()).
		Return("https://example.com/login", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RequestSsoLogin(ctx, RequestSsoLoginRequestObject{Body: &RequestSsoLoginJSONRequestBody{OrgId: orgId}})
	require.NoError(t, err)

	resp, ok := r.(RequestSsoLogin200JSONResponse)
	require.True(t, ok)
	require.Equal(t, "https://example.com/login", resp.RedirectUrl)
}

func TestGetSsoCallback_Success_NewUser(t *testing.T) {
	tests := []struct {
		name             string
		hasMemberships   bool
		expectedRoleName string
	}{
		{
			name:             "first user gets admin",
			hasMemberships:   false,
			expectedRoleName: RoleAdmin,
		},
		{
			name:             "subsequent user gets viewer",
			hasMemberships:   true,
			expectedRoleName: RoleViewer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s, fin := MockServer(t)
			defer fin()

			s.SsoProvider.(*mocksso.MockProvider).EXPECT().
				GetUserProfile(gomock.Any(), TestSsoAuthCode).
				Return(&ssoprovider.UserProfile{
					Email:          "foo@example.com",
					DisplayName:    "Jane Dow",
					ProviderOrgId:  TestSsoProviderOrgId,
					ProviderUserId: "user-12345",
					Role:           "viewer",
				}, nil)

			s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				GetSsoConfiguration(gomock.Any(), gomock.Not(nil), orgId).
				Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				GetUserIdByIdentity(gomock.Any(), gomock.Not(nil), model.UserIdentityProviderSso, TestSsoProviderOrgId+":user-12345").
				Return(nil, model.NewErrNotFound("not found"))

			// SSO linking: email-first check before JIT-create (no existing user in this test path).
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				FindUserByPrimaryEmail(gomock.Any(), gomock.Not(nil), "foo@example.com").
				Return(nil, model.NewErrNotFound("not found"))

			var (
				newUserId                 uuid.UUID
				createdAt, lastLoggedInAt time.Time
			)
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.User) (*model.User, error) {
					newUserId = in.Id
					createdAt = in.CreatedAt
					lastLoggedInAt = *in.LastLoggedInAt
					assert.Equal(t, opt.Of("foo@example.com"), in.PrimaryEmailAddress)
					assert.Equal(t, "Jane Dow", in.DisplayName)
					return in, nil
				})

			viewerRoleId := uuid.New()
			adminRoleId := uuid.New()
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				ListRoles(gomock.Any(), gomock.Not(nil), orgId).
				Return([]model.Role{
					{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer},
					{Id: adminRoleId, OrgId: orgId, DisplayName: RoleAdmin},
				}, nil)

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				HasMemberships(gomock.Any(), gomock.Not(nil), orgId).
				Return(tt.hasMemberships, nil)

			expectedRoleId := viewerRoleId
			if tt.expectedRoleName == RoleAdmin {
				expectedRoleId = adminRoleId
			}

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ model.Tx, in *model.Membership) (*model.Membership, error) {
					assert.Equal(t, newUserId, in.UserId)
					assert.Equal(t, orgId, in.OrgId)
					assert.Equal(t, expectedRoleId, in.Role.Must(), "expected role %s", tt.expectedRoleName)
					return in, nil
				})

			store := new(reliableoutbox.InMemoryStorage[*hstandardoutbox.PendingEventMessage])
			s.Database.(*mockmodel.MockDatabaser).EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
					store.Put(m)
					return m, nil
				})
			s.Database.(*mockmodel.MockDatabaser).EXPECT().AsReliableOutboxStore().Return(store)

			now := time.Now()
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateSessionToken(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.SessionToken) (*model.SessionToken, error) {
					assert.Equal(t, newUserId, in.UserId)
					return &model.SessionToken{
						Sha256Hash: in.Sha256Hash,
						CreatedAt:  now,
						ExpiresAt:  now.Add(time.Hour),
						UserId:     newUserId,
					}, nil
				})

			ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
			state := testSsoState(t)
			r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: ref.RefStringEmptyNil(TestSsoAuthCode), State: &state}})
			require.NoError(t, err)

			resp, ok := r.(GetSsoCallback200JSONResponse)
			require.True(t, ok, "unexpected response type: %T", r)
			assert.NotEmpty(t, resp.Headers.SetCookie)
			require.Equal(t, User{
				Id:                  newUserId,
				DisplayName:         "Jane Dow",
				PrimaryEmailAddress: opt.Of("foo@example.com").Ref(),
				CreatedAt:           createdAt,
				LastLoggedInAt:      &lastLoggedInAt,
				LoginProviders:      []string{"sso"},
			}, resp.Body)
		})
	}
}

func TestGetSsoCallback_Success_ExistingUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	existingUserId := uuid.New()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(&ssoprovider.UserProfile{
			Email:          "foo@example.com",
			DisplayName:    "Jane Dow",
			ProviderOrgId:  TestSsoProviderOrgId,
			ProviderUserId: "user-12345",
			Role:           "viewer",
		}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Not(nil), orgId).
		Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetUserIdByIdentity(gomock.Any(), gomock.Not(nil), model.UserIdentityProviderSso, TestSsoProviderOrgId+":user-12345").
		Return(&existingUserId, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		FindScimUserByUserId(gomock.Any(), gomock.Not(nil), orgId, existingUserId).
		Return(nil, model.NewErrNotFound("scim user not found"))

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetUser(gomock.Any(), gomock.Not(nil), existingUserId).
		Return(&model.User{
			Id:                  existingUserId,
			DisplayName:         "Jane Dow",
			PrimaryEmailAddress: opt.Of("bar@example.com"),
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		Return(&model.User{
			Id:                  existingUserId,
			DisplayName:         "Jane Dow",
			PrimaryEmailAddress: opt.Of("foo@example.com"),
		}, nil)

	roleId := uuid.New()
	adminRoleId := uuid.New()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Not(nil), orgId).
		Return([]model.Role{
			{Id: roleId, OrgId: orgId, DisplayName: RoleViewer},
			{Id: adminRoleId, OrgId: orgId, DisplayName: RoleAdmin},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMemberships(gomock.Any(), gomock.Not(nil), model.ListMembershipsParams{OrgId: &orgId, UserId: &existingUserId, SubjectType: ref.Ref(model.MembershipSubjectTypeRole)}).
		Return([]model.MembershipWithUserMetadata{
			{
				Membership: model.Membership{
					Id:          uuid.New(),
					OrgId:       orgId,
					UserId:      existingUserId,
					Role:        opt.Of(roleId),
					SubjectType: model.MembershipSubjectTypeRole,
					Subject:     adminRoleId.String(),
				},
			},
		}, nil)

	now := time.Now()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		CreateSessionToken(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.SessionToken) (*model.SessionToken, error) {
			assert.Equal(t, existingUserId, in.UserId)
			return &model.SessionToken{
				Sha256Hash: in.Sha256Hash,
				CreatedAt:  now,
				ExpiresAt:  now.Add(time.Hour),
				UserId:     existingUserId,
			}, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state := testSsoState(t)
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &state}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback200JSONResponse)
	require.True(t, ok, "unexpected response type: %T", r)
	assert.NotEmpty(t, resp.Headers.SetCookie)
	require.Equal(t, User{
		Id:                  existingUserId,
		DisplayName:         "Jane Dow",
		PrimaryEmailAddress: opt.Of("foo@example.com").Ref(),
	}, resp.Body)
}

func TestRequestSsoLogin_NonConfigurable_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()

	// Non-configurable provider validates org exists via CpClient
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetAuthorizationURL("", gomock.Any()).
		Return("https://keycloak.example.com/auth", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RequestSsoLogin(ctx, RequestSsoLoginRequestObject{Body: &RequestSsoLoginJSONRequestBody{OrgId: orgId}})
	require.NoError(t, err)

	resp, ok := r.(RequestSsoLogin200JSONResponse)
	require.True(t, ok)
	require.Equal(t, "https://keycloak.example.com/auth", resp.RedirectUrl)
}

func TestGetSsoCallback_NonConfigurable_NewUser(t *testing.T) {
	tests := []struct {
		name             string
		hasMemberships   bool
		expectedRoleName string
	}{
		{
			name:             "first user gets admin",
			hasMemberships:   false,
			expectedRoleName: RoleAdmin,
		},
		{
			name:             "subsequent user gets viewer",
			hasMemberships:   true,
			expectedRoleName: RoleViewer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s, fin := MockServer(t)
			defer fin()

			s.SsoProvider.(*mocksso.MockProvider).EXPECT().
				GetUserProfile(gomock.Any(), TestSsoAuthCode).
				Return(&ssoprovider.UserProfile{
					Email:          "foo@example.com",
					DisplayName:    "Jane Dow",
					ProviderUserId: "user-12345",
				}, nil)

			s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()

			// Non-configurable provider validates org exists via CpClient
			s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
				GetOrganizationWithResponse(gomock.Any(), orgId).
				Return(&cpclient.GetOrganizationResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusOK},
				}, nil)

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				GetUserIdByIdentity(gomock.Any(), gomock.Not(nil), model.UserIdentityProviderSso, ":user-12345").
				Return(nil, model.NewErrNotFound("not found"))

			// SSO linking: email-first check before JIT-create (no existing user in this test path).
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				FindUserByPrimaryEmail(gomock.Any(), gomock.Not(nil), "foo@example.com").
				Return(nil, model.NewErrNotFound("not found"))

			var (
				newUserId                 uuid.UUID
				createdAt, lastLoggedInAt time.Time
			)
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.User) (*model.User, error) {
					newUserId = in.Id
					createdAt = in.CreatedAt
					lastLoggedInAt = *in.LastLoggedInAt
					assert.Equal(t, opt.Of("foo@example.com"), in.PrimaryEmailAddress)
					assert.Equal(t, "Jane Dow", in.DisplayName)
					return in, nil
				})

			viewerRoleId := uuid.New()
			adminRoleId := uuid.New()
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				ListRoles(gomock.Any(), gomock.Not(nil), orgId).
				Return([]model.Role{
					{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer},
					{Id: adminRoleId, OrgId: orgId, DisplayName: RoleAdmin},
				}, nil)

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				HasMemberships(gomock.Any(), gomock.Not(nil), orgId).
				Return(tt.hasMemberships, nil)

			expectedRoleId := viewerRoleId
			if tt.expectedRoleName == RoleAdmin {
				expectedRoleId = adminRoleId
			}

			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ model.Tx, in *model.Membership) (*model.Membership, error) {
					assert.Equal(t, newUserId, in.UserId)
					assert.Equal(t, orgId, in.OrgId)
					assert.Equal(t, expectedRoleId, in.Role.Must(), "expected role %s", tt.expectedRoleName)
					return in, nil
				})

			store := new(reliableoutbox.InMemoryStorage[*hstandardoutbox.PendingEventMessage])
			s.Database.(*mockmodel.MockDatabaser).EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
					store.Put(m)
					return m, nil
				})
			s.Database.(*mockmodel.MockDatabaser).EXPECT().AsReliableOutboxStore().Return(store)

			now := time.Now()
			s.Database.(*mockmodel.MockDatabaser).EXPECT().
				CreateSessionToken(gomock.Any(), gomock.Not(nil), gomock.Any()).
				DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.SessionToken) (*model.SessionToken, error) {
					assert.Equal(t, newUserId, in.UserId)
					return &model.SessionToken{
						Sha256Hash: in.Sha256Hash,
						CreatedAt:  now,
						ExpiresAt:  now.Add(time.Hour),
						UserId:     newUserId,
					}, nil
				})

			ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
			state := testSsoState(t)
			r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: ref.RefStringEmptyNil(TestSsoAuthCode), State: &state}})
			require.NoError(t, err)

			resp, ok := r.(GetSsoCallback200JSONResponse)
			require.True(t, ok, "unexpected response type: %T", r)
			assert.NotEmpty(t, resp.Headers.SetCookie)
			require.Equal(t, User{
				Id:                  newUserId,
				DisplayName:         "Jane Dow",
				PrimaryEmailAddress: opt.Of("foo@example.com").Ref(),
				CreatedAt:           createdAt,
				LastLoggedInAt:      &lastLoggedInAt,
				LoginProviders:      []string{"sso"},
			}, resp.Body)
		})
	}
}

func TestGetSsoCallback_Failure_SsoError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	errDesc := "authentication error"

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{ErrorDescription: &errDesc}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback401JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-401", resp.Body.Error)
	require.Equal(t, errDesc, resp.Body.Message)
}

func TestGetSsoCallback_Failure_SsoProviderRequestError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(nil, fmt.Errorf("error getting user profile"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state := testSsoState(t)
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &state}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback401JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-401", resp.Body.Error)
	require.Equal(t, "error getting user profile", resp.Body.Message)
}

func TestGetSsoCallback_Failure_DatabaseError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(&ssoprovider.UserProfile{
			Email:          "foo@example.com",
			DisplayName:    "Jane Dow",
			ProviderOrgId:  TestSsoProviderOrgId,
			ProviderUserId: "user-12345",
		}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Not(nil), orgId).
		Return(nil, fmt.Errorf("database error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state := testSsoState(t)
	_, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &state}})
	require.ErrorContains(t, err, "database error")
}

func TestGetSsoCallback_Failure_NoStateError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref()}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback400JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-400", resp.Error)
	require.Equal(t, "Missing required state query parameter", resp.Message)
}

func TestGetSsoCallback_Failure_InvalidStateError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state, err := encodeState(map[string]string{"foo": "bar"}, TestSsoStateSecret)
	require.NoError(t, err)
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &state}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback400JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-400", resp.Error)
	require.Equal(t, "Invalid state, must contain non-empty platform_orchestrator_org_id field", resp.Message)
}

func TestGetSsoCallback_Failure_TamperedState(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	// Create a valid state with one org, then tamper with it to change the org
	state, err := encodeState(map[string]string{SsoStateOrgIdParamName: "original-org"}, TestSsoStateSecret)
	require.NoError(t, err)

	// Tamper: decode, modify org, re-encode (but signature will be invalid)
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	require.NoError(t, err)
	var stateData map[string]string
	require.NoError(t, json.Unmarshal(decoded, &stateData))
	stateData[SsoStateOrgIdParamName] = "tampered-org"
	tamperedJSON, _ := json.Marshal(stateData)
	tamperedState := base64.RawURLEncoding.EncodeToString(tamperedJSON)

	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &tamperedState}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback400JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-400", resp.Error)
	require.Contains(t, resp.Message, "signature verification failed")
}

func TestGetSsoCallback_Failure_UnsignedState(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	// Create an unsigned state (like the old format before HMAC was added)
	unsignedData := map[string]string{SsoStateOrgIdParamName: orgId}
	unsignedJSON, _ := json.Marshal(unsignedData)
	unsignedState := base64.RawURLEncoding.EncodeToString(unsignedJSON)

	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &unsignedState}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback400JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-400", resp.Error)
	require.Contains(t, resp.Message, "missing signature")
}

func TestGetSsoCallback_Failure_SsoNotConfigured(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(&ssoprovider.UserProfile{
			Email:          "foo@example.com",
			DisplayName:    "Jane Dow",
			ProviderOrgId:  TestSsoProviderOrgId,
			ProviderUserId: "user-12345",
		}, nil)

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(true).AnyTimes()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Not(nil), orgId).
		Return(nil, model.NewErrNotFound("sso configuration not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state := testSsoState(t)
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: opt.Of(TestSsoAuthCode).Ref(), State: &state}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback401JSONResponse)
	require.True(t, ok)
	require.Equal(t, "HTTP-401", resp.Body.Error)
	require.Equal(t, fmt.Sprintf("No SSO configuration found for organization %s", orgId), resp.Body.Message)
}

func TestRequestSsoLogin_NonConfigurable_OrgNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RequestSsoLogin(ctx, RequestSsoLoginRequestObject{Body: &RequestSsoLoginJSONRequestBody{OrgId: orgId}})
	require.NoError(t, err)

	resp, ok := r.(RequestSsoLogin404JSONResponse)
	require.True(t, ok)
	assert.Equal(t, fmt.Sprintf("organization doesn't exist: %s", orgId), resp.Message)
}

func TestGetSsoCallback_NonConfigurable_OrgNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	state := testSsoState(t)
	r, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{Params: GetSsoCallbackParams{Code: ref.RefStringEmptyNil(TestSsoAuthCode), State: &state}})
	require.NoError(t, err)

	resp, ok := r.(GetSsoCallback400JSONResponse)
	require.True(t, ok)
	assert.Equal(t, "HTTP-400", resp.Error)
	assert.Equal(t, fmt.Sprintf("Invalid state, no such organization: %s", orgId), resp.Message)
}

func TestInternalUpdateSsoConfiguration_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		UpsertSsoConfiguration(gomock.Any(), gomock.Nil(), orgId, &model.SsoConfiguration{ProviderOrgId: TestSsoProviderOrgId}).
		Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.InternalUpdateSsoConfiguration(ctx, InternalUpdateSsoConfigurationRequestObject{
		OrgId: orgId,
		Body:  &InternalUpdateSsoConfigurationJSONRequestBody{ProviderOrgId: TestSsoProviderOrgId},
	})
	require.NoError(t, err)

	resp, ok := r.(InternalUpdateSsoConfiguration200JSONResponse)
	require.True(t, ok)
	require.Equal(t, TestSsoProviderOrgId, resp.ProviderOrgId)
}

func TestInternalGetSsoConfiguration_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetSsoConfiguration(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.SsoConfiguration{OrgId: orgId, ProviderOrgId: TestSsoProviderOrgId}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.InternalGetSsoConfiguration(ctx, InternalGetSsoConfigurationRequestObject{OrgId: orgId})
	require.NoError(t, err)

	resp, ok := r.(InternalGetSsoConfiguration200JSONResponse)
	require.True(t, ok)
	require.Equal(t, TestSsoProviderOrgId, resp.ProviderOrgId)
}
