package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	mockauthorization "github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// scimRequest builds a test Echo context for a SCIM handler, injecting the
// authenticated user id (simulating the scimAuthMiddleware) and path params.
func scimRequest(t *testing.T, e *echo.Echo, method, path string, body interface{}, callerUserId uuid.UUID, params map[string]string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set(echo.HeaderContentType, "application/json")
	// Inject the From header the way scimAuthMiddleware reads it.
	req.Header.Set(authenticatedUserIdHeader, callerUserId.String())
	// Inject the user id into context (normally done by scimAuthMiddleware).
	req = req.WithContext(context.WithValue(req.Context(), hecho.ContextKeyUserID, callerUserId.String()))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	names := make([]string, 0, len(params))
	values := make([]string, 0, len(params))
	for k, v := range params {
		names = append(names, k)
		values = append(values, v)
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	return c, rec
}

// mockScimReadAuth sets up a successful provisioning_read authorization check.
func mockScimReadAuth(s *Server, userId uuid.UUID, orgId string) {
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, []authorization.Check{{Resource: "organization:" + orgId, Permission: "provisioning_read"}}).
		Return([]authorization.Result{{Check: authorization.Check{Resource: "organization:" + orgId, Permission: "provisioning_read"}, Allowed: true}}, nil).
		Times(1)
}

// mockScimWriteAuth sets up a successful provisioning_write authorization check.
func mockScimWriteAuth(s *Server, userId uuid.UUID, orgId string) {
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, []authorization.Check{{Resource: "organization:" + orgId, Permission: "provisioning_write"}}).
		Return([]authorization.Result{{Check: authorization.Check{Resource: "organization:" + orgId, Permission: "provisioning_write"}, Allowed: true}}, nil).
		Times(1)
}

// mockScimAuthDenied sets up a denied authorization check.
func mockScimAuthDenied(s *Server, userId uuid.UUID) {
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			return []authorization.Result{{Check: checks[0], Allowed: false}}, nil
		}).
		Times(1)
}

// ------------------------------------------------------------------ GET /Users

func TestScimGetUser_NotFound(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	mockScimReadAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(nil, model.NewErrNotFound("scim user not found"))

	c, rec := scimRequest(t, e, http.MethodGet, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	err := s.handleScimGetUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "404", errBody.Status)
}

func TestScimGetUser_Success(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimReadAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "alice@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{
			Id:                  globalUserId,
			DisplayName:         "Alice",
			PrimaryEmailAddress: opt.Of("alice@example.com"),
		}, nil)

	c, rec := scimRequest(t, e, http.MethodGet, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimGetUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, scimUserId, res.Id)
	assert.Equal(t, "alice@example.com", res.UserName)
	assert.True(t, bool(*res.Active))
}

// ------------------------------------------------------------------ POST /Users (provision)

func TestScimCreateUser_ProvisionNew(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)

	// resolveOrCreateGlobalUser: no scim identity, no email match → create user.
	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-001").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "alice@example.com").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.User{Id: globalUserId, DisplayName: "Alice", CreatedAt: now}, nil)

	// ensureOrgMembership
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{
			{Id: uuid.New(), OrgId: orgId, DisplayName: RoleAdmin, Permissions: []string{"manage_all"}, IsSystem: true},
			{Id: uuid.New(), OrgId: orgId, DisplayName: RoleViewer, Permissions: []string{"read_all"}, IsSystem: true},
		}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.Membership{Id: uuid.New(), OrgId: orgId, UserId: globalUserId}, nil)

	// CreateScimUser
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	// GetUser for resource rendering
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Alice", PrimaryEmailAddress: opt.Of("alice@example.com")}, nil)

	body := ScimUserResource{
		Schemas:    []string{scimSchemaUser},
		UserName:   "alice@example.com",
		ExternalId: "ext-001",
		Active:     ref.Ref(boolOrString(true)),
		Emails:     []scimEmail{{Value: "alice@example.com", Primary: true, Type: "work"}},
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "alice@example.com", res.UserName)
}

func TestScimCreateUser_MatchByExternalId(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)

	// resolveOrCreateGlobalUser: hits SCIM identity → existing user.
	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-999").
		Return(&globalUserId, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Any(), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Bob", CreatedAt: now}, nil)

	// ensureOrgMembership: already a member.
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{Id: uuid.New()}}}, nil)

	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Bob"}, nil)

	body := ScimUserResource{
		Schemas:    []string{scimSchemaUser},
		UserName:   "bob@example.com",
		ExternalId: "ext-999",
		Active:     ref.Ref(boolOrString(true)),
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestScimCreateUser_MatchByEmail(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)

	// No externalId, but email match exists.
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "carol@example.com").
		Return(&model.User{Id: globalUserId, DisplayName: "Carol", CreatedAt: now}, nil)

	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{
			{Id: uuid.New(), OrgId: orgId, DisplayName: RoleViewer, Permissions: []string{"read_all"}, IsSystem: true},
		}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.Membership{Id: uuid.New()}, nil)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Carol", PrimaryEmailAddress: opt.Of("carol@example.com")}, nil)

	body := ScimUserResource{
		Schemas:  []string{scimSchemaUser},
		UserName: "carol@example.com",
		Active:   ref.Ref(boolOrString(true)),
		Emails:   []scimEmail{{Value: "carol@example.com", Primary: true}},
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestScimCreateUser_ConflictUserName(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "dup@example.com").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.User{Id: globalUserId, CreatedAt: now}, nil)
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{{Id: uuid.New(), OrgId: orgId, DisplayName: RoleViewer, IsSystem: true}}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.Membership{Id: uuid.New()}, nil)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(model.NewErrConflict("scim user name already exists in org"))

	body := ScimUserResource{Schemas: []string{scimSchemaUser}, UserName: "dup@example.com", Active: ref.Ref(boolOrString(true)),
		Emails: []scimEmail{{Value: "dup@example.com", Primary: true}}}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "uniqueness", errBody.ScimType)
}

// ------------------------------------------------------------------ PATCH /Users

func TestScimPatchUser_DeactivateEntraStringBool(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	existing := &model.ScimUser{
		Id: scimUserId, OrgId: orgId, UserId: globalUserId,
		UserName: "dave@example.com", Active: true,
		CreatedAt: now, UpdatedAt: now,
	}

	// GET for the user.
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).Return(existing, nil)

	// deactivateUser path.
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(globalUserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{}, nil) // no remaining memberships anywhere
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), globalUserId).Return(int64(1), nil)
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	// After deactivation, we do another UpdateScimUser for field changes (same value).
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	// GetUser for response rendering.
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Dave"}, nil)

	// Entra sends string "False" for active.
	patchBody := scimPatchRequest{
		Schemas: []string{scimPatchOpSchema},
		Operations: []scimPatchOp{
			{Op: "Replace", Path: "active", Value: json.RawMessage(`"False"`)},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.False(t, bool(*res.Active))
}

func TestScimPatchUser_ReactivateUser(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	existing := &model.ScimUser{
		Id: scimUserId, OrgId: orgId, UserId: globalUserId,
		UserName: "eve@example.com", Active: false,
		CreatedAt: now, UpdatedAt: now,
	}

	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).Return(existing, nil)

	// reactivateUser path.
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{{Id: uuid.New(), OrgId: orgId, DisplayName: RoleViewer, IsSystem: true}}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.Membership{Id: uuid.New()}, nil)
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	// Field update after reactivation.
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Eve"}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`true`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.True(t, bool(*res.Active))
}

// ------------------------------------------------------------------ DELETE /Users

func TestScimDeleteUser_Success(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	existing := &model.ScimUser{
		Id: scimUserId, OrgId: orgId, UserId: globalUserId,
		UserName: "frank@example.com", Active: true,
		CreatedAt: now, UpdatedAt: now,
	}

	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).Return(existing, nil)
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(globalUserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), globalUserId).Return(int64(0), nil)
	db.EXPECT().DeleteScimUser(gomock.Any(), gomock.Any(), orgId, scimUserId).Return(nil)

	c, rec := scimRequest(t, e, http.MethodDelete, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimDeleteUser(c))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestScimDeleteUser_NotFound(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()

	mockScimWriteAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(nil, model.NewErrNotFound("not found"))

	c, rec := scimRequest(t, e, http.MethodDelete, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimDeleteUser(c))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ------------------------------------------------------------------ DELETE /Users — keeps sessions if user has other orgs

func TestScimDeleteUser_KeepsSessionsIfOtherMemberships(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).Return(&model.ScimUser{
		Id: scimUserId, OrgId: orgId, UserId: globalUserId,
		UserName: "grace@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
	}, nil)
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(1), nil)
	// Still has a membership in another org → no session revocation.
	otherOrgId := "other-org"
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{OrgId: otherOrgId}}}, nil)
	// DeleteSessionTokensByUserId should NOT be called.
	db.EXPECT().DeleteScimUser(gomock.Any(), gomock.Any(), orgId, scimUserId).Return(nil)

	c, rec := scimRequest(t, e, http.MethodDelete, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimDeleteUser(c))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// ------------------------------------------------------------------ authorization denial

func TestScimGetUser_AuthorizationDenied(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()

	mockScimAuthDenied(s, callerUserId)

	c, rec := scimRequest(t, e, http.MethodGet, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimGetUser(c))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "403", errBody.Status)
}

func TestScimCreateUser_NoFromHeader_Unauthorized(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	// Build a request without injecting ContextKeyUserID (simulates missing From header).
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(echo.HeaderContentType, "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("orgId")
	c.SetParamValues(orgId)

	// No user ID in context → GetAuthenticatedUserId should fail → 401.
	// scimCheckAuth will panic if the user is missing because hecho.GetUserID panics.
	// We handle this with a recover or return 401 from scimAuthMiddleware in production,
	// but here we just confirm the middleware path catches it.
	// Since the user id is not in context, GetAuthenticatedUserId returns an error.
	// We need to call handleScimCreateUser which calls scimCheckAuth.
	// Without ContextKeyUserID this will panic from hecho.GetUserID.
	// The test exercises the scimAuthMiddleware path instead.
	handler := s.scimAuthMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	// No From header → should return 401.
	require.NoError(t, handler(c))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ------------------------------------------------------------------ GET /Users list + filter

func TestScimListUsers_Filter_UserName(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := uuid.New()
	now := time.Now().UTC()

	mockScimReadAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().FindScimUserByUserName(gomock.Any(), nil, orgId, "hal@example.com").
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "hal@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Hal"}, nil)

	req := httptest.NewRequest(http.MethodGet, `/?filter=userName+eq+"hal@example.com"`, nil)
	req = req.WithContext(context.WithValue(req.Context(), hecho.ContextKeyUserID, callerUserId.String()))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("orgId")
	c.SetParamValues(orgId)

	require.NoError(t, s.handleScimListUsers(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var list scimListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 1, list.TotalResults)
}

func TestScimListUsers_InvalidFilter(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	req := httptest.NewRequest(http.MethodGet, `/?filter=userName+pr`, nil)
	req = req.WithContext(context.WithValue(req.Context(), hecho.ContextKeyUserID, callerUserId.String()))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("orgId")
	c.SetParamValues(orgId)

	require.NoError(t, s.handleScimListUsers(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "invalidFilter", errBody.ScimType)
}

// ------------------------------------------------------------------ ServiceProviderConfig

func TestScimServiceProviderConfig(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	c, rec := scimRequest(t, e, http.MethodGet, "/", nil, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimServiceProviderConfig(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var cfg scimServiceProviderConfig
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cfg))
	assert.True(t, cfg.Patch.Supported)
	assert.False(t, cfg.Bulk.Supported)
	assert.True(t, cfg.Filter.Supported)
	assert.Equal(t, 200, cfg.Filter.MaxResults)
}

// ------------------------------------------------------------------ Groups

func TestScimCreateGroup_Success(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().CreateScimGroup(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)

	body := ScimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		DisplayName: "Engineering",
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateGroup(c))
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestScimPatchGroup_BracketMemberRemove(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	memberId := uuid.New()
	groupId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimGroup(gomock.Any(), nil, orgId, groupId).Return(&model.ScimGroup{
		Id: groupId, OrgId: orgId, DisplayName: "Eng",
		MemberIds: []uuid.UUID{memberId, uuid.New()},
		CreatedAt: now, UpdatedAt: now,
	}, nil)
	db.EXPECT().UpdateScimGroup(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, g model.ScimGroup) error {
			// The member should have been removed.
			for _, id := range g.MemberIds {
				assert.NotEqual(t, memberId, id, "removed member should not be in updated group")
			}
			return nil
		})

	// Entra bracket remove path.
	patchBody := scimPatchRequest{
		Schemas: []string{scimPatchOpSchema},
		Operations: []scimPatchOp{
			{Op: "remove", Path: `members[value eq "` + memberId.String() + `"]`},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimPatchGroup(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// Entra can stage users with active=false; no membership may be created until
// activation.
func TestScimCreateUser_StagedInactive(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-staged").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "staged@example.com").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.User{Id: globalUserId, DisplayName: "Staged", CreatedAt: now}, nil)

	// No ListMemberships / ListRoles / CreateMembership expectations: creating a
	// membership for a staged user must fail this test.
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.False(t, u.Active, "staged user must be stored inactive")
			return nil
		})

	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Staged"}, nil)

	body := map[string]interface{}{
		"schemas":    []string{scimSchemaUser},
		"userName":   "staged@example.com",
		"externalId": "ext-staged",
		"active":     false,
		"emails":     []map[string]interface{}{{"value": "staged@example.com", "primary": true, "type": "work"}},
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.False(t, bool(*res.Active))
}

// The IDP is authoritative for names of provisioned users: a displayName PATCH
// must propagate to the global user record.
func TestScimPatchUser_DisplayNamePropagates(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "alice@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Old Name"}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, u *model.User) (*model.User, error) {
			assert.Equal(t, "New Name", u.DisplayName)
			return u, nil
		})

	// Resource rendering after the update.
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "New Name", PrimaryEmailAddress: opt.Of("alice@example.com")}, nil)

	body := map[string]interface{}{
		"schemas": []string{scimPatchOpSchema},
		"Operations": []map[string]interface{}{
			{"op": "Replace", "path": "displayName", "value": "New Name"},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "New Name", res.DisplayName)
}

// An IDP that omits `active` on create must still get a usable (active) user;
// the zero value of a plain bool would silently provision a membershipless husk.
func TestScimCreateUser_ActiveDefaultsTrueWhenOmitted(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "noactive@example.com").
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.User{Id: globalUserId, DisplayName: "No Active", CreatedAt: now}, nil)

	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{
			{Id: uuid.New(), OrgId: orgId, DisplayName: RoleViewer, Permissions: []string{"read_all"}, IsSystem: true},
		}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.Membership{Id: uuid.New(), OrgId: orgId, UserId: globalUserId}, nil)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.True(t, u.Active, "omitted active must default to true")
			return nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "No Active"}, nil)

	body := map[string]interface{}{
		"schemas":  []string{scimSchemaUser},
		"userName": "noactive@example.com",
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	require.NotNil(t, res.Active)
	assert.True(t, bool(*res.Active))
}
