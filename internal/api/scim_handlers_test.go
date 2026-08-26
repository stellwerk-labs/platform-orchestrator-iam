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
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
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

// mockReconcileNoMappings wires the role reconciler's lookups for a user whose
// groups map to nothing: mapped roles and managed memberships both come back
// empty, then existing memberships decide whether the Viewer fallback applies.
func mockReconcileNoMappings(db *mockmodel.MockDatabaser, globalUserId uuid.UUID, existing []model.MembershipWithUserMetadata) {
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		Return([]uuid.UUID{}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]uuid.UUID{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId, UserId: &globalUserId, SubjectType: &subjectTypeRole,
	}).Return(existing, nil)
}

// mockReconcileViewerFallback wires the full fallback path: no mappings, no
// managed memberships, no manual memberships → one SCIM-managed Viewer grant.
func mockReconcileViewerFallback(t *testing.T, db *mockmodel.MockDatabaser, globalUserId uuid.UUID) {
	t.Helper()
	mockReconcileNoMappings(db, globalUserId, []model.MembershipWithUserMetadata{})
	viewerRoleId := uuid.New()
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{
			{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer, Permissions: []string{"read_all"}, IsSystem: true},
		}, nil)
	var createdMembershipId uuid.UUID
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, m *model.Membership) (*model.Membership, error) {
			assert.Equal(t, orgId, m.OrgId)
			assert.Equal(t, globalUserId, m.UserId)
			assert.Equal(t, viewerRoleId.String(), m.Subject, "fallback must grant the Viewer role")
			createdMembershipId = m.Id
			return m, nil
		})
	db.EXPECT().CreateScimManagedMembership(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, membershipId uuid.UUID, _ uuid.UUID) error {
			assert.Equal(t, createdMembershipId, membershipId, "the created membership must be recorded as SCIM-managed")
			return nil
		})
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

	// Role reconciliation: no mappings, no manual grants → managed Viewer.
	mockReconcileViewerFallback(t, db, globalUserId)
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)

	// CreateScimUser — the stored row must carry exactly what the IDP sent.
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.Equal(t, orgId, u.OrgId)
			assert.Equal(t, globalUserId, u.UserId)
			assert.Equal(t, "alice@example.com", u.UserName)
			assert.Equal(t, "ext-001", u.ExternalId.Must())
			assert.True(t, u.Active)
			return nil
		})

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

	// Role reconciliation: already a (manually granted) member, so the Viewer
	// fallback must not add anything on top.
	mockReconcileNoMappings(db, globalUserId, []model.MembershipWithUserMetadata{{Membership: model.Membership{Id: uuid.New()}}})
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)

	// The SCIM row must be bound to the user the identity matched — not a fresh one.
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.Equal(t, globalUserId, u.UserId)
			assert.Equal(t, orgId, u.OrgId)
			assert.Equal(t, "bob@example.com", u.UserName)
			return nil
		})

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

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "bob@example.com", res.UserName)
	assert.Equal(t, "ext-999", res.ExternalId)
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

	mockReconcileViewerFallback(t, db, globalUserId)
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)
	// The SCIM row must reuse the email-matched user, not a fresh one.
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.Equal(t, globalUserId, u.UserId)
			assert.Equal(t, orgId, u.OrgId)
			return nil
		})
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
	// CreateScimUser conflicts before any membership reconciliation runs, so no
	// role or membership expectations belong here.
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
	// The detail must be the curated conflict message, never the internal error
	// chain with its Go wrap prefixes ("failed to create scim user: ...").
	assert.Equal(t, "scim user name already exists in org", errBody.Detail)
	assert.NotContains(t, errBody.Detail, "failed to")
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
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUserId).
		Return([]uuid.UUID{uuid.New()}, nil)
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(globalUserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{}, nil) // no remaining memberships anywhere
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), globalUserId).Return(int64(1), nil)
	// An accepted device-login request is a session in waiting; it dies with the sessions.
	db.EXPECT().DeleteDeviceLoginRequestsDecidedBy(gomock.Any(), gomock.Any(), globalUserId).Return(int64(0), nil)
	// Membership removal and the row update happen in ONE transaction with a
	// single UpdateScimUser call; the stored row must be inactive.
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.False(t, u.Active, "stored scim row must be inactive after deactivation")
			return nil
		})
	deprovisioned := expectScimUserEvent[genevents.ScimUserDeprovisionedData](t, db, genevents.IoPlatformOrchestratorScimUserDeprovisioned)

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
	assert.Equal(t, genevents.Deactivated, deprovisioned.Data.Reason)
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

	// Reactivation reconciles roles from group mappings (none here → Viewer).
	mockReconcileViewerFallback(t, db, globalUserId)
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.True(t, u.Active, "stored scim row must be active after reactivation")
			return nil
		})

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
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUserId).
		Return([]uuid.UUID{uuid.New()}, nil)
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(globalUserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), globalUserId).Return(int64(0), nil)
	// An accepted device-login request is a session in waiting; it dies with the sessions.
	db.EXPECT().DeleteDeviceLoginRequestsDecidedBy(gomock.Any(), gomock.Any(), globalUserId).Return(int64(0), nil)
	db.EXPECT().TombstoneScimUser(gomock.Any(), gomock.Any(), orgId, scimUserId).Return(nil)
	deprovisioned := expectScimUserEvent[genevents.ScimUserDeprovisionedData](t, db, genevents.IoPlatformOrchestratorScimUserDeprovisioned)

	c, rec := scimRequest(t, e, http.MethodDelete, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimDeleteUser(c))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, genevents.Deleted, deprovisioned.Data.Reason)
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
	// Membership removal must stay scoped to THIS org.
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUserId).
		Return([]uuid.UUID{uuid.New()}, nil)
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(globalUserId),
	}).Return(int64(1), nil)
	// Still has a membership in another org → no session revocation.
	otherOrgId := "other-org"
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &globalUserId}).
		Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{OrgId: otherOrgId}}}, nil)
	// DeleteSessionTokensByUserId should NOT be called.
	db.EXPECT().TombstoneScimUser(gomock.Any(), gomock.Any(), orgId, scimUserId).Return(nil)
	expectScimUserEvent[genevents.ScimUserDeprovisionedData](t, db, genevents.IoPlatformOrchestratorScimUserDeprovisioned)

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

// A denied caller must get 403 from a mutating handler and no database
// mutation may happen (no GetScimUser / delete expectations are registered,
// so any DB touch fails the test).
func TestScimDeleteUser_AuthorizationDenied(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()

	mockScimAuthDenied(s, callerUserId)

	c, rec := scimRequest(t, e, http.MethodDelete, "/", nil, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimDeleteUser(c))
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

	// The middleware is the only thing between a From-less request and the
	// handlers, so exercise it directly: no From header must yield 401 and the
	// wrapped handler must never run.
	handler := s.scimAuthMiddleware(func(c echo.Context) error {
		t.Fatal("handler must not be reached without a From header")
		return nil
	})
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

	// Discovery is unauthenticated: no auth mock, no permission check.
	callerUserId := userid.NewServiceUserTokenId()

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
	db.EXPECT().CreateScimGroup(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, g model.ScimGroup) error {
			assert.Equal(t, "Engineering", g.DisplayName)
			assert.Equal(t, orgId, g.OrgId, "group must be created in the caller's org")
			assert.Empty(t, g.MemberIds)
			return nil
		})

	body := ScimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		DisplayName: "Engineering",
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateGroup(c))
	assert.Equal(t, http.StatusCreated, rec.Code)

	var res ScimGroupResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "Engineering", res.DisplayName)
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
	db.EXPECT().LockScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(nil)
	db.EXPECT().GetScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(&model.ScimGroup{
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
	// Both affected members get their roles reconciled in one batch; returning
	// inactive users short-circuits that, keeping this test on the removal
	// semantics.
	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Any(), orgId, gomock.Len(2)).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, ids []uuid.UUID) ([]model.ScimUser, error) {
			out := make([]model.ScimUser, 0, len(ids))
			for _, id := range ids {
				out = append(out, model.ScimUser{Id: id, OrgId: orgId, Active: false})
			}
			return out, nil
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
	// Sole governing org → the global profile write is allowed.
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
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

	// An active user (via the omission default) must get the Viewer fallback.
	mockReconcileViewerFallback(t, db, globalUserId)
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)
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

// scimListRequest builds a context for a list handler with a raw query string.
func scimListRequest(e *echo.Echo, query string, callerUserId uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/"+query, nil)
	req = req.WithContext(context.WithValue(req.Context(), hecho.ContextKeyUserID, callerUserId.String()))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("orgId")
	c.SetParamValues(orgId)
	return c, rec
}

// A bad active value ("yes") must yield 400 invalidValue, not a panic/500.
func TestScimPatchUser_InvalidActiveValueReturns400InvalidValue(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	mockScimWriteAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{Id: scimUserId, OrgId: orgId, UserName: "x@example.com", Active: true}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`"yes"`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "invalidValue", errBody.ScimType)
}

// A whitespace-only filter parses to nil and must fall through to the
// unfiltered list instead of dereferencing a nil filter.
func TestScimListUsers_WhitespaceFilterFallsThroughToList(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().CountScimUsers(gomock.Any(), nil, orgId).Return(0, nil)
	db.EXPECT().ListScimUsers(gomock.Any(), nil, orgId, 100, 0).Return([]model.ScimUser{}, nil)

	c, rec := scimListRequest(e, "?filter=%20", callerUserId)
	require.NoError(t, s.handleScimListUsers(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestScimListGroups_WhitespaceFilterFallsThroughToList(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().CountScimGroups(gomock.Any(), nil, orgId).Return(0, nil)
	db.EXPECT().ListScimGroups(gomock.Any(), nil, orgId, 100, 0).Return([]model.ScimGroup{}, nil)

	c, rec := scimListRequest(e, "?filter=%20", callerUserId)
	require.NoError(t, s.handleScimListGroups(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// RFC 7644 §3.5.2.2: remove on "members" with no value removes ALL members.
func TestScimPatchGroup_RemoveAllMembers(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().LockScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(nil)
	db.EXPECT().GetScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(&model.ScimGroup{
		Id: groupId, OrgId: orgId, DisplayName: "Eng",
		MemberIds: []uuid.UUID{uuid.New(), uuid.New()},
		CreatedAt: now, UpdatedAt: now,
	}, nil)
	db.EXPECT().UpdateScimGroup(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, g model.ScimGroup) error {
			assert.Empty(t, g.MemberIds, "remove with no value must clear all members")
			return nil
		})
	// The removed members get their roles reconciled in one batch; returning
	// inactive users short-circuits that, keeping this test on the remove-all
	// semantics.
	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Any(), orgId, gomock.Len(2)).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, ids []uuid.UUID) ([]model.ScimUser, error) {
			out := make([]model.ScimUser, 0, len(ids))
			for _, id := range ids {
				out = append(out, model.ScimUser{Id: id, OrgId: orgId, Active: false})
			}
			return out, nil
		})

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "remove", Path: "members"}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimPatchGroup(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// A scalar remove on externalId must clear the stored value.
func TestScimPatchUser_RemoveExternalIdClearsIt(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).Return(&model.ScimUser{
		Id: scimUserId, OrgId: orgId, UserId: globalUserId,
		UserName: "x@example.com", ExternalId: opt.Of("ext-1"), Active: true,
		CreatedAt: now, UpdatedAt: now,
	}, nil)
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.False(t, u.ExternalId.IsSet(), "remove must clear externalId")
			return nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "X"}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "remove", Path: "externalId"}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Empty(t, res.ExternalId)
}

// Entra probes group externalId filters when its matching attribute is externalId.
func TestScimListGroups_FilterExternalId_Found(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	now := time.Now().UTC()

	mockScimReadAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		FindScimGroupByExternalId(gomock.Any(), nil, orgId, "grp-ext-1").
		Return(&model.ScimGroup{
			Id: groupId, OrgId: orgId, DisplayName: "Eng",
			ExternalId: opt.Of("grp-ext-1"), CreatedAt: now, UpdatedAt: now,
		}, nil)

	c, rec := scimListRequest(e, `?filter=externalId+eq+"grp-ext-1"`, callerUserId)
	require.NoError(t, s.handleScimListGroups(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var list scimListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 1, list.TotalResults)
}

func TestScimListGroups_FilterExternalId_MissReturnsEmptyList(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		FindScimGroupByExternalId(gomock.Any(), nil, orgId, "no-such").
		Return(nil, model.NewErrNotFound("scim group not found"))

	c, rec := scimListRequest(e, `?filter=externalId+eq+"no-such"`, callerUserId)
	require.NoError(t, s.handleScimListGroups(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var list scimListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 0, list.TotalResults)
	assert.Equal(t, 0, list.ItemsPerPage)
}

// Entra sets externalId via PATCH right after group create.
func TestScimPatchGroup_SetExternalId(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().LockScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(nil)
	db.EXPECT().GetScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).Return(&model.ScimGroup{
		Id: groupId, OrgId: orgId, DisplayName: "Eng", CreatedAt: now, UpdatedAt: now,
	}, nil)
	db.EXPECT().UpdateScimGroup(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, g model.ScimGroup) error {
			require.True(t, g.ExternalId.IsSet())
			assert.Equal(t, "grp-ext-9", *g.ExternalId.Ref())
			return nil
		})

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "externalId", Value: json.RawMessage(`"grp-ext-9"`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimPatchGroup(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimGroupResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "grp-ext-9", res.ExternalId)
}

// A bracket member path with a non-remove op must be rejected, not coerced
// into a remove.
func TestScimPatchGroup_BracketPathAddReturns400InvalidPath(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	memberId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	// The bracket path is rejected while normalising the ops, before the
	// transaction opens, so the group is never read.
	_ = now

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "add", Path: `members[value eq "` + memberId.String() + `"]`}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimPatchGroup(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "invalidPath", errBody.ScimType)
}

// ------------------------------------------------------------------ pagination

func TestScimPageParams(t *testing.T) {
	e := echo.New()
	cases := []struct {
		query     string
		wantStart int
		wantCount int
	}{
		{query: "", wantStart: 1, wantCount: 100},
		{query: "?count=0", wantStart: 1, wantCount: 0},
		{query: "?count=-5", wantStart: 1, wantCount: 0},
		{query: "?count=50", wantStart: 1, wantCount: 50},
		{query: "?count=1000", wantStart: 1, wantCount: 200},
		{query: "?startIndex=3&count=10", wantStart: 3, wantCount: 10},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/"+tc.query, nil)
		c := e.NewContext(req, httptest.NewRecorder())
		start, count := scimPageParams(c)
		assert.Equal(t, tc.wantStart, start, "query %q", tc.query)
		assert.Equal(t, tc.wantCount, count, "query %q", tc.query)
	}
}

// The unfiltered list must resolve every row's global user through ONE batched
// lookup — the strict mock fails this test if any per-row GetUser sneaks in.
func TestScimListUsers_BatchesGlobalUserLookup(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	now := time.Now().UTC()
	scimUsers := make([]model.ScimUser, 0, 3)
	globalUsers := make([]model.User, 0, 3)
	for i := 0; i < 3; i++ {
		globalUserId := userid.NewHumanUserId()
		scimUsers = append(scimUsers, model.ScimUser{
			Id: uuid.New(), OrgId: orgId, UserId: globalUserId,
			UserName: string(rune('a'+i)) + "@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		})
		globalUsers = append(globalUsers, model.User{
			Id: globalUserId, DisplayName: "User " + string(rune('A'+i)),
			PrimaryEmailAddress: opt.Of(string(rune('a'+i)) + "@example.com"),
		})
	}

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().CountScimUsers(gomock.Any(), nil, orgId).Return(3, nil)
	db.EXPECT().ListScimUsers(gomock.Any(), nil, orgId, 100, 0).Return(scimUsers, nil)
	db.EXPECT().GetUsersByIds(gomock.Any(), nil, gomock.Len(3)).Return(globalUsers, nil).Times(1)

	c, rec := scimListRequest(e, "", callerUserId)
	require.NoError(t, s.handleScimListUsers(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var list struct {
		TotalResults int                `json:"totalResults"`
		Resources    []ScimUserResource `json:"Resources"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 3, list.TotalResults)
	require.Len(t, list.Resources, 3)
	for i, resource := range list.Resources {
		assert.Equal(t, "User "+string(rune('A'+i)), resource.DisplayName, "display name must come from the batched lookup")
		require.Len(t, resource.Emails, 1)
		assert.Equal(t, string(rune('a'+i))+"@example.com", resource.Emails[0].Value)
	}
}

// RFC 7644 §3.4.2.4: count=0 returns no resources but an honest totalResults.
func TestScimListUsers_CountZeroReturnsHonestTotal(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimReadAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().CountScimUsers(gomock.Any(), nil, orgId).Return(42, nil)
	db.EXPECT().ListScimUsers(gomock.Any(), nil, orgId, 0, 0).Return([]model.ScimUser{}, nil)

	c, rec := scimListRequest(e, "?count=0", callerUserId)
	require.NoError(t, s.handleScimListUsers(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var list scimListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 42, list.TotalResults)
	assert.Equal(t, 0, list.ItemsPerPage)
}

// ------------------------------------------------------------------ meta.location scheme

// Behind TLS-terminating Envoy the request itself is plaintext; the scheme
// must come from X-Forwarded-Proto, not the TLS connection state.
func TestScimResourceLocation_HonorsXForwardedProto(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "iam.example.com"
	req.Header.Set(echo.HeaderXForwardedProto, "https")
	c := e.NewContext(req, httptest.NewRecorder())

	s := &Server{}
	loc := s.scimResourceLocation(c, "/scim/v2/orgs/o/Users/u")
	assert.Equal(t, "https://iam.example.com/scim/v2/orgs/o/Users/u", loc)
}

// A configured ApiHostUrl pins meta.location outright: the attacker-controlled
// Host header must not appear in what we hand to the IDP.
func TestScimResourceLocation_ConfiguredApiHostUrlWins(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example.net"
	req.Header.Set(echo.HeaderXForwardedProto, "https")
	c := e.NewContext(req, httptest.NewRecorder())

	s := &Server{ApiHostUrl: "https://iam.example.com/"}
	loc := s.scimResourceLocation(c, "/scim/v2/orgs/o/Users/u")
	assert.Equal(t, "https://iam.example.com/scim/v2/orgs/o/Users/u", loc)
}

// Without a configured base URL the Host fallback must refuse anything that is
// not a plain authority; the location degrades to a relative URI reference
// instead of reflecting attacker-shaped input.
func TestScimResourceLocation_RejectsMalformedHostHeader(t *testing.T) {
	e := echo.New()
	for _, host := range []string{
		"",
		"evil.example.net/phish",
		"user:pass@evil.example.net",
		"evil.example.net?q=1",
		"evil.example.net#frag",
		"evil example.net",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		c := e.NewContext(req, httptest.NewRecorder())

		s := &Server{}
		loc := s.scimResourceLocation(c, "/scim/v2/orgs/o/Users/u")
		assert.Equal(t, "/scim/v2/orgs/o/Users/u", loc, "host %q must not be reflected", host)
	}
	// Sanity check: an honest host (with port) still passes.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "iam.example.com:8443"
	c := e.NewContext(req, httptest.NewRecorder())
	s := &Server{}
	assert.Equal(t, "http://iam.example.com:8443/scim/v2/orgs/o/Users/u", s.scimResourceLocation(c, "/scim/v2/orgs/o/Users/u"))
}

// ------------------------------------------------------------------ blank scalar values

func TestScimPatchUser_BlankUserNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	mockScimWriteAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{Id: scimUserId, OrgId: orgId, UserName: "x@example.com", Active: true}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "userName", Value: json.RawMessage(`""`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "invalidValue", errBody.ScimType)
}

func TestScimPatchGroup_BlankDisplayNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	mockScimWriteAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		LockScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).
		Return(nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimGroup(gomock.Any(), gomock.Not(nil), orgId, groupId).
		Return(&model.ScimGroup{Id: groupId, OrgId: orgId, DisplayName: "Eng"}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "displayName", Value: json.RawMessage(`""`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimPatchGroup(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, "invalidValue", errBody.ScimType)
}

// ------------------------------------------------------------------ error envelope

// Internal errors leaving a SCIM handler must produce a SCIM Error envelope,
// not echo's default {"message":...} body. Exercised through the full router
// so the group middleware chain is what's under test.
func TestScimErrorEnvelope_InternalErrorReturnsScimBody(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	mockScimReadAuth(s, callerUserId, orgId)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(nil, assert.AnError)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/orgs/"+orgId+"/Users/"+scimUserId.String(), nil)
	req.Header.Set(authenticatedUserIdHeader, callerUserId.String())
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, []string{scimErrorSchema}, errBody.Schemas)
	assert.Equal(t, "500", errBody.Status)
}

// The middleware must not touch responses that handlers already committed.
func TestScimErrorEnvelopeMiddleware_PassesThroughCommittedResponses(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := scimErrorEnvelopeMiddleware(func(c echo.Context) error {
		return scimErrorResp(c, http.StatusNotFound, "", "user not found")
	})
	require.NoError(t, handler(c))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// Provisioning the same person into a second organization always matches by
// email, because the first org owns the only SCIM identity key. That match must
// still record this org's key, otherwise a later email change in the IDP makes
// the second org match nothing and create a duplicate global user.
func TestScimCreateUser_SecondOrgMatchByEmailPersistsItsOwnIdentity(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()
	externalId := "ext-multi-org"
	identityKey := orgId + ":" + externalId

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)

	// This org has no identity key yet (the other org holds its own).
	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, identityKey).
		Return(nil, model.NewErrNotFound("not found"))
	db.EXPECT().FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "dana@example.com").
		Return(&model.User{Id: globalUserId, DisplayName: "Dana", CreatedAt: now}, nil)

	db.EXPECT().
		AddUserIdentity(gomock.Any(), gomock.Any(), globalUserId, model.UserIdentityProviderScim, identityKey).
		Return(nil)

	// The fallback helper asserts the membership is created for globalUserId,
	// i.e. the existing global user is reused rather than a second one created.
	mockReconcileViewerFallback(t, db, globalUserId)
	expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			assert.Equal(t, globalUserId, u.UserId)
			return nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Dana", PrimaryEmailAddress: opt.Of("dana@example.com")}, nil)

	body := ScimUserResource{
		Schemas:    []string{scimSchemaUser},
		UserName:   "dana@example.com",
		ExternalId: externalId,
		Active:     ref.Ref(boolOrString(true)),
		Emails:     []scimEmail{{Value: "dana@example.com", Primary: true}},
	}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusCreated, rec.Code)
}

// ------------------------------------------------------------------ emails on PATCH (D18)

// A PATCH targeting the emails attribute must reach the global user record,
// exactly like a PUT would (D18: it used to be silently dropped).
func TestScimPatchUser_EmailsArrayPropagates(t *testing.T) {
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
			UserName: "grace@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)
	// Sole governing org → the global profile write is allowed.
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Grace", PrimaryEmailAddress: opt.Of("old@example.com")}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, u *model.User) (*model.User, error) {
			assert.Equal(t, "new@example.com", *u.PrimaryEmailAddress.Ref())
			return u, nil
		})

	// Resource rendering after the update.
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Grace", PrimaryEmailAddress: opt.Of("new@example.com")}, nil)

	body := map[string]interface{}{
		"schemas": []string{scimPatchOpSchema},
		"Operations": []map[string]interface{}{
			{"op": "Replace", "path": "emails", "value": []map[string]interface{}{
				{"value": "new@example.com", "type": "work", "primary": true},
			}},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	require.NotEmpty(t, res.Emails)
	assert.Equal(t, "new@example.com", res.Emails[0].Value)
}

// The Entra/Okta bracket form (`emails[type eq "work"].value` with a plain
// string) must land on the same email path.
func TestScimPatchUser_EmailsBracketFormPropagates(t *testing.T) {
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
			UserName: "heidi@example.com", Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)
	// Sole governing org → the global profile write is allowed.
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Heidi", PrimaryEmailAddress: opt.Of("old@example.com")}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, u *model.User) (*model.User, error) {
			assert.Equal(t, "bracket@example.com", *u.PrimaryEmailAddress.Ref())
			return u, nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Heidi", PrimaryEmailAddress: opt.Of("bracket@example.com")}, nil)

	body := map[string]interface{}{
		"schemas": []string{scimPatchOpSchema},
		"Operations": []map[string]interface{}{
			{"op": "Replace", "path": `emails[type eq "work"].value`, "value": "bracket@example.com"},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ------------------------------------------------------------------ input bounds (item: unbounded SCIM input)

// An oversized body is rejected by the route group's BodyLimit before any
// handler runs, and the 413 still goes out as a SCIM error envelope. This goes
// through the real router: the limit lives in middleware, not the handler.
func TestScimBodyLimit_OversizedBodyGets413ScimEnvelope(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	oversized := bytes.Repeat([]byte("a"), 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/orgs/"+orgId+"/Users", bytes.NewReader(oversized))
	req.Header.Set(echo.HeaderContentType, "application/scim+json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "body: %s", rec.Body.String())
	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Contains(t, errBody.Schemas, scimErrorSchema)
	assert.Equal(t, "413", errBody.Status)
}

// A group create carrying more members than the bound is a clean 400
// invalidValue, refused before the transaction (and its group row lock) opens.
func TestScimCreateGroup_TooManyMembersRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimWriteAuth(s, callerUserId, orgId)

	members := make([]scimGroupMember, scimMaxMembersPerRequest+1)
	for i := range members {
		members[i] = scimGroupMember{Value: uuid.New().String()}
	}
	body := ScimGroupResource{Schemas: []string{scimSchemaGroup}, DisplayName: "Everyone", Members: members}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateGroup(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, scimTypeInvalidValue, errBody.ScimType)
	assert.Contains(t, errBody.Detail, "exceeding the maximum")
}
