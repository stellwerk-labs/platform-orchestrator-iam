package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	mockauthorization "github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func ctxWithUser(t *testing.T, userId uuid.UUID) context.Context {
	t.Helper()
	return context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
}

func TestUpsertScimGroupMapping_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	created := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).
		Return(&model.Role{Id: roleId, OrgId: orgId, DisplayName: "Deployer"}, nil)
	// No group with that name has synced yet → nothing to lock, nobody to reconcile.
	db.EXPECT().LockScimGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers").
		Return(model.NewErrNotFound("scim group not found"))
	db.EXPECT().UpsertScimGroupRoleMapping(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers", roleId).
		Return(&model.ScimGroupRoleMapping{OrgId: orgId, GroupDisplayName: "Platform Engineers", RoleId: roleId, CreatedAt: created}, nil)
	db.EXPECT().ListScimUserIdsInGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers").
		Return([]uuid.UUID{}, nil)

	r, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
		Body:             &ScimGroupMappingWriteBody{RoleId: roleId},
	})
	require.NoError(t, err)
	require.Equal(t, UpsertScimGroupMapping200JSONResponse{
		GroupDisplayName: "Platform Engineers",
		RoleId:           roleId,
		CreatedAt:        created,
	}, r)
}

// The mutation must demand membership_write. A caller whose only permissions
// are the SCIM provisioning ones (i.e. the IDP's own service user) must be
// rejected, otherwise the SCIM client could map a group it controls to Admin
// and self-escalate.
func TestUpsertScimGroupMapping_ProvisioningWriteIsNotSufficient(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewServiceUserTokenId()
	var requestedPermissions []string
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			// Grant everything a provisioning caller has, deny everything else.
			results := make([]authorization.Result, 0, len(checks))
			for _, check := range checks {
				requestedPermissions = append(requestedPermissions, check.Permission)
				allowed := check.Permission == sharedauthz.PermissionProvisioningRead ||
					check.Permission == sharedauthz.PermissionProvisioningWrite
				results = append(results, authorization.Result{Check: check, Allowed: allowed})
			}
			return results, nil
		}).Times(1)

	_, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
		Body:             &ScimGroupMappingWriteBody{RoleId: uuid.New()},
	})
	require.Error(t, err)
	var poErr *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &poErr)
	assert.Equal(t, http.StatusForbidden, poErr.StatusCode)
	assert.Equal(t, []string{sharedauthz.PermissionMembershipWrite}, requestedPermissions,
		"the mutation must ask for membership_write, nothing weaker")
}

// Mapping a populated group to a role assigns access, which is membership
// administration. role_write only covers role definitions: a caller holding it
// (and nothing stronger) must NOT be able to grant a role to a whole group.
func TestUpsertScimGroupMapping_RoleWriteIsNotSufficient(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	var requestedPermissions []string
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			// Grant the full role-administration set, deny everything else.
			results := make([]authorization.Result, 0, len(checks))
			for _, check := range checks {
				requestedPermissions = append(requestedPermissions, check.Permission)
				allowed := check.Permission == sharedauthz.PermissionRoleRead ||
					check.Permission == sharedauthz.PermissionRoleWrite
				results = append(results, authorization.Result{Check: check, Allowed: allowed})
			}
			return results, nil
		}).Times(1)

	_, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
		Body:             &ScimGroupMappingWriteBody{RoleId: uuid.New()},
	})
	require.Error(t, err)
	var poErr *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &poErr)
	assert.Equal(t, http.StatusForbidden, poErr.StatusCode)
	assert.Equal(t, []string{sharedauthz.PermissionMembershipWrite}, requestedPermissions,
		"role_write alone must not open the mapping mutation")
}

// Same guarantee for the delete: dropping a mapping revokes access from the
// group's members, so role_write alone must not be enough either.
func TestDeleteScimGroupMapping_RoleWriteIsNotSufficient(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	var requestedPermissions []string
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			results := make([]authorization.Result, 0, len(checks))
			for _, check := range checks {
				requestedPermissions = append(requestedPermissions, check.Permission)
				allowed := check.Permission == sharedauthz.PermissionRoleRead ||
					check.Permission == sharedauthz.PermissionRoleWrite
				results = append(results, authorization.Result{Check: check, Allowed: allowed})
			}
			return results, nil
		}).Times(1)

	_, err := s.DeleteScimGroupMapping(ctxWithUser(t, userId), DeleteScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
	})
	require.Error(t, err)
	var poErr *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &poErr)
	assert.Equal(t, http.StatusForbidden, poErr.StatusCode)
	assert.Equal(t, []string{sharedauthz.PermissionMembershipWrite}, requestedPermissions,
		"role_write alone must not open the mapping delete")
}

func TestDeleteScimGroupMapping_RequiresMembershipWrite(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	var requestedPermissions []string
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			results := make([]authorization.Result, 0, len(checks))
			for _, check := range checks {
				requestedPermissions = append(requestedPermissions, check.Permission)
				results = append(results, authorization.Result{Check: check, Allowed: false})
			}
			return results, nil
		}).Times(1)

	_, err := s.DeleteScimGroupMapping(ctxWithUser(t, userId), DeleteScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
	})
	require.Error(t, err)
	var poErr *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &poErr)
	assert.Equal(t, http.StatusForbidden, poErr.StatusCode)
	assert.Equal(t, []string{sharedauthz.PermissionMembershipWrite}, requestedPermissions)
}

func TestListScimGroupMappings_RequiresMembershipRead(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	MockAuthorizationFailure(s, userId, orgId)

	_, err := s.ListScimGroupMappings(ctxWithUser(t, userId), ListScimGroupMappingsRequestObject{OrgId: orgId})
	require.Error(t, err)
	var poErr *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &poErr)
	assert.Equal(t, http.StatusForbidden, poErr.StatusCode)
}

func TestListScimGroupMappings_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	created := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipRead)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListScimGroupRoleMappings(gomock.Any(), nil, orgId).
		Return([]model.ScimGroupRoleMapping{
			{OrgId: orgId, GroupDisplayName: "Platform Engineers", RoleId: roleId, CreatedAt: created},
		}, nil)

	r, err := s.ListScimGroupMappings(ctxWithUser(t, userId), ListScimGroupMappingsRequestObject{OrgId: orgId})
	require.NoError(t, err)
	require.Equal(t, ListScimGroupMappings200JSONResponse{
		Items: []ScimGroupMapping{{GroupDisplayName: "Platform Engineers", RoleId: roleId, CreatedAt: created}},
	}, r)
}

// A role id from another org must be rejected: GetRole is org-scoped, so the
// lookup misses and the caller gets a 404 instead of a cross-org grant.
func TestUpsertScimGroupMapping_CrossOrgRoleRejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	foreignRoleId := uuid.New()

	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetRole(gomock.Any(), nil, orgId, foreignRoleId).
		Return(nil, model.NewErrNotFound("role not found"))

	r, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
		Body:             &ScimGroupMappingWriteBody{RoleId: foreignRoleId},
	})
	require.NoError(t, err)
	require.Equal(t, UpsertScimGroupMapping404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, r)
}

func TestUpsertScimGroupMapping_BlankNameRejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)

	r, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "   ",
		Body:             &ScimGroupMappingWriteBody{RoleId: uuid.New()},
	})
	require.NoError(t, err)
	require.Equal(t, UpsertScimGroupMapping400JSONResponse{N400BadRequestJSONResponse: Generate400Response("group display name must not be blank")}, r)
}

func TestDeleteScimGroupMapping_NotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().LockScimGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Ghosts").
		Return(model.NewErrNotFound("scim group not found"))
	db.EXPECT().DeleteScimGroupRoleMapping(gomock.Any(), gomock.Not(nil), orgId, "Ghosts").
		Return(model.NewErrNotFound("scim group role mapping not found"))

	r, err := s.DeleteScimGroupMapping(ctxWithUser(t, userId), DeleteScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Ghosts",
	})
	require.NoError(t, err)
	require.Equal(t, DeleteScimGroupMapping404JSONResponse{N404NotFoundJSONResponse: Generate404Response("scim group mapping not found")}, r)
}

func TestDeleteScimGroupMapping_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().LockScimGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers").
		Return(nil)
	db.EXPECT().
		DeleteScimGroupRoleMapping(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers").
		Return(nil)
	db.EXPECT().ListScimUserIdsInGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Platform Engineers").
		Return([]uuid.UUID{}, nil)

	r, err := s.DeleteScimGroupMapping(ctxWithUser(t, userId), DeleteScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Platform Engineers",
	})
	require.NoError(t, err)
	require.Equal(t, DeleteScimGroupMapping204Response{}, r)
}

// The whole point of reconciling on upsert: a user who is ALREADY in the group
// gets the mapped role the moment the mapping is created, with their managed
// Viewer swapped away — no SCIM traffic required.
func TestUpsertScimGroupMapping_GrantsMappedRoleToExistingMember(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	viewerRoleId := uuid.New()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	viewerMembershipId := uuid.New()
	created := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).
		Return(&model.Role{Id: roleId, OrgId: orgId, DisplayName: "Deployer"}, nil)
	// The group exists, so the mapping upsert must take its row lock to
	// serialise with concurrent SCIM group PATCHes.
	db.EXPECT().LockScimGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Engineers").
		Return(nil)
	db.EXPECT().UpsertScimGroupRoleMapping(gomock.Any(), gomock.Not(nil), orgId, "Engineers", roleId).
		Return(&model.ScimGroupRoleMapping{OrgId: orgId, GroupDisplayName: "Engineers", RoleId: roleId, CreatedAt: created}, nil)
	db.EXPECT().ListScimUserIdsInGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Engineers").
		Return([]uuid.UUID{scimUserId}, nil)
	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return([]model.ScimUser{{Id: scimUserId, OrgId: orgId, UserId: globalUserId, UserName: "in-group@example.com", Active: true}}, nil)

	// Reconciliation: the fresh mapping now applies, so the managed Viewer goes
	// and the mapped role comes.
	db.EXPECT().ListRoleIdsForScimUsersGroups(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return(map[uuid.UUID][]uuid.UUID{scimUserId: {roleId}}, nil)
	db.EXPECT().ListScimManagedMembershipsForScimUsers(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return([]model.ScimManagedMembership{
			{ScimUserId: scimUserId, MembershipId: viewerMembershipId, RoleId: opt.Of(viewerRoleId)},
		}, nil)
	db.EXPECT().DeleteMembershipsByIds(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{viewerMembershipId}).Return(nil)
	db.EXPECT().BulkCreateScimManagedMemberships(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, items []model.NewScimManagedMembership) error {
			require.Len(t, items, 1)
			assert.Equal(t, globalUserId, items[0].Membership.UserId)
			assert.Equal(t, roleId, items[0].Membership.Role.Must(), "existing member must be granted the freshly mapped role")
			assert.Equal(t, scimUserId, items[0].ScimUserId, "the created membership must be recorded as SCIM-managed")
			return nil
		})

	r, err := s.UpsertScimGroupMapping(ctxWithUser(t, userId), UpsertScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Engineers",
		Body:             &ScimGroupMappingWriteBody{RoleId: roleId},
	})
	require.NoError(t, err)
	require.Equal(t, UpsertScimGroupMapping200JSONResponse{
		GroupDisplayName: "Engineers",
		RoleId:           roleId,
		CreatedAt:        created,
	}, r)
}

// Deleting the mapping revokes the managed role from members immediately, and
// with nothing else applying the Viewer fallback restores baseline access.
func TestDeleteScimGroupMapping_RevokesRoleAndFallsBackToViewer(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	mappedRoleId := uuid.New()
	viewerRoleId := uuid.New()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	managedMembershipId := uuid.New()

	MockAuthorizationSuccess(s, userId, orgId, sharedauthz.PermissionMembershipWrite)
	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().LockScimGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Engineers").
		Return(nil)
	db.EXPECT().DeleteScimGroupRoleMapping(gomock.Any(), gomock.Not(nil), orgId, "Engineers").
		Return(nil)
	db.EXPECT().ListScimUserIdsInGroupByDisplayName(gomock.Any(), gomock.Not(nil), orgId, "Engineers").
		Return([]uuid.UUID{scimUserId}, nil)
	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return([]model.ScimUser{{Id: scimUserId, OrgId: orgId, UserId: globalUserId, UserName: "in-group@example.com", Active: true}}, nil)

	// Reconciliation: no mapping applies anymore; the only membership is the
	// managed one → it goes, and the Viewer fallback comes.
	db.EXPECT().ListRoleIdsForScimUsersGroups(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return(map[uuid.UUID][]uuid.UUID{}, nil)
	db.EXPECT().ListScimManagedMembershipsForScimUsers(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{scimUserId}).
		Return([]model.ScimManagedMembership{
			{ScimUserId: scimUserId, MembershipId: managedMembershipId, RoleId: opt.Of(mappedRoleId)},
		}, nil)
	db.EXPECT().ListRoleMembershipIdsByUser(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{globalUserId}).
		Return(map[uuid.UUID][]uuid.UUID{globalUserId: {managedMembershipId}}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Not(nil), orgId).
		Return([]model.Role{{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer, IsSystem: true}}, nil)
	db.EXPECT().DeleteMembershipsByIds(gomock.Any(), gomock.Not(nil), orgId, []uuid.UUID{managedMembershipId}).Return(nil)
	db.EXPECT().BulkCreateScimManagedMemberships(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, items []model.NewScimManagedMembership) error {
			require.Len(t, items, 1)
			assert.Equal(t, viewerRoleId.String(), items[0].Membership.Subject, "member must fall back to Viewer once the mapping is gone")
			assert.Equal(t, scimUserId, items[0].ScimUserId)
			return nil
		})

	r, err := s.DeleteScimGroupMapping(ctxWithUser(t, userId), DeleteScimGroupMappingRequestObject{
		OrgId:            orgId,
		GroupDisplayName: "Engineers",
	})
	require.NoError(t, err)
	require.Equal(t, DeleteScimGroupMapping204Response{}, r)
}
