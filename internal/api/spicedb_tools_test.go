package api

import (
	"context"
	"database/sql"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"
)

const mockZedToken = "mockzedtoken"

func TestMapRoleNameToOrgRelation(t *testing.T) {
	tests := []struct {
		name        string
		roleName    string
		expectedRel spicedb.Relation
	}{
		{
			name:        "Admin role maps to all_manager",
			roleName:    RoleAdmin,
			expectedRel: spicedb.RelationAllManager,
		},
		{
			name:        "Viewer role maps to all_reader",
			roleName:    RoleViewer,
			expectedRel: spicedb.RelationAllReader,
		},
		{
			name:        "Unknown role defaults to all_reader",
			roleName:    "CustomRole",
			expectedRel: spicedb.RelationAllReader,
		},
		{
			name:        "Empty role name defaults to all_reader",
			roleName:    "",
			expectedRel: spicedb.RelationAllReader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRelationByRoleDisplayName(tt.roleName)
			require.Equal(t, tt.expectedRel, result)
		})
	}
}

func TestSyncSpiceDBWithDB_OrgSync_OrgWideAndScopedRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zap.NewNop()

	mockDB := mockmodel.NewMockDatabaser(ctrl)
	mockSpiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	mockTx := mockmodel.NewMockTxWithCommit(ctrl)

	// Setup: Create roles, users, and scoped roles
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	humanUser1 := uuid.New()
	humanUser2 := uuid.New()
	serviceUser1 := uuid.New()
	serviceUser2 := uuid.New()
	projectId := uuid.New()
	envId := uuid.New()
	projectScope := "project:" + projectId.String()
	envScope := "environment:" + envId.String()

	scopedRoleForProject := model.ScopedRole{
		Id:        uuid.New(),
		OrgId:     orgId,
		Scope:     projectScope,
		OrgRoleId: viewerRoleId,
	}
	scopedRoleForEnv := model.ScopedRole{
		Id:        uuid.New(),
		OrgId:     orgId,
		Scope:     envScope,
		OrgRoleId: adminRoleId,
	}

	mockDB.EXPECT().BeginTx(ctx, &sql.TxOptions{ReadOnly: true}).Return(mockTx, nil)
	mockTx.EXPECT().Commit().Return(nil)
	mockTx.EXPECT().Rollback().Return(sql.ErrTxDone)

	// Return org-wide roles
	mockDB.EXPECT().ListRoles(ctx, mockTx, orgId).Return([]model.Role{
		{
			Id:          adminRoleId,
			DisplayName: RoleAdmin,
			Permissions: []string{PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: RoleViewer,
			Permissions: []string{PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}, nil)

	// Return scoped roles
	mockDB.EXPECT().ListScopedRoles(ctx, mockTx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{scopedRoleForProject, scopedRoleForEnv}, nil)

	// Return memberships: 1 org-wide admin, 1 project-scoped viewer
	mockDB.EXPECT().ListMemberships(ctx, mockTx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				UserId:      humanUser1,
				SubjectType: model.MembershipSubjectTypeRole,
				Role:        opt.Of(adminRoleId),
				Scope:       "", // Org-wide
			},
		},
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				UserId:      humanUser2,
				SubjectType: model.MembershipSubjectTypeRole,
				Role:        opt.Of(viewerRoleId),
				Scope:       projectScope, // Project-scoped
			},
		},
	}, nil)

	// Return service user roles: 1 org-wide viewer, 1 env-scoped admin
	mockDB.EXPECT().ListServiceUserRoles(ctx, mockTx, model.ListServiceUserRolesParams{
		OrgId: &orgId,
	}).Return([]model.ServiceUserRole{
		{
			ServiceUserId: serviceUser1,
			RoleId:        viewerRoleId,
			Scope:         "", // Org-wide
		},
		{
			ServiceUserId: serviceUser2,
			RoleId:        adminRoleId,
			Scope:         envScope, // Environment-scoped
		},
	}, nil)

	// Verify SpiceDB sync is called with correct relationships
	var capturedRelationships []*v1.Relationship
	mockSpiceDB.EXPECT().SyncOrgRelationships(ctx, orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, _ *uuid.UUID, _ []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			capturedRelationships = relationships
			return mockZedToken, 0, len(relationships), nil
		})

	_, _, _, _, err := SyncSpiceDBWithDB(ctx, logger, SyncSpiceDBParams{OrgId: orgId}, mockDB, mockSpiceDB)
	require.NoError(t, err)

	// Verify that we have the correct number of relationships:
	// - 2 org-wide roles: 2 relationships each (scoped_role->org, org->scoped_role) = 4
	// - 2 memberships: 1 relationship each (user->scoped_role member) = 2
	// - 2 service user roles: 1 relationship each (user->scoped_role member) = 2
	// Total = 8
	require.Len(t, capturedRelationships, 8)

	// Helper to check if a member relationship exists
	hasMemberRelationship := func(userId uuid.UUID, roleId uuid.UUID) bool {
		for _, rel := range capturedRelationships {
			if rel.Relation == spicedb.RelationMember.String() &&
				rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
				rel.Resource.ObjectId == roleId.String() &&
				rel.Subject.Object.ObjectType == spicedb.ObjectTypeUser.String() &&
				rel.Subject.Object.ObjectId == userId.String() {
				return true
			}
		}
		return false
	}

	// Verify org-wide relationships
	require.True(t, hasMemberRelationship(humanUser1, adminRoleId), "Expected org-wide admin membership for humanUser1")
	require.True(t, hasMemberRelationship(serviceUser1, viewerRoleId), "Expected org-wide viewer service user role for serviceUser1")

	// Verify scoped relationships
	require.True(t, hasMemberRelationship(humanUser2, scopedRoleForProject.Id), "Expected project-scoped viewer membership for humanUser2")
	require.True(t, hasMemberRelationship(serviceUser2, scopedRoleForEnv.Id), "Expected env-scoped admin service user role for serviceUser2")
}

func TestSyncSpiceDBWithDB_UserSync_HumanUser_OrgWideAndScopedRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zap.NewNop()

	mockDB := mockmodel.NewMockDatabaser(ctrl)
	mockSpiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	mockTx := mockmodel.NewMockTxWithCommit(ctrl)

	// Setup
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	humanUser := uuid.New()
	projectId := uuid.New()
	projectScope := "project:" + projectId.String()

	scopedRoleForProject := model.ScopedRole{
		Id:        uuid.New(),
		OrgId:     orgId,
		Scope:     projectScope,
		OrgRoleId: viewerRoleId,
	}

	mockDB.EXPECT().BeginTx(ctx, &sql.TxOptions{ReadOnly: true}).Return(mockTx, nil)
	mockTx.EXPECT().Commit().Return(nil)
	mockTx.EXPECT().Rollback().Return(sql.ErrTxDone)

	mockDB.EXPECT().ListRoles(ctx, mockTx, orgId).Return([]model.Role{
		{
			Id:          adminRoleId,
			DisplayName: RoleAdmin,
			Permissions: []string{PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: RoleViewer,
			Permissions: []string{PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}, nil)

	mockDB.EXPECT().ListScopedRoles(ctx, mockTx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{scopedRoleForProject}, nil)

	// Return memberships only for the specific human user: 1 org-wide admin, 1 project-scoped viewer
	mockDB.EXPECT().ListMemberships(ctx, mockTx, model.ListMembershipsParams{
		OrgId:  &orgId,
		UserId: &humanUser,
	}).Return([]model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				UserId:      humanUser,
				SubjectType: model.MembershipSubjectTypeRole,
				Role:        opt.Of(adminRoleId),
				Scope:       "", // Org-wide
			},
		},
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				UserId:      humanUser,
				SubjectType: model.MembershipSubjectTypeRole,
				Role:        opt.Of(viewerRoleId),
				Scope:       projectScope, // Project-scoped
			},
		},
	}, nil)

	// For a human user, service user roles will be empty
	mockDB.EXPECT().ListServiceUserRoles(ctx, mockTx, model.ListServiceUserRolesParams{
		OrgId:         &orgId,
		ServiceUserId: &humanUser,
	}).Return([]model.ServiceUserRole{}, nil)

	// Verify SpiceDB sync is called with userId
	var capturedUserId *uuid.UUID
	var capturedRelationships []*v1.Relationship
	mockSpiceDB.EXPECT().SyncOrgRelationships(ctx, orgId, gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, userId *uuid.UUID, _ []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			capturedUserId = userId
			capturedRelationships = relationships
			return mockZedToken, 0, len(relationships), nil
		})

	_, _, _, _, err := SyncSpiceDBWithDB(ctx, logger, SyncSpiceDBParams{OrgId: orgId, UserId: opt.Of(humanUser)}, mockDB, mockSpiceDB)
	require.NoError(t, err)

	// Verify userId was passed to SpiceDB
	require.NotNil(t, capturedUserId)
	require.Equal(t, humanUser, *capturedUserId)

	// Verify that we have the correct number of relationships:
	// - 2 org-wide roles: 2 relationships each (scoped_role->org, org->scoped_role) = 4
	// - 2 memberships: 1 relationship each (user->scoped_role member) = 2
	// Total = 6
	require.Len(t, capturedRelationships, 6)

	// Helper to check if a member relationship exists
	hasMemberRelationship := func(userId uuid.UUID, roleId uuid.UUID) bool {
		for _, rel := range capturedRelationships {
			if rel.Relation == spicedb.RelationMember.String() &&
				rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
				rel.Resource.ObjectId == roleId.String() &&
				rel.Subject.Object.ObjectType == spicedb.ObjectTypeUser.String() &&
				rel.Subject.Object.ObjectId == userId.String() {
				return true
			}
		}
		return false
	}

	// Verify both org-wide and scoped relationships exist
	require.True(t, hasMemberRelationship(humanUser, adminRoleId), "Expected org-wide admin membership")
	require.True(t, hasMemberRelationship(humanUser, scopedRoleForProject.Id), "Expected project-scoped viewer membership")
}

func TestSyncSpiceDBWithDB_UserSync_ServiceUser_OrgWideAndScopedRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zap.NewNop()

	mockDB := mockmodel.NewMockDatabaser(ctrl)
	mockSpiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	mockTx := mockmodel.NewMockTxWithCommit(ctrl)

	// Setup
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	serviceUser := uuid.New()
	envId := uuid.New()
	envScope := "environment:" + envId.String()

	scopedRoleForEnv := model.ScopedRole{
		Id:        uuid.New(),
		OrgId:     orgId,
		Scope:     envScope,
		OrgRoleId: adminRoleId,
	}

	mockDB.EXPECT().BeginTx(ctx, &sql.TxOptions{ReadOnly: true}).Return(mockTx, nil)
	mockTx.EXPECT().Commit().Return(nil)
	mockTx.EXPECT().Rollback().Return(sql.ErrTxDone)

	mockDB.EXPECT().ListRoles(ctx, mockTx, orgId).Return([]model.Role{
		{
			Id:          adminRoleId,
			DisplayName: RoleAdmin,
			Permissions: []string{PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: RoleViewer,
			Permissions: []string{PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}, nil)

	mockDB.EXPECT().ListScopedRoles(ctx, mockTx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{scopedRoleForEnv}, nil)

	// For a service user, memberships will be empty
	mockDB.EXPECT().ListMemberships(ctx, mockTx, model.ListMembershipsParams{
		OrgId:  &orgId,
		UserId: &serviceUser,
	}).Return([]model.MembershipWithUserMetadata{}, nil)

	// Return service user roles only for the specific service user: 1 org-wide viewer, 1 env-scoped admin
	mockDB.EXPECT().ListServiceUserRoles(ctx, mockTx, model.ListServiceUserRolesParams{
		OrgId:         &orgId,
		ServiceUserId: &serviceUser,
	}).Return([]model.ServiceUserRole{
		{
			ServiceUserId: serviceUser,
			RoleId:        viewerRoleId,
			Scope:         "", // Org-wide
		},
		{
			ServiceUserId: serviceUser,
			RoleId:        adminRoleId,
			Scope:         envScope, // Environment-scoped
		},
	}, nil)

	// Verify SpiceDB sync is called with userId
	var capturedUserId *uuid.UUID
	var capturedRelationships []*v1.Relationship
	mockSpiceDB.EXPECT().SyncOrgRelationships(ctx, orgId, gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, userId *uuid.UUID, _ []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			capturedUserId = userId
			capturedRelationships = relationships
			return mockZedToken, 0, len(relationships), nil
		})

	_, _, _, _, err := SyncSpiceDBWithDB(ctx, logger, SyncSpiceDBParams{OrgId: orgId, UserId: opt.Of(serviceUser)}, mockDB, mockSpiceDB)
	require.NoError(t, err)

	// Verify userId was passed to SpiceDB
	require.NotNil(t, capturedUserId)
	require.Equal(t, serviceUser, *capturedUserId)

	// Verify that we have 2 service user roles * 3 relationships each = 6 total
	require.Len(t, capturedRelationships, 6)

	// Helper to check if a member relationship exists
	hasMemberRelationship := func(userId uuid.UUID, roleId uuid.UUID) bool {
		for _, rel := range capturedRelationships {
			if rel.Relation == spicedb.RelationMember.String() &&
				rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
				rel.Resource.ObjectId == roleId.String() &&
				rel.Subject.Object.ObjectType == spicedb.ObjectTypeUser.String() &&
				rel.Subject.Object.ObjectId == userId.String() {
				return true
			}
		}
		return false
	}

	// Verify both org-wide and scoped relationships exist
	require.True(t, hasMemberRelationship(serviceUser, viewerRoleId), "Expected org-wide viewer service user role")
	require.True(t, hasMemberRelationship(serviceUser, scopedRoleForEnv.Id), "Expected env-scoped admin service user role")
}
