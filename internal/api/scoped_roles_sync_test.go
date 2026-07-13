package api

import (
	"context"
	"database/sql"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"
)

const testOrgId = "test-org-123"

func TestSyncProjectsAndEnvsToSpiceDB_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	project1Uuid := uuid.New()
	project2Uuid := uuid.New()
	env1Uuid := uuid.New()
	env2Uuid := uuid.New()

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		project1Uuid: {env1Uuid},
		project2Uuid: {env2Uuid},
	}

	// Setup org roles
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	orgRoles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       testOrgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   uuid.New(),
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       testOrgId,
			DisplayName: RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   uuid.New(),
			Permissions: []string{PermissionsReadAll},
		},
		{
			Id:          deployerRoleId,
			OrgId:       testOrgId,
			DisplayName: RoleDeployer,
			CreatedAt:   time.Now(),
			CreatedBy:   uuid.New(),
			Permissions: []string{PermissionsWriteAll},
		},
	}

	// Mock database expectations
	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)

	// Mock batch upsert - expect 2 projects * 3 roles + 2 envs * 3 roles = 12 scoped roles
	db.EXPECT().BatchUpsertScopedRoles(ctx, tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRoles []model.ScopedRole) ([]model.ScopedRole, error) {
			require.Len(t, scopedRoles, 12)

			// Verify project scoped roles
			var projectRoles int
			var envRoles int
			for _, sr := range scopedRoles {
				require.Equal(t, testOrgId, sr.OrgId)
				if sr.Scope == ScopeProject+":"+project1Uuid.String() || sr.Scope == ScopeProject+":"+project2Uuid.String() {
					projectRoles++
				} else if sr.Scope == ScopeEnvironment+":"+env1Uuid.String() || sr.Scope == ScopeEnvironment+":"+env2Uuid.String() {
					envRoles++
				}
			}
			require.Equal(t, 6, projectRoles, "Expected 6 project scoped roles (2 projects * 3 roles)")
			require.Equal(t, 6, envRoles, "Expected 6 environment scoped roles (2 envs * 3 roles)")

			return scopedRoles, nil
		})

	tx.EXPECT().Commit().Return(nil)

	// Mock SpiceDB sync
	spiceDB.EXPECT().SyncOrgRelationships(ctx, testOrgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected relationships:
			// - 2 projects: each has 1 project->org + 3 roles * 2 relationships = 2 * 7 = 14
			// - 2 environments: each has 1 env->project + 3 roles * 2 relationships = 2 * 7 = 14
			// Total = 28
			require.Len(t, relationships, 28)

			// Verify relationship types
			var projectOrgRels int
			var envProjectRels int
			var scopedRoleOrgRels int
			var scopeRoleRels int

			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					projectOrgRels++
				} else if rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String() &&
					rel.Relation == spicedb.RelationProject.String() {
					envProjectRels++
				} else if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels++
				} else if (rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() ||
					rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String()) &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeScopedRole.String() {
					scopeRoleRels++
				}
			}

			require.Equal(t, 2, projectOrgRels, "Expected 2 project->org relationships")
			require.Equal(t, 2, envProjectRels, "Expected 2 env->project relationships")
			require.Equal(t, 12, scopedRoleOrgRels, "Expected 12 scoped_role->org relationships")
			require.Equal(t, 12, scopeRoleRels, "Expected 12 scope->scoped_role relationships")

			return zedToken, 5, 28, nil
		})

	db.EXPECT().UpsertOrgZedToken(ctx, nil, testOrgId, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, orgId string, token *model.OrgZedTokens) (*model.OrgZedTokens, error) {
			require.Equal(t, zedToken, token.ZedToken)
			return token, nil
		})

	// Execute function
	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	// Verify results
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 12, result.ScopedRolesCreated)
	require.Equal(t, 28, result.RelationshipsAdded)
	require.Equal(t, 5, result.RelationshipsRemoved)
}

func TestSyncProjectsAndEnvsToSpiceDB_InsufficientRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		uuid.New(): {uuid.New()},
	}

	// Return only 2 roles, but we need at least 3 (BuiltinRolesNumber)
	insufficientRoles := []model.Role{
		{Id: uuid.New(), DisplayName: RoleAdmin},
		{Id: uuid.New(), DisplayName: RoleViewer},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(insufficientRoles, nil)

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.Error(t, err)
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrBuiltinRolesNotSeeded)
}

func TestSyncProjectsAndEnvsToSpiceDB_BatchUpsertError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		uuid.New(): {uuid.New()},
	}

	orgRoles := []model.Role{
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}},
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}},
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)
	db.EXPECT().BatchUpsertScopedRoles(ctx, tx, gomock.Any()).Return(nil, errors.New("batch upsert error"))

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to batch upsert scoped roles")
}

func TestSyncProjectsAndEnvsToSpiceDB_SpiceDBSyncError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		uuid.New(): {uuid.New()},
	}

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	orgRoles := []model.Role{
		{Id: adminRoleId, OrgId: testOrgId, DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}},
		{Id: viewerRoleId, OrgId: testOrgId, DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}},
		{Id: deployerRoleId, OrgId: testOrgId, DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)
	db.EXPECT().BatchUpsertScopedRoles(ctx, tx, gomock.Any()).Return([]model.ScopedRole{
		{Id: uuid.New(), OrgId: testOrgId, OrgRoleId: adminRoleId},
	}, nil)
	tx.EXPECT().Commit().Return(nil)
	spiceDB.EXPECT().SyncOrgRelationships(ctx, testOrgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		Return("", 0, 0, errors.New("spicedb sync error"))

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to sync organization relationships to SpiceDB")
}

func TestSyncProjectsAndEnvsToSpiceDB_UpsertZedTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		uuid.New(): {uuid.New()},
	}

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	orgRoles := []model.Role{
		{Id: adminRoleId, OrgId: testOrgId, DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}},
		{Id: viewerRoleId, OrgId: testOrgId, DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}},
		{Id: deployerRoleId, OrgId: testOrgId, DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)
	db.EXPECT().BatchUpsertScopedRoles(ctx, tx, gomock.Any()).Return([]model.ScopedRole{
		{Id: uuid.New(), OrgId: testOrgId, OrgRoleId: adminRoleId},
	}, nil)
	tx.EXPECT().Commit().Return(nil)
	spiceDB.EXPECT().SyncOrgRelationships(ctx, testOrgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		Return("zed-token-123", 0, 5, nil)
	db.EXPECT().UpsertOrgZedToken(ctx, nil, testOrgId, gomock.Any()).
		Return(nil, errors.New("upsert zed token error"))

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to upsert organization zed token")
}

func TestSyncProjectsAndEnvsToSpiceDB_EmptyProjectsMap(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectToEnvs := map[uuid.UUID][]uuid.UUID{}

	orgRoles := []model.Role{
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}},
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}},
		{Id: uuid.New(), OrgId: testOrgId, DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)
	tx.EXPECT().Commit().Return(nil)
	spiceDB.EXPECT().SyncOrgRelationships(ctx, testOrgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			require.Empty(t, relationships)
			return "", 0, 0, nil
		})

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 0, result.ScopedRolesCreated)
	require.Equal(t, 0, result.RelationshipsAdded)
	require.Equal(t, 0, result.RelationshipsRemoved)
}

func TestSyncProjectsAndEnvsToSpiceDB_MultipleEnvironmentsPerProject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	projectUuid := uuid.New()
	env1Uuid := uuid.New()
	env2Uuid := uuid.New()
	env3Uuid := uuid.New()

	projectToEnvs := map[uuid.UUID][]uuid.UUID{
		projectUuid: {env1Uuid, env2Uuid, env3Uuid},
	}

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	orgRoles := []model.Role{
		{Id: adminRoleId, OrgId: testOrgId, DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}},
		{Id: viewerRoleId, OrgId: testOrgId, DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}},
		{Id: deployerRoleId, OrgId: testOrgId, DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}},
	}

	db.EXPECT().BeginTx(ctx, nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(ctx, tx, testOrgId).Return(orgRoles, nil)

	// Mock batch upsert - expect 1 project * 3 roles + 3 envs * 3 roles = 12 scoped roles
	db.EXPECT().BatchUpsertScopedRoles(ctx, tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRoles []model.ScopedRole) ([]model.ScopedRole, error) {
			require.Len(t, scopedRoles, 12)
			return scopedRoles, nil
		})

	tx.EXPECT().Commit().Return(nil)

	spiceDB.EXPECT().SyncOrgRelationships(ctx, testOrgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected relationships:
			// - 1 project: 1 project->org + 3 roles * 2 relationships = 7
			// - 3 environments: 3 * (1 env->project + 3 roles * 2 relationships) = 3 * 7 = 21
			// Total = 28
			require.Len(t, relationships, 28)
			return zedToken, 0, 28, nil
		})

	db.EXPECT().UpsertOrgZedToken(ctx, nil, testOrgId, gomock.Any()).Return(&model.OrgZedTokens{}, nil)

	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, db, spiceDB, testOrgId, projectToEnvs)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 12, result.ScopedRolesCreated)
	require.Equal(t, 28, result.RelationshipsAdded)
}
