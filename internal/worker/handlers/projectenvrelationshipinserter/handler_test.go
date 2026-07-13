package projectenvrelationshipinserter

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	mockcpclient "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	v2 "github.com/stellwerk-labs/golib/hrabbitmq/delayqueues/v2"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
	"github.com/wagslane/go-rabbitmq"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

const (
	orgId        = "test-org-123"
	mockZedToken = "mockzedtoken"
	projectId    = "my-project"
)

func TestHandle_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorProjectCreated),
			Body:       []byte("invalid json"),
		},
	}

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal")
}

func TestHandle_UnknownRoutingKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: "unknown.event.type",
			Body:       []byte("{}"),
		},
	}

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

// ProjectCreated event tests

func TestHandle_ProjectCreated_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectCreated),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorProjectCreated),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: api.RoleAdmin,
			Permissions: []string{api.PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          deployerRoleId,
			DisplayName: api.RoleDeployer,
			Permissions: []string{api.PermissionsWriteAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: api.RoleViewer,
			Permissions: []string{api.PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}

	// Transaction for creating scoped roles
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)

	// Expectations
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)

	// Upsert scoped roles for each org role
	db.EXPECT().UpsertScopedRole(gomock.Any(), tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRole *model.ScopedRole) (*model.ScopedRole, error) {
			require.Equal(t, orgId, scopedRole.OrgId)
			require.Equal(t, "project:"+projectUuid.String(), scopedRole.Scope)
			require.Contains(t, []uuid.UUID{adminRoleId, viewerRoleId, deployerRoleId}, scopedRole.OrgRoleId)
			return scopedRole, nil
		}).Times(3)

	tx.EXPECT().Commit().Return(nil)

	// SpiceDB sync
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected relationships:
			// 1 project->org relationship
			// 3 scoped roles × 2 relationships each (scoped_role->org, project->scoped_role) = 6
			// Total = 7
			require.Len(t, relationships, 7)

			// Verify project->org relationship
			var projectOrgRel *v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() &&
					rel.Resource.ObjectId == projectUuid.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					projectOrgRel = rel
					require.Equal(t, spicedb.ObjectTypeOrg.String(), rel.Subject.Object.ObjectType)
					require.Equal(t, orgId, rel.Subject.Object.ObjectId)
					break
				}
			}
			require.NotNil(t, projectOrgRel, "Expected project->org relationship")

			// Verify scoped_role->org relationships
			var scopedRoleOrgRels []*v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels = append(scopedRoleOrgRels, rel)
				}
			}
			require.Len(t, scopedRoleOrgRels, 3, "Expected 3 scoped_role->org relationships")

			// Verify project->scoped_role relationships
			var projectRoleRels []*v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() &&
					rel.Resource.ObjectId == projectUuid.String() &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeScopedRole.String() {
					projectRoleRels = append(projectRoleRels, rel)
				}
			}
			require.Len(t, projectRoleRels, 3, "Expected 3 project->scoped_role relationships")

			return mockZedToken, 0, len(relationships), nil
		})

	// UpsertOrgZedToken
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: mockZedToken}).
		Return(&model.OrgZedTokens{ZedToken: mockZedToken}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_ProjectCreated_ListRolesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectCreated),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorProjectCreated),
			Body:       jsonBody,
		},
	}

	// Transaction for creating scoped roles
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(nil, errors.New("list roles error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list organization roles")
}

func TestHandle_ProjectCreated_OrgRolesNotSeededYet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectCreated),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorProjectCreated),
			Body:       jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	// Return only 2 roles (less than BuiltinRolesNumber which is 3)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{
		{Id: uuid.New(), DisplayName: api.RoleAdmin},
		{Id: uuid.New(), DisplayName: api.RoleViewer},
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	// Should be a graceful retry error
	var gracefulRetryErr v2.GracefulRetryError
	require.ErrorAs(t, err, &gracefulRetryErr, "Expected GracefulRetryError")
}

func TestHandle_ProjectCreated_UpsertScopedRoleError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectCreated),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorProjectCreated),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{Id: adminRoleId, DisplayName: api.RoleAdmin},
		{Id: deployerRoleId, DisplayName: api.RoleDeployer},
		{Id: viewerRoleId, DisplayName: api.RoleViewer},
	}

	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().UpsertScopedRole(gomock.Any(), tx, gomock.Any()).
		Return(nil, errors.New("upsert error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to upsert scoped role for new project")
}

// EnvironmentCreated event tests

func TestHandle_EnvironmentCreated_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()
	envId := "development"
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentCreated),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
			EnvId:       envId,
			EnvUuid:     envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentCreated),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: api.RoleAdmin,
			Permissions: []string{api.PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          deployerRoleId,
			DisplayName: api.RoleDeployer,
			Permissions: []string{api.PermissionsWriteAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: api.RoleViewer,
			Permissions: []string{api.PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}

	// Transaction for creating scoped roles
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)

	// Expectations
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	// Upsert scoped roles for each org role
	db.EXPECT().UpsertScopedRole(gomock.Any(), tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRole *model.ScopedRole) (*model.ScopedRole, error) {
			require.Equal(t, orgId, scopedRole.OrgId)
			require.Equal(t, "env:"+envUuid.String(), scopedRole.Scope)
			require.Contains(t, []uuid.UUID{adminRoleId, viewerRoleId, deployerRoleId}, scopedRole.OrgRoleId)
			return scopedRole, nil
		}).Times(3)

	tx.EXPECT().Commit().Return(nil)

	// SpiceDB sync
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected relationships:
			// 1 env->project relationship
			// 3 scoped roles × 2 relationships each (scoped_role->org, env->scoped_role) = 6
			// Total = 7
			require.Len(t, relationships, 7)

			// Verify env->project relationship
			var envProjectRel *v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String() &&
					rel.Resource.ObjectId == envUuid.String() &&
					rel.Relation == spicedb.RelationProject.String() {
					envProjectRel = rel
					require.Equal(t, spicedb.ObjectTypeProject.String(), rel.Subject.Object.ObjectType)
					require.Equal(t, projectUuid.String(), rel.Subject.Object.ObjectId)
					break
				}
			}
			require.NotNil(t, envProjectRel, "Expected env->project relationship")

			// Verify scoped_role->org relationships
			var scopedRoleOrgRels []*v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels = append(scopedRoleOrgRels, rel)
				}
			}
			require.Len(t, scopedRoleOrgRels, 3, "Expected 3 scoped_role->org relationships")

			// Verify env->scoped_role relationships
			var envRoleRels []*v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String() &&
					rel.Resource.ObjectId == envUuid.String() &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeScopedRole.String() {
					envRoleRels = append(envRoleRels, rel)
				}
			}
			require.Len(t, envRoleRels, 3, "Expected 3 env->scoped_role relationships")

			return mockZedToken, 0, len(relationships), nil
		})

	// UpsertOrgZedToken
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: mockZedToken}).
		Return(&model.OrgZedTokens{ZedToken: mockZedToken}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_EnvironmentCreated_OrgRolesNotSeededYet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()

	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentCreated),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
			EnvId:       "development",
			EnvUuid:     envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentCreated),
			Body:       jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	// Return only 2 roles (less than BuiltinRolesNumber which is 3)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{
		{Id: uuid.New(), DisplayName: api.RoleAdmin},
		{Id: uuid.New(), DisplayName: api.RoleViewer},
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	// Should be a graceful retry error
	var gracefulRetryErr v2.GracefulRetryError
	require.ErrorAs(t, err, &gracefulRetryErr, "Expected GracefulRetryError")
}

func TestHandle_EnvironmentCreated_UpsertScopedRoleError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentCreated),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
			EnvId:       "development",
			EnvUuid:     envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentCreated),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{Id: adminRoleId, DisplayName: api.RoleAdmin},
		{Id: deployerRoleId, DisplayName: api.RoleDeployer},
		{Id: viewerRoleId, DisplayName: api.RoleViewer},
	}

	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	db.EXPECT().UpsertScopedRole(gomock.Any(), tx, gomock.Any()).
		Return(nil, errors.New("upsert error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to upsert scoped role for new project")
}

func TestHandle_EnvironmentCreated_SpiceDBSyncError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentCreated),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgId,
			ProjectId:   "my-project",
			ProjectUuid: projectUuid,
			EnvId:       "development",
			EnvUuid:     envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentCreated),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{Id: adminRoleId, DisplayName: api.RoleAdmin},
		{Id: deployerRoleId, DisplayName: api.RoleDeployer},
		{Id: viewerRoleId, DisplayName: api.RoleViewer},
	}

	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	db.EXPECT().UpsertScopedRole(gomock.Any(), tx, gomock.Any()).Return(&model.ScopedRole{Id: uuid.New()}, nil).Times(3)
	tx.EXPECT().Commit().Return(nil)
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Nil(), gomock.Any()).
		Return("", 0, 0, errors.New("spicedb sync error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to sync organization relationships to SpiceDB")
}

// ScopeSync event tests

func TestHandle_ScopeSync_ProjectScope_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	env1Uuid := uuid.New()
	env2Uuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[genevents.ScopeSyncData]{
		Type: genevents.IoPlatformOrchestratorScopeSync,
		Time: time.Now(),
		Data: genevents.ScopeSyncData{
			OrgId: orgId,
			Scope: "project:" + projectUuid.String(),
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: api.RoleAdmin,
			Permissions: []string{api.PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          deployerRoleId,
			DisplayName: api.RoleDeployer,
			Permissions: []string{api.PermissionsWriteAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: api.RoleViewer,
			Permissions: []string{api.PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}

	// Mock CP client to list environments by project UUID
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, projectUuid, gomock.Any()).
		Return(&cpclient.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: 200},
			JSON200: &cpclient.EnvironmentPage{
				Items: []cpclient.Environment{
					{Uuid: env1Uuid},
					{Uuid: env2Uuid},
				},
				NextPageToken: nil,
			},
		}, nil)

	// Single transaction for batch creating all scoped roles
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)

	// Batch upsert all scoped roles (1 project + 2 environments × 3 roles each = 9 total)
	db.EXPECT().BatchUpsertScopedRoles(gomock.Any(), tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRoles []model.ScopedRole) ([]model.ScopedRole, error) {
			require.Len(t, scopedRoles, 9) // 3 scopes × 3 roles
			// Verify we have project + 2 envs
			scopeCounts := make(map[string]int)
			for _, sr := range scopedRoles {
				require.Equal(t, orgId, sr.OrgId)
				require.Contains(t, []uuid.UUID{adminRoleId, viewerRoleId, deployerRoleId}, sr.OrgRoleId)
				scopeCounts[sr.Scope]++
			}
			require.Len(t, scopeCounts, 3) // project + 2 envs
			require.Equal(t, 3, scopeCounts["project:"+projectUuid.String()])
			require.Equal(t, 3, scopeCounts["env:"+env1Uuid.String()])
			require.Equal(t, 3, scopeCounts["env:"+env2Uuid.String()])
			// Return the same scoped roles (simulating new inserts)
			return scopedRoles, nil
		})
	tx.EXPECT().Commit().Return(nil)

	// Single SpiceDB sync for all relationships
	// Expected: 1 project->org + 2 env->project + 3 scopes × 3 roles × 2 relationships/role = 3 + 18 = 21 relationships
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			require.Len(t, relationships, 21)
			return mockZedToken, 0, len(relationships), nil
		})
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: mockZedToken}).
		Return(&model.OrgZedTokens{ZedToken: mockZedToken}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_ScopeSync_EnvScope_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()

	body := events.CloudEvent[genevents.ScopeSyncData]{
		Type: genevents.IoPlatformOrchestratorScopeSync,
		Time: time.Now(),
		Data: genevents.ScopeSyncData{
			OrgId: orgId,
			Scope: "env:" + envUuid.String(),
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
			Body:       jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: api.RoleAdmin,
			Permissions: []string{api.PermissionsManageAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          deployerRoleId,
			DisplayName: api.RoleDeployer,
			Permissions: []string{api.PermissionsWriteAll},
			CreatedAt:   time.Now(),
		},
		{
			Id:          viewerRoleId,
			DisplayName: api.RoleViewer,
			Permissions: []string{api.PermissionsReadAll},
			CreatedAt:   time.Now(),
		},
	}

	// Mock CP client call to get environment
	cpClient.EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, envUuid).
		Return(&cpclient.GetInternalEnvironmentByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: 200},
			JSON200:      &cpclient.Environment{ProjectUuid: &projectUuid},
		}, nil)

	// Single transaction for batch creating all scoped roles (project + env)
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)

	// Batch upsert all scoped roles (1 project + 1 environment × 3 roles each = 6 total)
	db.EXPECT().BatchUpsertScopedRoles(gomock.Any(), tx, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, scopedRoles []model.ScopedRole) ([]model.ScopedRole, error) {
			require.Len(t, scopedRoles, 6) // 2 scopes × 3 roles
			// Verify we have project + env
			scopeCounts := make(map[string]int)
			for _, sr := range scopedRoles {
				require.Equal(t, orgId, sr.OrgId)
				require.Contains(t, []uuid.UUID{adminRoleId, viewerRoleId, deployerRoleId}, sr.OrgRoleId)
				scopeCounts[sr.Scope]++
			}
			require.Len(t, scopeCounts, 2) // project + env
			require.Equal(t, 3, scopeCounts["project:"+projectUuid.String()])
			require.Equal(t, 3, scopeCounts["env:"+envUuid.String()])
			// Return the same scoped roles (simulating new inserts)
			return scopedRoles, nil
		})
	tx.EXPECT().Commit().Return(nil)

	// Single SpiceDB sync for all relationships
	// Expected: 1 project->org + 1 env->project + 2 scopes × 3 roles × 2 relationships/role = 2 + 12 = 14 relationships
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			require.Len(t, relationships, 14)
			return mockZedToken, 0, len(relationships), nil
		})
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: mockZedToken}).
		Return(&model.OrgZedTokens{ZedToken: mockZedToken}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_ScopeSync_ProjectScope_GracefulRetryError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()

	body := events.CloudEvent[genevents.ScopeSyncData]{
		Type: genevents.IoPlatformOrchestratorScopeSync,
		Time: time.Now(),
		Data: genevents.ScopeSyncData{
			OrgId: orgId,
			Scope: "project:" + projectUuid.String(),
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
			Body:       jsonBody,
		},
	}

	// Mock CP client to list environments (empty list for simplicity in this error test)
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, projectUuid, gomock.Any()).
		Return(&cpclient.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: 200},
			JSON200: &cpclient.EnvironmentPage{
				Items:         []cpclient.Environment{},
				NextPageToken: nil,
			},
		}, nil)

	// Transaction for creating scoped roles
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	// Return only 2 roles (less than BuiltinRolesNumber which is 3)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{
		{Id: uuid.New(), DisplayName: api.RoleAdmin},
		{Id: uuid.New(), DisplayName: api.RoleViewer},
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	// Should be a graceful retry error
	var gracefulRetryErr v2.GracefulRetryError
	require.ErrorAs(t, err, &gracefulRetryErr, "Expected GracefulRetryError")
}

func TestHandle_ScopeSync_EnvScope_GracefulRetryError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	cpClient := mockcpclient.NewMockClientWithResponsesInterface(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, cpClient)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	envUuid := uuid.New()

	body := events.CloudEvent[genevents.ScopeSyncData]{
		Type: genevents.IoPlatformOrchestratorScopeSync,
		Time: time.Now(),
		Data: genevents.ScopeSyncData{
			OrgId: orgId,
			Scope: "env:" + envUuid.String(),
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
			Body:       jsonBody,
		},
	}

	// Mock CP client call to get environment
	cpClient.EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, envUuid).
		Return(&cpclient.GetInternalEnvironmentByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: 200},
			JSON200:      &cpclient.Environment{ProjectUuid: &projectUuid},
		}, nil)

	// Transaction for creating project scoped roles - returns graceful retry error
	db.EXPECT().BeginTx(gomock.Any(), nil).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	// Return only 2 roles (less than BuiltinRolesNumber which is 3)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{
		{Id: uuid.New(), DisplayName: api.RoleAdmin},
		{Id: uuid.New(), DisplayName: api.RoleViewer},
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	// Should be a graceful retry error
	var gracefulRetryErr v2.GracefulRetryError
	require.ErrorAs(t, err, &gracefulRetryErr, "Expected GracefulRetryError")
}
