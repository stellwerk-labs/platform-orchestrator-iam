package spicedbsynchandler

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	v2 "github.com/stellwerk-labs/golib/hrabbitmq/delayqueues/v2"
	"github.com/stellwerk-labs/golib/hstandardreliableoutbox"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
	"github.com/wagslane/go-rabbitmq"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

var orgId string = "test-org-123"

func TestHandle_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: []byte("invalid json"),
		},
	}

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal")
}

func TestHandle_MissingOrgId(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: "", // Empty org_id
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing org_id")
}

func TestHandle_ListRolesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(nil, errors.New("list roles error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list roles")
}

func TestHandle_ListMembershipsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{}, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(nil, errors.New("list memberships error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list memberships")
}

func TestHandle_ListServiceUserRolesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{}, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return(nil, errors.New("list service user roles error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list service user roles")
}

func TestHandle_TransactionCommitError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{}, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(errors.New("commit error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to commit transaction")
}

func TestHandle_SpiceDBSyncError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{}, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)
	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		Return("", 0, 0, errors.New("SpiceDB sync failed"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to sync organization relationships to SpiceDB")
}

func TestHandle_Success_EmptyOrg(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return([]model.Role{}, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 1 for org (no roles)
			require.Empty(t, filters)

			// Expected relationships: empty (no roles, memberships, or service users)
			require.Empty(t, relationships)

			return "", 0, 0, nil
		})

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_Success_WithRolesAndMemberships(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	userId1 := uuid.New()
	userId2 := uuid.New()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   userId1,
			Permissions: []string{api.PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   userId1,
			Permissions: []string{api.PermissionsReadAll},
		},
	}

	memberships := []model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId1,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     adminRoleId.String(),
				Role:        opt.Of(adminRoleId),
			},
			UserDisplayName: "User 1",
		},
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId2,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     viewerRoleId.String(),
				Role:        opt.Of(viewerRoleId),
			},
			UserDisplayName: "User 2",
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(memberships, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 2 for roles
			require.Len(t, filters, 2)

			// Expected relationships:
			// 2 roles × 2 relationships each (scoped_role->org, org->role) = 4
			// 2 memberships × 1 relationship each (user->scoped_role) = 2
			// Total = 6
			require.Len(t, relationships, 6)

			// Verify scoped_role->org relationships
			var scopedRoleOrgRels []*v1.Relationship
			var orgRoleRels []*v1.Relationship
			var userMemberRels []*v1.Relationship

			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels = append(scopedRoleOrgRels, rel)
				}
				if rel.Resource.ObjectType == spicedb.ObjectTypeOrg.String() &&
					(rel.Relation == spicedb.RelationAllManager.String() || rel.Relation == spicedb.RelationAllReader.String()) {
					orgRoleRels = append(orgRoleRels, rel)
				}
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationMember.String() {
					userMemberRels = append(userMemberRels, rel)
				}
			}

			require.Len(t, scopedRoleOrgRels, 2)
			require.Len(t, orgRoleRels, 2)
			require.Len(t, userMemberRels, 2)

			return "zedToken", 0, 6, nil
		})
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: "zedToken"}).Return(&model.OrgZedTokens{
		ZedToken: "zedToken",
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_Success_WithServiceUserRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adminRoleId := uuid.New()
	serviceUserId := uuid.New()
	createdBy := uuid.New()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{api.PermissionsManageAll},
		},
	}

	serviceUserRoles := []model.ServiceUserRole{
		{
			ServiceUserId: serviceUserId,
			RoleId:        adminRoleId,
			OrgId:         orgId,
			CreatedAt:     time.Now(),
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return(serviceUserRoles, nil)
	tx.EXPECT().Commit().Return(nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 1 for org + 1 for role = 2
			require.Len(t, filters, 1)

			// Expected relationships:
			// 1 role × 2 relationships each (scoped_role->org, org->role) = 2
			// 1 service user role × 1 relationship (user->scoped_role) = 1
			// Total = 3
			require.Len(t, relationships, 3)

			// Verify service user relationship exists
			var serviceUserRel *v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationMember.String() &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeUser.String() &&
					rel.Subject.Object.ObjectId == serviceUserId.String() {
					serviceUserRel = rel
					break
				}
			}
			require.NotNil(t, serviceUserRel)
			require.Equal(t, adminRoleId.String(), serviceUserRel.Resource.ObjectId)

			return "zedToken", 0, 6, nil
		})
	db.EXPECT().UpsertOrgZedToken(gomock.Any(), nil, orgId, &model.OrgZedTokens{ZedToken: "zedToken"}).Return(&model.OrgZedTokens{
		ZedToken: "zedToken",
	}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_GracefulRetryError_ScopedRoleNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adminRoleId := uuid.New()
	userId := uuid.New()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   userId,
			Permissions: []string{api.PermissionsManageAll},
		},
	}

	// Create a membership with a scoped role that doesn't exist in the scoped roles list
	memberships := []model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     adminRoleId.String(),
				Role:        opt.Of(adminRoleId),
				Scope:       "project/test-project", // Scoped membership
			},
			UserDisplayName: "Test User",
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	// Return empty scoped roles list - this will cause the scoped role lookup to fail
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(memberships, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)
	// Expect InsertPendingEventMessages to be called with nil transaction to trigger a scope sync
	db.EXPECT().InsertPendingEventMessages(gomock.Any(), nil, gomock.Any()).Return([]*hstandardreliableoutbox.PendingEventMessage{}, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)

	// Verify that the error is a GracefulRetryError
	var gracefulErr v2.GracefulRetryError
	require.True(t, errors.As(err, &gracefulErr), "expected error to be a GracefulRetryError")
}

func TestHandle_GracefulRetryError_WithPendingMessagesCreated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adminRoleId := uuid.New()
	userId := uuid.New()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	// Test with nil publisher to verify pending messages are created even without publishing
	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   userId,
			Permissions: []string{api.PermissionsManageAll},
		},
	}

	// Create a membership with a scoped role that doesn't exist in the scoped roles list
	memberships := []model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     adminRoleId.String(),
				Role:        opt.Of(adminRoleId),
				Scope:       "project/test-project", // Scoped membership
			},
			UserDisplayName: "Test User",
		},
	}

	// Create sample pending messages that will be returned
	pendingMessage := &hstandardreliableoutbox.PendingEventMessage{
		Id:         1,
		CreatedAt:  time.Now(),
		Exchange:   events.DefaultExchange,
		RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
		Payload:    []byte(`{"org_id":"test-org-123","scope":"project/test-project"}`),
	}
	pendingMessages := []*hstandardreliableoutbox.PendingEventMessage{pendingMessage}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	// Return empty scoped roles list - this will cause the scoped role lookup to fail
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(memberships, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)
	// Expect InsertPendingEventMessages to be called and return pending messages
	// This verifies that scope.sync events are created when scoped roles are missing
	db.EXPECT().InsertPendingEventMessages(gomock.Any(), nil, gomock.Any()).Return(pendingMessages, nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)

	// Verify that the error is a GracefulRetryError
	var gracefulErr v2.GracefulRetryError
	require.True(t, errors.As(err, &gracefulErr), "expected error to be a GracefulRetryError")
}

func TestHandle_GracefulRetryError_NoPendingMessages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adminRoleId := uuid.New()
	userId := uuid.New()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)

	handler := New(spiceDB, db, nil)
	logger := zap.NewNop()

	body := events.CloudEvent[genevents.SpiceDBSyncData]{
		SpecVersion: events.CloudEventSpecVersion1{},
		Type:        genevents.IoPlatformOrchestratorSpicedbSync,
		Time:        time.Now(),
		Data: genevents.SpiceDBSyncData{
			OrgId: orgId,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			Body: jsonBody,
		},
	}

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: api.RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   userId,
			Permissions: []string{api.PermissionsManageAll},
		},
	}

	// Create a membership with a scoped role that doesn't exist in the scoped roles list
	memberships := []model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     adminRoleId.String(),
				Role:        opt.Of(adminRoleId),
				Scope:       "project/test-project", // Scoped membership
			},
			UserDisplayName: "Test User",
		},
	}

	db.EXPECT().BeginTx(gomock.Any(), &sql.TxOptions{ReadOnly: true}).Return(tx, nil)
	tx.EXPECT().Rollback().Return(nil)
	db.EXPECT().ListRoles(gomock.Any(), tx, orgId).Return(roles, nil)
	// Return empty scoped roles list - this will cause the scoped role lookup to fail
	db.EXPECT().ListScopedRoles(gomock.Any(), tx, model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)
	db.EXPECT().ListMemberships(gomock.Any(), tx, model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(memberships, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), tx, model.ListServiceUserRolesParams{OrgId: &orgId}).
		Return([]model.ServiceUserRole{}, nil)
	tx.EXPECT().Commit().Return(nil)
	// Return empty pending messages - no scope sync events created
	db.EXPECT().InsertPendingEventMessages(gomock.Any(), nil, gomock.Any()).Return([]*hstandardreliableoutbox.PendingEventMessage{}, nil)

	// Verify that publisher is NOT called when there are no pending messages
	// (no expectations set on mockPublisher or reliableOutboxStore)

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)

	// Verify that the error is a GracefulRetryError
	var gracefulErr v2.GracefulRetryError
	require.True(t, errors.As(err, &gracefulErr), "expected error to be a GracefulRetryError")
}
