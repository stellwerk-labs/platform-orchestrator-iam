package envdeletedhandler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
	"github.com/wagslane/go-rabbitmq"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"
)

const (
	orgId = "test-org-123"
	envId = "my-env"
)

func TestHandle_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	// Expect database deletions in order
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(3), nil)

	// Expect SpiceDB deletion
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeEnv,
		ResourceId:   envUuid.String(),
	}).Return(nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}

func TestHandle_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
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

	handler := New(db, spiceDB)
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

func TestHandle_DeleteMembershipsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), errors.New("database error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
}

func TestHandle_DeleteServiceUserRolesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), errors.New("database error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
}

func TestHandle_DeleteScopedRolesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), errors.New("database error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
}

func TestHandle_SpiceDBError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(3), nil)
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeEnv,
		ResourceId:   envUuid.String(),
	}).Return(errors.New("spicedb error"))

	err := handler.Handle(context.Background(), logger, delivery)
	require.Error(t, err)
	require.Contains(t, err.Error(), "spicedb error")
}

func TestHandle_NoRowsDeleted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	envUuid := uuid.New()
	body := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:   orgId,
			EnvId:   envId,
			EnvUuid: envUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &rabbitmq.Delivery{
		Delivery: amqp091.Delivery{
			RoutingKey: string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
			Body:       jsonBody,
		},
	}

	envScope := "env:" + envUuid.String()

	// No rows deleted is not an error
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(envScope),
	}).Return(int64(0), nil)
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeEnv,
		ResourceId:   envUuid.String(),
	}).Return(nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}
