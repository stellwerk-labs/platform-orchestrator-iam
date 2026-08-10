package projectdeletedhandler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hmessaging"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/stretchr/testify/require"
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
	orgId     = "test-org-123"
	projectId = "my-project"
)

func TestHandle_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	spiceDB := mockspicedb.NewMockSpiceDB(ctrl)

	handler := New(db, spiceDB)
	logger := zap.NewNop()

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	// Expect database deletions in order
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(3), nil)

	// Expect SpiceDB deletion
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeProject,
		ResourceId:   projectUuid.String(),
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

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    []byte("invalid json"),
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

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: "unknown.event.type",
			Data:    []byte("{}"),
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

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
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

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
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

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(projectScope),
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

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(5), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(3), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(3), nil)
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeProject,
		ResourceId:   projectUuid.String(),
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

	projectUuid := uuid.New()
	body := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}
	jsonBody, _ := json.Marshal(body)

	delivery := &hmessaging.Delivery{
		Message: hmessaging.Message{
			Subject: string(cpevents.IoPlatformOrchestratorProjectDeleted),
			Data:    jsonBody,
		},
	}

	projectScope := "project:" + projectUuid.String()

	// No rows deleted is not an error
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(0), nil)
	db.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(0), nil)
	db.EXPECT().BulkDeleteScopedRoles(gomock.Any(), nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(projectScope),
	}).Return(int64(0), nil)
	spiceDB.EXPECT().BulkDeleteScopedRoles(gomock.Any(), spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeProject,
		ResourceId:   projectUuid.String(),
	}).Return(nil)

	err := handler.Handle(context.Background(), logger, delivery)
	require.NoError(t, err)
}
