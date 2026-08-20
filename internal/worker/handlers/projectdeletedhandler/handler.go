package projectdeletedhandler

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/logging"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

type ProjectDeletedHandler struct {
	db model.Databaser
}

func New(db model.Databaser) *ProjectDeletedHandler {
	return &ProjectDeletedHandler{db: db}
}

func (h *ProjectDeletedHandler) Handle(ctx context.Context, logger *zap.Logger, delivery *hmessaging.Delivery) error {
	if delivery.Subject != string(cpevents.IoPlatformOrchestratorProjectDeleted) {
		return nil
	}
	var event events.CloudEvent[cpevents.ProjectChangedData]
	if err := json.Unmarshal(delivery.Data, &event); err != nil {
		return errors.Wrap(err, "failed to unmarshal project deletion event")
	}
	logger = hlogger.TraceScopedLoggerFromCtx(logger, ctx).With(
		logging.ZapOrgId(event.Data.OrgId), logging.ZapProjectId(event.Data.ProjectId), zap.String("po-project-uuid", event.Data.ProjectUuid.String()),
	)
	return h.removeProjectAccess(ctx, logger, event.Data.ProjectUuid.String())
}

func (h *ProjectDeletedHandler) removeProjectAccess(ctx context.Context, logger *zap.Logger, projectId string) error {
	scope := "project:" + projectId
	if rows, err := h.db.BulkDeleteMemberships(ctx, nil, model.BulkDeleteMembershipsParams{Scope: opt.Of(scope)}); err != nil {
		return errors.Wrap(err, "failed to delete project memberships")
	} else {
		logger.Info("deleted project memberships", zap.Int64("rows", rows))
	}
	if rows, err := h.db.BulkDeleteServiceUserRoles(ctx, nil, model.BulkDeleteServiceUserRolesParams{Scope: opt.Of(scope)}); err != nil {
		return errors.Wrap(err, "failed to delete project service-user roles")
	} else {
		logger.Info("deleted project service-user roles", zap.Int64("rows", rows))
	}
	return h.db.DeleteAuthorizationResource(ctx, nil, scope)
}
