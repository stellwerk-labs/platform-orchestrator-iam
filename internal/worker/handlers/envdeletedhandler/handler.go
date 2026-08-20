package envdeletedhandler

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

type EnvDeletedHandler struct {
	db model.Databaser
}

func New(db model.Databaser) *EnvDeletedHandler {
	return &EnvDeletedHandler{db: db}
}

func (h *EnvDeletedHandler) Handle(ctx context.Context, logger *zap.Logger, delivery *hmessaging.Delivery) error {
	if delivery.Subject != string(cpevents.IoPlatformOrchestratorEnvironmentDeleted) {
		return nil
	}
	var event events.CloudEvent[cpevents.EnvChangedData]
	if err := json.Unmarshal(delivery.Data, &event); err != nil {
		return errors.Wrap(err, "failed to unmarshal environment deletion event")
	}
	logger = hlogger.TraceScopedLoggerFromCtx(logger, ctx).With(
		logging.ZapOrgId(event.Data.OrgId), logging.ZapEnvId(event.Data.EnvId), zap.String("po-env-uuid", event.Data.EnvUuid.String()),
	)
	return h.removeEnvironmentAccess(ctx, logger, event.Data.EnvUuid.String())
}

func (h *EnvDeletedHandler) removeEnvironmentAccess(ctx context.Context, logger *zap.Logger, environmentId string) error {
	scope := "env:" + environmentId
	if rows, err := h.db.BulkDeleteMemberships(ctx, nil, model.BulkDeleteMembershipsParams{Scope: opt.Of(scope)}); err != nil {
		return errors.Wrap(err, "failed to delete environment memberships")
	} else {
		logger.Info("deleted environment memberships", zap.Int64("rows", rows))
	}
	if rows, err := h.db.BulkDeleteServiceUserRoles(ctx, nil, model.BulkDeleteServiceUserRolesParams{Scope: opt.Of(scope)}); err != nil {
		return errors.Wrap(err, "failed to delete environment service-user roles")
	} else {
		logger.Info("deleted environment service-user roles", zap.Int64("rows", rows))
	}
	return h.db.DeleteAuthorizationResource(ctx, nil, scope)
}
