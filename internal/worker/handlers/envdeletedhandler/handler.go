package envdeletedhandler

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/wagslane/go-rabbitmq"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/logging"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
)

// EnvDeletedHandler handles events indicating that an environment has been deleted.
// It triggers the deletion of all scoped roles associated with the environment from both the database and SpiceDB.
type EnvDeletedHandler struct {
	db      model.Databaser
	spiceDB spicedb.SpiceDB
}

// New is the constructor for EnvDeletedHandler.
func New(db model.Databaser, spiceDB spicedb.SpiceDB) *EnvDeletedHandler {
	return &EnvDeletedHandler{
		db:      db,
		spiceDB: spiceDB,
	}
}

// Handle is the entrypoint for new messages. It unmarshals the event data and executes the cleanup logic.
func (h *EnvDeletedHandler) Handle(ctx context.Context, logger *zap.Logger, d *rabbitmq.Delivery) error {
	switch d.RoutingKey {
	case string(cpevents.IoPlatformOrchestratorEnvironmentDeleted):
		var e events.CloudEvent[cpevents.EnvChangedData]
		if err := json.Unmarshal(d.Body, &e); err != nil {
			return errors.Wrap(err, "failed to unmarshal event body")
		}

		envId := e.Data.EnvId
		orgId := e.Data.OrgId

		logger = hlogger.TraceScopedLoggerFromCtx(logger, ctx).With(
			logging.ZapOrgId(orgId),
			logging.ZapEnvId(envId),
			zap.String("po-env-uuid", e.Data.EnvUuid.String()),
		)

		return h.removeEnvScopedRoles(ctx, logger, orgId, e.Data.EnvUuid.String())
	default:
		return nil
	}
}

// removeEnvScopedRoles deletes all scoped roles associated with an environment.
// This includes deleting from database tables (memberships, service_user_roles, scoped_roles)
// and from SpiceDB.
func (h *EnvDeletedHandler) removeEnvScopedRoles(ctx context.Context, logger *zap.Logger, orgId, envId string) error {
	logger.Info("starting deletion of scope roles for environment")

	// Delete from database tables BEFORE deleting from SpiceDB
	envScope := "env:" + envId

	// Delete memberships with this scope
	if rows, err := h.db.BulkDeleteMemberships(ctx, nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(envScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete memberships by scope")
	} else {
		logger.Info("deleted memberships", zap.Int64("rows", rows))
	}

	// Delete service user roles with this scope
	if rows, err := h.db.BulkDeleteServiceUserRoles(ctx, nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(envScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete service user roles by scope")
	} else {
		logger.Info("deleted service user roles", zap.Int64("rows", rows))
	}

	// Delete scoped roles with this scope
	if rows, err := h.db.BulkDeleteScopedRoles(ctx, nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(envScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete scoped roles by scope")
	} else {
		logger.Info("deleted scoped roles", zap.Int64("rows", rows))
	}

	// Delete from SpiceDB AFTER database deletion
	if err := h.spiceDB.BulkDeleteScopedRoles(ctx, spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeEnv,
		ResourceId:   envId,
	}); err != nil {
		logger.Error("failed to delete scope roles from SpiceDB", zap.Error(err))
		return err
	}

	logger.Info("successfully deleted all scope roles for environment")
	return nil
}
