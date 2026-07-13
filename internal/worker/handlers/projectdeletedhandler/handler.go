package projectdeletedhandler

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

// ProjectDeletedHandler handles events indicating that a project has been deleted.
// It triggers the deletion of all scoped roles associated with the project from both the database and SpiceDB.
type ProjectDeletedHandler struct {
	db      model.Databaser
	spiceDB spicedb.SpiceDB
}

// New is the constructor for ProjectDeletedHandler.
func New(db model.Databaser, spiceDB spicedb.SpiceDB) *ProjectDeletedHandler {
	return &ProjectDeletedHandler{
		db:      db,
		spiceDB: spiceDB,
	}
}

// Handle is the entrypoint for new messages. It unmarshals the event data and executes the cleanup logic.
func (h *ProjectDeletedHandler) Handle(ctx context.Context, logger *zap.Logger, d *rabbitmq.Delivery) error {
	switch d.RoutingKey {
	case string(cpevents.IoPlatformOrchestratorProjectDeleted):
		var e events.CloudEvent[cpevents.ProjectChangedData]
		if err := json.Unmarshal(d.Body, &e); err != nil {
			return errors.Wrap(err, "failed to unmarshal event body")
		}

		projectId := e.Data.ProjectId
		orgId := e.Data.OrgId

		logger = hlogger.TraceScopedLoggerFromCtx(logger, ctx).With(
			logging.ZapOrgId(orgId),
			logging.ZapProjectId(projectId),
			zap.String("po-project-uuid", e.Data.ProjectUuid.String()),
		)

		return h.removeProjectScopedRoles(ctx, logger, orgId, e.Data.ProjectUuid.String())
	default:
		return nil
	}
}

// removeProjectScopedRoles deletes all scoped roles associated with a project.
// This includes deleting from database tables (memberships, service_user_roles, scoped_roles)
// and from SpiceDB.
func (h *ProjectDeletedHandler) removeProjectScopedRoles(ctx context.Context, logger *zap.Logger, orgId, projectId string) error {
	logger.Info("starting deletion of scope roles for project")

	// Delete from database tables BEFORE deleting from SpiceDB
	projectScope := "project:" + projectId

	// Delete memberships with this scope
	if rows, err := h.db.BulkDeleteMemberships(ctx, nil, model.BulkDeleteMembershipsParams{
		Scope: opt.Of(projectScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete memberships by scope")
	} else {
		logger.Info("deleted memberships", zap.Int64("rows", rows))
	}

	// Delete service user roles with this scope
	if rows, err := h.db.BulkDeleteServiceUserRoles(ctx, nil, model.BulkDeleteServiceUserRolesParams{
		Scope: opt.Of(projectScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete service user roles by scope")
	} else {
		logger.Info("deleted service user roles", zap.Int64("rows", rows))
	}

	// Delete scoped roles with this scope
	if rows, err := h.db.BulkDeleteScopedRoles(ctx, nil, model.BulkDeleteScopedRolesParams{
		Scope: opt.Of(projectScope),
	}); err != nil {
		return errors.Wrap(err, "failed to delete scoped roles by scope")
	} else {
		logger.Info("deleted scoped roles", zap.Int64("rows", rows))
	}

	// Delete from SpiceDB AFTER database deletion
	if err := h.spiceDB.BulkDeleteScopedRoles(ctx, spicedb.BulkDeleteScopedRolesParams{
		ResourceType: spicedb.ObjectTypeProject,
		ResourceId:   projectId,
	}); err != nil {
		logger.Error("failed to delete project scoped roles from SpiceDB", zap.Error(err))
		return err
	}

	logger.Info("successfully deleted all scope roles for project")
	return nil
}
