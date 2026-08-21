package api

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

type SyncResult struct {
	ResourcesUpserted int
}

// SyncAuthorizationResources persists the resource hierarchy Casbin uses for inherited
// organization and project role bindings.
func SyncAuthorizationResources(ctx context.Context, logger *zap.Logger, db model.Databaser, orgId string, projectToEnvs map[uuid.UUID][]uuid.UUID) (*SyncResult, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin authorization resource sync")
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			logger.Error("failed to rollback authorization resource sync", zap.Error(rollbackErr))
		}
	}()

	organizationResource := "organization:" + orgId
	if err := db.UpsertAuthorizationResource(ctx, tx, &model.AuthorizationResource{
		Resource: organizationResource, ResourceType: "organization", ResourceId: orgId, OrgId: orgId,
	}); err != nil {
		return nil, err
	}
	upserted := 1
	for projectId, environmentIds := range projectToEnvs {
		projectResource := "project:" + projectId.String()
		if err := db.UpsertAuthorizationResource(ctx, tx, &model.AuthorizationResource{
			Resource: projectResource, ResourceType: "project", ResourceId: projectId.String(), OrgId: orgId, ParentResource: &organizationResource,
		}); err != nil {
			return nil, err
		}
		upserted++
		for _, environmentId := range environmentIds {
			if err := db.UpsertAuthorizationResource(ctx, tx, &model.AuthorizationResource{
				Resource: "env:" + environmentId.String(), ResourceType: "env", ResourceId: environmentId.String(), OrgId: orgId, ParentResource: &projectResource,
			}); err != nil {
				return nil, err
			}
			upserted++
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit authorization resource sync")
	}
	return &SyncResult{ResourcesUpserted: upserted}, nil
}
