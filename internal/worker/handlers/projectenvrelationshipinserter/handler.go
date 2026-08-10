package projectenvrelationshipinserter

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hmessaging"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/logging"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
)

// BranchPattern is the branch match pattern for incoming events.
var BranchPattern = regexp.MustCompile(regexp.QuoteMeta(string(cpevents.IoPlatformOrchestratorProjectCreated)) + `|` + regexp.QuoteMeta(string(cpevents.IoPlatformOrchestratorEnvironmentCreated)))

// ProjectEnvRelationshipInserter handles events indicating that the project or an environment has been created.
// It triggers the creation of the default scoped roles for the new project environment in both spiceDB and db.
// This should run only when a scoped role is assigned to a project or an environment for the first time and if it
// does not already exist. All the new projects/environments created after the deployment of this handler will have the proper
// scoped roles and relationships created by other handlers.
type ProjectEnvRelationshipInserter struct {
	spiceDB  spicedb.SpiceDB
	db       model.Databaser
	cpClient cpclient.ClientWithResponsesInterface
}

// New is the constructor so that we don't miss new arguments.
func New(spiceDB spicedb.SpiceDB, db model.Databaser, cpClient cpclient.ClientWithResponsesInterface) *ProjectEnvRelationshipInserter {
	return &ProjectEnvRelationshipInserter{
		spiceDB:  spiceDB,
		db:       db,
		cpClient: cpClient,
	}
}

// Handle is the entrypoint for new messages. Here we unwrap the typed data and decide which relationships to create in spiceDB.
func (h *ProjectEnvRelationshipInserter) Handle(ctx context.Context, logger *zap.Logger, d *hmessaging.Delivery) error {
	switch d.Subject {
	case string(cpevents.IoPlatformOrchestratorProjectCreated):
		var e events.CloudEvent[cpevents.ProjectChangedData]
		if err := json.Unmarshal(d.Data, &e); err != nil {
			return errors.Wrap(err, "failed to unmarshal event body")
		}
		projectUuid := e.Data.ProjectUuid
		orgId := e.Data.OrgId

		logger = logger.With(logging.ZapOrgId(orgId), logging.ZapProjectId(e.Data.ProjectId), zap.String("po-project-uuid", projectUuid.String()))
		logger.Sugar().Debug("create roles and relationships for project")
		return h.createRolesAndRelationshipsForProject(ctx, logger, orgId, projectUuid)
	case string(cpevents.IoPlatformOrchestratorEnvironmentCreated):
		var e events.CloudEvent[cpevents.EnvChangedData]
		if err := json.Unmarshal(d.Data, &e); err != nil {
			return errors.Wrap(err, "failed to unmarshal event body")
		}
		projectUuid := e.Data.ProjectUuid
		envUuid := e.Data.EnvUuid
		orgId := e.Data.OrgId

		logger = logger.With(logging.ZapOrgId(orgId), logging.ZapProjectId(e.Data.ProjectId), logging.ZapEnvId(e.Data.EnvId), zap.String("po-env-uuid", envUuid.String()))
		logger.Sugar().Debug("create roles and relationships for environment")
		return h.createRelationshipsForEnvironment(ctx, logger, orgId, envUuid, projectUuid)
	case string(genevents.IoPlatformOrchestratorScopeSync):
		var e events.CloudEvent[genevents.ScopeSyncData]
		if err := json.Unmarshal(d.Data, &e); err != nil {
			return errors.Wrap(err, "failed to unmarshal event body")
		}
		orgId := e.Data.OrgId
		scope := e.Data.Scope
		logger = logger.With(logging.ZapOrgId(orgId), zap.String("po-scope", scope))
		return h.handleScopeSync(ctx, orgId, scope, logger)
	default:
		return nil
	}

}

// handleScopeSync processes a scope.sync event by determining the type of scope (project or environment)
// and creating the necessary roles and relationships in SpiceDB accordingly using batch operations.
// When the scope is a project, it creates roles and relationships for the project and its environments.
// When the scope is an environment, it creates roles and relationships for the environment
// and ensures the associated project's roles and relationships are also created.
func (h *ProjectEnvRelationshipInserter) handleScopeSync(ctx context.Context, orgId, scope string, logger *zap.Logger) error {
	splittedScope := strings.SplitN(scope, ":", 2)
	if len(splittedScope) != 2 {
		logger.Warn("unsupported scope format, skipping scope sync")
		return nil
	}
	var projectUuid uuid.UUID
	var envUuids []uuid.UUID
	switch splittedScope[0] {
	case api.ScopeProject:
		if projectUuidFromScope, err := uuid.Parse(splittedScope[1]); err != nil {
			return errors.Wrap(err, "failed to parse project uuid from scope")
		} else {
			projectUuid = projectUuidFromScope
		}
		var pageToken *string
		// Get all environments for the project
		for {
			if resp, err := h.cpClient.ListInternalEnvironmentsByProjectUuidWithResponse(ctx, orgId, projectUuid, &cpclient.ListInternalEnvironmentsByProjectUuidParams{Page: pageToken}); err != nil {
				return errors.Wrap(err, "failed to get project envs from control plane")
			} else if resp.StatusCode() != 200 {
				return errors.Errorf("unexpected status code %d when getting project envs	 from control plane", resp.StatusCode())
			} else {
				for _, env := range resp.JSON200.Items {
					envUuids = append(envUuids, env.Uuid)
				}
				if resp.JSON200.NextPageToken != nil {
					pageToken = resp.JSON200.NextPageToken
				} else {
					break
				}
			}
		}
	case api.ScopeEnvironment:
		if envUuid, err := uuid.Parse(splittedScope[1]); err != nil {
			return errors.Wrap(err, "failed to parse environment uuid from scope")
		} else {
			envUuids = append(envUuids, envUuid)
			if resp, err := h.cpClient.GetInternalEnvironmentByUuidWithResponse(ctx, orgId, envUuid); err != nil {
				return errors.Wrap(err, "failed to get environment from control plane")
			} else if resp.StatusCode() != 200 {
				return errors.Errorf("unexpected status code %d when getting environment from control plane", resp.StatusCode())
			} else if resp.JSON200.ProjectUuid != nil {
				projectUuid = *resp.JSON200.ProjectUuid
			}
		}
	default:
		logger.Sugar().Warnw("unsupported scope format, skipping spiceDB sync", "po-scope", scope)
		return nil
	}

	// Build a map of projects to their environments for the shared sync logic
	projectToEnvs := make(map[uuid.UUID][]uuid.UUID)
	if projectUuid != uuid.Nil {
		projectToEnvs[projectUuid] = envUuids
	}

	// Use shared sync logic to create scoped roles and relationships
	result, err := api.SyncProjectsAndEnvsToSpiceDB(ctx, logger, h.db, h.spiceDB, orgId, projectToEnvs)
	if err != nil {
		// Check if it's a graceful retry error from org roles not being seeded
		if errors.Is(err, api.ErrBuiltinRolesNotSeeded) {
			return hmessaging.NewRetryError(err)
		}
		return err
	}

	logger.Info("successfully processed scope sync event",
		zap.Int("scoped_roles_created", result.ScopedRolesCreated),
		zap.Int("relationships_added", result.RelationshipsAdded),
		zap.Int("relationships_removed", result.RelationshipsRemoved),
	)
	return nil
}

// createRolesAndRelationshipsForProject creates the default scoped roles and their relationships in SpiceDB for the given project.
func (h *ProjectEnvRelationshipInserter) createRolesAndRelationshipsForProject(ctx context.Context, logger *zap.Logger, orgId string, projectUuid uuid.UUID) error {
	relationships := []*v1.Relationship{spicedb.BuildRelation(spicedb.RelationOrg, spicedb.ObjectTypeProject, projectUuid.String(), spicedb.ObjectTypeOrg, orgId)}
	scopedRoles, err := h.createScopedRoles(ctx, logger, orgId, "project:"+projectUuid.String())
	if err != nil {
		var gracefulErr hmessaging.RetryError
		if errors.As(err, &gracefulErr) {
			return gracefulErr
		}
		return errors.Wrap(err, "failed to create scoped roles for new project")
	}

	return h.createRelationshipsInSpiceDB(ctx, logger, orgId, append(relationships, createScopedRoleRelationships(orgId, scopedRoles, spicedb.ObjectTypeProject, projectUuid.String())...))
}

// createRelationshipsForEnvironment creates the relationships in SpiceDB for the given environment.
func (h *ProjectEnvRelationshipInserter) createRelationshipsForEnvironment(ctx context.Context, logger *zap.Logger, orgId string, envUuid uuid.UUID, projectUuid uuid.UUID) error {
	relationships := []*v1.Relationship{spicedb.BuildRelation(spicedb.RelationProject, spicedb.ObjectTypeEnv, envUuid.String(), spicedb.ObjectTypeProject, projectUuid.String())}
	scopedRoleToRelationMap, err := h.createScopedRoles(ctx, logger, orgId, "env:"+envUuid.String())
	if err != nil {
		var gracefulErr hmessaging.RetryError
		if errors.As(err, &gracefulErr) {
			return gracefulErr
		}
		return errors.Wrap(err, "failed to create scoped roles for new environment")
	}
	return h.createRelationshipsInSpiceDB(ctx, logger, orgId, append(relationships, createScopedRoleRelationships(orgId, scopedRoleToRelationMap, spicedb.ObjectTypeEnv, envUuid.String())...))
}

// createScopedRoles creates the scoped roles for the given scope (project or environment) in the database.
// It returns a map of scoped role IDs to their corresponding relation strings according to the role display names.
func (h *ProjectEnvRelationshipInserter) createScopedRoles(ctx context.Context, logger *zap.Logger, orgId, scope string) (map[uuid.UUID]string, error) {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	orgRoles, err := h.db.ListRoles(ctx, tx, orgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list organization roles")
	} else if len(orgRoles) == 0 {
		orgRoles, err = api.SeedBuiltinOrgRoles(ctx, logger, h.db, tx, orgId)
		if err != nil {
			return nil, errors.Wrap(err, "failed to seed organization roles")
		}
	} else if len(orgRoles) < api.BuiltinRolesNumber {
		return nil, hmessaging.NewRetryError(api.ErrBuiltinRolesNotSeeded)
	}

	scopedRoles := make(map[uuid.UUID]string)

	for _, orgRole := range orgRoles {
		scopedRole, err := h.db.UpsertScopedRole(ctx, tx, &model.ScopedRole{
			Id:        uuid.Must(uuid.NewV7()),
			OrgId:     orgId,
			Scope:     scope,
			OrgRoleId: orgRole.Id,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to upsert scoped role for new project")
		} else {
			logger.Info("created scoped role", zap.String("po-scope", scope), zap.String("po-scoped-role-id", scopedRole.Id.String()))
			scopedRoles[scopedRole.Id] = api.GetRelationByRoleDisplayName(orgRole.DisplayName).String()
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	return scopedRoles, nil
}

// createRelationshipsInSpiceDB creates the given relationships in SpiceDB for the specified organization.
func (h *ProjectEnvRelationshipInserter) createRelationshipsInSpiceDB(ctx context.Context, logger *zap.Logger, orgId string, relationships []*v1.Relationship) error {
	if zedToken, removed, added, err := h.spiceDB.SyncOrgRelationships(ctx, orgId, nil, nil, relationships); err != nil {
		return errors.Wrap(err, "failed to sync organization relationships to SpiceDB")
	} else {
		if zedToken != "" {
			// Store the zed token for this org
			if _, err := h.db.UpsertOrgZedToken(ctx, nil, orgId, &model.OrgZedTokens{ZedToken: zedToken}); err != nil {
				return errors.Wrap(err, "failed to upsert organization zed token")
			}
		}
		logger.Info("successfully synced organization to SpiceDB", zap.Int("removed", removed), zap.Int("added", added))
		return nil
	}
}

// createScopedRoleRelationships constructs the SpiceDB relationships for the given scoped roles and scope object.
// It creates 2 relationships per scoped role: one linking the scoped role to the organization, and another linking the scope object to the scoped role.
func createScopedRoleRelationships(orgId string, mapScopedRoleIdToRelation map[uuid.UUID]string, scopeObjectType spicedb.ObjectType, scopeObjectId string) []*v1.Relationship {
	var relationships []*v1.Relationship
	for roleId, relation := range mapScopedRoleIdToRelation {
		relationships = append(relationships,
			spicedb.BuildRelation(spicedb.RelationOrg, spicedb.ObjectTypeScopedRole, roleId.String(), spicedb.ObjectTypeOrg, orgId),
			spicedb.BuildRelation(spicedb.Relation(relation), scopeObjectType, scopeObjectId, spicedb.ObjectTypeScopedRole, roleId.String()),
		)
	}
	return relationships
}
