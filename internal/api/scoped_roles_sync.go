package api

import (
	"context"
	"database/sql"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
)

var ErrBuiltinRolesNotSeeded = errors.New("organization roles not seeded yet")

// SyncResult contains the results of a scope sync operation
type SyncResult struct {
	ScopedRolesCreated   int
	RelationshipsAdded   int
	RelationshipsRemoved int
}

// SyncProjectsAndEnvsToSpiceDB handles the common logic of syncing scoped roles and relationships
// for a set of projects and environments to the database and SpiceDB.
// It performs the following steps:
// 1. Lists and validates org roles
// 2. Collects scoped roles for all projects and environments
// 3. Batch upserts scoped roles to the database
// 4. Builds SpiceDB relationships using actual database IDs
// 5. Syncs relationships to SpiceDB
func SyncProjectsAndEnvsToSpiceDB(
	ctx context.Context,
	logger *zap.Logger,
	db model.Databaser,
	spiceDB spicedb.SpiceDB,
	orgId string,
	projectToEnvs map[uuid.UUID][]uuid.UUID,
) (*SyncResult, error) {
	// 1. Get org roles and validate
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	orgRoles, err := db.ListRoles(ctx, tx, orgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list organization roles")
	}
	if len(orgRoles) < BuiltinRolesNumber {
		return nil, ErrBuiltinRolesNotSeeded
	}

	// 2. Collect all scoped roles and scope metadata
	type scopeMetadata struct {
		scopeType      spicedb.ObjectType
		scopeId        string
		parentRelation spicedb.Relation
		parentType     spicedb.ObjectType
		parentId       string
		scopedRoleKeys []string // Keys to find scoped roles: "orgId|scope|orgRoleId"
	}

	var allScopedRoles []model.ScopedRole
	var scopes []scopeMetadata

	// Collect scoped roles for each project and its environments
	for projectUuid, envUuids := range projectToEnvs {
		// Create scoped roles for project
		projectScope := ScopeProject + ":" + projectUuid.String()
		projectScopedRoles := CreateScopedRolesForScope(orgId, projectScope, orgRoles)

		// Track keys for this project's scoped roles
		projectKeys := make([]string, len(projectScopedRoles))
		for i, role := range projectScopedRoles {
			projectKeys[i] = role.OrgId + "|" + role.Scope + "|" + role.OrgRoleId.String()
		}
		allScopedRoles = append(allScopedRoles, projectScopedRoles...)

		scopes = append(scopes, scopeMetadata{
			scopeType:      spicedb.ObjectTypeProject,
			scopeId:        projectUuid.String(),
			parentRelation: spicedb.RelationOrg,
			parentType:     spicedb.ObjectTypeOrg,
			parentId:       orgId,
			scopedRoleKeys: projectKeys,
		})

		// Create scoped roles for each environment
		projectUuidStr := projectUuid.String()
		for _, envUuid := range envUuids {
			envScope := ScopeEnvironment + ":" + envUuid.String()
			envScopedRoles := CreateScopedRolesForScope(orgId, envScope, orgRoles)

			// Track keys for this environment's scoped roles
			envKeys := make([]string, len(envScopedRoles))
			for i, role := range envScopedRoles {
				envKeys[i] = role.OrgId + "|" + role.Scope + "|" + role.OrgRoleId.String()
			}
			allScopedRoles = append(allScopedRoles, envScopedRoles...)

			scopes = append(scopes, scopeMetadata{
				scopeType:      spicedb.ObjectTypeEnv,
				scopeId:        envUuid.String(),
				parentRelation: spicedb.RelationProject,
				parentType:     spicedb.ObjectTypeProject,
				parentId:       projectUuidStr,
				scopedRoleKeys: envKeys,
			})
		}
	}

	// 3. Batch upsert all scoped roles in the database
	logger.Info("upserting scoped roles in database", zap.Int("scoped_roles_count", len(allScopedRoles)))
	var upsertedScopedRoles []model.ScopedRole
	if len(allScopedRoles) > 0 {
		upsertedScopedRoles, err = db.BatchUpsertScopedRoles(ctx, tx, allScopedRoles)
		if err != nil {
			return nil, errors.Wrap(err, "failed to batch upsert scoped roles")
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	// 4. Build a map from scoped role key to actual ID and relation
	scopedRoleMap := make(map[string]struct {
		id       uuid.UUID
		relation string
	})
	for _, role := range upsertedScopedRoles {
		key := role.OrgId + "|" + role.Scope + "|" + role.OrgRoleId.String()
		// Find the org role to get the relation
		for _, orgRole := range orgRoles {
			if orgRole.Id == role.OrgRoleId {
				scopedRoleMap[key] = struct {
					id       uuid.UUID
					relation string
				}{
					id:       role.Id,
					relation: GetRelationByRoleDisplayName(orgRole.DisplayName).String(),
				}
				break
			}
		}
	}

	// 5. Build all relationships using the actual IDs
	var allRelationships []*v1.Relationship
	for _, scope := range scopes {
		// Add parent relationship (project->org or env->project)
		allRelationships = append(allRelationships,
			spicedb.BuildRelation(
				scope.parentRelation,
				scope.scopeType,
				scope.scopeId,
				scope.parentType,
				scope.parentId,
			),
		)

		// Add scoped role relationships using actual IDs
		for _, key := range scope.scopedRoleKeys {
			if roleInfo, found := scopedRoleMap[key]; found {
				allRelationships = append(allRelationships,
					spicedb.BuildRelation(spicedb.RelationOrg, spicedb.ObjectTypeScopedRole, roleInfo.id.String(), spicedb.ObjectTypeOrg, orgId),
					spicedb.BuildRelation(spicedb.Relation(roleInfo.relation), scope.scopeType, scope.scopeId, spicedb.ObjectTypeScopedRole, roleInfo.id.String()),
				)
			}
		}
	}

	// 6. Batch sync all relationships to SpiceDB
	logger.Info("syncing relationships to SpiceDB", zap.Int("relationships_count", len(allRelationships)))
	zedToken, removed, added, err := spiceDB.SyncOrgRelationships(ctx, orgId, nil, nil, allRelationships)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sync organization relationships to SpiceDB")
	}

	// Store the zed token for this org
	if zedToken != "" {
		if _, err := db.UpsertOrgZedToken(ctx, nil, orgId, &model.OrgZedTokens{ZedToken: zedToken}); err != nil {
			return nil, errors.Wrap(err, "failed to upsert organization zed token")
		}
	}

	return &SyncResult{
		ScopedRolesCreated:   len(allScopedRoles),
		RelationshipsAdded:   added,
		RelationshipsRemoved: removed,
	}, nil
}
