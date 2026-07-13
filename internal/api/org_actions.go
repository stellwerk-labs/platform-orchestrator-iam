package api

import (
	"context"
	"net/http"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
)

func (s *Server) InternalSyncOrgToSpiceDB(ctx context.Context, request InternalSyncOrgToSpiceDBRequestObject) (InternalSyncOrgToSpiceDBResponseObject, error) {
	orgId := request.OrgId
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	logger.Info("starting SpiceDB sync for organization")

	// Verify the organization exists by calling the control plane
	resp, err := s.CpClient.GetInternalOrganizationWithResponse(ctx, orgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get organization from control plane")
	}

	if resp.StatusCode() == http.StatusNotFound {
		return InternalSyncOrgToSpiceDB404JSONResponse{
			N404NotFoundJSONResponse: Generate404Response("organization not found"),
		}, nil
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code %d when getting organization from control plane: %s", resp.StatusCode(), string(resp.Body))
	}

	if zedToken, removed, added, _, err := SyncSpiceDBWithDB(ctx, logger, SyncSpiceDBParams{OrgId: orgId}, s.Database, s.SpiceDB); err != nil {
		return nil, errors.Wrap(err, "failed to sync organization to SpiceDB")
	} else {
		if zedToken != "" {
			// Store the zed token for this org
			if _, err := s.Database.UpsertOrgZedToken(ctx, nil, orgId, &model.OrgZedTokens{ZedToken: zedToken}); err != nil {
				return nil, errors.Wrap(err, "failed to upsert organization zed token")
			}
		}
		logger.Info("successfully synced organization to SpiceDB", zap.Int("removed", removed), zap.Int("added", added))
		return InternalSyncOrgToSpiceDB200JSONResponse{
			Removed: &removed,
			Added:   added,
		}, nil
	}
}

func (s *Server) InternalSyncOrgScopes(ctx context.Context, request InternalSyncOrgScopesRequestObject) (InternalSyncOrgScopesResponseObject, error) {
	orgId := request.OrgId
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	logger.Info("starting scope sync for organization")

	// 1. Verify the organization exists by calling the control plane
	orgResp, err := s.CpClient.GetInternalOrganizationWithResponse(ctx, orgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get organization from control plane")
	}

	if orgResp.StatusCode() == http.StatusNotFound {
		return InternalSyncOrgScopes404JSONResponse{
			N404NotFoundJSONResponse: Generate404Response("organization not found"),
		}, nil
	}

	if orgResp.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code %d when getting organization from control plane: %s", orgResp.StatusCode(), string(orgResp.Body))
	}

	// 2. List all projects of the organization with pagination
	var projects []uuid.UUID
	var pageToken *string
	for {
		projectsResp, err := s.CpClient.ListProjectsWithResponse(ctx, orgId, &cpclient.ListProjectsParams{Page: pageToken})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list projects from control plane")
		}
		if projectsResp.StatusCode() != http.StatusOK {
			return nil, errors.Errorf("unexpected status code %d when listing projects from control plane: %s", projectsResp.StatusCode(), string(projectsResp.Body))
		}

		for _, project := range projectsResp.JSON200.Items {
			projects = append(projects, project.Uuid)
		}

		if projectsResp.JSON200.NextPageToken != nil {
			pageToken = projectsResp.JSON200.NextPageToken
		} else {
			break
		}
	}

	logger.Info("found projects for organization", zap.Int("project_count", len(projects)))

	// 3. Build a map of projects to their environments
	projectToEnvs := make(map[uuid.UUID][]uuid.UUID)
	totalEnvCount := 0

	for _, projectUuid := range projects {
		projectLogger := logger.With(zap.String("po-project-uuid", projectUuid.String()))

		// Get all environments for this project
		var envPageToken *string
		var envUuids []uuid.UUID
		for {
			envsResp, err := s.CpClient.ListInternalEnvironmentsByProjectUuidWithResponse(ctx, orgId, projectUuid, &cpclient.ListInternalEnvironmentsByProjectUuidParams{Page: envPageToken})
			if err != nil {
				return nil, errors.Wrap(err, "failed to list environments from control plane")
			}
			if envsResp.StatusCode() != http.StatusOK {
				return nil, errors.Errorf("unexpected status code %d when listing environments from control plane: %s", envsResp.StatusCode(), string(envsResp.Body))
			}

			for _, env := range envsResp.JSON200.Items {
				envUuids = append(envUuids, env.Uuid)
			}

			if envsResp.JSON200.NextPageToken != nil {
				envPageToken = envsResp.JSON200.NextPageToken
			} else {
				break
			}
		}

		totalEnvCount += len(envUuids)
		projectLogger.Info("found environments for project", zap.Int("env_count", len(envUuids)))
		projectToEnvs[projectUuid] = envUuids
	}

	// 4. Use shared sync logic to create scoped roles and relationships
	result, err := SyncProjectsAndEnvsToSpiceDB(ctx, logger, s.Database, s.SpiceDB, orgId, projectToEnvs)
	if err != nil {
		return nil, err
	}

	logger.Info("successfully synced scopes for organization",
		zap.Int("projects_synced", len(projects)),
		zap.Int("environments_synced", totalEnvCount),
		zap.Int("scoped_roles_created", result.ScopedRolesCreated),
		zap.Int("relationships_added", result.RelationshipsAdded),
		zap.Int("relationships_removed", result.RelationshipsRemoved),
	)

	return InternalSyncOrgScopes200JSONResponse{
		ProjectsSynced:     len(projects),
		EnvironmentsSynced: totalEnvCount,
		ScopedRolesCreated: result.ScopedRolesCreated,
		RelationshipsAdded: result.RelationshipsAdded,
	}, nil
}
