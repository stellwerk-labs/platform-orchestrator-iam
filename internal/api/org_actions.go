package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	"go.uber.org/zap"
)

func (s *Server) InternalSyncOrgScopes(ctx context.Context, request InternalSyncOrgScopesRequestObject) (InternalSyncOrgScopesResponseObject, error) {
	orgId := request.OrgId
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	orgResponse, err := s.CpClient.GetInternalOrganizationWithResponse(ctx, orgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get organization from control plane")
	}
	if orgResponse.StatusCode() == http.StatusNotFound {
		return InternalSyncOrgScopes404JSONResponse{N404NotFoundJSONResponse: Generate404Response("organization not found")}, nil
	}
	if orgResponse.StatusCode() != http.StatusOK {
		return nil, errors.Errorf("unexpected status code %d when getting organization", orgResponse.StatusCode())
	}

	projects := make([]uuid.UUID, 0)
	var projectPage *string
	for {
		response, err := s.CpClient.ListProjectsWithResponse(ctx, orgId, &cpclient.ListProjectsParams{Page: projectPage})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list projects")
		}
		if response.StatusCode() != http.StatusOK {
			return nil, errors.Errorf("unexpected status code %d when listing projects", response.StatusCode())
		}
		for _, project := range response.JSON200.Items {
			projects = append(projects, project.Uuid)
		}
		if response.JSON200.NextPageToken == nil {
			break
		}
		projectPage = response.JSON200.NextPageToken
	}

	projectToEnvironments := make(map[uuid.UUID][]uuid.UUID, len(projects))
	totalEnvironments := 0
	for _, projectId := range projects {
		var environmentPage *string
		for {
			response, err := s.CpClient.ListInternalEnvironmentsByProjectUuidWithResponse(ctx, orgId, projectId, &cpclient.ListInternalEnvironmentsByProjectUuidParams{Page: environmentPage})
			if err != nil {
				return nil, errors.Wrap(err, "failed to list project environments")
			}
			if response.StatusCode() != http.StatusOK {
				return nil, errors.Errorf("unexpected status code %d when listing project environments", response.StatusCode())
			}
			for _, environment := range response.JSON200.Items {
				projectToEnvironments[projectId] = append(projectToEnvironments[projectId], environment.Uuid)
				totalEnvironments++
			}
			if response.JSON200.NextPageToken == nil {
				break
			}
			environmentPage = response.JSON200.NextPageToken
		}
	}

	result, err := SyncAuthorizationResources(ctx, logger, s.Database, orgId, projectToEnvironments)
	if err != nil {
		return nil, err
	}
	logger.Info("synchronized authorization resource hierarchy", zap.Int("resources_upserted", result.ResourcesUpserted))
	return InternalSyncOrgScopes200JSONResponse{
		ProjectsSynced:     len(projects),
		EnvironmentsSynced: totalEnvironments,
		ResourcesUpserted:  result.ResourcesUpserted,
	}, nil
}
