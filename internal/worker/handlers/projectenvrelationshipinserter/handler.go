package projectenvrelationshipinserter

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hmessaging"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/logging"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

var BranchPattern = regexp.MustCompile(regexp.QuoteMeta(string(cpevents.IoPlatformOrchestratorProjectCreated)) + `|` + regexp.QuoteMeta(string(cpevents.IoPlatformOrchestratorEnvironmentCreated)))

type ProjectEnvRelationshipInserter struct {
	db       model.Databaser
	cpClient cpclient.ClientWithResponsesInterface
	reloader authorization.PolicyReloader
}

func New(db model.Databaser, cpClient cpclient.ClientWithResponsesInterface, reloaders ...authorization.PolicyReloader) *ProjectEnvRelationshipInserter {
	handler := &ProjectEnvRelationshipInserter{db: db, cpClient: cpClient}
	if len(reloaders) > 0 {
		handler.reloader = reloaders[0]
	}
	return handler
}

func (h *ProjectEnvRelationshipInserter) Handle(ctx context.Context, logger *zap.Logger, delivery *hmessaging.Delivery) error {
	switch delivery.Subject {
	case string(cpevents.IoPlatformOrchestratorProjectCreated):
		var event events.CloudEvent[cpevents.ProjectChangedData]
		if err := json.Unmarshal(delivery.Data, &event); err != nil {
			return errors.Wrap(err, "failed to unmarshal project event")
		}
		logger = logger.With(logging.ZapOrgId(event.Data.OrgId), logging.ZapProjectId(event.Data.ProjectId))
		return h.sync(ctx, logger, event.Data.OrgId, map[uuid.UUID][]uuid.UUID{event.Data.ProjectUuid: {}})
	case string(cpevents.IoPlatformOrchestratorEnvironmentCreated):
		var event events.CloudEvent[cpevents.EnvChangedData]
		if err := json.Unmarshal(delivery.Data, &event); err != nil {
			return errors.Wrap(err, "failed to unmarshal environment event")
		}
		logger = logger.With(logging.ZapOrgId(event.Data.OrgId), logging.ZapProjectId(event.Data.ProjectId), logging.ZapEnvId(event.Data.EnvId))
		return h.sync(ctx, logger, event.Data.OrgId, map[uuid.UUID][]uuid.UUID{event.Data.ProjectUuid: {event.Data.EnvUuid}})
	case string(genevents.IoPlatformOrchestratorScopeSync):
		var event events.CloudEvent[genevents.ScopeSyncData]
		if err := json.Unmarshal(delivery.Data, &event); err != nil {
			return errors.Wrap(err, "failed to unmarshal scope sync event")
		}
		return h.syncScope(ctx, logger, event.Data.OrgId, event.Data.Scope)
	default:
		return nil
	}
}

func (h *ProjectEnvRelationshipInserter) syncScope(ctx context.Context, logger *zap.Logger, orgId, scope string) error {
	scopeType, rawId, found := strings.Cut(scope, ":")
	if !found {
		return errors.Errorf("invalid scope %q", scope)
	}
	resourceId, err := uuid.Parse(rawId)
	if err != nil {
		return errors.Wrap(err, "failed to parse scope resource id")
	}

	switch scopeType {
	case api.ScopeProject:
		environments, err := h.listProjectEnvironments(ctx, orgId, resourceId)
		if err != nil {
			return err
		}
		return h.sync(ctx, logger, orgId, map[uuid.UUID][]uuid.UUID{resourceId: environments})
	case api.ScopeEnvironment:
		response, err := h.cpClient.GetInternalEnvironmentByUuidWithResponse(ctx, orgId, resourceId)
		if err != nil {
			return errors.Wrap(err, "failed to get environment from control plane")
		}
		if response.StatusCode() != 200 || response.JSON200.ProjectUuid == nil {
			return errors.Errorf("unexpected status code %d when getting environment from control plane", response.StatusCode())
		}
		return h.sync(ctx, logger, orgId, map[uuid.UUID][]uuid.UUID{*response.JSON200.ProjectUuid: {resourceId}})
	default:
		return errors.Errorf("unsupported scope type %q", scopeType)
	}
}

func (h *ProjectEnvRelationshipInserter) listProjectEnvironments(ctx context.Context, orgId string, projectId uuid.UUID) ([]uuid.UUID, error) {
	var environments []uuid.UUID
	var page *string
	for {
		response, err := h.cpClient.ListInternalEnvironmentsByProjectUuidWithResponse(ctx, orgId, projectId, &cpclient.ListInternalEnvironmentsByProjectUuidParams{Page: page})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list project environments")
		}
		if response.StatusCode() != 200 {
			return nil, errors.Errorf("unexpected status code %d when listing project environments", response.StatusCode())
		}
		for _, environment := range response.JSON200.Items {
			environments = append(environments, environment.Uuid)
		}
		if response.JSON200.NextPageToken == nil {
			return environments, nil
		}
		page = response.JSON200.NextPageToken
	}
}

func (h *ProjectEnvRelationshipInserter) sync(ctx context.Context, logger *zap.Logger, orgId string, resources map[uuid.UUID][]uuid.UUID) error {
	result, err := api.SyncAuthorizationResources(ctx, logger, h.db, orgId, resources)
	if err != nil {
		return err
	}
	if h.reloader != nil {
		if err := h.reloader.ReloadPolicy(); err != nil {
			return errors.Wrap(err, "failed to reload authorization policy")
		}
	}
	logger.Info("synchronized authorization resources", zap.Int("resources_upserted", result.ResourcesUpserted))
	return nil
}
