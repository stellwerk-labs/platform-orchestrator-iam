package authorizationmigration

import (
	"context"
	"database/sql"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

type ReconcileResult struct {
	Organizations int `json:"organizations"`
	Projects      int `json:"projects"`
	Environments  int `json:"environments"`
	Resources     int `json:"resources"`
}

// Reconcile rebuilds the complete Casbin resource hierarchy from the control
// plane. The legacy database records scopes but not environment-to-project
// parentage, so this must complete before the upgraded IAM accepts traffic.
func Reconcile(ctx context.Context, logger *zap.Logger, rawDB *sql.DB, db model.Databaser, cp cpclient.ClientWithResponsesInterface) (ReconcileResult, error) {
	result := ReconcileResult{}
	orgIDs, err := listOrganizationIDs(ctx, rawDB)
	if err != nil {
		return result, err
	}

	for _, orgID := range orgIDs {
		projectToEnvironments, err := loadOrganizationResources(ctx, cp, orgID)
		if err != nil {
			return result, errors.Wrapf(err, "failed to load authorization hierarchy for organization %s", orgID)
		}
		syncResult, err := api.SyncAuthorizationResources(ctx, logger, db, orgID, projectToEnvironments)
		if err != nil {
			return result, errors.Wrapf(err, "failed to store authorization hierarchy for organization %s", orgID)
		}
		result.Organizations++
		result.Projects += len(projectToEnvironments)
		for _, environments := range projectToEnvironments {
			result.Environments += len(environments)
		}
		result.Resources += syncResult.ResourcesUpserted
	}
	return result, nil
}

func listOrganizationIDs(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT org_id FROM roles
		UNION SELECT org_id FROM memberships WHERE subject_type = 'role'
		UNION SELECT org_id FROM service_user_roles`)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list organizations with authorization data")
	}
	defer func() { _ = rows.Close() }()

	orgIDs := make([]string, 0)
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return nil, errors.Wrap(err, "failed to scan authorization organization")
		}
		orgIDs = append(orgIDs, orgID)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate authorization organizations")
	}
	slices.Sort(orgIDs)
	return orgIDs, nil
}

func loadOrganizationResources(ctx context.Context, cp cpclient.ClientWithResponsesInterface, orgID string) (map[uuid.UUID][]uuid.UUID, error) {
	projects := make([]uuid.UUID, 0)
	var projectPage *string
	for {
		response, err := cp.ListProjectsWithResponse(ctx, orgID, &cpclient.ListProjectsParams{Page: projectPage})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list projects")
		}
		if response.StatusCode() != http.StatusOK || response.JSON200 == nil {
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
	for _, projectID := range projects {
		projectToEnvironments[projectID] = []uuid.UUID{}
		var environmentPage *string
		for {
			response, err := cp.ListInternalEnvironmentsByProjectUuidWithResponse(ctx, orgID, projectID, &cpclient.ListInternalEnvironmentsByProjectUuidParams{Page: environmentPage})
			if err != nil {
				return nil, errors.Wrapf(err, "failed to list environments for project %s", projectID)
			}
			if response.StatusCode() != http.StatusOK || response.JSON200 == nil {
				return nil, errors.Errorf("unexpected status code %d when listing environments for project %s", response.StatusCode(), projectID)
			}
			for _, environment := range response.JSON200.Items {
				projectToEnvironments[projectID] = append(projectToEnvironments[projectID], environment.Uuid)
			}
			if response.JSON200.NextPageToken == nil {
				break
			}
			environmentPage = response.JSON200.NextPageToken
		}
	}
	return projectToEnvironments, nil
}
