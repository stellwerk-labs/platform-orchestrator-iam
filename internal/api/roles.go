package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"

	usererrors "github.com/stellwerk-labs/platform-orchestrator-iam/internal/errors"
)

const (
	BuiltinRolesNumber   = 3
	RoleAdmin            = "Admin"
	RoleViewer           = "Viewer"
	RoleDeployer         = "Deployer"
	PermissionsManageAll = "manage_all"
	PermissionsReadAll   = "read_all"
	PermissionsWriteAll  = "write_all"
	ScopeProject         = "project"
	ScopeEnvironment     = "env"
)

var AllowedScopesForRoles = []string{ScopeProject, ScopeEnvironment}

func fromModelToAPIRole(r *model.Role) Role {
	return Role{
		CreatedAt:   r.CreatedAt,
		CreatedBy:   r.CreatedBy,
		DisplayName: r.DisplayName,
		Id:          r.Id,
		Permissions: r.Permissions,
	}
}

func (s *Server) GetRole(ctx context.Context, request GetRoleRequestObject) (GetRoleResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	r, err := s.Database.GetRole(ctx, nil, request.OrgId, request.RoleId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return GetRole404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get role")
	}

	return GetRole200JSONResponse(fromModelToAPIRole(r)), nil
}

func (s *Server) ListRoles(ctx context.Context, request ListRolesRequestObject) (ListRolesResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	roles, err := s.listOrSeedRoles(ctx, logger, tx, request.OrgId)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		out = append(out, fromModelToAPIRole(&r))
	}

	return ListRoles200JSONResponse{
		Items: out,
	}, nil
}

// SeedBuiltinOrgRoles creates the default roles for an organization.
func SeedBuiltinOrgRoles(ctx context.Context, logger *zap.Logger, database model.Databaser, tx model.TxWithCommit, orgId string) ([]model.Role, error) {
	var roles = []model.Role{
		{DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7())},
		{DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7())},
		{DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7())},
	}
	if err := database.SeedRoles(ctx, tx, orgId, roles); err != nil {
		return nil, errors.Wrap(err, "failed to seed roles")
	} else {
		logger.Info("seeded default roles", zap.String("org_id", orgId))
		return roles, nil
	}
}

func (s *Server) seedBuiltinOrgRoles(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, orgId string) ([]model.Role, error) {
	return SeedBuiltinOrgRoles(ctx, logger, s.Database, tx, orgId)
}

func (s *Server) listOrSeedRoles(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, orgId string) (roles []model.Role, err error) {
	if roles, err = s.Database.ListRoles(ctx, tx, orgId); err != nil {
		return nil, errors.Wrap(err, "failed to list roles")
	} else if len(roles) == 0 {
		if roles, err = s.seedBuiltinOrgRoles(ctx, logger, tx, orgId); err != nil {
			return nil, errors.Wrap(err, "failed to seed admin and viewer roles")
		}
	}
	return roles, nil
}

func isScopeValidForRole(ctx context.Context, scope *string, orgId string, cpClient cpclient.ClientWithResponsesInterface) (bool, error) {
	if scope == nil || *scope == "" {
		return true, nil
	}

	scopeValue := *scope
	resourceKindIdSplitted := strings.Split(scopeValue, ":")
	if len(resourceKindIdSplitted) != 2 {
		return false, usererrors.NewUserError(fmt.Sprintf("invalid scope format '%s', expected <resource_kind>:<resource_uuid>", scopeValue))
	}
	var resourceKind string
	if !slices.Contains(AllowedScopesForRoles, resourceKindIdSplitted[0]) {
		return false, usererrors.NewUserError(fmt.Sprintf("invalid resource kind in scope '%s'", scopeValue))
	} else {
		resourceKind = resourceKindIdSplitted[0]
	}

	if resourceId, err := uuid.Parse(resourceKindIdSplitted[1]); err != nil {
		return false, usererrors.NewUserError(fmt.Sprintf("invalid resource id in scope '%s', must be a valid uuid", scopeValue))
	} else {
		switch resourceKind {
		case ScopeProject:
			if res, err := cpClient.GetInternalProjectByUuidWithResponse(ctx, orgId, resourceId); err != nil {
				return false, errors.Wrap(err, "failed to get project for scope validation")
			} else if res.StatusCode() == http.StatusNotFound {
				return false, usererrors.NewUserError(fmt.Sprintf("project in the scope '%s' does not exist", scopeValue))
			} else if res.StatusCode() != http.StatusOK {
				return false, errors.Errorf("unexpected status code %d when validating project scope", res.StatusCode())
			} else {
				return true, nil
			}
		case ScopeEnvironment:
			if res, err := cpClient.GetInternalEnvironmentByUuidWithResponse(ctx, orgId, resourceId); err != nil {
				return false, errors.Wrap(err, "failed to get environment for scope validation")
			} else if res.StatusCode() == http.StatusNotFound {
				return false, usererrors.NewUserError(fmt.Sprintf("environment in the scope '%s' does not exist", scopeValue))
			} else if res.StatusCode() != http.StatusOK {
				return false, errors.Errorf("unexpected status code %d when validating environment scope", res.StatusCode())
			} else {
				return true, nil
			}
		}
	}
	return true, nil
}

// CreateScopedRolesForScope creates scoped role models for a given scope (project or environment).
// Returns a slice of ScopedRole models with generated IDs.
// This is a shared helper used by both the API endpoint and worker handlers.
func CreateScopedRolesForScope(orgId, scope string, orgRoles []model.Role) []model.ScopedRole {
	scopedRoles := make([]model.ScopedRole, 0, len(orgRoles))

	for _, orgRole := range orgRoles {
		scopedRoles = append(scopedRoles, model.ScopedRole{
			Id:        uuid.Must(uuid.NewV7()),
			OrgId:     orgId,
			Scope:     scope,
			OrgRoleId: orgRole.Id,
		})
	}

	return scopedRoles
}
