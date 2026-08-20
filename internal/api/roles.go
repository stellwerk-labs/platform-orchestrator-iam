package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
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

var rolePermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}[a-z0-9]$`)

func fromModelToAPIRole(r *model.Role) Role {
	return Role{
		CreatedAt:   r.CreatedAt,
		CreatedBy:   r.CreatedBy,
		DisplayName: r.DisplayName,
		Id:          r.Id,
		IsSystem:    r.IsSystem,
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

func validateRoleWrite(body *RoleWriteBody) (string, []string, error) {
	if body == nil {
		return "", nil, usererrors.NewUserError("role body is required")
	}
	displayName := strings.TrimSpace(body.DisplayName)
	if len(displayName) < 2 || len(displayName) > 100 {
		return "", nil, usererrors.NewUserError("role display name must contain between 2 and 100 characters")
	}
	if displayName == RoleAdmin || displayName == RoleDeployer || displayName == RoleViewer {
		return "", nil, usererrors.NewUserError("built-in role names are reserved")
	}
	if len(body.Permissions) == 0 {
		return "", nil, usererrors.NewUserError("at least one permission is required")
	}
	permissionSet := make(map[string]struct{}, len(body.Permissions))
	for _, permission := range body.Permissions {
		if !rolePermissionPattern.MatchString(permission) {
			return "", nil, usererrors.NewUserError(fmt.Sprintf("invalid permission %q", permission))
		}
		permissionSet[permission] = struct{}{}
	}
	permissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		permissions = append(permissions, permission)
	}
	slices.Sort(permissions)
	return displayName, permissions, nil
}

func (s *Server) CreateRole(ctx context.Context, request CreateRoleRequestObject) (CreateRoleResponseObject, error) {
	userId, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if err := s.checkOrgAdminAuthorization(ctx, userId, request.OrgId); err != nil {
		return nil, err
	}
	displayName, permissions, validationErr := validateRoleWrite(request.Body)
	if validationErr != nil {
		return CreateRole400JSONResponse{N400BadRequestJSONResponse: Generate400Response(validationErr.Error())}, nil
	}
	role, err := s.Database.CreateRole(ctx, nil, &model.Role{
		Id: uuid.Must(uuid.NewV7()), OrgId: request.OrgId, DisplayName: displayName,
		Permissions: permissions, CreatedAt: time.Now().UTC(), CreatedBy: userId,
	})
	if err != nil {
		if _, conflict := model.IsErrConflict(err); conflict {
			return CreateRole409JSONResponse{N409ConflictJSONResponse: Generate409Response(err.Error())}, nil
		}
		return nil, err
	}
	return CreateRole201JSONResponse(fromModelToAPIRole(role)), nil
}

func (s *Server) UpdateRole(ctx context.Context, request UpdateRoleRequestObject) (UpdateRoleResponseObject, error) {
	userId, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if err := s.checkOrgAdminAuthorization(ctx, userId, request.OrgId); err != nil {
		return nil, err
	}
	existing, err := s.Database.GetRole(ctx, nil, request.OrgId, request.RoleId)
	if err != nil {
		if _, notFound := model.IsErrNotFound(err); notFound {
			return UpdateRole404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, nil
		}
		return nil, err
	}
	if existing.IsSystem {
		return UpdateRole409JSONResponse{N409ConflictJSONResponse: Generate409Response("built-in roles cannot be modified")}, nil
	}
	displayName, permissions, validationErr := validateRoleWrite(request.Body)
	if validationErr != nil {
		return UpdateRole400JSONResponse{N400BadRequestJSONResponse: Generate400Response(validationErr.Error())}, nil
	}
	existing.DisplayName = displayName
	existing.Permissions = permissions
	updated, err := s.Database.UpdateRole(ctx, nil, existing)
	if err != nil {
		if _, conflict := model.IsErrConflict(err); conflict {
			return UpdateRole409JSONResponse{N409ConflictJSONResponse: Generate409Response(err.Error())}, nil
		}
		return nil, err
	}
	return UpdateRole200JSONResponse(fromModelToAPIRole(updated)), nil
}

func (s *Server) DeleteRole(ctx context.Context, request DeleteRoleRequestObject) (DeleteRoleResponseObject, error) {
	userId, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if err := s.checkOrgAdminAuthorization(ctx, userId, request.OrgId); err != nil {
		return nil, err
	}
	existing, err := s.Database.GetRole(ctx, nil, request.OrgId, request.RoleId)
	if err != nil {
		if _, notFound := model.IsErrNotFound(err); notFound {
			return DeleteRole404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, nil
		}
		return nil, err
	}
	if existing.IsSystem {
		return DeleteRole409JSONResponse{N409ConflictJSONResponse: Generate409Response("built-in roles cannot be deleted")}, nil
	}
	if err := s.Database.DeleteRole(ctx, nil, request.OrgId, request.RoleId); err != nil {
		if _, conflict := model.IsErrConflict(err); conflict {
			return DeleteRole409JSONResponse{N409ConflictJSONResponse: Generate409Response(err.Error())}, nil
		}
		return nil, err
	}
	return DeleteRole204Response{}, nil
}

// SeedBuiltinOrgRoles creates the default roles for an organization.
func SeedBuiltinOrgRoles(ctx context.Context, logger *zap.Logger, database model.Databaser, tx model.TxWithCommit, orgId string) ([]model.Role, error) {
	var roles = []model.Role{
		{DisplayName: RoleAdmin, Permissions: []string{PermissionsManageAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7()), IsSystem: true},
		{DisplayName: RoleDeployer, Permissions: []string{PermissionsWriteAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7()), IsSystem: true},
		{DisplayName: RoleViewer, Permissions: []string{PermissionsReadAll}, CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, Id: uuid.Must(uuid.NewV7()), IsSystem: true},
	}
	if err := database.SeedRoles(ctx, tx, orgId, roles); err != nil {
		return nil, errors.Wrap(err, "failed to seed roles")
	} else if err := database.UpsertAuthorizationResource(ctx, tx, &model.AuthorizationResource{
		Resource: "organization:" + orgId, ResourceType: "organization", ResourceId: orgId, OrgId: orgId,
	}); err != nil {
		return nil, errors.Wrap(err, "failed to seed organization authorization resource")
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
