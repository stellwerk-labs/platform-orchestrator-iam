package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
)

const defaultPermissionUsersPageSize = 100

func validatePermissionUsersCursor(cursor *string) error {
	if cursor == nil || *cursor == "" {
		return nil
	}
	if _, err := uuid.Parse(*cursor); err != nil {
		return herrors.NewWithStatus(http.StatusBadRequest, "invalid pagination cursor", nil)
	}
	return nil
}

func roleRank(role model.EffectiveRoleBinding) int {
	rank := len(role.Permissions)
	for _, permission := range role.Permissions {
		switch permission {
		case PermissionsManageAll:
			return 300
		case PermissionsWriteAll:
			if rank < 200 {
				rank = 200
			}
		case PermissionsReadAll:
			if rank < 100 {
				rank = 100
			}
		}
	}
	return rank
}

func (s *Server) listUsersWithPermissionsOnResource(ctx context.Context, resource string, typeFilter *string, cursor string, perPage int) ([]UserWithRole, string, error) {
	bindings, err := s.Database.ListEffectiveRoleBindings(ctx, nil, resource)
	if err != nil {
		return nil, "", err
	}
	selected := make(map[uuid.UUID]model.EffectiveRoleBinding)
	for _, binding := range bindings {
		current, found := selected[binding.SubjectId]
		if !found || roleRank(binding) > roleRank(current) || (roleRank(binding) == roleRank(current) && binding.RoleId.String() < current.RoleId.String()) {
			selected[binding.SubjectId] = binding
		}
	}

	items := make([]UserWithRole, 0, len(selected))
	for subjectId, binding := range selected {
		userType := UserWithRoleTypeUser
		if userid.IsServiceUser(subjectId) {
			userType = UserWithRoleTypeServiceUser
		}
		if typeFilter != nil && string(userType) != *typeFilter {
			continue
		}
		items = append(items, UserWithRole{Id: subjectId, Type: userType, SubjectType: SubjectTypeRole, SubjectId: binding.RoleId})
	}
	slices.SortFunc(items, func(left, right UserWithRole) int { return strings.Compare(left.Id.String(), right.Id.String()) })

	if cursor != "" {
		cursorId, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", herrors.NewWithStatus(http.StatusBadRequest, "invalid pagination cursor", nil)
		}
		items = slices.DeleteFunc(items, func(item UserWithRole) bool { return item.Id.String() <= cursorId.String() })
	}
	if perPage <= 0 {
		perPage = defaultPermissionUsersPageSize
	}
	nextCursor := ""
	if len(items) > perPage {
		nextCursor = items[perPage-1].Id.String()
		items = items[:perPage]
	}
	return items, nextCursor, nil
}

func (s *Server) ListProjectUsers(ctx context.Context, request ListProjectUsersRequestObject) (ListProjectUsersResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())
	uid, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	middleware.SetAuthAsserterChecked(ctx)
	if err := validatePermissionUsersCursor(request.Params.Page); err != nil {
		return nil, err
	}

	response, err := s.CpClient.GetProjectWithResponse(ctx, request.OrgId, request.ProjectId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get project from control plane")
	}
	if response.StatusCode() == http.StatusNotFound {
		return ListProjectUsers404JSONResponse{N404NotFoundJSONResponse: Generate404Response("project not found")}, nil
	}
	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when getting project", response.StatusCode())
	}
	resource := "project:" + response.JSON200.Uuid.String()
	decisions, err := s.Authorizer.Authorize(ctx, uid, []authorization.Check{{Resource: resource, Permission: "read"}})
	if err != nil {
		return nil, errors.Wrap(err, "failed to authorize project user listing")
	}
	if len(decisions) != 1 || !decisions[0].Allowed {
		return ListProjectUsers403JSONResponse{N403ForbiddenJSONResponse: Generate403Response("insufficient permissions to view project users")}, nil
	}

	perPage := defaultPermissionUsersPageSize
	if request.Params.PerPage != nil {
		perPage = *request.Params.PerPage
	}
	var typeFilter *string
	if request.Params.Type != nil {
		typeFilter = ref.Ref(string(*request.Params.Type))
	}
	items, nextCursor, err := s.listUsersWithPermissionsOnResource(ctx, resource, typeFilter, ref.DerefOr(request.Params.Page, ""), perPage)
	if err != nil {
		return nil, err
	}
	page := UserWithRolePage{Items: items}
	if nextCursor != "" {
		page.NextPageToken = &nextCursor
	}
	logger.Info("listed project users", zap.Int("count", len(items)))
	return ListProjectUsers200JSONResponse(page), nil
}

func (s *Server) ListEnvironmentUsers(ctx context.Context, request ListEnvironmentUsersRequestObject) (ListEnvironmentUsersResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())
	uid, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	middleware.SetAuthAsserterChecked(ctx)
	if err := validatePermissionUsersCursor(request.Params.Page); err != nil {
		return nil, err
	}

	response, err := s.CpClient.GetEnvironmentWithResponse(ctx, request.OrgId, request.ProjectId, request.EnvId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get environment from control plane")
	}
	if response.StatusCode() == http.StatusNotFound {
		return ListEnvironmentUsers404JSONResponse{N404NotFoundJSONResponse: Generate404Response("environment not found")}, nil
	}
	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when getting environment", response.StatusCode())
	}
	resource := "env:" + response.JSON200.Uuid.String()
	decisions, err := s.Authorizer.Authorize(ctx, uid, []authorization.Check{{Resource: resource, Permission: "read"}})
	if err != nil {
		return nil, errors.Wrap(err, "failed to authorize environment user listing")
	}
	if len(decisions) != 1 || !decisions[0].Allowed {
		return ListEnvironmentUsers403JSONResponse{N403ForbiddenJSONResponse: Generate403Response("insufficient permissions to view environment users")}, nil
	}

	perPage := defaultPermissionUsersPageSize
	if request.Params.PerPage != nil {
		perPage = *request.Params.PerPage
	}
	var typeFilter *string
	if request.Params.Type != nil {
		typeFilter = ref.Ref(string(*request.Params.Type))
	}
	items, nextCursor, err := s.listUsersWithPermissionsOnResource(ctx, resource, typeFilter, ref.DerefOr(request.Params.Page, ""), perPage)
	if err != nil {
		return nil, err
	}
	page := UserWithRolePage{Items: items}
	if nextCursor != "" {
		page.NextPageToken = &nextCursor
	}
	logger.Info("listed environment users", zap.Int("count", len(items)))
	return ListEnvironmentUsers200JSONResponse(page), nil
}
