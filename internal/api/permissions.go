package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"
)

// addSubjectsWithRole parses subject IDs and adds them to the userRoles map with the given role.
func addSubjectsWithRole(subjects []*v1.ResolvedSubject, roleId uuid.UUID, userRoles map[uuid.UUID]uuid.UUID, logger *zap.Logger) {
	for _, subject := range subjects {
		if subject.SubjectObjectId == "" {
			continue
		}
		userId, err := uuid.Parse(subject.SubjectObjectId)
		if err != nil {
			logger.Warn("failed to parse subject ID as UUID", zap.String("subject_id", subject.SubjectObjectId), zap.Error(err))
			continue
		}
		userRoles[userId] = roleId
	}
}

// listUsersWithPermissionsOnResource is a generic method that fetches all users/service users
// with permissions on a resource (project or environment) and returns them with their highest role.
// It handles authentication, fetching subjects from SpiceDB for all permission levels,
// determining the highest role for each user, and building the response.
func (s *Server) listUsersWithPermissionsOnResource(
	ctx context.Context,
	logger *zap.Logger,
	orgId string,
	resourceType spicedb.ObjectType,
	resourceId string,
	typeFilter *string,
	cursor string,
) ([]UserWithRole, string, error) {
	// Get role IDs from database
	tx, txErr := s.Database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if txErr != nil {
		return nil, "", errors.Wrap(txErr, "failed to begin transaction")
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(rbErr))
		}
	}()

	roles, rolesErr := s.Database.ListRoles(ctx, tx, orgId)
	if rolesErr != nil {
		return nil, "", errors.Wrap(rolesErr, "failed to list roles")
	}

	// Build role name to role ID map
	roleNameToId := make(map[string]uuid.UUID)
	for _, role := range roles {
		roleNameToId[role.DisplayName] = role.Id
	}
	var zedToken string
	if zedTokenFromDB, err := s.Database.GetOrgZedToken(ctx, tx, orgId); err != nil {
		return nil, "", errors.Wrap(err, "failed to get org zed token")
	} else if zedTokenFromDB != nil {
		zedToken = zedTokenFromDB.ZedToken
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return nil, "", errors.Wrap(commitErr, "failed to commit transaction")
	}

	// Fetch subjects with all three permission levels
	// We are using the same cursor for all three lookups to keep pagination consistent
	// However, only the viewer lookup's next cursor will be returned for pagination
	// since it is the lowest permission level and will have the most subjects
	// This means that if there are more subjects with higher permissions,
	// they will be included in the next page when the client paginates
	// This is acceptable since the client is expected to paginate through all users anyway
	// and we want to avoid complex pagination logic across multiple permission levels
	// that could lead to missing or duplicate users in the results
	// instead, we prioritize simplicity and consistency in pagination
	// while ensuring all users with any permission level are eventually returned
	adminSubjects, _, adminErr := s.SpiceDB.LookupSubjects(ctx, resourceType, resourceId, spicedb.PermissionManage, cursor, zedToken)
	if adminErr != nil {
		return nil, "", errors.Wrap(adminErr, "failed to lookup subjects with manage permission")
	}

	deployerSubjects, _, deployerErr := s.SpiceDB.LookupSubjects(ctx, resourceType, resourceId, spicedb.PermissionWrite, cursor, zedToken)
	if deployerErr != nil {
		return nil, "", errors.Wrap(deployerErr, "failed to lookup subjects with write permission")
	}

	viewerSubjects, nextCursor, viewerErr := s.SpiceDB.LookupSubjects(ctx, resourceType, resourceId, spicedb.PermissionRead, cursor, zedToken)
	if viewerErr != nil {
		return nil, "", errors.Wrap(viewerErr, "failed to lookup subjects with read permission")
	}

	// Build a map of userId -> highest role
	// Priority: Admin > Deployer > Viewer
	userRoles := make(map[uuid.UUID]uuid.UUID)

	// Add in order of priority (lowest to highest) so higher priorities override lower ones
	addSubjectsWithRole(viewerSubjects, roleNameToId[RoleViewer], userRoles, logger)
	addSubjectsWithRole(deployerSubjects, roleNameToId[RoleDeployer], userRoles, logger)
	addSubjectsWithRole(adminSubjects, roleNameToId[RoleAdmin], userRoles, logger)

	// Build the response
	items := make([]UserWithRole, 0, len(userRoles))

	for userId, roleId := range userRoles {
		// Determine user type
		userType := UserWithRoleTypeUser
		if userid.IsServiceUser(userId) {
			userType = UserWithRoleTypeServiceUser
		}

		// Filter by user type if specified
		if typeFilter != nil && string(userType) != *typeFilter {
			continue
		}

		items = append(items, UserWithRole{
			Id:          userId,
			Type:        userType,
			SubjectType: SubjectTypeRole,
			SubjectId:   roleId,
		})
	}

	slices.SortFunc(items, func(userWithRoleA, userWithRoleB UserWithRole) int {
		return strings.Compare(userWithRoleA.Id.String(), userWithRoleB.Id.String())
	})

	return items, nextCursor, nil
}

// List the users and service users hat have access to this project.
// (GET /orgs/{orgId}/projects/{projectId}/users)
func (s *Server) ListProjectUsers(ctx context.Context, request ListProjectUsersRequestObject) (ListProjectUsersResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	var uid uuid.UUID
	// Check authentication
	if userId, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else {
		// Mark auth asserter checked in middleware
		middleware.SetAuthAsserterChecked(ctx)
		uid = userId
	}

	// Get the project to verify it exists and get its UUID
	resp, cpErr := s.CpClient.GetProjectWithResponse(ctx, request.OrgId, request.ProjectId)
	if cpErr != nil {
		return nil, errors.Wrap(cpErr, "failed to get project from control plane")
	}

	if resp.StatusCode() == http.StatusNotFound {
		return ListProjectUsers404JSONResponse{N404NotFoundJSONResponse: Generate404Response("project not found")}, nil
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when getting project from control plane: %s", resp.StatusCode(), string(resp.Body))
	}

	projectUuid := resp.JSON200.Uuid

	// Check authorization - user must have read permission on the resource
	if hasPermission, permErr := s.SpiceDB.HasSubjectPermissionOnObj(ctx, spicedb.SubjectTypeUser, uid.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), ""); permErr != nil {
		return nil, errors.Wrap(permErr, "failed to check permission of user on project")
	} else if !hasPermission {
		return ListProjectUsers403JSONResponse{N403ForbiddenJSONResponse: Generate403Response("insufficient permissions to view project users as user can't view project")}, nil
	}

	// Get cursor for pagination
	cursor := ref.DerefOr(request.Params.Page, "")

	// Convert type filter to string pointer
	var userTypeFilter *string
	if request.Params.Type != nil {
		userTypeFilter = ref.Ref(string(*request.Params.Type))
	}

	// Fetch users with permissions on the project
	items, nextCursor, listErr := s.listUsersWithPermissionsOnResource(
		ctx,
		logger,
		request.OrgId,
		spicedb.ObjectTypeProject,
		projectUuid.String(),
		userTypeFilter,
		cursor,
	)
	if listErr != nil {
		if errors.Is(listErr, spicedb.ErrInvalidCursor) {
			return nil, herrors.NewWithStatus(http.StatusBadRequest, "invalid pagination cursor", nil)
		}
		return nil, errors.Wrap(listErr, "failed to list users with permissions on project")
	}

	response := UserWithRolePage{
		Items: items,
	}

	if nextCursor != "" {
		response.NextPageToken = ref.Ref(nextCursor)
	}

	logger.Info("listed project users", zap.Int("count", len(items)))
	return ListProjectUsers200JSONResponse(response), nil
}

// List the users and service users that have access to this environment.
// (GET /orgs/{orgId}/projects/{projectId}/envs/{envId}/users)
func (s *Server) ListEnvironmentUsers(ctx context.Context, request ListEnvironmentUsersRequestObject) (ListEnvironmentUsersResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	var uid uuid.UUID
	// Check authentication
	if userId, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else {
		// Mark auth asserter checked in middleware
		middleware.SetAuthAsserterChecked(ctx)
		uid = userId
	}

	// Get the environment to verify it exists and get its UUID
	resp, cpErr := s.CpClient.GetEnvironmentWithResponse(ctx, request.OrgId, request.ProjectId, request.EnvId)
	if cpErr != nil {
		return nil, errors.Wrap(cpErr, "failed to get environment from control plane")
	}

	if resp.StatusCode() == http.StatusNotFound {
		return ListEnvironmentUsers404JSONResponse{N404NotFoundJSONResponse: Generate404Response("environment not found")}, nil
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when getting environment from control plane: %s", resp.StatusCode(), string(resp.Body))
	}

	envUuid := resp.JSON200.Uuid

	// Check authorization - user must have read permission on the resource
	if hasPermission, permErr := s.SpiceDB.HasSubjectPermissionOnObj(ctx, spicedb.SubjectTypeUser, uid.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), ""); permErr != nil {
		return nil, errors.Wrap(permErr, "failed to check permission of user on environment")
	} else if !hasPermission {
		return ListEnvironmentUsers403JSONResponse{N403ForbiddenJSONResponse: Generate403Response("insufficient permissions to view environment users as user can't view environment")}, nil
	}

	// Get cursor for pagination
	cursor := ref.DerefOr(request.Params.Page, "")

	// Convert type filter to string pointer
	var userTypeFilter *string
	if request.Params.Type != nil {
		userTypeFilter = ref.Ref(string(*request.Params.Type))
	}

	// Fetch users with permissions on the environment
	items, nextCursor, listErr := s.listUsersWithPermissionsOnResource(
		ctx,
		logger,
		request.OrgId,
		spicedb.ObjectTypeEnv,
		envUuid.String(),
		userTypeFilter,
		cursor,
	)
	if listErr != nil {
		if errors.Is(listErr, spicedb.ErrInvalidCursor) {
			return nil, herrors.NewWithStatus(http.StatusBadRequest, "invalid pagination cursor", nil)
		}
		return nil, errors.Wrap(listErr, "failed to list users with permissions on environment")
	}

	response := UserWithRolePage{
		Items: items,
	}

	if nextCursor != "" {
		response.NextPageToken = ref.Ref(nextCursor)
	}

	logger.Info("listed environment users", zap.Int("count", len(items)))
	return ListEnvironmentUsers200JSONResponse(response), nil
}
