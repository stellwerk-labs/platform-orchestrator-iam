package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	usererrors "github.com/stellwerk-labs/platform-orchestrator-iam/internal/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	ServiceUserTokenEntropyBytes = 33
	ServiceUserTokenPrefix       = "SU-"
)

func EncodeServiceUserToken(raw []byte) string {
	return ServiceUserTokenPrefix + base64.URLEncoding.EncodeToString(raw)
}

func RegenerateServiceUserToken(subject *model.ServiceUserToken, expireDays int) string {
	raw := make([]byte, ServiceUserTokenEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		// panic if we can't get entropy
		panic(err)
	}
	hashSum := sha256.Sum256(raw)
	now := time.Now().UTC()
	subject.GeneratedAt = now
	subject.CurrentTokenExpiresAt = now.Add(time.Duration(expireDays*24) * time.Hour)
	subject.CurrentTokenSha256Hash = hashSum[:]
	return EncodeServiceUserToken(raw)
}

func (s *Server) ListServiceUsers(ctx context.Context, request ListServiceUsersRequestObject) (ListServiceUsersResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	page, err := s.Database.ListServiceUserTokens(ctx, nil, request.OrgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list service user tokens")
	}

	out := make([]ServiceUserSummary, 0, len(page))
	for _, item := range page {
		var roles []ServiceUserRole
		for _, r := range item.ServiceUserRoles {
			roles = append(roles, ServiceUserRole{
				Id:    r.RoleId,
				Scope: ref.Ref(r.Scope),
			})
		}
		out = append(out, ServiceUserSummary{
			Id:                    item.Id,
			DisplayName:           item.DisplayName,
			GeneratedAt:           item.GeneratedAt,
			GeneratedBy:           item.GeneratedBy,
			CurrentTokenExpiresAt: item.CurrentTokenExpiresAt,
			Roles:                 roles,
		})
	}

	return ListServiceUsers200JSONResponse{Items: out}, nil
}

func (s *Server) CreateServiceUser(ctx context.Context, request CreateServiceUserRequestObject) (CreateServiceUserResponseObject, error) {
	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	} else if userid.IsServiceUser(uid) {
		// For now, prevent service users from extending their time by creating new service users. In the future, allow
		// service users to do this as long as the next service user is lesser-scoped (eg: org SU can create app SU).
		return CreateServiceUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response("service users may not create service users")}, nil
	}
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	newToken := &model.ServiceUserToken{
		Id:          userid.NewServiceUserTokenId(),
		DisplayName: request.Body.DisplayName,
		GeneratedBy: uid,
	}
	raw := RegenerateServiceUserToken(newToken, request.Body.ExpiryInDays)

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	if newToken, err = s.Database.CreateServiceUserToken(ctx, tx, request.OrgId, newToken); err != nil {
		return nil, errors.Wrap(err, "failed to create service user token")
	}

	creationTime := time.Now().UTC()

	var serviceUserRoles []model.ServiceUserRole
	if request.Body.Roles == nil {
		var roles []model.Role
		if roles, err = s.listOrSeedRoles(ctx, logger, tx, request.OrgId); err != nil {
			return nil, err
		}
		if adminRole := getRoleByDisplayName(roles, RoleAdmin); adminRole == nil {
			// we should never end up here
			return nil, errors.New("failed to find admin role")
		} else {
			serviceUserRoles = append(serviceUserRoles, model.ServiceUserRole{
				ServiceUserId: newToken.Id,
				OrgId:         request.OrgId,
				RoleId:        adminRole.Id,
				CreatedAt:     creationTime,
			})
		}
	} else {
		for _, r := range *request.Body.Roles {
			if isValid, err := isScopeValidForRole(ctx, r.Scope, request.OrgId, s.CpClient); !isValid {
				var userErr *usererrors.UserError
				if errors.As(err, &userErr) {
					return CreateServiceUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response(userErr.Error())}, nil
				} else if err != nil {
					return nil, errors.Wrap(err, "failed to validate scope for role membership")
				} else {
					scopeValue := ""
					if r.Scope != nil {
						scopeValue = *r.Scope
					}
					return CreateServiceUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response(fmt.Sprintf("invalid scope for service user role: %s", scopeValue))}, nil
				}
			}

			serviceUserRoles = append(serviceUserRoles, model.ServiceUserRole{
				ServiceUserId: newToken.Id,
				OrgId:         request.OrgId,
				RoleId:        r.Id,
				CreatedAt:     creationTime,
				Scope:         ref.DerefOr(r.Scope, ""),
			})
		}
	}

	if err := s.Database.CreateServiceUserRoles(ctx, tx, serviceUserRoles); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return CreateServiceUser409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, nil
		}
		if errConflict, ok := model.IsErrConflict(err); ok {
			return CreateServiceUser409JSONResponse{N409ConflictJSONResponse: Generate409Response(errConflict.Message)}, nil
		}
		return nil, errors.Wrap(err, "failed to create service user roles")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	apiRoles := make([]ServiceUserRole, 0, len(serviceUserRoles))
	for _, r := range serviceUserRoles {
		apiRoles = append(apiRoles, ServiceUserRole{
			Id:    r.RoleId,
			Scope: ref.Ref(r.Scope),
		})
	}

	logger.Info("created service user", zap.String("service_user_id", newToken.Id.String()))
	return CreateServiceUser201JSONResponse(ServiceUserWithToken{
		Id:                    newToken.Id,
		DisplayName:           newToken.DisplayName,
		GeneratedAt:           newToken.GeneratedAt,
		GeneratedBy:           newToken.GeneratedBy,
		CurrentTokenExpiresAt: newToken.CurrentTokenExpiresAt,
		Token:                 raw,
		Roles:                 apiRoles,
	}), nil
}

func (s *Server) RegenerateServiceUser(ctx context.Context, request RegenerateServiceUserRequestObject) (RegenerateServiceUserResponseObject, error) {
	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
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

	t, err := s.Database.GetServiceUserToken(ctx, tx, request.ServiceUserId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return RegenerateServiceUser404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get service user token")
	} else if t.OrgId != request.OrgId {
		return RegenerateServiceUser404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, nil
	}

	raw := RegenerateServiceUserToken(t, request.Body.ExpiryInDays)
	t.GeneratedBy = uid

	if t, err = s.Database.UpdateServiceUserToken(ctx, tx, t); err != nil {
		return nil, errors.Wrap(err, "failed to update service user token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	return RegenerateServiceUser200JSONResponse{
		CurrentTokenExpiresAt: t.CurrentTokenExpiresAt,
		DisplayName:           t.DisplayName,
		GeneratedAt:           t.GeneratedAt,
		GeneratedBy:           t.GeneratedBy,
		Id:                    t.Id,
		Token:                 raw,
	}, nil
}

func (s *Server) DeleteServiceUser(ctx context.Context, request DeleteServiceUserRequestObject) (DeleteServiceUserResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
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

	if err := s.Database.DeleteServiceUserToken(ctx, tx, request.OrgId, request.ServiceUserId); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return DeleteServiceUser404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to delete service user token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	logger.Info("deleted service user", zap.String("service_user_id", request.ServiceUserId.String()))
	return DeleteServiceUser204Response{}, nil
}

// Replace all roles for a service user in an organization
// (PUT /orgs/{orgId}/service-users/{serviceUserId})
func (s *Server) ReplaceServiceUserRoles(ctx context.Context, request ReplaceServiceUserRolesRequestObject) (ReplaceServiceUserRolesResponseObject, error) {
	// Authentication and authorization
	currentUserId, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if err := s.checkOrgAdminAuthorization(ctx, currentUserId, request.OrgId); err != nil {
		return nil, err
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zap.String("service_user_id", request.ServiceUserId.String())).WithLazy(ids.AsLogField())

	// Begin transaction
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	// Check if the service user exists
	serviceUser, err := s.Database.GetServiceUserToken(ctx, tx, request.ServiceUserId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return ReplaceServiceUserRoles404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get service user")
	}

	// Verify the service user belongs to the correct organization
	if serviceUser.OrgId != request.OrgId {
		return ReplaceServiceUserRoles404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, nil
	}

	// Delete all existing service user roles for this service user in this organization
	deletedCount, err := s.Database.BulkDeleteServiceUserRoles(ctx, tx, model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(request.ServiceUserId),
		OrgId:         opt.Of(request.OrgId),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to delete existing service user roles")
	}

	// Create new service user roles from request
	creationTime := time.Now().UTC()
	var newServiceUserRoles []model.ServiceUserRole
	for _, roleRequest := range request.Body.Roles {
		if isValid, err := isScopeValidForRole(ctx, roleRequest.Scope, request.OrgId, s.CpClient); !isValid {
			var userErr *usererrors.UserError
			if errors.As(err, &userErr) {
				return ReplaceServiceUserRoles400JSONResponse{N400BadRequestJSONResponse: Generate400Response(userErr.Error())}, nil
			} else if err != nil {
				return nil, errors.Wrap(err, "failed to validate scope for service user role")
			} else {
				return ReplaceServiceUserRoles400JSONResponse{N400BadRequestJSONResponse: Generate400Response(fmt.Sprintf("invalid scope for service user role: %s", ref.DerefOr(roleRequest.Scope, "")))}, nil
			}
		}

		newServiceUserRoles = append(newServiceUserRoles, model.ServiceUserRole{
			ServiceUserId: request.ServiceUserId,
			OrgId:         request.OrgId,
			RoleId:        roleRequest.Id,
			CreatedAt:     creationTime,
			Scope:         ref.DerefOr(roleRequest.Scope, ""),
		})
	}

	// Insert the new service user roles
	if err := s.Database.CreateServiceUserRoles(ctx, tx, newServiceUserRoles); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return ReplaceServiceUserRoles409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, nil
		}
		if errConflict, ok := model.IsErrConflict(err); ok {
			return ReplaceServiceUserRoles409JSONResponse{N409ConflictJSONResponse: Generate409Response(errConflict.Message)}, nil
		}
		return nil, errors.Wrap(err, "failed to create service user roles")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	// Convert to response format
	apiRoles := make([]ServiceUserRole, 0, len(newServiceUserRoles))
	for _, role := range newServiceUserRoles {
		apiRoles = append(apiRoles, ServiceUserRole{
			Id:    role.RoleId,
			Scope: ref.Ref(role.Scope),
		})
	}
	slices.SortFunc(apiRoles, func(roleA, roleB ServiceUserRole) int {
		if strings.Compare(ref.DerefOr(roleA.Scope, ""), ref.DerefOr(roleB.Scope, "")) != 0 {
			return strings.Compare(ref.DerefOr(roleA.Scope, ""), ref.DerefOr(roleB.Scope, ""))
		}
		return strings.Compare(roleA.Id.String(), roleB.Id.String())
	})

	logger.Info("replaced service user roles",
		zap.Int64("deleted_count", deletedCount),
		zap.Int("created_count", len(newServiceUserRoles)))

	return ReplaceServiceUserRoles200JSONResponse{
		Id:                    serviceUser.Id,
		DisplayName:           serviceUser.DisplayName,
		GeneratedAt:           serviceUser.GeneratedAt,
		GeneratedBy:           serviceUser.GeneratedBy,
		CurrentTokenExpiresAt: serviceUser.CurrentTokenExpiresAt,
		Roles:                 apiRoles,
	}, nil
}
