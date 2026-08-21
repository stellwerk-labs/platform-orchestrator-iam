package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	readPermission              = "read"
	authorizationFailureMessage = "one or more authorization checks failed"
	failedChecksField           = "failed_checks"
)

// InternalAuthorizeInner is the internal implementation of authorization
func (s *Server) InternalAuthorizeInner(ctx context.Context, body InternalAuthorizeBody) (bool, []ResourcePermissionCheck, error) {
	failedChecks := make([]ResourcePermissionCheck, 0, len(body.Checks))
	validChecks := make([]authorization.Check, 0, len(body.Checks))
	validOriginalChecks := make([]ResourcePermissionCheck, 0, len(body.Checks))
	for _, check := range body.Checks {
		if _, _, err := authorization.ParseResource(check.Resource); err != nil {
			failedChecks = append(failedChecks, check)
			continue
		}
		normalizedPermission := check.Permission
		if normalizedPermission == "member" {
			normalizedPermission = readPermission
		}
		validChecks = append(validChecks, authorization.Check{Resource: check.Resource, Permission: normalizedPermission})
		validOriginalChecks = append(validOriginalChecks, check)
	}

	results, err := s.Authorizer.Authorize(ctx, body.UserId, validChecks)
	if err != nil {
		return false, nil, err
	}
	for index, result := range results {
		if !result.Allowed {
			failedChecks = append(failedChecks, validOriginalChecks[index])
		}
	}

	return len(failedChecks) == 0, failedChecks, nil
}

func (s *Server) InternalAuthorize(ctx context.Context, request InternalAuthorizeRequestObject) (InternalAuthorizeResponseObject, error) {
	_, failedChecks, err := s.InternalAuthorizeInner(ctx, *request.Body)
	if err != nil {
		return nil, err
	} else if len(failedChecks) > 0 {
		return InternalAuthorize403JSONResponse{N403ForbiddenJSONResponse: N403ForbiddenJSONResponse{
			Error:   forbiddenErrorCode,
			Message: authorizationFailureMessage,
			Details: &map[string]interface{}{
				failedChecksField: failedChecks,
			},
		}}, nil
	}
	return InternalAuthorize204Response{}, nil
}

// TODO: rename 1: use permission instead of role in the function name
// TODO: rename 2: indicate it is not just role verification, but context is being mutated
func (s *Server) checkOrgMemberAuthorization(ctx context.Context, userId uuid.UUID, orgId string) error {
	return innerCheck(s, ctx, userId, orgId, ResourcePermissionCheck{
		Permission: readPermission,
		Resource:   "organization:" + orgId,
	})
}

func (s *Server) checkOrgAdminAuthorization(ctx context.Context, userId uuid.UUID, orgId string) error {
	return innerCheck(s, ctx, userId, orgId, ResourcePermissionCheck{
		Permission: "manage",
		Resource:   "organization:" + orgId,
	})
}

func innerCheck(s *Server, ctx context.Context, userId uuid.UUID, orgId string, check ResourcePermissionCheck) error {
	if userId == userid.InternalSystemUuid {
		// system user id can do these things for now
	} else if ok, failedChecks, err := s.InternalAuthorizeInner(ctx, InternalAuthorizeBody{
		UserId: userId,
		Checks: []ResourcePermissionCheck{check},
	}); err != nil {
		return err
	} else if !ok {
		return &herrors.PlatformOrchestratorError{
			StatusCode: http.StatusForbidden,
			Details: map[string]interface{}{
				failedChecksField: failedChecks,
			},
		}
	}

	if ids, ok := hlogger.GetPlatformOrchestratorIdsFromCtx(ctx); ok {
		ids.OrgId = orgId
		ids.UserId = userId.String()
	}
	middleware.SetAuthAsserterChecked(ctx)
	return nil
}

func (s *Server) checkUserIdSelfAuthorization(ctx context.Context, userId, requestUserId uuid.UUID) error {
	if userId == userid.InternalSystemUuid {
		// system user id can do these things for now
	} else if !userid.IsHumanUser(userId) {
		// service users are not users
		return herrors.NewWithStatus(http.StatusForbidden, "service user token cannot access this endpoint", nil)
	} else if userId != requestUserId {
		return &herrors.PlatformOrchestratorError{
			StatusCode: http.StatusForbidden,
			Details: map[string]interface{}{
				failedChecksField: []ResourcePermissionCheck{
					{
						Resource:   fmt.Sprintf("user:%s", requestUserId),
						Permission: "self",
					},
				},
			},
		}
	}
	if ids, ok := hlogger.GetPlatformOrchestratorIdsFromCtx(ctx); ok {
		ids.UserId = userId.String()
	}
	middleware.SetAuthAsserterChecked(ctx)
	return nil
}
