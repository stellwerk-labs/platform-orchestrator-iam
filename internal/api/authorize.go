package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	authorizedRequestsCacheTTL  = 10 * time.Second
	maxCacheSize                = 10000
	readPermission              = "read"
	authorizationFailureMessage = "one or more authorization checks failed"
	failedChecksField           = "failed_checks"
)

var authorizedRequestCache = ccache.New(ccache.Configure().MaxSize(maxCacheSize))

// InternalAuthorizeInner is the internal implementation of authorization
func (s *Server) InternalAuthorizeInner(ctx context.Context, body InternalAuthorizeBody) (bool, []ResourcePermissionCheck, error) {
	failedChecks := make([]ResourcePermissionCheck, 0, len(body.Checks))

	// check if the user has permissions specified in the checks
	for _, check := range body.Checks {
		if objectType, objectId, err := spicedb.ParseResource(check.Resource); err != nil {
			failedChecks = append(failedChecks, check)
		} else {
			// normalize member permission to read
			// this is temporary until we update all references to use readmake  consistently
			// in the future we should only use read
			if check.Permission == "member" {
				check.Permission = readPermission
			}

			// check cache first to see if the request was recently authorized
			cacheKey := fmt.Sprintf("%s|%s|%s|%s", body.UserId.String(), objectType, objectId, check.Permission)
			if authorizedRequest := authorizedRequestCache.Get(cacheKey); authorizedRequest == nil || authorizedRequest.Expired() {
				var zedToken *model.OrgZedTokens
				if objectType == spicedb.ObjectTypeOrg {
					zedToken, err = s.Database.GetOrgZedToken(ctx, nil, objectId)
					if err != nil {
						if _, ok := model.IsErrNotFound(err); ok {
							zedToken = &model.OrgZedTokens{OrgId: objectId, ZedToken: ""}
						} else {
							return false, nil, err
						}
					}
				} else {
					// For non-org resources, use empty zedToken
					zedToken = &model.OrgZedTokens{ZedToken: ""}
				}
				if allowed, err := s.SpiceDB.HasSubjectPermissionOnObj(ctx, spicedb.SubjectTypeUser, body.UserId.String(), check.Permission, objectType, objectId, zedToken.ZedToken); err != nil {
					if st, ok := status.FromError(err); ok && st.Code() == codes.InvalidArgument {
						// treat invalid argument errors as not allowed
						failedChecks = append(failedChecks, check)
					} else {
						return false, nil, err
					}
				} else if allowed {
					authorizedRequestCache.Set(cacheKey, true, authorizedRequestsCacheTTL)
				} else {
					failedChecks = append(failedChecks, check)
				}
			}
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
