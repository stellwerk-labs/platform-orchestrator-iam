package api

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
)

func (s *Server) CheckPermissions(ctx context.Context, request CheckPermissionsRequestObject) (CheckPermissionsResponseObject, error) {
	subjId, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else {
		middleware.SetAuthAsserterChecked(ctx)
	}
	if request.Body == nil || len(*request.Body) == 0 {
		return CheckPermissions400JSONResponse{
			N400BadRequestJSONResponse: N400BadRequestJSONResponse{
				Message: "At least one permission check is required",
			},
		}, nil
	}

	checks := make([]authorization.Check, 0, len(*request.Body))
	for _, permCheck := range *request.Body {
		if _, _, err := authorization.ParseResource(permCheck.Resource); err != nil {
			return CheckPermissions400JSONResponse{
				N400BadRequestJSONResponse: N400BadRequestJSONResponse{
					Message: "Invalid resource format in one of the permission checks: " + permCheck.Resource,
				},
			}, nil
		}
		checks = append(checks, authorization.Check{Resource: permCheck.Resource, Permission: permCheck.Permission})
	}

	decisionResults, err := s.Authorizer.Authorize(ctx, subjId, checks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check permissions")
	}
	results := make([]ResourcePermissionCheckResultItem, len(decisionResults))
	for index, result := range decisionResults {
		if result.Invalid {
			return CheckPermissions400JSONResponse{
				N400BadRequestJSONResponse: N400BadRequestJSONResponse{
					Error:   badRequestErrorCode,
					Message: fmt.Sprintf("permission request not valid: %s on %s", result.Check.Permission, result.Check.Resource),
				},
			}, nil
		}
		results[index] = ResourcePermissionCheckResultItem{
			PermissionCheck: (*request.Body)[index],
			Allowed:         result.Allowed,
		}
	}
	return CheckPermissions200JSONResponse{Items: results}, nil
}
