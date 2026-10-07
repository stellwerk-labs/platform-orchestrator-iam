package api

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
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

	results := make([]ResourcePermissionCheckResultItem, len(*request.Body))
	checks := make([]authorization.Check, 0, len(*request.Body))
	checkIndexes := make([]int, 0, len(*request.Body))
	for index, permCheck := range *request.Body {
		results[index].PermissionCheck = permCheck
		if permCheck.Resource == sharedauthz.PlatformResource {
			held, err := s.holdsPlatformPermission(ctx, subjId, permCheck.Permission)
			if err != nil {
				return nil, errors.Wrap(err, "failed to check permissions")
			}
			results[index].Allowed = held
			continue
		}
		if _, _, err := authorization.ParseResource(permCheck.Resource); err != nil {
			return CheckPermissions400JSONResponse{
				N400BadRequestJSONResponse: N400BadRequestJSONResponse{
					Message: "Invalid resource format in one of the permission checks: " + permCheck.Resource,
				},
			}, nil
		}
		checks = append(checks, authorization.Check{Resource: permCheck.Resource, Permission: permCheck.Permission})
		checkIndexes = append(checkIndexes, index)
	}

	decisionResults, err := s.Authorizer.Authorize(ctx, subjId, checks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check permissions")
	}
	for position, result := range decisionResults {
		if result.Invalid {
			return CheckPermissions400JSONResponse{
				N400BadRequestJSONResponse: N400BadRequestJSONResponse{
					Error:   badRequestErrorCode,
					Message: fmt.Sprintf("permission request not valid: %s on %s", result.Check.Permission, result.Check.Resource),
				},
			}, nil
		}
		results[checkIndexes[position]].Allowed = result.Allowed
	}
	return CheckPermissions200JSONResponse{Items: results}, nil
}
