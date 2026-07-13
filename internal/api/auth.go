package api

import (
	"context"
	"fmt"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
)

const orgObjectType = "org"

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

	// Build the checks for the spicedb request
	var checks []*v1.CheckBulkPermissionsRequestItem
	for _, permCheck := range *request.Body {
		if objectType, objectID, err := spicedb.ParseResource(permCheck.Resource); err != nil {
			return CheckPermissions400JSONResponse{
				N400BadRequestJSONResponse: N400BadRequestJSONResponse{
					Message: "Invalid resource format in one of the permission checks: " + permCheck.Resource,
				},
			}, nil
		} else {
			checks = append(checks, &v1.CheckBulkPermissionsRequestItem{
				Resource: &v1.ObjectReference{
					ObjectType: objectType.String(),
					ObjectId:   objectID,
				},
				Permission: permCheck.Permission,
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: spicedb.SubjectTypeUser.String(),
						ObjectId:   subjId.String(),
					},
				},
			})
		}
	}

	if resp, err := s.SpiceDB.CheckBulkPermissions(ctx, checks); err != nil {
		return nil, errors.Wrap(err, "failed to check bulk permissions")
	} else {
		var results []ResourcePermissionCheckResultItem
		for _, pair := range resp {
			pairRequest := pair.GetRequest()
			requestResource := pairRequest.Resource
			if requestResource.ObjectType == orgObjectType {
				requestResource.ObjectType = "organization"
			}
			if spicedbPermErr := pair.GetError(); spicedbPermErr != nil {
				return CheckPermissions400JSONResponse{
					N400BadRequestJSONResponse: N400BadRequestJSONResponse{
						Error:   badRequestErrorCode,
						Message: fmt.Sprintf("permission request not valid: %s on %s:%s", pairRequest.GetPermission(), requestResource.ObjectType, requestResource.ObjectId),
					},
				}, nil
			}

			results = append(results, ResourcePermissionCheckResultItem{
				PermissionCheck: ResourcePermissionCheck{
					Permission: pairRequest.GetPermission(),
					Resource:   requestResource.ObjectType + ":" + requestResource.ObjectId,
				},
				Allowed: pair.GetItem().Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
			})
		}
		return CheckPermissions200JSONResponse{Items: results}, nil
	}
}
