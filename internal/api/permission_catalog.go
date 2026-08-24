package api

import (
	"context"

	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
)

func (s *Server) ListPermissions(ctx context.Context, request ListPermissionsRequestObject) (ListPermissionsResponseObject, error) {
	userID, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if err := s.checkOrgAuthorization(ctx, userID, request.OrgId, sharedauthz.PermissionRoleRead); err != nil {
		return nil, err
	}

	catalog := sharedauthz.PermissionCatalog()
	items := make([]PermissionDefinition, 0, len(catalog))
	for _, permission := range catalog {
		scopes := make([]PermissionDefinitionScopes, len(permission.Scopes))
		for index, scope := range permission.Scopes {
			scopes[index] = PermissionDefinitionScopes(scope)
		}
		items = append(items, PermissionDefinition{
			Id:          permission.ID,
			DisplayName: permission.DisplayName,
			Description: permission.Description,
			Category:    permission.Category,
			Level:       PermissionDefinitionLevel(permission.Level),
			Scopes:      scopes,
		})
	}

	return ListPermissions200JSONResponse{Items: items}, nil
}
