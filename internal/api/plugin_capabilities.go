package api

import (
	"context"
	"errors"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/plugincapabilities"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
)

func (s *Server) ReplacePluginCapabilities(ctx context.Context, request ReplacePluginCapabilitiesRequestObject) (ReplacePluginCapabilitiesResponseObject, error) {
	userID, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if err := s.checkOrgAuthorization(ctx, userID, request.OrgId, sharedauthz.PermissionPluginRegistrationWrite); err != nil {
		return nil, err
	}
	// Operators keep their authority over every plugin. A plugin workload may
	// only register capabilities in the namespace of its own binding.
	if binding, err := s.pluginWorkloadBinding(ctx, nil, userID); err != nil {
		return nil, err
	} else if binding != nil && binding.PluginID != request.PluginId {
		return ReplacePluginCapabilities403JSONResponse{Generate403Response("a plugin workload can only register capabilities for its own plugin")}, nil
	}
	if request.Body == nil {
		return ReplacePluginCapabilities400JSONResponse{Generate400Response("request body is required")}, nil
	}
	if s.PluginCapabilities == nil {
		return nil, errors.New("plugin capability registration is not configured")
	}

	definitions := make([]plugincapabilities.Definition, len(request.Body.Capabilities))
	for index, capability := range request.Body.Capabilities {
		scopes := make([]sharedauthz.PermissionScope, len(capability.Scopes))
		for scopeIndex, scope := range capability.Scopes {
			scopes[scopeIndex] = sharedauthz.PermissionScope(scope)
		}
		definitions[index] = plugincapabilities.Definition{
			Name: capability.Name, DisplayName: capability.DisplayName,
			Description: capability.Description, Category: capability.Category,
			Level: sharedauthz.PermissionLevel(capability.Level), Scopes: scopes,
		}
	}
	if err := s.PluginCapabilities.Replace(ctx, request.OrgId, request.PluginId, definitions); err != nil {
		if errors.Is(err, plugincapabilities.ErrInvalidDefinition) {
			return ReplacePluginCapabilities400JSONResponse{Generate400Response(err.Error())}, nil
		}
		return nil, err
	}
	return ReplacePluginCapabilities204Response{}, nil
}
