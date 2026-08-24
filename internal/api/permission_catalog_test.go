package api

import (
	"context"
	"testing"

	"github.com/stellwerk-labs/golib/hecho"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
)

func TestListPermissions(t *testing.T) {
	_, server, finish := MockServer(t)
	defer finish()

	userID := userid.NewHumanUserId()
	MockAuthorizationSuccess(server, userID, orgId, sharedauthz.PermissionRoleRead)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userID.String())
	response, err := server.ListPermissions(ctx, ListPermissionsRequestObject{OrgId: orgId})
	require.NoError(t, err)

	result, ok := response.(ListPermissions200JSONResponse)
	require.True(t, ok)
	require.Len(t, result.Items, len(sharedauthz.PermissionCatalog()))

	byID := make(map[string]PermissionDefinition, len(result.Items))
	for _, permission := range result.Items {
		byID[permission.Id] = permission
	}
	for _, expected := range sharedauthz.PermissionCatalog() {
		actual, found := byID[expected.ID]
		require.True(t, found, expected.ID)
		require.Equal(t, expected.DisplayName, actual.DisplayName)
		require.Equal(t, expected.Description, actual.Description)
		require.Equal(t, expected.Category, actual.Category)
		require.Equal(t, string(expected.Level), string(actual.Level))
		require.Len(t, actual.Scopes, len(expected.Scopes))
		for index := range expected.Scopes {
			require.Equal(t, string(expected.Scopes[index]), string(actual.Scopes[index]))
		}
	}
}
