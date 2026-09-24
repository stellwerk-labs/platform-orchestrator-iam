package authorization

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyModuleGrantsPreserveOnlyEquivalentOperations(t *testing.T) {
	allowed := map[string]map[string]bool{
		sharedauthz.PermissionModuleRead: {
			sharedauthz.PermissionModuleRead:        true,
			sharedauthz.PermissionModuleCoreRead:    true,
			sharedauthz.PermissionModuleVersionRead: true,
		},
		sharedauthz.PermissionModuleWrite: {
			sharedauthz.PermissionModuleWrite:          true,
			sharedauthz.PermissionModuleVersionPublish: true,
			sharedauthz.PermissionModuleVersionPromote: true,
			sharedauthz.PermissionModuleArchive:        true,
		},
	}
	for grant, equivalents := range allowed {
		for _, requested := range sharedauthz.PermissionCatalog() {
			t.Run(grant+"/"+requested.ID, func(t *testing.T) {
				actual, err := permissionMatch(requested.ID, grant)
				require.NoError(t, err)
				assert.Equal(t, equivalents[requested.ID], actual)
			})
		}
		actual, err := permissionMatch("example.plugin.control", grant)
		require.NoError(t, err)
		assert.Equal(t, false, actual)
	}
}

func TestLegacyModuleCompatibilityPreservesCustomRoleScope(t *testing.T) {
	actor := uuid.New()
	authorizer, err := New(t.Context(), &testStore{
		policies:  []model.AuthorizationPolicy{{SubjectId: actor, Resource: "organization:acme", Permission: sharedauthz.PermissionModuleWrite, RoleId: uuid.New()}},
		relations: []model.AuthorizationResourceRelation{{Resource: "env:development", ParentResource: "organization:acme"}},
	})
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	checks := []Check{
		{Resource: "organization:acme", Permission: sharedauthz.PermissionModuleVersionPublish},
		{Resource: "organization:acme", Permission: sharedauthz.PermissionModuleVersionPromote},
		{Resource: "organization:acme", Permission: sharedauthz.PermissionModuleArchive},
		{Resource: "organization:other", Permission: sharedauthz.PermissionModuleVersionPublish},
		{Resource: "organization:other", Permission: sharedauthz.PermissionModuleVersionPromote},
		{Resource: "organization:acme", Permission: sharedauthz.PermissionModuleVersionDefective},
		{Resource: "organization:acme", Permission: sharedauthz.PermissionModuleVersionRestore},
		{Resource: "env:development", Permission: sharedauthz.PermissionModuleVersionPin},
		{Resource: "env:development", Permission: sharedauthz.PermissionModuleVersionUnpin},
		{Resource: "env:development", Permission: sharedauthz.PermissionModuleVersionPinOverride},
		{Resource: "env:development", Permission: sharedauthz.PermissionModulePinDefective},
	}
	results, err := authorizer.Authorize(t.Context(), actor, checks)
	require.NoError(t, err)
	require.Len(t, results, len(checks))
	for index, result := range results {
		assert.Equal(t, index < 3, result.Allowed, "%+v", result.Check)
	}
	results, err = authorizer.Authorize(t.Context(), uuid.New(), checks)
	require.NoError(t, err)
	for _, result := range results {
		assert.False(t, result.Allowed)
	}
}
