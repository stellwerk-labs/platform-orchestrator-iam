package authz

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionCatalog(t *testing.T) {
	permissionPattern := regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}[a-z0-9]$`)
	known := make(map[string]struct{})

	for _, permission := range PermissionCatalog() {
		assert.Regexp(t, permissionPattern, permission.ID)
		assert.NotEmpty(t, permission.DisplayName)
		assert.NotEmpty(t, permission.Description)
		assert.NotEmpty(t, permission.Category)
		assert.Contains(t, []PermissionLevel{PermissionLevelRead, PermissionLevelWrite, PermissionLevelManage}, permission.Level)
		assert.NotEmpty(t, permission.Scopes)
		_, duplicate := known[permission.ID]
		assert.False(t, duplicate, "permission %s is duplicated", permission.ID)
		known[permission.ID] = struct{}{}

		found, ok := FindPermission(permission.ID)
		require.True(t, ok)
		assert.Equal(t, permission, found)
	}

	_, ok := FindPermission("not_a_platform_permission")
	assert.False(t, ok)
}

func TestPermissionCatalogReturnsCopies(t *testing.T) {
	first := PermissionCatalog()
	require.NotEmpty(t, first)
	require.NotEmpty(t, first[0].Scopes)
	first[0].Scopes[0] = PermissionScopeEnvironment

	second := PermissionCatalog()
	assert.Equal(t, PermissionScopeOrganization, second[0].Scopes[0])
}
