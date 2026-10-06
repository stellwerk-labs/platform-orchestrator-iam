package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// Consumers of the published shared module use these generated names. A new
// enum with overlapping values makes oapi-codegen prefix every colliding
// constant unless that enum declares x-enum-varnames.
func TestGeneratedClientKeepsPublishedPermissionEnumNames(t *testing.T) {
	require.Equal(t,
		[]genclient.PermissionDefinitionLevel{"read", "write", "manage"},
		[]genclient.PermissionDefinitionLevel{genclient.Read, genclient.Write, genclient.Manage})
	require.Equal(t,
		[]genclient.PermissionDefinitionScopes{"organization", "project", "environment"},
		[]genclient.PermissionDefinitionScopes{genclient.Organization, genclient.Project, genclient.Environment})
}

// Use the generated server schema: changing only the source document does not
// fix request validation in a running IAM server.
func TestPermissionCheckContractAcceptsRegisteredPluginIdentityLengths(t *testing.T) {
	spec, err := GetSwagger()
	require.NoError(t, err)
	schema := spec.Components.Schemas["ResourcePermissionCheck"].Value
	for _, permission := range []string{
		"module.version.read",
		"plugin.dev.example.progressive-workflows.approve-environment-resources",
		"plugin.dev.example." + strings.Repeat("a", 255-len("plugin.dev.example.")),
	} {
		t.Run(permission, func(t *testing.T) {
			require.NoError(t, schema.VisitJSON(map[string]any{
				"resource": "env:01234567-89ab-cdef-0123-456789abcdef", "permission": permission,
			}))
		})
	}
	for _, permission := range []string{
		"", "ab", strings.Repeat("a", 256), "plugin.dev.example.*",
		"plugin.dev.example/reader", "plugin.dev.example.Reader", "permission\n",
	} {
		t.Run("invalid/"+permission, func(t *testing.T) {
			require.Error(t, schema.VisitJSON(map[string]any{
				"resource": "env:01234567-89ab-cdef-0123-456789abcdef", "permission": permission,
			}))
		})
	}
}
