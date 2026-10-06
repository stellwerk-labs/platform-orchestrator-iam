package api

import (
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
