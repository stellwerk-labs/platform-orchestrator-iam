package plugincapabilities

import (
	"strings"
	"testing"

	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stretchr/testify/require"
)

func TestValidateBuildsNamespacedHumanCapabilities(t *testing.T) {
	pluginID := "dev.stellwerk.progressive-rollouts"
	definitions := []Definition{{
		Name:        "approve-environment-with-an-intentionally-long-specific-action",
		DisplayName: "Approve rollout environment", Description: "Approve one frozen rollout target.",
		Category: "Progressive rollouts", Level: sharedauthz.PermissionLevelWrite,
		Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization, sharedauthz.PermissionScopeEnvironment},
	}}
	capabilities, err := validate("org", pluginID, definitions)
	require.NoError(t, err)
	require.Len(t, capabilities, 1)
	require.Equal(t, "plugin."+pluginID+"."+definitions[0].Name, capabilities[0].ID)
	require.Greater(t, len(capabilities[0].ID), 64)
}

func TestValidateRejectsNamespaceAndDefinitionAmbiguity(t *testing.T) {
	valid := Definition{
		Name: "rollout-read", DisplayName: "View rollouts", Description: "View rollout state.",
		Category: "Progressive rollouts", Level: sharedauthz.PermissionLevelRead,
		Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization},
	}
	for name, testCase := range map[string]struct {
		pluginID    string
		definitions []Definition
	}{
		"invalid plugin":  {pluginID: "Dev/Stellwerk", definitions: []Definition{valid}},
		"path-like name":  {pluginID: "dev.stellwerk.rollouts", definitions: []Definition{{Name: "rollout/read", DisplayName: valid.DisplayName, Description: valid.Description, Category: valid.Category, Level: valid.Level, Scopes: valid.Scopes}}},
		"dotted name":     {pluginID: "dev.stellwerk.rollouts", definitions: []Definition{{Name: "rollout.read", DisplayName: valid.DisplayName, Description: valid.Description, Category: valid.Category, Level: valid.Level, Scopes: valid.Scopes}}},
		"duplicate":       {pluginID: "dev.stellwerk.rollouts", definitions: []Definition{valid, valid}},
		"oversized":       {pluginID: "dev.stellwerk.rollouts", definitions: []Definition{{Name: "a" + strings.Repeat("b", 255), DisplayName: valid.DisplayName, Description: valid.Description, Category: valid.Category, Level: valid.Level, Scopes: valid.Scopes}}},
		"core permission": {pluginID: "dev.stellwerk.rollouts", definitions: []Definition{{Name: sharedauthz.PermissionPluginRegistrationWrite, DisplayName: valid.DisplayName, Description: valid.Description, Category: valid.Category, Level: valid.Level, Scopes: valid.Scopes}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validate("org", testCase.pluginID, testCase.definitions)
			require.Error(t, err)
		})
	}
}

func TestValidateCannotEscapeInstalledPluginNamespace(t *testing.T) {
	definition := Definition{
		Name: "plugin-someone-else-manage", DisplayName: "Manage someone else", Description: "Still local.",
		Category: "Plugin", Level: sharedauthz.PermissionLevelManage,
		Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization},
	}
	capabilities, err := validate("org", "dev.stellwerk.rollouts", []Definition{definition})
	require.NoError(t, err)
	require.Equal(t, "plugin.dev.stellwerk.rollouts.plugin-someone-else-manage", capabilities[0].ID)
	require.NotEqual(t, "plugin.someone-else.manage", capabilities[0].ID)
}

func TestValidateCapabilityNamespaceIsUnambiguous(t *testing.T) {
	definition := Definition{
		Name: "reader.read", DisplayName: "Read", Description: "Read plugin state.",
		Category: "Plugin", Level: sharedauthz.PermissionLevelRead,
		Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization},
	}
	_, err := validate("org", "dev.example", []Definition{definition})
	require.ErrorIs(t, err, ErrInvalidDefinition)

	definition.Name = "read"
	capabilities, err := validate("org", "dev.example.reader", []Definition{definition})
	require.NoError(t, err)
	require.Equal(t, "plugin.dev.example.reader.read", capabilities[0].ID)
}

func TestValidateAcceptsSingleCharacterCapabilitySlug(t *testing.T) {
	definition := Definition{
		Name: "r", DisplayName: "Read", Description: "Read plugin state.",
		Category: "Plugin", Level: sharedauthz.PermissionLevelRead,
		Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization},
	}
	capabilities, err := validate("org", "dev.example", []Definition{definition})
	require.NoError(t, err)
	require.Equal(t, "plugin.dev.example.r", capabilities[0].ID)
}
