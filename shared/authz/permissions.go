package authz

import "slices"

type PermissionLevel string

const (
	PermissionLevelRead   PermissionLevel = "read"
	PermissionLevelWrite  PermissionLevel = "write"
	PermissionLevelManage PermissionLevel = "manage"
)

type PermissionScope string

const (
	PermissionScopeOrganization PermissionScope = "organization"
	PermissionScopeProject      PermissionScope = "project"
	PermissionScopeEnvironment  PermissionScope = "environment"
)

const (
	PermissionOrganizationRead     = "organization_read"
	PermissionInvitationRead       = "invitation_read"
	PermissionInvitationWrite      = "invitation_write"
	PermissionMembershipRead       = "membership_read"
	PermissionMembershipWrite      = "membership_write"
	PermissionRoleRead             = "role_read"
	PermissionRoleWrite            = "role_write"
	PermissionServiceUserRead      = "service_user_read"
	PermissionServiceUserWrite     = "service_user_write"
	PermissionProjectRead          = "project_read"
	PermissionProjectWrite         = "project_write"
	PermissionEnvironmentRead      = "environment_read"
	PermissionEnvironmentWrite     = "environment_write"
	PermissionEnvironmentTypeRead  = "environment_type_read"
	PermissionEnvironmentTypeWrite = "environment_type_write"
	PermissionModuleRead           = "module_read"
	PermissionModuleWrite          = "module_write"
	PermissionModuleProviderRead   = "module_provider_read"
	PermissionModuleProviderWrite  = "module_provider_write"
	PermissionModuleRuleRead       = "module_rule_read"
	PermissionModuleRuleWrite      = "module_rule_write"
	PermissionResourceTypeRead     = "resource_type_read"
	PermissionResourceTypeWrite    = "resource_type_write"
	PermissionRunnerRead           = "runner_read"
	PermissionRunnerWrite          = "runner_write"
	PermissionRunnerRuleRead       = "runner_rule_read"
	PermissionRunnerRuleWrite      = "runner_rule_write"
	PermissionActiveResourceRead   = "active_resource_read"
	PermissionDeploymentRead       = "deployment_read"
	PermissionDeploymentWrite      = "deployment_write"
	PermissionDeploymentDebugRead  = "deployment_debug_read"
	PermissionMetadataKeyRead      = "metadata_key_read"
	PermissionMetadataKeyWrite     = "metadata_key_write"
	PermissionResourceGraphRead    = "resource_graph_read"
)

type PermissionDefinition struct {
	ID          string
	DisplayName string
	Description string
	Category    string
	Level       PermissionLevel
	Scopes      []PermissionScope
}

var organizationScope = []PermissionScope{PermissionScopeOrganization}
var allScopes = []PermissionScope{PermissionScopeOrganization, PermissionScopeProject, PermissionScopeEnvironment}

var permissionCatalog = []PermissionDefinition{
	{ID: PermissionOrganizationRead, DisplayName: "View organization", Description: "View organization details.", Category: "Organization", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionInvitationRead, DisplayName: "View invitations", Description: "List pending organization invitations.", Category: "Access", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionInvitationWrite, DisplayName: "Manage invitations", Description: "Create, inspect, and revoke organization invitations.", Category: "Access", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionMembershipRead, DisplayName: "View memberships", Description: "View members and effective access assignments.", Category: "Access", Level: PermissionLevelRead, Scopes: allScopes},
	{ID: PermissionMembershipWrite, DisplayName: "Manage memberships", Description: "Assign, replace, and remove member roles.", Category: "Access", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionRoleRead, DisplayName: "View roles", Description: "View built-in and configurable roles.", Category: "Access", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionRoleWrite, DisplayName: "Manage roles", Description: "Create, update, and delete configurable roles.", Category: "Access", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionServiceUserRead, DisplayName: "View service users", Description: "View service users and their role assignments.", Category: "Access", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionServiceUserWrite, DisplayName: "Manage service users", Description: "Create, update, delete, and rotate credentials for service users.", Category: "Access", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionProjectRead, DisplayName: "View projects", Description: "View projects and their configuration.", Category: "Projects and environments", Level: PermissionLevelRead, Scopes: allScopes[:2]},
	{ID: PermissionProjectWrite, DisplayName: "Manage projects", Description: "Create, update, and delete projects.", Category: "Projects and environments", Level: PermissionLevelManage, Scopes: allScopes[:2]},
	{ID: PermissionEnvironmentRead, DisplayName: "View environments", Description: "View environments and their configuration.", Category: "Projects and environments", Level: PermissionLevelRead, Scopes: allScopes},
	{ID: PermissionEnvironmentWrite, DisplayName: "Manage environments", Description: "Create, update, and delete environments.", Category: "Projects and environments", Level: PermissionLevelManage, Scopes: allScopes},
	{ID: PermissionEnvironmentTypeRead, DisplayName: "View environment types", Description: "View organization environment types.", Category: "Projects and environments", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionEnvironmentTypeWrite, DisplayName: "Manage environment types", Description: "Create, update, and delete organization environment types.", Category: "Projects and environments", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionModuleRead, DisplayName: "View modules", Description: "View modules and module versions.", Category: "Modules", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionModuleWrite, DisplayName: "Manage modules", Description: "Create, update, and delete modules.", Category: "Modules", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionModuleProviderRead, DisplayName: "View module providers", Description: "View module providers.", Category: "Modules", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionModuleProviderWrite, DisplayName: "Manage module providers", Description: "Create, update, and delete module providers.", Category: "Modules", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionModuleRuleRead, DisplayName: "View module rules", Description: "View module selection rules.", Category: "Modules", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionModuleRuleWrite, DisplayName: "Manage module rules", Description: "Create and delete module selection rules.", Category: "Modules", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionResourceTypeRead, DisplayName: "View resource types", Description: "View available and configured resource types.", Category: "Resources", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionResourceTypeWrite, DisplayName: "Manage resource types", Description: "Create, update, and delete resource types.", Category: "Resources", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionRunnerRead, DisplayName: "View runners", Description: "View runners and their configuration.", Category: "Runners", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionRunnerWrite, DisplayName: "Manage runners", Description: "Create, update, delete, and assign runners.", Category: "Runners", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionRunnerRuleRead, DisplayName: "View runner rules", Description: "View runner selection rules.", Category: "Runners", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionRunnerRuleWrite, DisplayName: "Manage runner rules", Description: "Create and delete runner selection rules.", Category: "Runners", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionActiveResourceRead, DisplayName: "View active resources", Description: "View active resources in the organization.", Category: "Deployments", Level: PermissionLevelRead, Scopes: allScopes},
	{ID: PermissionDeploymentRead, DisplayName: "View deployments", Description: "View deployments, logs, outputs, and calculated differences.", Category: "Deployments", Level: PermissionLevelRead, Scopes: allScopes},
	{ID: PermissionDeploymentWrite, DisplayName: "Create deployments", Description: "Create deployments and wait for their completion.", Category: "Deployments", Level: PermissionLevelWrite, Scopes: allScopes},
	{ID: PermissionDeploymentDebugRead, DisplayName: "View deployment debug data", Description: "View generated deployment infrastructure code.", Category: "Deployments", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionMetadataKeyRead, DisplayName: "View metadata keys", Description: "View deployment metadata key definitions.", Category: "Deployments", Level: PermissionLevelRead, Scopes: organizationScope},
	{ID: PermissionMetadataKeyWrite, DisplayName: "Manage metadata keys", Description: "Create, update, and delete deployment metadata key definitions.", Category: "Deployments", Level: PermissionLevelManage, Scopes: organizationScope},
	{ID: PermissionResourceGraphRead, DisplayName: "View resource graphs", Description: "View resources produced by deployments.", Category: "Deployments", Level: PermissionLevelRead, Scopes: allScopes},
}

func PermissionCatalog() []PermissionDefinition {
	catalog := make([]PermissionDefinition, len(permissionCatalog))
	for index, definition := range permissionCatalog {
		catalog[index] = definition
		catalog[index].Scopes = slices.Clone(definition.Scopes)
	}
	return catalog
}

func FindPermission(permission string) (PermissionDefinition, bool) {
	for _, definition := range permissionCatalog {
		if definition.ID == permission {
			definition.Scopes = slices.Clone(definition.Scopes)
			return definition, true
		}
	}
	return PermissionDefinition{}, false
}
