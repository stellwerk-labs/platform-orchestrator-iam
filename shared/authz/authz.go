package authz

import (
	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

func OrgCheck(orgId, permission string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: permission,
		Resource:   "organization:" + orgId,
	}
}

func ProjectCheck(projectUuid uuid.UUID, permission string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: permission,
		Resource:   "project:" + projectUuid.String(),
	}
}

func EnvironmentCheck(envUuid uuid.UUID, permission string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: permission,
		Resource:   "env:" + envUuid.String(),
	}
}

// CanReadOrgCheck generates a temporary permission check to validate that a user id has at least read permissions on an org
func CanReadOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return OrgCheck(orgId, "read")
}

// CanManageOrgCheck generates a temporary permission check to validate that a user id has manage permissions on an org
func CanManageOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return OrgCheck(orgId, "manage")
}

// CanWriteOrgCheck generates a temporary permission check to validate that a user id has write permissions on an org
func CanWriteOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return OrgCheck(orgId, "write")
}

// CanManageProjectCheck generates a temporary permission check to validate that a user id has manage permissions on a project
func CanManageProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return ProjectCheck(projectUuid, "manage")
}

// CanWriteProjectCheck generates a temporary permission check to validate that a user id has write permissions on a project
func CanWriteProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return ProjectCheck(projectUuid, "write")
}

// CanReadProjectCheck generates a temporary permission check to validate that a user id has read permissions on a project
func CanReadProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return ProjectCheck(projectUuid, "read")
}

// CanManageEnvironmentCheck generates a temporary permission check to validate that a user id has manage permissions on an environment
func CanManageEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return EnvironmentCheck(envUuid, "manage")
}

// CanWriteEnvironmentCheck generates a temporary permission check to validate that a user id has write permissions on an environment
func CanWriteEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return EnvironmentCheck(envUuid, "write")
}

// CanReadEnvironmentCheck generates a temporary permission check to validate that a user id has read permissions on an environment
func CanReadEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return EnvironmentCheck(envUuid, "read")
}
