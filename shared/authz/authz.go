package authz

import (
	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// CanReadOrgCheck generates a temporary permission check to validate that a user id has at least read permissions on an org
func CanReadOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "read",
		Resource:   "organization:" + orgId,
	}
}

// CanManageOrgCheck generates a temporary permission check to validate that a user id has manage permissions on an org
func CanManageOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "manage",
		Resource:   "organization:" + orgId,
	}
}

// CanWriteOrgCheck generates a temporary permission check to validate that a user id has write permissions on an org
func CanWriteOrgCheck(orgId string) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "write",
		Resource:   "organization:" + orgId,
	}
}

// CanManageProjectCheck generates a temporary permission check to validate that a user id has manage permissions on a project
func CanManageProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "manage",
		Resource:   "project:" + projectUuid.String(),
	}
}

// CanWriteProjectCheck generates a temporary permission check to validate that a user id has write permissions on a project
func CanWriteProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "write",
		Resource:   "project:" + projectUuid.String(),
	}
}

// CanReadProjectCheck generates a temporary permission check to validate that a user id has read permissions on a project
func CanReadProjectCheck(projectUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "read",
		Resource:   "project:" + projectUuid.String(),
	}
}

// CanManageEnvironmentCheck generates a temporary permission check to validate that a user id has manage permissions on an environment
func CanManageEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "manage",
		Resource:   "env:" + envUuid.String(),
	}
}

// CanWriteEnvironmentCheck generates a temporary permission check to validate that a user id has write permissions on an environment
func CanWriteEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "write",
		Resource:   "env:" + envUuid.String(),
	}
}

// CanReadEnvironmentCheck generates a temporary permission check to validate that a user id has read permissions on an environment
func CanReadEnvironmentCheck(envUuid uuid.UUID) genclient.ResourcePermissionCheck {
	return genclient.ResourcePermissionCheck{
		Permission: "read",
		Resource:   "env:" + envUuid.String(),
	}
}
