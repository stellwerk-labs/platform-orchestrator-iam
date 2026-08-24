package authz

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestScopedChecks(t *testing.T) {
	projectID := uuid.New()
	environmentID := uuid.New()

	assert.Equal(t, "organization:acme", OrgCheck("acme", PermissionRoleRead).Resource)
	assert.Equal(t, PermissionRoleRead, OrgCheck("acme", PermissionRoleRead).Permission)
	assert.Equal(t, "project:"+projectID.String(), ProjectCheck(projectID, PermissionEnvironmentWrite).Resource)
	assert.Equal(t, PermissionEnvironmentWrite, ProjectCheck(projectID, PermissionEnvironmentWrite).Permission)
	assert.Equal(t, "env:"+environmentID.String(), EnvironmentCheck(environmentID, PermissionDeploymentWrite).Resource)
	assert.Equal(t, PermissionDeploymentWrite, EnvironmentCheck(environmentID, PermissionDeploymentWrite).Permission)
}
