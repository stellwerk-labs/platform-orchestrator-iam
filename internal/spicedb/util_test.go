package spicedb

import (
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateConsistency_WithZedToken(t *testing.T) {
	consistency := calculateConsistency("test-zed-token-123")

	require.NotNil(t, consistency)
	require.NotNil(t, consistency.Requirement)

	atLeastAsFresh, ok := consistency.Requirement.(*v1.Consistency_AtLeastAsFresh)
	require.True(t, ok, "expected AtLeastAsFresh requirement")
	require.NotNil(t, atLeastAsFresh.AtLeastAsFresh)
	assert.Equal(t, "test-zed-token-123", atLeastAsFresh.AtLeastAsFresh.Token)
}

func TestCalculateConsistency_WithEmptyZedToken(t *testing.T) {
	consistency := calculateConsistency("")

	require.NotNil(t, consistency)
	require.NotNil(t, consistency.Requirement)

	fullyConsistent, ok := consistency.Requirement.(*v1.Consistency_FullyConsistent)
	require.True(t, ok, "expected FullyConsistent requirement")
	assert.True(t, fullyConsistent.FullyConsistent)
}

func TestParseResource_ValidUserResource(t *testing.T) {
	objType, objId, err := ParseResource("user:user-456")

	require.NoError(t, err)
	assert.Equal(t, ObjectTypeUser, objType)
	assert.Equal(t, "user-456", objId)
}

func TestParseResource_ValidScopedRoleResource(t *testing.T) {
	objType, objId, err := ParseResource("scoped_role:role-789")

	require.NoError(t, err)
	assert.Equal(t, ObjectTypeScopedRole, objType)
	assert.Equal(t, "role-789", objId)
}

func TestParseResource_OrganizationNormalizedToOrg(t *testing.T) {
	objType, objId, err := ParseResource("organization:123")

	require.NoError(t, err)
	assert.Equal(t, ObjectTypeOrg, objType, "organization should be normalized to org")
	assert.Equal(t, "123", objId)
}

func TestParseResource_ResourceIdWithColon(t *testing.T) {
	// Resource IDs can contain colons, only the first colon is used as separator
	objType, objId, err := ParseResource("organization:123:456:789")

	require.NoError(t, err)
	assert.Equal(t, ObjectTypeOrg, objType)
	assert.Equal(t, "123:456:789", objId)
}

func TestParseResource_InvalidFormat_NoColon(t *testing.T) {
	objType, objId, err := ParseResource("org123")

	require.Error(t, err)
	assert.Empty(t, string(objType))
	assert.Empty(t, objId)
	assert.ErrorContains(t, err, "invalid resource format")
}

func TestParseResource_InvalidFormat_EmptyString(t *testing.T) {
	objType, objId, err := ParseResource("")

	require.Error(t, err)
	assert.Empty(t, string(objType))
	assert.Empty(t, objId)
	assert.ErrorContains(t, err, "invalid resource format")
}

func TestParseResource_InvalidFormat_OnlyColon(t *testing.T) {
	objType, objId, err := ParseResource(":")

	require.NoError(t, err, "colon separates into two empty parts")
	assert.Empty(t, string(objType))
	assert.Empty(t, objId)
}

func TestParseResource_EmptyObjectType(t *testing.T) {
	objType, objId, err := ParseResource(":123")

	require.NoError(t, err)
	assert.Empty(t, string(objType))
	assert.Equal(t, "123", objId)
}

func TestParseResource_EmptyObjectId(t *testing.T) {
	objType, objId, err := ParseResource("organization:")

	require.NoError(t, err)
	assert.Equal(t, ObjectTypeOrg, objType)
	assert.Empty(t, objId)
}
