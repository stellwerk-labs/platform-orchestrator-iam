package authorization

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

type testStore struct {
	policies  []model.AuthorizationPolicy
	relations []model.AuthorizationResourceRelation
	known     []model.AuthorizationPermissionCheck
}

func (s *testStore) ListAuthorizationPolicies(context.Context, model.Tx, uuid.UUID) ([]model.AuthorizationPolicy, error) {
	return s.policies, nil
}

func (s *testStore) ListAuthorizationResourceRelations(context.Context, model.Tx, []string) ([]model.AuthorizationResourceRelation, error) {
	return s.relations, nil
}

func (s *testStore) ListKnownAuthorizationPermissions(context.Context, model.Tx, []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error) {
	return s.known, nil
}

func TestCasbinAuthorizer(t *testing.T) {
	subjectId := uuid.New()
	store := &testStore{
		policies: []model.AuthorizationPolicy{
			{SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionWriteAll},
		},
		relations: []model.AuthorizationResourceRelation{
			{Resource: "env:test", ParentResource: "project:test"},
			{Resource: "env:test", ParentResource: "organization:acme"},
		},
	}

	results, err := New(store).Authorize(t.Context(), subjectId, []Check{
		{Resource: "env:test", Permission: "read"},
		{Resource: "env:test", Permission: "write"},
		{Resource: "env:test", Permission: "manage"},
	})
	require.NoError(t, err)
	assert.Equal(t, []Result{
		{Check: Check{Resource: "env:test", Permission: "read"}, Allowed: true},
		{Check: Check{Resource: "env:test", Permission: "write"}, Allowed: true},
		{Check: Check{Resource: "env:test", Permission: "manage"}, Allowed: false},
	}, results)
}

func TestCasbinAuthorizerCustomPermission(t *testing.T) {
	subjectId := uuid.New()
	store := &testStore{
		policies: []model.AuthorizationPolicy{
			{SubjectId: subjectId, Resource: "project:test", Permission: "deployment_cancel"},
		},
		known: []model.AuthorizationPermissionCheck{{Resource: "project:test", Permission: "deployment_cancel"}},
	}

	results, err := New(store).Authorize(t.Context(), subjectId, []Check{{Resource: "project:test", Permission: "deployment_cancel"}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Allowed)
}

func TestCasbinAuthorizerRejectsUnknownPermission(t *testing.T) {
	subjectId := uuid.New()
	store := &testStore{policies: []model.AuthorizationPolicy{
		{SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionManageAll},
	}}

	results, err := New(store).Authorize(t.Context(), subjectId, []Check{{Resource: "organization:acme", Permission: "typo"}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Invalid)
	assert.False(t, results[0].Allowed)
}

func TestParseResource(t *testing.T) {
	resourceType, resourceId, err := ParseResource("organization:acme")
	require.NoError(t, err)
	assert.Equal(t, "organization", resourceType)
	assert.Equal(t, "acme", resourceId)

	_, _, err = ParseResource("invalid")
	require.Error(t, err)
}
