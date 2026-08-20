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
	policies      []model.AuthorizationPolicy
	relations     []model.AuthorizationResourceRelation
	known         []model.AuthorizationPermissionCheck
	policyLoads   int
	relationLoads int
	knownLoads    int
}

func (s *testStore) ListAuthorizationPolicies(context.Context, model.Tx) ([]model.AuthorizationPolicy, error) {
	s.policyLoads++
	return s.policies, nil
}

func (s *testStore) ListAuthorizationResourceRelations(context.Context, model.Tx) ([]model.AuthorizationResourceRelation, error) {
	s.relationLoads++
	return s.relations, nil
}

func (s *testStore) ListKnownAuthorizationPermissions(context.Context, model.Tx, []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error) {
	s.knownLoads++
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

	authorizer, err := New(t.Context(), store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	results, err := authorizer.Authorize(t.Context(), subjectId, []Check{
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

	authorizer, err := New(t.Context(), store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	for range 2 {
		results, err := authorizer.Authorize(t.Context(), subjectId, []Check{{Resource: "project:test", Permission: "deployment_cancel"}})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].Allowed)
	}
	assert.Equal(t, 1, store.knownLoads)
}

func TestCasbinAuthorizerRejectsUnknownPermission(t *testing.T) {
	subjectId := uuid.New()
	store := &testStore{policies: []model.AuthorizationPolicy{
		{SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionManageAll},
	}}

	authorizer, err := New(t.Context(), store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	results, err := authorizer.Authorize(t.Context(), subjectId, []Check{{Resource: "organization:acme", Permission: "typo"}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Invalid)
	assert.False(t, results[0].Allowed)
}

func TestCasbinAuthorizerReusesPolicyAndInvalidatesDecisionsOnReload(t *testing.T) {
	subjectId := uuid.New()
	store := &testStore{}
	authorizer, err := New(t.Context(), store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)

	check := []Check{{Resource: "organization:acme", Permission: "read"}}
	for range 2 {
		results, err := authorizer.Authorize(t.Context(), subjectId, check)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.False(t, results[0].Allowed)
	}
	assert.Equal(t, 1, store.policyLoads)
	assert.Equal(t, 1, store.relationLoads)

	store.policies = []model.AuthorizationPolicy{{
		SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionReadAll,
	}}
	require.NoError(t, authorizer.ReloadPolicy())

	results, err := authorizer.Authorize(t.Context(), subjectId, check)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Allowed)
	assert.Equal(t, 2, store.policyLoads)
	assert.Equal(t, 2, store.relationLoads)
}

func TestParseResource(t *testing.T) {
	resourceType, resourceId, err := ParseResource("organization:acme")
	require.NoError(t, err)
	assert.Equal(t, "organization", resourceType)
	assert.Equal(t, "acme", resourceId)

	_, _, err = ParseResource("invalid")
	require.Error(t, err)
}
