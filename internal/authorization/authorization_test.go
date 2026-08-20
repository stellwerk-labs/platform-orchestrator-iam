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
	roleId := uuid.New()
	store := &testStore{
		policies: []model.AuthorizationPolicy{
			{SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionWriteAll, RoleId: roleId},
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
	roleId := uuid.New()
	store := &testStore{
		policies: []model.AuthorizationPolicy{
			{SubjectId: subjectId, Resource: "project:test", Permission: "deployment_cancel", RoleId: roleId},
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
	roleId := uuid.New()
	store := &testStore{policies: []model.AuthorizationPolicy{
		{SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionManageAll, RoleId: roleId},
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
	roleId := uuid.New()
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
		SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionReadAll, RoleId: roleId,
	}}
	require.NoError(t, authorizer.ReloadPolicy())

	results, err := authorizer.Authorize(t.Context(), subjectId, check)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Allowed)
	assert.Equal(t, 2, store.policyLoads)
	assert.Equal(t, 2, store.relationLoads)
}

func TestCasbinAuthorizerSharesRolePoliciesWithoutSharingAssignments(t *testing.T) {
	firstSubject := uuid.New()
	secondSubject := uuid.New()
	roleId := uuid.New()
	store := &testStore{policies: []model.AuthorizationPolicy{
		{SubjectId: firstSubject, Resource: "organization:acme", Permission: PermissionReadAll, RoleId: roleId},
		{SubjectId: firstSubject, Resource: "organization:acme", Permission: "deployment_cancel", RoleId: roleId},
		{SubjectId: secondSubject, Resource: "organization:acme", Permission: PermissionReadAll, RoleId: roleId},
		{SubjectId: secondSubject, Resource: "organization:acme", Permission: "deployment_cancel", RoleId: roleId},
	}}

	authorizer, err := New(t.Context(), store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)

	policies, err := authorizer.enforcer.GetPolicy()
	require.NoError(t, err)
	assert.Len(t, policies, 2, "permissions on a shared role binding should only be loaded once")
	bindings, err := authorizer.enforcer.GetGroupingPolicy()
	require.NoError(t, err)
	assert.Len(t, bindings, 2, "each subject should retain an independent role assignment")

	for _, subjectId := range []uuid.UUID{firstSubject, secondSubject} {
		results, err := authorizer.Authorize(t.Context(), subjectId, []Check{{Resource: "organization:acme", Permission: "read"}})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].Allowed)
	}
	unknownResults, err := authorizer.Authorize(t.Context(), uuid.New(), []Check{{Resource: "organization:acme", Permission: "read"}})
	require.NoError(t, err)
	require.Len(t, unknownResults, 1)
	assert.False(t, unknownResults[0].Allowed)
}

func TestParseResource(t *testing.T) {
	resourceType, resourceId, err := ParseResource("organization:acme")
	require.NoError(t, err)
	assert.Equal(t, "organization", resourceType)
	assert.Equal(t, "acme", resourceId)

	_, _, err = ParseResource("invalid")
	require.Error(t, err)
}
