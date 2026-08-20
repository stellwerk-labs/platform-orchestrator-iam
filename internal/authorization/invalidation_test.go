package authorization

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

type mutableTestStore struct {
	mutex        sync.RWMutex
	policies     []model.AuthorizationPolicy
	policyLoads  int
	relationLoad int
}

func (s *mutableTestStore) ListAuthorizationPolicies(context.Context, model.Tx) ([]model.AuthorizationPolicy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.policyLoads++
	return append([]model.AuthorizationPolicy(nil), s.policies...), nil
}

func (s *mutableTestStore) ListAuthorizationResourceRelations(context.Context, model.Tx) ([]model.AuthorizationResourceRelation, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.relationLoad++
	return []model.AuthorizationResourceRelation{}, nil
}

func (s *mutableTestStore) ListKnownAuthorizationPermissions(context.Context, model.Tx, []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error) {
	return []model.AuthorizationPermissionCheck{}, nil
}

func (s *mutableTestStore) setPolicies(policies []model.AuthorizationPolicy) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.policies = append([]model.AuthorizationPolicy(nil), policies...)
}

func (s *mutableTestStore) loadCounts() (int, int) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.policyLoads, s.relationLoad
}

type testInvalidationBus struct {
	mutex       sync.Mutex
	nextId      int
	subscribers map[int]func([]byte)
	publishes   int
}

func newTestInvalidationBus() *testInvalidationBus {
	return &testInvalidationBus{subscribers: make(map[int]func([]byte))}
}

func (b *testInvalidationBus) Publish(_ string, data []byte) error {
	b.mutex.Lock()
	b.publishes++
	subscribers := make([]func([]byte), 0, len(b.subscribers))
	for _, subscriber := range b.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	b.mutex.Unlock()

	for _, subscriber := range subscribers {
		subscriber(data)
	}
	return nil
}

func (b *testInvalidationBus) Subscribe(_ string, handler func([]byte)) (PolicyInvalidationSubscription, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	id := b.nextId
	b.nextId++
	b.subscribers[id] = handler
	return &testInvalidationSubscription{bus: b, id: id}, nil
}

func (b *testInvalidationBus) publishCount() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.publishes
}

type testInvalidationSubscription struct {
	bus *testInvalidationBus
	id  int
}

func (s *testInvalidationSubscription) Unsubscribe() error {
	s.bus.mutex.Lock()
	defer s.bus.mutex.Unlock()
	delete(s.bus.subscribers, s.id)
	return nil
}

func TestPolicyReloadInvalidatesOtherInstances(t *testing.T) {
	subjectId := uuid.New()
	roleId := uuid.New()
	store := &mutableTestStore{}
	bus := newTestInvalidationBus()

	first, err := New(t.Context(), store, bus)
	require.NoError(t, err)
	t.Cleanup(first.Close)
	second, err := New(t.Context(), store, bus)
	require.NoError(t, err)
	t.Cleanup(second.Close)

	check := []Check{{Resource: "organization:acme", Permission: "read"}}
	results, err := second.Authorize(t.Context(), subjectId, check)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Allowed)

	store.setPolicies([]model.AuthorizationPolicy{{
		SubjectId: subjectId, Resource: "organization:acme", Permission: PermissionReadAll, RoleId: roleId,
	}})
	require.NoError(t, first.ReloadPolicy())

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		results, err := second.Authorize(t.Context(), subjectId, check)
		assert.NoError(collect, err)
		if assert.Len(collect, results, 1) {
			assert.True(collect, results[0].Allowed)
		}
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, 1, bus.publishCount())
	policyLoads, relationLoads := store.loadCounts()
	assert.Equal(t, 4, policyLoads, "two initial loads plus one local and one remote reload")
	assert.Equal(t, 4, relationLoads, "the publishing instance must ignore its own invalidation")
}
