package authorization

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	casbincache "github.com/casbin/casbin/v2/persist/cache"
	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

//go:generate go tool mockgen -destination mocks/authorization.go github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization Authorizer

const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (r.obj == p.obj || g2(r.obj, p.obj)) && permissionMatch(r.act, p.act)
`

const (
	PermissionRead      = "read"
	PermissionWrite     = "write"
	PermissionManage    = "manage"
	PermissionManageAll = "manage_all"
	PermissionWriteAll  = "write_all"
	PermissionReadAll   = "read_all"

	authorizationCacheSize = 10_000
	authorizationCacheTTL  = 10 * time.Second
)

type Check struct {
	Resource   string
	Permission string
}

type Result struct {
	Check   Check
	Allowed bool
	Invalid bool
}

type Authorizer interface {
	Authorize(ctx context.Context, subjectId uuid.UUID, checks []Check) ([]Result, error)
}

type PolicyReloader interface {
	ReloadPolicy() error
}

type Store interface {
	ListAuthorizationPolicies(ctx context.Context, optionalTx model.Tx) ([]model.AuthorizationPolicy, error)
	ListAuthorizationResourceRelations(ctx context.Context, optionalTx model.Tx) ([]model.AuthorizationResourceRelation, error)
	ListKnownAuthorizationPermissions(ctx context.Context, optionalTx model.Tx, checks []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error)
}

type CasbinAuthorizer struct {
	store                    Store
	enforcer                 *casbin.SyncedCachedEnforcer
	cache                    *boundedCache
	invalidationBus          PolicyInvalidationBus
	invalidationSubscription PolicyInvalidationSubscription
	instanceId               string
	invalidationRequests     chan struct{}
	stopInvalidations        chan struct{}
	invalidationsStopped     chan struct{}
	closeOnce                sync.Once
	policyMutex              sync.RWMutex
}

// New creates one process-wide Casbin engine. Its policy snapshot and bounded
// decision cache are refreshed together, so authorization does not load policy
// or hierarchy data on the request hot path.
func New(ctx context.Context, store Store, invalidationBuses ...PolicyInvalidationBus) (*CasbinAuthorizer, error) {
	m, err := casbinmodel.NewModelFromString(casbinModel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build Casbin model")
	}
	adapter := &storeAdapter{ctx: ctx, store: store}
	enforcer, err := casbin.NewSyncedCachedEnforcer(m, adapter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Casbin enforcer")
	}
	enforcer.EnableAutoSave(false)
	enforcer.AddFunction("permissionMatch", permissionMatch)

	cache := newBoundedCache(authorizationCacheSize)
	enforcer.SetCache(cache)
	enforcer.SetExpireTime(authorizationCacheTTL)

	authorizer := &CasbinAuthorizer{
		store:                store,
		enforcer:             enforcer,
		cache:                cache,
		instanceId:           uuid.NewString(),
		invalidationRequests: make(chan struct{}, 1),
		stopInvalidations:    make(chan struct{}),
		invalidationsStopped: make(chan struct{}),
	}
	if len(invalidationBuses) == 0 || invalidationBuses[0] == nil {
		go authorizer.processInvalidations()
		return authorizer, nil
	}

	authorizer.invalidationBus = invalidationBuses[0]
	subscription, err := authorizer.invalidationBus.Subscribe(policyInvalidationSubject, authorizer.handleInvalidation)
	if err != nil {
		cache.Stop()
		return nil, err
	}
	authorizer.invalidationSubscription = subscription
	go authorizer.processInvalidations()
	return authorizer, nil
}

// Close releases cache and policy-refresh workers during graceful shutdown.
func (a *CasbinAuthorizer) Close() {
	a.closeOnce.Do(func() {
		if a.invalidationSubscription != nil {
			if err := a.invalidationSubscription.Unsubscribe(); err != nil {
				zap.L().Error("failed to unsubscribe from authorization policy invalidations", zap.Error(err))
			}
		}
		close(a.stopInvalidations)
		<-a.invalidationsStopped
		a.cache.Stop()
	})
}

// ReloadPolicy immediately refreshes the in-memory policy and clears cached
// decisions. The periodic reload remains a cross-instance safety net.
func (a *CasbinAuthorizer) ReloadPolicy() error {
	if err := a.reloadPolicy(); err != nil {
		return err
	}
	if a.invalidationBus != nil {
		if err := a.invalidationBus.Publish(policyInvalidationSubject, []byte(a.instanceId)); err != nil {
			return errors.Wrap(err, "failed to publish authorization policy invalidation")
		}
	}
	return nil
}

func (a *CasbinAuthorizer) reloadPolicy() error {
	a.policyMutex.Lock()
	defer a.policyMutex.Unlock()
	return a.enforcer.LoadPolicy()
}

func (a *CasbinAuthorizer) handleInvalidation(origin []byte) {
	if string(origin) == a.instanceId {
		return
	}
	select {
	case a.invalidationRequests <- struct{}{}:
	default:
	}
}

func (a *CasbinAuthorizer) processInvalidations() {
	defer close(a.invalidationsStopped)
	ticker := time.NewTicker(authorizationCacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopInvalidations:
			return
		case <-ticker.C:
			if err := a.reloadPolicy(); err != nil {
				zap.L().Error("failed to periodically reload authorization policy", zap.Error(err))
			}
		case <-a.invalidationRequests:
			if err := a.reloadPolicy(); err != nil {
				zap.L().Error("failed to reload invalidated authorization policy", zap.Error(err))
			}
		}
	}
}

func ParseResource(resource string) (resourceType, resourceId string, err error) {
	resourceType, resourceId, found := strings.Cut(resource, ":")
	if !found || resourceId == "" {
		return "", "", errors.Errorf("invalid resource %q", resource)
	}
	if resourceType == "org" {
		resourceType = "organization"
	}
	switch resourceType {
	case "organization", "project", "env":
	default:
		return "", "", errors.Errorf("unsupported resource type %q", resourceType)
	}
	return resourceType, resourceId, nil
}

func NormalizeResource(resource string) (string, error) {
	resourceType, resourceId, err := ParseResource(resource)
	if err != nil {
		return "", err
	}
	return resourceType + ":" + resourceId, nil
}

func permissionMatch(arguments ...interface{}) (interface{}, error) {
	if len(arguments) != 2 {
		return false, fmt.Errorf("permissionMatch expects two arguments")
	}
	requested, requestedOK := arguments[0].(string)
	granted, grantedOK := arguments[1].(string)
	if !requestedOK || !grantedOK {
		return false, fmt.Errorf("permissionMatch arguments must be strings")
	}
	if requested == "member" {
		requested = PermissionRead
	}
	if requested == granted || granted == PermissionManageAll {
		return true, nil
	}
	switch granted {
	case PermissionWriteAll:
		return requested == PermissionWrite || requested == PermissionRead, nil
	case PermissionReadAll:
		return requested == PermissionRead, nil
	default:
		return false, nil
	}
}

func (a *CasbinAuthorizer) Authorize(ctx context.Context, subjectId uuid.UUID, checks []Check) ([]Result, error) {
	a.policyMutex.RLock()
	defer a.policyMutex.RUnlock()

	if len(checks) == 0 {
		return []Result{}, nil
	}

	type preparedCheck struct {
		original   Check
		normalized Check
	}
	preparedChecks := make([]preparedCheck, len(checks))
	for index, check := range checks {
		normalizedResource, err := NormalizeResource(check.Resource)
		if err != nil {
			return nil, err
		}
		preparedChecks[index] = preparedCheck{
			original:   check,
			normalized: Check{Resource: normalizedResource, Permission: check.Permission},
		}
	}

	normalizedChecks := make([]Check, len(preparedChecks))
	for index, prepared := range preparedChecks {
		normalizedChecks[index] = prepared.normalized
	}
	known, err := a.knownCustomPermissions(ctx, normalizedChecks)
	if err != nil {
		return nil, err
	}

	results := make([]Result, len(preparedChecks))
	for index, prepared := range preparedChecks {
		check := prepared.normalized
		permissionCheck := model.AuthorizationPermissionCheck{Resource: check.Resource, Permission: check.Permission}
		if isCustomPermission(check.Permission) && !known[permissionCheck] {
			results[index] = Result{Check: prepared.original, Invalid: true}
			continue
		}
		allowed, err := a.enforcer.Enforce(subjectId.String(), check.Resource, check.Permission)
		if err != nil {
			return nil, errors.Wrap(err, "failed to evaluate Casbin policy")
		}
		results[index] = Result{Check: prepared.original, Allowed: allowed}
	}
	return results, nil
}

func (a *CasbinAuthorizer) knownCustomPermissions(ctx context.Context, checks []Check) (map[model.AuthorizationPermissionCheck]bool, error) {
	known := make(map[model.AuthorizationPermissionCheck]bool)
	misses := make([]model.AuthorizationPermissionCheck, 0)
	for _, check := range checks {
		if !isCustomPermission(check.Permission) {
			continue
		}
		permissionCheck := model.AuthorizationPermissionCheck{Resource: check.Resource, Permission: check.Permission}
		if cached, found := a.cache.GetPermission(permissionCheck); found {
			known[permissionCheck] = cached
		} else {
			misses = append(misses, permissionCheck)
		}
	}
	if len(misses) == 0 {
		return known, nil
	}

	loaded, err := a.store.ListKnownAuthorizationPermissions(ctx, nil, misses)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load known authorization permissions")
	}
	loadedSet := make(map[model.AuthorizationPermissionCheck]struct{}, len(loaded))
	for _, check := range loaded {
		loadedSet[check] = struct{}{}
	}
	for _, check := range misses {
		_, isKnown := loadedSet[check]
		a.cache.SetPermission(check, isKnown, authorizationCacheTTL)
		known[check] = isKnown
	}
	return known, nil
}

func isCustomPermission(permission string) bool {
	switch permission {
	case PermissionRead, PermissionWrite, PermissionManage, PermissionReadAll, PermissionWriteAll, PermissionManageAll:
		return false
	default:
		return true
	}
}

type storeAdapter struct {
	ctx   context.Context
	store Store
}

func (a *storeAdapter) LoadPolicy(m casbinmodel.Model) error {
	policies, err := a.store.ListAuthorizationPolicies(a.ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed to load authorization policies")
	}
	loadedBindings := make(map[string]struct{}, len(policies))
	loadedPolicies := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		binding := roleBindingKey(policy.RoleId, policy.Resource)
		membershipKey := policy.SubjectId.String() + "$$" + binding
		if _, found := loadedBindings[membershipKey]; !found {
			if err := persist.LoadPolicyArray([]string{"g", policy.SubjectId.String(), binding}, m); err != nil {
				return errors.Wrap(err, "failed to load Casbin role binding")
			}
			loadedBindings[membershipKey] = struct{}{}
		}

		policyKey := binding + "$$" + policy.Permission
		if _, found := loadedPolicies[policyKey]; found {
			continue
		}
		if err := persist.LoadPolicyArray([]string{"p", binding, policy.Resource, policy.Permission}, m); err != nil {
			return errors.Wrap(err, "failed to load Casbin policy")
		}
		loadedPolicies[policyKey] = struct{}{}
	}

	relations, err := a.store.ListAuthorizationResourceRelations(a.ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed to load authorization resource hierarchy")
	}
	for _, relation := range relations {
		if err := persist.LoadPolicyArray([]string{"g2", relation.Resource, relation.ParentResource}, m); err != nil {
			return errors.Wrap(err, "failed to load Casbin resource relation")
		}
	}
	return nil
}

func roleBindingKey(roleId uuid.UUID, resource string) string {
	return "role:" + roleId.String() + "@" + resource
}

func (a *storeAdapter) SavePolicy(casbinmodel.Model) error {
	return errors.New("authorization policy adapter is read-only")
}

func (a *storeAdapter) AddPolicy(string, string, []string) error {
	return errors.New("authorization policy adapter is read-only")
}

func (a *storeAdapter) RemovePolicy(string, string, []string) error {
	return errors.New("authorization policy adapter is read-only")
}

func (a *storeAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return errors.New("authorization policy adapter is read-only")
}

type boundedCache struct {
	inner *ccache.Cache
}

func newBoundedCache(size int64) *boundedCache {
	return &boundedCache{inner: ccache.New(ccache.Configure().MaxSize(size))}
}

func (c *boundedCache) Set(key string, value bool, extra ...interface{}) error {
	ttl := authorizationCacheTTL
	if len(extra) > 0 {
		if configuredTTL, ok := extra[0].(time.Duration); ok && configuredTTL > 0 {
			ttl = configuredTTL
		}
	}
	c.inner.Set(key, value, ttl)
	return nil
}

func (c *boundedCache) Get(key string) (bool, error) {
	item := c.inner.Get(key)
	if item == nil || item.Expired() {
		return false, casbincache.ErrNoSuchKey
	}
	value, ok := item.Value().(bool)
	if !ok {
		return false, casbincache.ErrNoSuchKey
	}
	return value, nil
}

func (c *boundedCache) Delete(key string) error {
	if !c.inner.Delete(key) {
		return casbincache.ErrNoSuchKey
	}
	return nil
}

func (c *boundedCache) Clear() error {
	c.inner.Clear()
	return nil
}

func (c *boundedCache) Stop() {
	c.inner.Stop()
}

func (c *boundedCache) permissionKey(check model.AuthorizationPermissionCheck) string {
	return "permission$$" + check.Resource + "$$" + check.Permission
}

func (c *boundedCache) GetPermission(check model.AuthorizationPermissionCheck) (bool, bool) {
	value, err := c.Get(c.permissionKey(check))
	return value, err == nil
}

func (c *boundedCache) SetPermission(check model.AuthorizationPermissionCheck, known bool, ttl time.Duration) {
	_ = c.Set(c.permissionKey(check), known, ttl)
}
