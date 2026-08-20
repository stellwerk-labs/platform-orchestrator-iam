package authorization

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	casbincache "github.com/casbin/casbin/v2/persist/cache"
	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"

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

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (r.obj == p.obj || g(r.obj, p.obj)) && permissionMatch(r.act, p.act)
`

const (
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
	store    Store
	enforcer *casbin.SyncedCachedEnforcer
	cache    *boundedCache
}

// New creates one process-wide Casbin engine. Its policy snapshot and bounded
// decision cache are refreshed together, so authorization does not load policy
// or hierarchy data on the request hot path.
func New(ctx context.Context, store Store) (*CasbinAuthorizer, error) {
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
	enforcer.StartAutoLoadPolicy(authorizationCacheTTL)

	return &CasbinAuthorizer{store: store, enforcer: enforcer, cache: cache}, nil
}

// Close releases cache and policy-refresh workers during graceful shutdown.
func (a *CasbinAuthorizer) Close() {
	a.enforcer.StopAutoLoadPolicy()
	a.cache.Stop()
}

// ReloadPolicy immediately refreshes the in-memory policy and clears cached
// decisions. The periodic reload remains a cross-instance safety net.
func (a *CasbinAuthorizer) ReloadPolicy() error {
	return a.enforcer.LoadPolicy()
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
		requested = "read"
	}
	if requested == granted || granted == PermissionManageAll {
		return true, nil
	}
	switch granted {
	case PermissionWriteAll:
		return requested == "write" || requested == "read", nil
	case PermissionReadAll:
		return requested == "read", nil
	default:
		return false, nil
	}
}

func (a *CasbinAuthorizer) Authorize(ctx context.Context, subjectId uuid.UUID, checks []Check) ([]Result, error) {
	if len(checks) == 0 {
		return []Result{}, nil
	}

	normalizedChecks := make([]Check, len(checks))
	for index, check := range checks {
		normalizedResource, err := NormalizeResource(check.Resource)
		if err != nil {
			return nil, err
		}
		normalizedChecks[index] = Check{Resource: normalizedResource, Permission: check.Permission}
	}

	known, err := a.knownCustomPermissions(ctx, normalizedChecks)
	if err != nil {
		return nil, err
	}

	results := make([]Result, len(normalizedChecks))
	for index, check := range normalizedChecks {
		permissionCheck := model.AuthorizationPermissionCheck{Resource: check.Resource, Permission: check.Permission}
		if isCustomPermission(check.Permission) && !known[permissionCheck] {
			results[index] = Result{Check: checks[index], Invalid: true}
			continue
		}
		allowed, err := a.enforcer.Enforce(subjectId.String(), check.Resource, check.Permission)
		if err != nil {
			return nil, errors.Wrap(err, "failed to evaluate Casbin policy")
		}
		results[index] = Result{Check: checks[index], Allowed: allowed}
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
	case "read", "write", "manage", PermissionReadAll, PermissionWriteAll, PermissionManageAll:
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
	for _, policy := range policies {
		if err := persist.LoadPolicyArray([]string{"p", policy.SubjectId.String(), policy.Resource, policy.Permission}, m); err != nil {
			return errors.Wrap(err, "failed to load Casbin policy")
		}
	}

	relations, err := a.store.ListAuthorizationResourceRelations(a.ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed to load authorization resource hierarchy")
	}
	for _, relation := range relations {
		if err := persist.LoadPolicyArray([]string{"g", relation.Resource, relation.ParentResource}, m); err != nil {
			return errors.Wrap(err, "failed to load Casbin resource relation")
		}
	}
	return nil
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
