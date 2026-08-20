package authorization

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/google/uuid"
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

type Store interface {
	ListAuthorizationPolicies(ctx context.Context, optionalTx model.Tx, subjectId uuid.UUID) ([]model.AuthorizationPolicy, error)
	ListAuthorizationResourceRelations(ctx context.Context, optionalTx model.Tx, resources []string) ([]model.AuthorizationResourceRelation, error)
	ListKnownAuthorizationPermissions(ctx context.Context, optionalTx model.Tx, checks []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error)
}

type CasbinAuthorizer struct {
	store Store
}

func New(store Store) *CasbinAuthorizer {
	return &CasbinAuthorizer{store: store}
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
	resources := make([]string, 0, len(checks))
	for index, check := range checks {
		normalizedResource, err := NormalizeResource(check.Resource)
		if err != nil {
			return nil, err
		}
		normalizedChecks[index] = Check{Resource: normalizedResource, Permission: check.Permission}
		resources = append(resources, normalizedResource)
	}
	customChecks := make([]model.AuthorizationPermissionCheck, 0, len(checks))
	for _, check := range normalizedChecks {
		switch check.Permission {
		case "read", "write", "manage":
		case PermissionReadAll, PermissionWriteAll, PermissionManageAll:
		default:
			customChecks = append(customChecks, model.AuthorizationPermissionCheck{Resource: check.Resource, Permission: check.Permission})
		}
	}
	knownCustomPermissions, err := a.store.ListKnownAuthorizationPermissions(ctx, nil, customChecks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load known authorization permissions")
	}
	known := make(map[model.AuthorizationPermissionCheck]struct{}, len(knownCustomPermissions))
	for _, check := range knownCustomPermissions {
		known[check] = struct{}{}
	}

	policies, err := a.store.ListAuthorizationPolicies(ctx, nil, subjectId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load authorization policies")
	}
	relations, err := a.store.ListAuthorizationResourceRelations(ctx, nil, resources)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load authorization resource hierarchy")
	}

	casbinModel, err := casbinmodel.NewModelFromString(casbinModel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build Casbin model")
	}
	enforcer, err := casbin.NewEnforcer(casbinModel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Casbin enforcer")
	}
	enforcer.AddFunction("permissionMatch", permissionMatch)

	for _, policy := range policies {
		if _, err := enforcer.AddPolicy(policy.SubjectId.String(), policy.Resource, policy.Permission); err != nil {
			return nil, errors.Wrap(err, "failed to add Casbin policy")
		}
	}
	for _, relation := range relations {
		if _, err := enforcer.AddGroupingPolicy(relation.Resource, relation.ParentResource); err != nil {
			return nil, errors.Wrap(err, "failed to add Casbin resource relation")
		}
	}

	results := make([]Result, len(normalizedChecks))
	for index, check := range normalizedChecks {
		if check.Permission != "read" && check.Permission != "write" && check.Permission != "manage" {
			_, customPermissionKnown := known[model.AuthorizationPermissionCheck{Resource: check.Resource, Permission: check.Permission}]
			if !customPermissionKnown {
				results[index] = Result{Check: checks[index], Invalid: true}
				continue
			}
		}
		allowed, err := enforcer.Enforce(subjectId.String(), check.Resource, check.Permission)
		if err != nil {
			return nil, errors.Wrap(err, "failed to evaluate Casbin policy")
		}
		results[index] = Result{Check: checks[index], Allowed: allowed}
	}
	return results, nil
}
