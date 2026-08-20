package model

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxAuthorizationResourceDepth = 3

type AuthorizationPolicy struct {
	SubjectId  uuid.UUID
	Resource   string
	Permission string
	RoleId     uuid.UUID
}

type AuthorizationResourceRelation struct {
	Resource       string
	ParentResource string
}

type AuthorizationPermissionCheck struct {
	Resource   string
	Permission string
}

type AuthorizationResource struct {
	Resource       string
	ResourceType   string
	ResourceId     string
	OrgId          string
	ParentResource *string
}

type EffectiveRoleBinding struct {
	SubjectId   uuid.UUID
	RoleId      uuid.UUID
	DisplayName string
	Permissions []string
	Scope       string
}

func (d *databaser) ListAuthorizationPolicies(ctx context.Context, optionalTx Tx, subjectId uuid.UUID) ([]AuthorizationPolicy, error) {
	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, `
		SELECT m.user_id,
		       CASE WHEN m.scope = '' THEN 'organization:' || m.org_id ELSE m.scope END,
		       permission,
		       r.id
		FROM memberships m
		JOIN roles r ON r.id = m.role AND r.org_id = m.org_id
		CROSS JOIN LATERAL unnest(r.permissions) AS permission
		WHERE m.user_id = $1 AND m.subject_type = 'role' AND m.role IS NOT NULL
		UNION ALL
		SELECT sur.service_user_id,
		       CASE WHEN sur.scope = '' THEN 'organization:' || sur.org_id ELSE sur.scope END,
		       permission,
		       r.id
		FROM service_user_roles sur
		JOIN roles r ON r.id = sur.role_id AND r.org_id = sur.org_id
		CROSS JOIN LATERAL unnest(r.permissions) AS permission
		WHERE sur.service_user_id = $1
	`, subjectId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list authorization policies")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close authorization policy rows", zap.Error(closeErr))
		}
	}()

	policies := make([]AuthorizationPolicy, 0)
	for rows.Next() {
		var policy AuthorizationPolicy
		if err := rows.Scan(&policy.SubjectId, &policy.Resource, &policy.Permission, &policy.RoleId); err != nil {
			return nil, errors.Wrap(err, "failed to scan authorization policy")
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate authorization policies")
	}
	return policies, nil
}

func (d *databaser) ListAuthorizationResourceRelations(ctx context.Context, optionalTx Tx, resources []string) ([]AuthorizationResourceRelation, error) {
	if len(resources) == 0 {
		return []AuthorizationResourceRelation{}, nil
	}
	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, `
		WITH RECURSIVE ancestors(resource, parent_resource, depth) AS (
			SELECT resource, parent_resource, 1
			FROM authorization_resources
			WHERE resource = ANY($1::text[]) AND parent_resource IS NOT NULL
			UNION ALL
			SELECT a.resource, parent.parent_resource, a.depth + 1
			FROM ancestors a
			JOIN authorization_resources parent ON parent.resource = a.parent_resource
			WHERE parent.parent_resource IS NOT NULL AND a.depth < $2
		)
		SELECT DISTINCT resource, parent_resource FROM ancestors
	`, pq.Array(resources), maxAuthorizationResourceDepth)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list authorization resource relations")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close authorization relation rows", zap.Error(closeErr))
		}
	}()

	relations := make([]AuthorizationResourceRelation, 0)
	for rows.Next() {
		var relation AuthorizationResourceRelation
		if err := rows.Scan(&relation.Resource, &relation.ParentResource); err != nil {
			return nil, errors.Wrap(err, "failed to scan authorization resource relation")
		}
		relations = append(relations, relation)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate authorization resource relations")
	}
	return relations, nil
}

func (d *databaser) ListKnownAuthorizationPermissions(ctx context.Context, optionalTx Tx, checks []AuthorizationPermissionCheck) ([]AuthorizationPermissionCheck, error) {
	if len(checks) == 0 {
		return []AuthorizationPermissionCheck{}, nil
	}
	resources := make([]string, len(checks))
	permissions := make([]string, len(checks))
	for index, check := range checks {
		resources[index] = check.Resource
		permissions[index] = check.Permission
	}

	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, `
		WITH requested(resource, permission) AS (
			SELECT * FROM unnest($1::text[], $2::text[])
		)
		SELECT DISTINCT requested.resource, requested.permission
		FROM requested
		JOIN authorization_resources resources ON resources.resource = requested.resource
		JOIN roles ON roles.org_id = resources.org_id
		WHERE requested.permission = ANY(roles.permissions)
	`, pq.Array(resources), pq.Array(permissions))
	if err != nil {
		return nil, errors.Wrap(err, "failed to list known authorization permissions")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close known authorization permission rows", zap.Error(closeErr))
		}
	}()

	known := make([]AuthorizationPermissionCheck, 0, len(checks))
	for rows.Next() {
		var check AuthorizationPermissionCheck
		if err := rows.Scan(&check.Resource, &check.Permission); err != nil {
			return nil, errors.Wrap(err, "failed to scan known authorization permission")
		}
		known = append(known, check)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate known authorization permissions")
	}
	return known, nil
}

func (d *databaser) UpsertAuthorizationResource(ctx context.Context, optionalTx Tx, resource *AuthorizationResource) error {
	_, err := d.txOrDb(optionalTx).ExecContext(ctx, `
		INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (resource) DO UPDATE SET
			resource_type = EXCLUDED.resource_type,
			resource_id = EXCLUDED.resource_id,
			org_id = EXCLUDED.org_id,
			parent_resource = EXCLUDED.parent_resource
	`, resource.Resource, resource.ResourceType, resource.ResourceId, resource.OrgId, resource.ParentResource)
	return errors.Wrap(err, "failed to upsert authorization resource")
}

func (d *databaser) DeleteAuthorizationResource(ctx context.Context, optionalTx Tx, resource string) error {
	_, err := d.txOrDb(optionalTx).ExecContext(ctx, `DELETE FROM authorization_resources WHERE resource = $1`, resource)
	return errors.Wrap(err, "failed to delete authorization resource")
}

func (d *databaser) ListEffectiveRoleBindings(ctx context.Context, optionalTx Tx, resource string) ([]EffectiveRoleBinding, error) {
	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, `
		WITH RECURSIVE ancestors(resource, parent_resource, depth) AS (
			SELECT resource, parent_resource, 0
			FROM authorization_resources
			WHERE resource = $1
			UNION ALL
			SELECT parent.resource, parent.parent_resource, a.depth + 1
			FROM ancestors a
			JOIN authorization_resources parent ON parent.resource = a.parent_resource
			WHERE a.depth < $2
		), effective_scopes AS (
			SELECT resource FROM ancestors
			UNION SELECT $1
		)
		SELECT m.user_id, r.id, r.display_name, r.permissions,
		       CASE WHEN m.scope = '' THEN 'organization:' || m.org_id ELSE m.scope END
		FROM memberships m
		JOIN roles r ON r.id = m.role AND r.org_id = m.org_id
		WHERE m.subject_type = 'role' AND m.role IS NOT NULL
		  AND (CASE WHEN m.scope = '' THEN 'organization:' || m.org_id ELSE m.scope END) IN (SELECT resource FROM effective_scopes)
		UNION ALL
		SELECT sur.service_user_id, r.id, r.display_name, r.permissions,
		       CASE WHEN sur.scope = '' THEN 'organization:' || sur.org_id ELSE sur.scope END
		FROM service_user_roles sur
		JOIN roles r ON r.id = sur.role_id AND r.org_id = sur.org_id
		WHERE (CASE WHEN sur.scope = '' THEN 'organization:' || sur.org_id ELSE sur.scope END) IN (SELECT resource FROM effective_scopes)
	`, resource, maxAuthorizationResourceDepth)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list effective role bindings")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close effective role binding rows", zap.Error(closeErr))
		}
	}()

	bindings := make([]EffectiveRoleBinding, 0)
	for rows.Next() {
		var binding EffectiveRoleBinding
		var permissions pq.StringArray
		if err := rows.Scan(&binding.SubjectId, &binding.RoleId, &binding.DisplayName, &permissions, &binding.Scope); err != nil {
			return nil, errors.Wrap(err, "failed to scan effective role binding")
		}
		binding.Permissions = permissions
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate effective role bindings")
	}
	return bindings, nil
}
