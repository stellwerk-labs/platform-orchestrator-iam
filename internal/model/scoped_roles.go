package model

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

type ScopedRole struct {
	Id        uuid.UUID
	OrgId     string
	Scope     string
	OrgRoleId uuid.UUID
}

type ScopedRoleListParams struct {
	OrgId string
	Scope *string
}

func (d *databaser) UpsertScopedRole(ctx context.Context, optionalTx Tx, request *ScopedRole) (*ScopedRole, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request

	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO scoped_roles (id, org_id, scope, org_role_id) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id, org_role_id, scope) DO UPDATE SET id = scoped_roles.id
		 RETURNING id`,
		request.Id, request.OrgId, request.Scope, request.OrgRoleId,
	).Scan(&out.Id); err != nil {
		return nil, errors.Wrap(err, "failed to upsert scoped role")
	}
	return &out, nil
}

func (d *databaser) BatchUpsertScopedRoles(ctx context.Context, optionalTx Tx, requests []ScopedRole) ([]ScopedRole, error) {
	optionalTx = d.txOrDb(optionalTx)

	if len(requests) == 0 {
		return []ScopedRole{}, nil
	}

	// Prepare arrays for unnest
	ids := make([]uuid.UUID, len(requests))
	orgIds := make([]string, len(requests))
	scopes := make([]string, len(requests))
	orgRoleIds := make([]uuid.UUID, len(requests))

	for i, role := range requests {
		ids[i] = role.Id
		orgIds[i] = role.OrgId
		scopes[i] = role.Scope
		orgRoleIds[i] = role.OrgRoleId
	}

	rows, err := optionalTx.QueryContext(
		ctx,
		`INSERT INTO scoped_roles (id, org_id, scope, org_role_id)
		 SELECT unnest($1::uuid[]), unnest($2::text[]), unnest($3::text[]), unnest($4::uuid[])
		 ON CONFLICT (org_id, org_role_id, scope) DO UPDATE SET id = scoped_roles.id
		 RETURNING id, org_id, scope, org_role_id`,
		pq.Array(ids), pq.Array(orgIds), pq.Array(scopes), pq.Array(orgRoleIds),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to batch upsert scoped roles")
	}
	defer func() {
		if err := rows.Close(); err != nil {
			d.logger.Error("failed to close row set", zap.Error(err))
		}
	}()

	out := make([]ScopedRole, 0, len(requests))
	for rows.Next() {
		var role ScopedRole
		if err := rows.Scan(&role.Id, &role.OrgId, &role.Scope, &role.OrgRoleId); err != nil {
			return nil, errors.Wrap(err, "failed to scan scoped role")
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to batch upsert scoped roles")
	}

	return out, nil
}

func (d *databaser) ListScopedRoles(ctx context.Context, optionalTx Tx, params ScopedRoleListParams) ([]ScopedRole, error) {
	optionalTx = d.txOrDb(optionalTx)

	rows, err := optionalTx.QueryContext(
		ctx,
		`SELECT id, org_id, scope, org_role_id FROM scoped_roles
		WHERE org_id = $1
		AND (scope = $2 OR $2 IS NULL)
		ORDER BY scope`,
		params.OrgId,
		params.Scope,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list scoped roles")
	}

	defer func() {
		if err = rows.Close(); err != nil {
			d.logger.Error("failed to close row set", zap.Error(err))
		}
	}()

	out := []ScopedRole{}
	for rows.Next() {
		r := ScopedRole{}
		if err := rows.Scan(&r.Id, &r.OrgId, &r.Scope, &r.OrgRoleId); err != nil {
			return nil, errors.Wrap(err, "failed to scan scoped role")
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to list scoped roles")
	}

	return out, nil
}

type BulkDeleteScopedRolesParams struct {
	OrgId opt.Opt[string]
	Scope opt.Opt[string]
}

// BulkDeleteScopedRoles deletes all scoped roles matching the given parameters.
func (d *databaser) BulkDeleteScopedRoles(ctx context.Context, optionalTx Tx, params BulkDeleteScopedRolesParams) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM scoped_roles WHERE ($1::text IS NULL OR org_id = $1) AND ($2::text IS NULL OR scope = $2)`,
		params.OrgId.Ref(), params.Scope.Ref(),
	); err != nil {
		return 0, errors.Wrap(err, "failed to bulk delete scoped roles")
	} else {
		rc, _ := rs.RowsAffected()
		return rc, nil
	}
}
