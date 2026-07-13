package model

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

type ServiceUserRole struct {
	ServiceUserId uuid.UUID `json:"service_user_id"`
	RoleId        uuid.UUID `json:"role_id"`
	OrgId         string    `json:"org_id"`
	CreatedAt     time.Time `json:"created_at"`
	Scope         string    `json:"scope"`
}

type ListServiceUserRolesParams struct {
	OrgId         *string
	ServiceUserId *uuid.UUID
}

// CreateServiceUserRoles creates the given service user roles in the database.
func (d *databaser) CreateServiceUserRoles(ctx context.Context, optionalTx Tx, request []ServiceUserRole) error {
	optionalTx = d.txOrDb(optionalTx)
	serviceUserIds := make([]uuid.UUID, len(request))
	roleIds := make([]uuid.UUID, len(request))
	orgIds := make([]string, len(request))
	createdAts := make([]time.Time, len(request))
	scopes := make([]string, len(request))
	for i, r := range request {
		serviceUserIds[i] = r.ServiceUserId
		roleIds[i] = r.RoleId
		orgIds[i] = r.OrgId
		createdAts[i] = r.CreatedAt
		scopes[i] = r.Scope
	}
	out := make([]*ServiceUserRole, len(request))
	for i, r := range request {
		out[i] = &ServiceUserRole{
			ServiceUserId: r.ServiceUserId,
			RoleId:        r.RoleId,
			OrgId:         r.OrgId,
		}
	}

	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO service_user_roles (service_user_id, role_id, org_id, created_at, scope)
		SELECT unnest($1::uuid[]), unnest($2::uuid[]), unnest($3::text[]), unnest($4::timestamp[]), unnest($5::text[])`,
		pq.Array(serviceUserIds), pq.Array(roleIds), pq.Array(orgIds), pq.Array(createdAts), pq.Array(scopes),
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Constraint == "fk_service_user_roles_role_org_id" {
				return NewErrNotFound("role not found in the organization")
			}
			if pqErr.Constraint == "service_user_roles_pkey" {
				return NewErrConflict("duplicate service user role")
			}
		}
		return errors.Wrap(err, "failed to insert service user roles")
	}
	return nil
}

// ListServiceUserRoles lists all service user roles for a given organization.
func (d *databaser) ListServiceUserRoles(ctx context.Context, optionalTx Tx, params ListServiceUserRolesParams) ([]ServiceUserRole, error) {
	if params.OrgId == nil {
		return nil, errors.New("orgId is required")
	}
	optionalTx = d.txOrDb(optionalTx)

	rows, err := optionalTx.QueryContext(
		ctx,
		`SELECT service_user_id, role_id, org_id, created_at, scope
		FROM service_user_roles
		WHERE org_id = $1 OR $1 IS NULL
		AND ($2::uuid IS NULL OR service_user_id = $2)
		ORDER BY created_at ASC`,
		params.OrgId,
		params.ServiceUserId,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list service user roles")
	}
	defer func() {
		if err = rows.Close(); err != nil {
			d.logger.Error("failed to close row set", zap.Error(err))
		}
	}()

	var result []ServiceUserRole
	for rows.Next() {
		var sur ServiceUserRole
		if err := rows.Scan(&sur.ServiceUserId, &sur.RoleId, &sur.OrgId, &sur.CreatedAt, &sur.Scope); err != nil {
			return nil, errors.Wrap(err, "failed to scan service user role")
		}
		result = append(result, sur)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate service user roles")
	}

	return result, nil
}

type BulkDeleteServiceUserRolesParams struct {
	ServiceUserId opt.Opt[uuid.UUID]
	OrgId         opt.Opt[string]
	Scope         opt.Opt[string]
}

// BulkDeleteServiceUserRoles deletes all service user roles matching the given parameters.
func (d *databaser) BulkDeleteServiceUserRoles(ctx context.Context, optionalTx Tx, params BulkDeleteServiceUserRolesParams) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM service_user_roles WHERE ($1::uuid IS NULL OR service_user_id = $1) AND ($2::text IS NULL OR org_id = $2) AND ($3::text IS NULL OR scope = $3)`,
		params.ServiceUserId.Ref(), params.OrgId.Ref(), params.Scope.Ref(),
	); err != nil {
		return 0, errors.Wrap(err, "failed to bulk delete service user roles")
	} else {
		rc, _ := rs.RowsAffected()
		return rc, nil
	}
}
