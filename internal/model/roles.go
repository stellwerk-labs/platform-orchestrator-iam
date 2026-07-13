package model

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Role struct {
	Id          uuid.UUID
	OrgId       string
	DisplayName string
	CreatedAt   time.Time
	CreatedBy   uuid.UUID
	Permissions []string
}

func (d *databaser) GetRole(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*Role, error) {
	out := Role{Id: id, OrgId: orgId}
	var permissions pq.StringArray
	if err := d.txOrDb(optionalTx).QueryRowContext(
		ctx,
		`SELECT display_name, created_at, created_by, permissions FROM roles WHERE id = $1 AND org_id = $2`,
		id, orgId,
	).Scan(&out.DisplayName, &out.CreatedAt, &out.CreatedBy, &permissions); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("role not found")
		}
		return nil, errors.Wrap(err, "failed to get role")
	}
	out.Permissions = permissions
	return &out, nil
}

func (d *databaser) ListRoles(ctx context.Context, optionalTx Tx, orgId string) ([]Role, error) {
	rows, err := d.txOrDb(optionalTx).QueryContext(
		ctx,
		`SELECT id, display_name, created_at, created_by, permissions FROM roles WHERE org_id = $1 ORDER BY display_name`,
		orgId,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list roles")
	}

	defer func() {
		if err = rows.Close(); err != nil {
			d.logger.Error("failed to close row set", zap.Error(err))
		}
	}()

	out := []Role{}
	for rows.Next() {
		var permissions pq.StringArray
		r := Role{OrgId: orgId}
		if err := rows.Scan(&r.Id, &r.DisplayName, &r.CreatedAt, &r.CreatedBy, &permissions); err != nil {
			return nil, errors.Wrap(err, "failed to scan role")
		}
		r.Permissions = permissions
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to list roles")
	}

	return out, nil
}

// SeedRoles creates default roles for an organization which does not have any roles yet.
func (d *databaser) SeedRoles(ctx context.Context, tx Tx, orgId string, roles []Role) error {
	if tx == nil {
		return errors.New("tx is nil")
	}
	if len(roles) == 0 {
		return errors.New("no roles to seed")
	}
	ids := make([]uuid.UUID, len(roles))
	displayNames := make([]string, len(roles))
	createdBy := make([]uuid.UUID, len(roles))
	createdAt := make([]time.Time, len(roles))
	permissionArrays := make([]string, len(roles))
	for i, r := range roles {
		ids[i] = r.Id
		displayNames[i] = r.DisplayName
		createdBy[i] = r.CreatedBy
		createdAt[i] = r.CreatedAt
		permissionArrays[i] = strings.Join(r.Permissions, ",")
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO roles (id, display_name, created_at, created_by, permissions, org_id)
		SELECT
			unnest($1::uuid[]),
			unnest($2::text[]),
			unnest($3::timestamp[]),
			unnest($4::uuid[]),
			string_to_array(unnest($5::text[]), ','),
			$6`,
		pq.Array(ids), pq.Array(displayNames), pq.Array(createdAt), pq.Array(createdBy), pq.Array(permissionArrays), orgId,
	); err != nil {
		return errors.Wrap(err, "failed to seed roles")
	}

	return nil
}
