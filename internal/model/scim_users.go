package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

type ScimUser struct {
	Id         uuid.UUID
	OrgId      string
	UserId     uuid.UUID
	UserName   string
	ExternalId opt.Opt[string]
	Active     bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (d *databaser) CreateScimUser(ctx context.Context, optionalTx Tx, u ScimUser) error {
	optionalTx = d.txOrDb(optionalTx)
	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO scim_users (id, org_id, user_id, user_name, external_id, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.Id, u.OrgId, u.UserId, u.UserName, u.ExternalId.Ref(), u.Active, u.CreatedAt, u.UpdatedAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Constraint == "unique_scim_user_name" {
				return NewErrConflict("scim user name already exists in org")
			}
			if pqErr.Constraint == "unique_scim_user_user" {
				return NewErrConflict("user already provisioned in org")
			}
		}
		return errors.Wrap(err, "failed to insert scim user")
	}
	return nil
}

func (d *databaser) GetScimUser(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at FROM scim_users WHERE org_id = $1 AND id = $2`,
		orgId, id,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to get scim user")
	}
	return &out, nil
}

func (d *databaser) FindScimUserByUserName(ctx context.Context, optionalTx Tx, orgId string, userName string) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at FROM scim_users WHERE org_id = $1 AND user_name = $2`,
		orgId, userName,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to find scim user by user name")
	}
	return &out, nil
}

func (d *databaser) FindScimUserByExternalId(ctx context.Context, optionalTx Tx, orgId string, externalId string) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at FROM scim_users WHERE org_id = $1 AND external_id = $2`,
		orgId, externalId,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to find scim user by external id")
	}
	return &out, nil
}

func (d *databaser) ListScimUsers(ctx context.Context, optionalTx Tx, orgId string, limit int, offset int) ([]ScimUser, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at FROM scim_users WHERE org_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3`,
		orgId, limit, offset,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list scim users")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]ScimUser, 0)
		for rs.Next() {
			var item ScimUser
			if err := rs.Scan(&item.Id, &item.OrgId, &item.UserId, &item.UserName, opt.Scan(&item.ExternalId), &item.Active, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return nil, errors.Wrap(err, "failed to scan scim user")
			}
			out = append(out, item)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate scim users")
		}
		return out, nil
	}
}

func (d *databaser) CountScimUsers(ctx context.Context, optionalTx Tx, orgId string) (int, error) {
	optionalTx = d.txOrDb(optionalTx)
	var count int
	if err := optionalTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users WHERE org_id = $1`, orgId).Scan(&count); err != nil {
		return 0, errors.Wrap(err, "failed to count scim users")
	}
	return count, nil
}

func (d *databaser) UpdateScimUser(ctx context.Context, optionalTx Tx, u ScimUser) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`UPDATE scim_users SET user_name = $3, external_id = $4, active = $5, updated_at = $6 WHERE org_id = $1 AND id = $2`,
		u.OrgId, u.Id, u.UserName, u.ExternalId.Ref(), u.Active, u.UpdatedAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "unique_scim_user_name" {
			return NewErrConflict("scim user name already exists in org")
		}
		return errors.Wrap(err, "failed to update scim user")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim user not found")
	}
	return nil
}

func (d *databaser) DeleteScimUser(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(ctx, `DELETE FROM scim_users WHERE org_id = $1 AND id = $2`, orgId, id); err != nil {
		return errors.Wrap(err, "failed to delete scim user")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim user not found")
	}
	return nil
}

func (d *databaser) FindScimUserByUserId(ctx context.Context, optionalTx Tx, orgId string, userId uuid.UUID) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at FROM scim_users WHERE org_id = $1 AND user_id = $2`,
		orgId, userId,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to find scim user by user id")
	}
	return &out, nil
}
