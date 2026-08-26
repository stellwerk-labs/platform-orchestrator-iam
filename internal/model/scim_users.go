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
	// DeletedAt marks a tombstone: the IDP deleted the user via SCIM. The row
	// survives so an SSO login cannot pass for never-provisioned and JIT its
	// way back in. All SCIM read paths treat tombstones as absent; only
	// FindScimUserByUserId surfaces them, for the SSO gate.
	DeletedAt opt.Opt[time.Time]
}

// Deprovisioned reports whether this org's IDP has withdrawn the user's
// access: either deactivated (active=false) or deleted (tombstoned). An SSO
// login for a deprovisioned user must be rejected outright.
func (u ScimUser) Deprovisioned() bool {
	return u.DeletedAt.IsSet() || !u.Active
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
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at FROM scim_users WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
		orgId, id,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt, opt.Scan(&out.DeletedAt)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to get scim user")
	}
	return &out, nil
}

// GetScimUsersByIds returns the live (non-tombstoned) SCIM users among the
// given ids in one query. Ids that are missing, tombstoned, or foreign to the
// org are simply absent from the result — the bulk reconciler treats them the
// same way the per-user path treats a not-found: nothing to reconcile.
func (d *databaser) GetScimUsersByIds(ctx context.Context, optionalTx Tx, orgId string, ids []uuid.UUID) ([]ScimUser, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if len(ids) == 0 {
		return []ScimUser{}, nil
	}
	idStrings := make([]string, 0, len(ids))
	for _, id := range ids {
		idStrings = append(idStrings, id.String())
	}
	rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at FROM scim_users WHERE org_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		orgId, pq.Array(idStrings),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get scim users by ids")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			logger.Error("failed to close row set", zap.Error(err))
		}
	}()
	out := make([]ScimUser, 0, len(ids))
	for rs.Next() {
		var item ScimUser
		if err := rs.Scan(&item.Id, &item.OrgId, &item.UserId, &item.UserName, opt.Scan(&item.ExternalId), &item.Active, &item.CreatedAt, &item.UpdatedAt, opt.Scan(&item.DeletedAt)); err != nil {
			return nil, errors.Wrap(err, "failed to scan scim user")
		}
		out = append(out, item)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate scim users")
	}
	return out, nil
}

// FindScimUserByUserName matches case-insensitively: /Schemas advertises
// userName with caseExact=false, and migration 000035 enforces uniqueness on
// LOWER(user_name), so at most one live row can match.
func (d *databaser) FindScimUserByUserName(ctx context.Context, optionalTx Tx, orgId string, userName string) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at FROM scim_users WHERE org_id = $1 AND LOWER(user_name) = LOWER($2) AND deleted_at IS NULL`,
		orgId, userName,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt, opt.Scan(&out.DeletedAt)); err != nil {
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
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at FROM scim_users WHERE org_id = $1 AND external_id = $2 AND deleted_at IS NULL`,
		orgId, externalId,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt, opt.Scan(&out.DeletedAt)); err != nil {
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
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at FROM scim_users WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT $2 OFFSET $3`,
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
			if err := rs.Scan(&item.Id, &item.OrgId, &item.UserId, &item.UserName, opt.Scan(&item.ExternalId), &item.Active, &item.CreatedAt, &item.UpdatedAt, opt.Scan(&item.DeletedAt)); err != nil {
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

// CountLiveScimUsersForUser counts how many organizations currently hold a
// live (non-tombstoned) SCIM record for the given global user. The multi-org
// profile ownership rule keys off it: an IDP may only write to the shared
// global profile while its organization is the sole SCIM governor of the user.
func (d *databaser) CountLiveScimUsersForUser(ctx context.Context, optionalTx Tx, userId uuid.UUID) (int, error) {
	optionalTx = d.txOrDb(optionalTx)
	var count int
	if err := optionalTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users WHERE user_id = $1 AND deleted_at IS NULL`, userId).Scan(&count); err != nil {
		return 0, errors.Wrap(err, "failed to count live scim users for user")
	}
	return count, nil
}

func (d *databaser) CountScimUsers(ctx context.Context, optionalTx Tx, orgId string) (int, error) {
	optionalTx = d.txOrDb(optionalTx)
	var count int
	if err := optionalTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users WHERE org_id = $1 AND deleted_at IS NULL`, orgId).Scan(&count); err != nil {
		return 0, errors.Wrap(err, "failed to count scim users")
	}
	return count, nil
}

func (d *databaser) UpdateScimUser(ctx context.Context, optionalTx Tx, u ScimUser) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`UPDATE scim_users SET user_name = $3, external_id = $4, active = $5, updated_at = $6 WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
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

// TombstoneScimUser implements SCIM DELETE: the row is kept with deleted_at
// set (and active forced false) so the SSO gate keeps rejecting the user, and
// its group membership rows are removed — they used to cascade away with the
// hard delete. The caller must supply a non-nil Tx so both statements land
// together with the membership removal and audit event.
func (d *databaser) TombstoneScimUser(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	now := time.Now().UTC()
	if rs, err := optionalTx.ExecContext(
		ctx,
		`UPDATE scim_users SET active = false, deleted_at = $3, updated_at = $3 WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
		orgId, id, now,
	); err != nil {
		return errors.Wrap(err, "failed to tombstone scim user")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim user not found")
	}
	if _, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM scim_group_members WHERE org_id = $1 AND scim_user_id = $2`,
		orgId, id,
	); err != nil {
		return errors.Wrap(err, "failed to remove tombstoned scim user from groups")
	}
	return nil
}

// FindScimUserByUserId is the SSO gate's lookup and deliberately sees through
// tombstones. It returns the live row if one exists, otherwise the most
// recently tombstoned row (DeletedAt set), otherwise not-found. That lets the
// caller distinguish the three governance states: never SCIM-provisioned in
// this org (not found), currently provisioned (live row, Active decides), and
// provisioned-then-deleted (tombstone → access must stay revoked).
func (d *databaser) FindScimUserByUserId(ctx context.Context, optionalTx Tx, orgId string, userId uuid.UUID) (*ScimUser, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimUser
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, org_id, user_id, user_name, external_id, active, created_at, updated_at, deleted_at
		FROM scim_users
		WHERE org_id = $1 AND user_id = $2
		ORDER BY (deleted_at IS NULL) DESC, deleted_at DESC
		LIMIT 1`,
		orgId, userId,
	).Scan(&out.Id, &out.OrgId, &out.UserId, &out.UserName, opt.Scan(&out.ExternalId), &out.Active, &out.CreatedAt, &out.UpdatedAt, opt.Scan(&out.DeletedAt)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim user not found")
		}
		return nil, errors.Wrap(err, "failed to find scim user by user id")
	}
	return &out, nil
}
