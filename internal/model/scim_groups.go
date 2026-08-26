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

type ScimGroup struct {
	Id          uuid.UUID
	OrgId       string
	DisplayName string
	ExternalId  opt.Opt[string]
	CreatedAt   time.Time
	UpdatedAt   time.Time
	MemberIds   []uuid.UUID // scim_users.id values
}

func (d *databaser) CreateScimGroup(ctx context.Context, optionalTx Tx, g ScimGroup) error {
	optionalTx = d.txOrDb(optionalTx)
	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO scim_groups (id, org_id, display_name, external_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		g.Id, g.OrgId, g.DisplayName, g.ExternalId.Ref(), g.CreatedAt, g.UpdatedAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "unique_scim_group_name" {
			return NewErrConflict("scim group display name already exists in org")
		}
		return errors.Wrap(err, "failed to insert scim group")
	}
	if len(g.MemberIds) > 0 {
		if err := insertScimGroupMembers(ctx, optionalTx, g.OrgId, g.Id, g.MemberIds); err != nil {
			return err
		}
	}
	return nil
}

func (d *databaser) GetScimGroup(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*ScimGroup, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimGroup
	var memberIdStrings pq.StringArray
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(su.id::text ORDER BY su.id) FILTER (WHERE su.id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
		LEFT JOIN scim_users su ON su.id = m.scim_user_id AND su.deleted_at IS NULL
		WHERE g.org_id = $1 AND g.id = $2
		GROUP BY g.id`,
		orgId, id,
	).Scan(&out.Id, &out.OrgId, &out.DisplayName, opt.Scan(&out.ExternalId), &out.CreatedAt, &out.UpdatedAt, &memberIdStrings); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim group not found")
		}
		return nil, errors.Wrap(err, "failed to get scim group")
	}
	if err := parseScimMemberIds(memberIdStrings, &out.MemberIds); err != nil {
		return nil, err
	}
	return &out, nil
}

// FindScimGroupByDisplayName matches case-insensitively: /Schemas advertises
// displayName with caseExact=false, and migration 000035 enforces uniqueness
// on LOWER(display_name), so at most one group can match.
func (d *databaser) FindScimGroupByDisplayName(ctx context.Context, optionalTx Tx, orgId string, displayName string) (*ScimGroup, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimGroup
	var memberIdStrings pq.StringArray
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(su.id::text ORDER BY su.id) FILTER (WHERE su.id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
		LEFT JOIN scim_users su ON su.id = m.scim_user_id AND su.deleted_at IS NULL
		WHERE g.org_id = $1 AND LOWER(g.display_name) = LOWER($2)
		GROUP BY g.id`,
		orgId, displayName,
	).Scan(&out.Id, &out.OrgId, &out.DisplayName, opt.Scan(&out.ExternalId), &out.CreatedAt, &out.UpdatedAt, &memberIdStrings); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim group not found")
		}
		return nil, errors.Wrap(err, "failed to find scim group by display name")
	}
	if err := parseScimMemberIds(memberIdStrings, &out.MemberIds); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *databaser) FindScimGroupByExternalId(ctx context.Context, optionalTx Tx, orgId string, externalId string) (*ScimGroup, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimGroup
	var memberIdStrings pq.StringArray
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(su.id::text ORDER BY su.id) FILTER (WHERE su.id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
		LEFT JOIN scim_users su ON su.id = m.scim_user_id AND su.deleted_at IS NULL
		WHERE g.org_id = $1 AND g.external_id = $2
		GROUP BY g.id`,
		orgId, externalId,
	).Scan(&out.Id, &out.OrgId, &out.DisplayName, opt.Scan(&out.ExternalId), &out.CreatedAt, &out.UpdatedAt, &memberIdStrings); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("scim group not found")
		}
		return nil, errors.Wrap(err, "failed to find scim group by external id")
	}
	if err := parseScimMemberIds(memberIdStrings, &out.MemberIds); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *databaser) ListScimGroups(ctx context.Context, optionalTx Tx, orgId string, limit int, offset int) ([]ScimGroup, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(su.id::text ORDER BY su.id) FILTER (WHERE su.id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
		LEFT JOIN scim_users su ON su.id = m.scim_user_id AND su.deleted_at IS NULL
		WHERE g.org_id = $1
		GROUP BY g.id
		ORDER BY g.created_at ASC
		LIMIT $2 OFFSET $3`,
		orgId, limit, offset,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list scim groups")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]ScimGroup, 0)
		for rs.Next() {
			var item ScimGroup
			var memberIdStrings pq.StringArray
			if err := rs.Scan(&item.Id, &item.OrgId, &item.DisplayName, opt.Scan(&item.ExternalId), &item.CreatedAt, &item.UpdatedAt, &memberIdStrings); err != nil {
				return nil, errors.Wrap(err, "failed to scan scim group")
			}
			if err := parseScimMemberIds(memberIdStrings, &item.MemberIds); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate scim groups")
		}
		return out, nil
	}
}

func (d *databaser) CountScimGroups(ctx context.Context, optionalTx Tx, orgId string) (int, error) {
	optionalTx = d.txOrDb(optionalTx)
	var count int
	if err := optionalTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_groups WHERE org_id = $1`, orgId).Scan(&count); err != nil {
		return 0, errors.Wrap(err, "failed to count scim groups")
	}
	return count, nil
}

// UpdateScimGroup updates the group row and atomically replaces the full member set.
// The caller must supply a non-nil Tx so the row update and member replacement are atomic.
func (d *databaser) UpdateScimGroup(ctx context.Context, optionalTx Tx, g ScimGroup) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`UPDATE scim_groups SET display_name = $3, external_id = $4, updated_at = $5 WHERE org_id = $1 AND id = $2`,
		g.OrgId, g.Id, g.DisplayName, g.ExternalId.Ref(), g.UpdatedAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "unique_scim_group_name" {
			return NewErrConflict("scim group display name already exists in org")
		}
		return errors.Wrap(err, "failed to update scim group")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim group not found")
	}

	if _, err := optionalTx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, g.Id); err != nil {
		return errors.Wrap(err, "failed to clear scim group members")
	}
	if len(g.MemberIds) > 0 {
		if err := insertScimGroupMembers(ctx, optionalTx, g.OrgId, g.Id, g.MemberIds); err != nil {
			return err
		}
	}
	return nil
}

func (d *databaser) DeleteScimGroup(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(ctx, `DELETE FROM scim_groups WHERE org_id = $1 AND id = $2`, orgId, id); err != nil {
		return errors.Wrap(err, "failed to delete scim group")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim group not found")
	}
	return nil
}

// insertScimGroupMembers adds members to a group, accepting only live SCIM
// users of the same organization (a tombstoned user is a stale id, not a
// member). Selecting the members through scim_users means a foreign or stale
// id is reported as a bad request instead of surfacing as a constraint
// violation. Duplicate ids in the input are collapsed.
func insertScimGroupMembers(ctx context.Context, tx Tx, orgId string, groupId uuid.UUID, memberIds []uuid.UUID) error {
	seen := make(map[uuid.UUID]struct{}, len(memberIds))
	memberStrings := make([]string, 0, len(memberIds))
	for _, id := range memberIds {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		memberStrings = append(memberStrings, id.String())
	}
	if len(memberStrings) == 0 {
		return nil
	}
	rs, err := tx.ExecContext(
		ctx,
		`INSERT INTO scim_group_members (group_id, org_id, scim_user_id)
		SELECT $1, $2, u.id FROM scim_users u WHERE u.org_id = $2 AND u.id = ANY($3::uuid[]) AND u.deleted_at IS NULL`,
		groupId, orgId, pq.Array(memberStrings),
	)
	if err != nil {
		return errors.Wrap(err, "failed to insert scim group members")
	}
	if rc, _ := rs.RowsAffected(); rc != int64(len(memberStrings)) {
		return NewErrBadRequest("one or more group members do not exist in this organization")
	}
	return nil
}

func parseScimMemberIds(raw pq.StringArray, out *[]uuid.UUID) error {
	result := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return errors.Wrap(err, "invalid scim group member id")
		}
		result = append(result, id)
	}
	*out = result
	return nil
}

// LockScimGroup takes a row lock on the group for the remainder of the
// transaction. Callers that read-modify-write the member set must hold it,
// otherwise two concurrent PATCHes each compute their new set from the same
// baseline and the second one silently drops the first one's change.
//
// It is a separate statement because GetScimGroup aggregates members with
// GROUP BY, and Postgres rejects FOR UPDATE alongside GROUP BY.
func (d *databaser) LockScimGroup(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	var found uuid.UUID
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id FROM scim_groups WHERE org_id = $1 AND id = $2 FOR UPDATE`,
		orgId, id,
	).Scan(&found); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NewErrNotFound("scim group not found")
		}
		return errors.Wrap(err, "failed to lock scim group")
	}
	return nil
}
