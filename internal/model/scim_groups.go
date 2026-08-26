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
		if err := insertScimGroupMembers(ctx, optionalTx, g.Id, g.MemberIds); err != nil {
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
			COALESCE(ARRAY_AGG(m.scim_user_id::text ORDER BY m.scim_user_id) FILTER (WHERE m.scim_user_id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
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

func (d *databaser) FindScimGroupByDisplayName(ctx context.Context, optionalTx Tx, orgId string, displayName string) (*ScimGroup, error) {
	optionalTx = d.txOrDb(optionalTx)
	var out ScimGroup
	var memberIdStrings pq.StringArray
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(m.scim_user_id::text ORDER BY m.scim_user_id) FILTER (WHERE m.scim_user_id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
		WHERE g.org_id = $1 AND g.display_name = $2
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

func (d *databaser) ListScimGroups(ctx context.Context, optionalTx Tx, orgId string, limit int, offset int) ([]ScimGroup, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT g.id, g.org_id, g.display_name, g.external_id, g.created_at, g.updated_at,
			COALESCE(ARRAY_AGG(m.scim_user_id::text ORDER BY m.scim_user_id) FILTER (WHERE m.scim_user_id IS NOT NULL), '{}')
		FROM scim_groups g
		LEFT JOIN scim_group_members m ON g.id = m.group_id
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
		if err := insertScimGroupMembers(ctx, optionalTx, g.Id, g.MemberIds); err != nil {
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

func insertScimGroupMembers(ctx context.Context, tx Tx, groupId uuid.UUID, memberIds []uuid.UUID) error {
	memberStrings := make([]string, len(memberIds))
	for i, id := range memberIds {
		memberStrings[i] = id.String()
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO scim_group_members (group_id, scim_user_id) SELECT $1, unnest($2::uuid[])`,
		groupId, pq.Array(memberStrings),
	); err != nil {
		return errors.Wrap(err, "failed to insert scim group members")
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
