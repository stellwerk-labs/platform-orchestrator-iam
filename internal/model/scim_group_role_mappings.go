package model

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
)

// ScimGroupRoleMapping maps a SCIM group display name to the role its members
// should hold in the org. Names are matched case-insensitively but stored as
// the operator typed them.
type ScimGroupRoleMapping struct {
	OrgId            string
	GroupDisplayName string
	RoleId           uuid.UUID
	CreatedAt        time.Time
}

func (d *databaser) UpsertScimGroupRoleMapping(ctx context.Context, optionalTx Tx, orgId string, groupDisplayName string, roleId uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO scim_group_role_mappings (org_id, group_display_name, role_id, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, LOWER(group_display_name))
		DO UPDATE SET group_display_name = EXCLUDED.group_display_name, role_id = EXCLUDED.role_id`,
		orgId, groupDisplayName, roleId, time.Now().UTC(),
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "scim_group_role_mappings_role" {
			return NewErrNotFound("role not found in the organization")
		}
		return errors.Wrap(err, "failed to upsert scim group role mapping")
	}
	return nil
}

func (d *databaser) DeleteScimGroupRoleMapping(ctx context.Context, optionalTx Tx, orgId string, groupDisplayName string) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM scim_group_role_mappings WHERE org_id = $1 AND LOWER(group_display_name) = LOWER($2)`,
		orgId, groupDisplayName,
	); err != nil {
		return errors.Wrap(err, "failed to delete scim group role mapping")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("scim group role mapping not found")
	}
	return nil
}

func (d *databaser) ListScimGroupRoleMappings(ctx context.Context, optionalTx Tx, orgId string) ([]ScimGroupRoleMapping, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT org_id, group_display_name, role_id, created_at FROM scim_group_role_mappings WHERE org_id = $1 ORDER BY group_display_name ASC`,
		orgId,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list scim group role mappings")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]ScimGroupRoleMapping, 0)
		for rs.Next() {
			var item ScimGroupRoleMapping
			if err := rs.Scan(&item.OrgId, &item.GroupDisplayName, &item.RoleId, &item.CreatedAt); err != nil {
				return nil, errors.Wrap(err, "failed to scan scim group role mapping")
			}
			out = append(out, item)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate scim group role mappings")
		}
		return out, nil
	}
}

// ListRoleIdsForScimUserGroups returns the distinct role ids mapped (via
// scim_group_role_mappings, matched case-insensitively on group display name)
// to the groups the SCIM user is a member of.
func (d *databaser) ListRoleIdsForScimUserGroups(ctx context.Context, optionalTx Tx, orgId string, scimUserId uuid.UUID) ([]uuid.UUID, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT DISTINCT m.role_id
		FROM scim_group_members gm
		JOIN scim_groups g ON gm.group_id = g.id
		JOIN scim_group_role_mappings m ON m.org_id = g.org_id AND LOWER(m.group_display_name) = LOWER(g.display_name)
		WHERE gm.org_id = $1 AND gm.scim_user_id = $2`,
		orgId, scimUserId,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list role ids for scim user groups")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]uuid.UUID, 0)
		for rs.Next() {
			var id uuid.UUID
			if err := rs.Scan(&id); err != nil {
				return nil, errors.Wrap(err, "failed to scan mapped role id")
			}
			out = append(out, id)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate mapped role ids")
		}
		return out, nil
	}
}

// ListScimUserIdsInGroupByDisplayName returns the ids of the SCIM users that
// are currently members of a group whose display name matches the given name
// case-insensitively. Used when a group→role mapping changes: the members of
// the affected group must be reconciled right away, not at the next sync.
func (d *databaser) ListScimUserIdsInGroupByDisplayName(ctx context.Context, optionalTx Tx, orgId string, groupDisplayName string) ([]uuid.UUID, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT gm.scim_user_id
		FROM scim_group_members gm
		JOIN scim_groups g ON gm.group_id = g.id
		WHERE g.org_id = $1 AND LOWER(g.display_name) = LOWER($2)`,
		orgId, groupDisplayName,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list scim user ids in group by display name")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]uuid.UUID, 0)
		for rs.Next() {
			var id uuid.UUID
			if err := rs.Scan(&id); err != nil {
				return nil, errors.Wrap(err, "failed to scan scim user id")
			}
			out = append(out, id)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate scim user ids")
		}
		return out, nil
	}
}

// CreateScimManagedMembership records that a membership was created by SCIM
// group→role reconciliation, so reconciliation may later remove it. Memberships
// without such a record are human-made and reconciliation never touches them.
func (d *databaser) CreateScimManagedMembership(ctx context.Context, optionalTx Tx, membershipId uuid.UUID, scimUserId uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO scim_managed_memberships (membership_id, scim_user_id) VALUES ($1, $2)`,
		membershipId, scimUserId,
	); err != nil {
		return errors.Wrap(err, "failed to insert scim managed membership")
	}
	return nil
}

func (d *databaser) ListScimManagedMembershipIds(ctx context.Context, optionalTx Tx, scimUserId uuid.UUID) ([]uuid.UUID, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT membership_id FROM scim_managed_memberships WHERE scim_user_id = $1`,
		scimUserId,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list scim managed membership ids")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]uuid.UUID, 0)
		for rs.Next() {
			var id uuid.UUID
			if err := rs.Scan(&id); err != nil {
				return nil, errors.Wrap(err, "failed to scan scim managed membership id")
			}
			out = append(out, id)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate scim managed membership ids")
		}
		return out, nil
	}
}
