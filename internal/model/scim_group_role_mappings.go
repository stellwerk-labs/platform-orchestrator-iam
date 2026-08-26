package model

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
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
		JOIN scim_users su ON su.id = gm.scim_user_id AND su.deleted_at IS NULL
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

// ListRoleIdsForScimUsersGroups is the multi-user form of
// ListRoleIdsForScimUserGroups: one query returning, per SCIM user, the
// distinct role ids mapped to the groups that user is in. Users with no mapped
// roles have no entry in the result map.
func (d *databaser) ListRoleIdsForScimUsersGroups(ctx context.Context, optionalTx Tx, orgId string, scimUserIds []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	out := make(map[uuid.UUID][]uuid.UUID, len(scimUserIds))
	if len(scimUserIds) == 0 {
		return out, nil
	}
	idStrings := make([]string, 0, len(scimUserIds))
	for _, id := range scimUserIds {
		idStrings = append(idStrings, id.String())
	}
	rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT DISTINCT gm.scim_user_id, m.role_id
		FROM scim_group_members gm
		JOIN scim_users su ON su.id = gm.scim_user_id AND su.deleted_at IS NULL
		JOIN scim_groups g ON gm.group_id = g.id
		JOIN scim_group_role_mappings m ON m.org_id = g.org_id AND LOWER(m.group_display_name) = LOWER(g.display_name)
		WHERE gm.org_id = $1 AND gm.scim_user_id = ANY($2::uuid[])`,
		orgId, pq.Array(idStrings),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list role ids for scim users groups")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			logger.Error("failed to close row set", zap.Error(err))
		}
	}()
	for rs.Next() {
		var scimUserId, roleId uuid.UUID
		if err := rs.Scan(&scimUserId, &roleId); err != nil {
			return nil, errors.Wrap(err, "failed to scan mapped role id")
		}
		out[scimUserId] = append(out[scimUserId], roleId)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate mapped role ids")
	}
	return out, nil
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
		JOIN scim_users su ON su.id = gm.scim_user_id AND su.deleted_at IS NULL
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

// ScimManagedMembership is one SCIM-managed membership row joined with the
// role the membership grants, as returned by
// ListScimManagedMembershipsForScimUsers. The role is optional in the schema
// (memberships.role is nullable), though SCIM-managed memberships always carry
// one in practice.
type ScimManagedMembership struct {
	ScimUserId   uuid.UUID
	MembershipId uuid.UUID
	RoleId       opt.Opt[uuid.UUID]
}

// ListScimManagedMembershipsForScimUsers is the multi-user form of
// ListScimManagedMembershipIds, with the membership's role joined in so the
// bulk reconciler does not need a GetMembership per row.
func (d *databaser) ListScimManagedMembershipsForScimUsers(ctx context.Context, optionalTx Tx, scimUserIds []uuid.UUID) ([]ScimManagedMembership, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if len(scimUserIds) == 0 {
		return []ScimManagedMembership{}, nil
	}
	idStrings := make([]string, 0, len(scimUserIds))
	for _, id := range scimUserIds {
		idStrings = append(idStrings, id.String())
	}
	rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT smm.scim_user_id, smm.membership_id, m.role
		FROM scim_managed_memberships smm
		JOIN memberships m ON m.id = smm.membership_id
		WHERE smm.scim_user_id = ANY($1::uuid[])`,
		pq.Array(idStrings),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list scim managed memberships for scim users")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			logger.Error("failed to close row set", zap.Error(err))
		}
	}()
	out := make([]ScimManagedMembership, 0)
	for rs.Next() {
		var item ScimManagedMembership
		if err := rs.Scan(&item.ScimUserId, &item.MembershipId, opt.Scan(&item.RoleId)); err != nil {
			return nil, errors.Wrap(err, "failed to scan scim managed membership")
		}
		out = append(out, item)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate scim managed memberships")
	}
	return out, nil
}

// NewScimManagedMembership is one membership the bulk reconciler wants to
// create and record as SCIM-managed.
type NewScimManagedMembership struct {
	Membership Membership
	ScimUserId uuid.UUID
}

// BulkCreateScimManagedMemberships inserts the given memberships and records
// each successfully inserted one as SCIM-managed, in two statements total.
//
// Conflict semantics match the per-user reconciler exactly: when a membership
// already exists (a human granted the same role), the insert is skipped via ON
// CONFLICT DO NOTHING and NO scim_managed_memberships row is written — the
// grant stays human-owned, so a later group removal cannot revoke it.
func (d *databaser) BulkCreateScimManagedMemberships(ctx context.Context, optionalTx Tx, items []NewScimManagedMembership) error {
	optionalTx = d.txOrDb(optionalTx)
	if len(items) == 0 {
		return nil
	}
	ids := make([]string, 0, len(items))
	createdAts := make([]time.Time, 0, len(items))
	userIds := make([]string, 0, len(items))
	orgIds := make([]string, 0, len(items))
	subjectTypes := make([]string, 0, len(items))
	subjects := make([]string, 0, len(items))
	roleIds := make([]*string, 0, len(items))
	scopes := make([]string, 0, len(items))
	scimUserIdByMembershipId := make(map[uuid.UUID]uuid.UUID, len(items))
	for _, item := range items {
		m := item.Membership
		ids = append(ids, m.Id.String())
		createdAts = append(createdAts, m.CreatedAt)
		userIds = append(userIds, m.UserId.String())
		orgIds = append(orgIds, m.OrgId)
		subjectTypes = append(subjectTypes, string(m.SubjectType))
		subjects = append(subjects, m.Subject)
		var roleId *string
		if m.Role.IsSet() {
			roleIdString := m.Role.Must().String()
			roleId = &roleIdString
		}
		roleIds = append(roleIds, roleId)
		scopes = append(scopes, m.Scope)
		scimUserIdByMembershipId[m.Id] = item.ScimUserId
	}

	insertedMembershipIds, err := insertMembershipsSkippingConflicts(ctx, d.logger, optionalTx, ids, createdAts, userIds, orgIds, subjectTypes, subjects, roleIds, scopes)
	if err != nil {
		return err
	}
	if len(insertedMembershipIds) == 0 {
		return nil
	}
	insertedIdStrings := make([]string, 0, len(insertedMembershipIds))
	insertedScimUserIds := make([]string, 0, len(insertedMembershipIds))
	for _, membershipId := range insertedMembershipIds {
		insertedIdStrings = append(insertedIdStrings, membershipId.String())
		insertedScimUserIds = append(insertedScimUserIds, scimUserIdByMembershipId[membershipId].String())
	}

	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO scim_managed_memberships (membership_id, scim_user_id)
		SELECT unnest($1::uuid[]), unnest($2::uuid[])`,
		pq.Array(insertedIdStrings), pq.Array(insertedScimUserIds),
	); err != nil {
		return errors.Wrap(err, "failed to bulk insert scim managed membership records")
	}
	return nil
}

// insertMembershipsSkippingConflicts runs the unnest-based bulk membership
// insert and returns the ids that were actually inserted (conflicting rows —
// existing human grants — are skipped by ON CONFLICT DO NOTHING and therefore
// not returned).
func insertMembershipsSkippingConflicts(ctx context.Context, logger *zap.Logger, tx Tx, ids []string, createdAts []time.Time, userIds, orgIds, subjectTypes, subjects []string, roleIds []*string, scopes []string) ([]uuid.UUID, error) {
	scopedLogger := hlogger.TraceScopedLoggerFromCtx(logger, ctx)
	rs, err := tx.QueryContext(
		ctx,
		`INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role, scope)
		SELECT unnest($1::uuid[]), unnest($2::timestamptz[]), unnest($3::uuid[]), unnest($4::text[]), unnest($5::membership_subject_type[]), unnest($6::text[]), unnest($7::uuid[]), unnest($8::text[])
		ON CONFLICT ON CONSTRAINT unique_membership_scope DO NOTHING
		RETURNING id`,
		pq.Array(ids), pq.Array(createdAts), pq.Array(userIds), pq.Array(orgIds), pq.Array(subjectTypes), pq.Array(subjects), pq.Array(roleIds), pq.Array(scopes),
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "fk_memberships_role_org_id" {
			return nil, NewErrNotFound("role not found in the organization")
		}
		return nil, errors.Wrap(err, "failed to bulk insert scim managed memberships")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			scopedLogger.Error("failed to close row set", zap.Error(err))
		}
	}()
	inserted := make([]uuid.UUID, 0, len(ids))
	for rs.Next() {
		var membershipId uuid.UUID
		if err := rs.Scan(&membershipId); err != nil {
			return nil, errors.Wrap(err, "failed to scan inserted membership id")
		}
		inserted = append(inserted, membershipId)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate inserted membership ids")
	}
	return inserted, nil
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
