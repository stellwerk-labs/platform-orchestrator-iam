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
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/pagination"
)

type MembershipSubjectType string

var membersPageTokenCodec = pagination.PageTokenCodec{Parts: 2}

const defaultMembersPerPage = 100

const (
	MembershipSubjectTypeRole MembershipSubjectType = "role"

	MembershipSubjectOrganizationOwners = "owners"
)

type Membership struct {
	Id          uuid.UUID
	CreatedAt   time.Time
	UserId      uuid.UUID
	OrgId       string
	SubjectType MembershipSubjectType
	Subject     string
	Role        opt.Opt[uuid.UUID]
	Scope       string
}

type MembershipWithUserMetadata struct {
	Membership
	UserDisplayName         string
	UserPrimaryEmailAddress opt.Opt[string]
}

type MembershipWithIdentityProvider struct {
	Membership
	UserDisplayName         string
	UserPrimaryEmailAddress opt.Opt[string]
	UserIdentities          map[UserIdentityProvider]string
}

func (d *databaser) CreateMembership(ctx context.Context, optionalTx Tx, request *Membership) (*Membership, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request

	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role, scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at`,
		request.Id, request.CreatedAt, request.UserId, request.OrgId, request.SubjectType, request.Subject, request.Role.Ref(), request.Scope,
	).Scan(&out.CreatedAt); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Constraint == "fk_memberships_role_org_id" {
				return nil, NewErrNotFound("role not found in the organization")
			}
			if pqErr.Constraint == "unique_membership_scope" {
				return nil, NewErrConflict("duplicate membership")
			}
		}
		return nil, errors.Wrap(err, "failed to insert membership")
	}

	return &out, nil
}

func (d *databaser) GetMembership(ctx context.Context, optionalTx Tx, id uuid.UUID) (*Membership, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := Membership{Id: id}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT created_at, user_id, org_id, subject_type, subject, role, scope FROM memberships WHERE id = $1`,
		id,
	).Scan(&out.CreatedAt, &out.UserId, &out.OrgId, &out.SubjectType, &out.Subject, opt.Scan(&out.Role), &out.Scope); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("membership not found")
		}
		return nil, errors.Wrap(err, "failed to get membership")
	}
	return &out, nil
}

type ListMembershipsParams struct {
	UserId      *uuid.UUID
	OrgId       *string
	SubjectType *MembershipSubjectType
	Subject     *string
	PageToken   string
	PerPage     int
}

func (d *databaser) HasMemberships(ctx context.Context, optionalTx Tx, orgId string) (bool, error) {
	optionalTx = d.txOrDb(optionalTx)
	var exists bool
	if err := optionalTx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id = $1)`,
		orgId,
	).Scan(&exists); err != nil {
		return false, errors.Wrap(err, "failed to check memberships existence")
	}
	return exists, nil
}

func (d *databaser) ListMemberships(ctx context.Context, optionalTx Tx, params ListMembershipsParams) ([]MembershipWithUserMetadata, error) {
	if params.UserId == nil && params.OrgId == nil {
		return nil, errors.New("must specify at least user_id or org_id")
	} else if params.Subject != nil && params.SubjectType == nil {
		return nil, errors.New("subject_type must be specified when subject is specified")
	}

	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)

	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT m.id, m.created_at, m.user_id, m.org_id, m.subject_type, m.subject, m.role, m.scope, u.display_name, u.primary_email_address FROM memberships m INNER JOIN users u ON m.user_id = u.id WHERE
		($1::uuid IS NULL OR m.user_id = $1)
		AND ($2::text IS NULL OR m.org_id = $2)
        AND ($3::membership_subject_type IS NULL OR m.subject_type = $3)
		AND ($4::text IS NULL OR m.subject = $4)
		ORDER BY created_at ASC
		`,
		params.UserId, params.OrgId, params.SubjectType, params.Subject,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list memberships")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]MembershipWithUserMetadata, 0)
		for rs.Next() {
			var outItem MembershipWithUserMetadata
			if err := rs.Scan(&outItem.Id, &outItem.CreatedAt, &outItem.UserId, &outItem.OrgId, &outItem.SubjectType, &outItem.Subject, opt.Scan(&outItem.Role), &outItem.Scope, &outItem.UserDisplayName, opt.Scan(&outItem.UserPrimaryEmailAddress)); err != nil {
				return nil, errors.Wrap(err, "failed to scan membership")
			}
			out = append(out, outItem)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate rows")
		}
		return out, nil
	}
}

func (d *databaser) ListMembersWithIdentities(ctx context.Context, optionalTx Tx, params ListMembershipsParams) ([]MembershipWithIdentityProvider, string, error) {
	if params.UserId == nil && params.OrgId == nil {
		return nil, "", errors.New("must specify at least user_id or org_id")
	} else if params.Subject != nil && params.SubjectType == nil {
		return nil, "", errors.New("subject_type must be specified when subject is specified")
	}

	perPage := params.PerPage
	if perPage <= 0 {
		perPage = defaultMembersPerPage
	}

	parts, parseErr := membersPageTokenCodec.Parse(params.PageToken)
	if parseErr != nil {
		return nil, "", NewErrBadRequest(parseErr.Error())
	}

	var cursorTime *time.Time
	var cursorUUID *uuid.UUID
	if parts[0] != "" {
		t, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return nil, "", NewErrBadRequest("invalid page token")
		}
		id, err := uuid.Parse(parts[1])
		if err != nil {
			return nil, "", NewErrBadRequest("invalid page token")
		}
		cursorTime = &t
		cursorUUID = &id
	}

	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)

	if rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT
			m.id,
			m.created_at,
			m.user_id,
			m.org_id,
			m.subject_type,
			m.subject,
			m.role,
			u.display_name,
			u.primary_email_address,
			COALESCE(json_object_agg(i.provider, i.provider_user_id) FILTER (WHERE i.user_id IS NOT NULL), '{}') AS identities
		FROM memberships m
		INNER JOIN users u ON m.user_id = u.id
		LEFT JOIN identities i ON m.user_id = i.user_id
		WHERE m.scope = ''
		AND ($1::uuid IS NULL OR m.user_id = $1)
		AND ($2::text IS NULL OR m.org_id = $2)
		AND ($3::membership_subject_type IS NULL OR m.subject_type = $3)
		AND ($4::text IS NULL OR m.subject = $4)
		AND ($5::timestamptz IS NULL OR (m.created_at, m.id) > ($5::timestamptz, $6::uuid))
		GROUP BY m.id, u.id
		ORDER BY m.created_at ASC, m.id ASC
		LIMIT $7
		`,
		params.UserId, params.OrgId, params.SubjectType, params.Subject, cursorTime, cursorUUID, perPage+1,
	); err != nil {
		return nil, "", errors.Wrap(err, "failed to list unscoped memberships")
	} else {
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]MembershipWithIdentityProvider, 0)
		for rs.Next() {
			outItem := MembershipWithIdentityProvider{UserIdentities: make(map[UserIdentityProvider]string)}
			if err := rs.Scan(&outItem.Id, &outItem.CreatedAt, &outItem.UserId, &outItem.OrgId, &outItem.SubjectType, &outItem.Subject, opt.Scan(&outItem.Role), &outItem.UserDisplayName, opt.Scan(&outItem.UserPrimaryEmailAddress), asJson(&outItem.UserIdentities)); err != nil {
				return nil, "", errors.Wrap(err, "failed to scan membership")
			}
			out = append(out, outItem)
		}
		if err := rs.Err(); err != nil {
			return nil, "", errors.Wrap(err, "failed to iterate rows")
		}

		var nextPageToken string
		if len(out) > perPage {
			next := out[perPage]
			nextPageToken = membersPageTokenCodec.Generate(
				next.CreatedAt.UTC().Format(time.RFC3339Nano),
				next.Id.String(),
			)
			out = out[:perPage]
		}

		return out, nextPageToken, nil
	}
}

// ListRoleMembershipIdsByUser returns, per user, the ids of the user's
// role-subject memberships in the org — one query for many users. The bulk
// SCIM reconciler uses it to decide the Viewer fallback: a user with a
// role membership that is NOT SCIM-managed has a human-made grant, and the
// fallback must not pile Viewer on top of it.
func (d *databaser) ListRoleMembershipIdsByUser(ctx context.Context, optionalTx Tx, orgId string, userIds []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	out := make(map[uuid.UUID][]uuid.UUID, len(userIds))
	if len(userIds) == 0 {
		return out, nil
	}
	idStrings := make([]string, 0, len(userIds))
	for _, id := range userIds {
		idStrings = append(idStrings, id.String())
	}
	rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT user_id, id FROM memberships WHERE org_id = $1 AND subject_type = $2 AND user_id = ANY($3::uuid[])`,
		orgId, MembershipSubjectTypeRole, pq.Array(idStrings),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list role membership ids by user")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			logger.Error("failed to close row set", zap.Error(err))
		}
	}()
	for rs.Next() {
		var userId, membershipId uuid.UUID
		if err := rs.Scan(&userId, &membershipId); err != nil {
			return nil, errors.Wrap(err, "failed to scan membership id")
		}
		out[userId] = append(out[userId], membershipId)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate membership ids")
	}
	return out, nil
}

// DeleteMembershipsByIds deletes the given memberships in one statement. Ids
// that no longer exist are ignored — the bulk SCIM reconciler computes its
// delete set inside the same transaction, so a miss can only mean the row was
// already gone. The org_id predicate is defense in depth: the callers only
// pass ids they resolved within orgId, but a bare delete-by-id whose id set is
// computed elsewhere is exactly the shape that turns a future refactor into a
// cross-tenant delete.
func (d *databaser) DeleteMembershipsByIds(ctx context.Context, optionalTx Tx, orgId string, ids []uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if len(ids) == 0 {
		return nil
	}
	idStrings := make([]string, 0, len(ids))
	for _, id := range ids {
		idStrings = append(idStrings, id.String())
	}
	if _, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM memberships WHERE org_id = $1 AND id = ANY($2::uuid[])`,
		orgId, pq.Array(idStrings),
	); err != nil {
		return errors.Wrap(err, "failed to delete memberships by ids")
	}
	return nil
}

func (d *databaser) DeleteMembership(ctx context.Context, optionalTx Tx, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM memberships WHERE id = $1`,
		id,
	); err != nil {
		return errors.Wrap(err, "failed to delete membership")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("membership not found")
	}
	return nil
}

type BulkDeleteMembershipsParams struct {
	UserId opt.Opt[uuid.UUID]
	OrgId  opt.Opt[string]
	Scope  opt.Opt[string]
}

func (d *databaser) BulkDeleteMemberships(ctx context.Context, optionalTx Tx, params BulkDeleteMembershipsParams) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM memberships WHERE ($1::uuid IS NULL OR user_id = $1) AND ($2::text IS NULL OR org_id = $2) AND ($3::text IS NULL OR scope = $3)`,
		params.UserId.Ref(), params.OrgId.Ref(), params.Scope.Ref(),
	); err != nil {
		return 0, errors.Wrap(err, "failed to bulk delete memberships")
	} else {
		rc, _ := rs.RowsAffected()
		return rc, nil
	}
}
