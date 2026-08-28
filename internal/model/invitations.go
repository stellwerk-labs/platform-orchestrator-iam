package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

type Invitation struct {
	OrgId                        string
	Id                           uuid.UUID
	CreatedAt                    time.Time
	ExpiresAt                    time.Time
	CreatedBy                    uuid.UUID
	CreatedByDisplayName         string
	CreatedByPrimaryEmailAddress opt.Opt[string]
	RedemptionTokenSha256Hash    []byte
	EmailAddress                 string
	MembershipSubjectType        MembershipSubjectType
	MembershipSubject            string
}

func (d *databaser) CreateInvitation(ctx context.Context, optionalTx Tx, request *Invitation) (*Invitation, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO invitations (id, org_id, created_at, expires_at, created_by, redemption_token_hash, email_address, membership_subject_type, membership_subject) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at, expires_at`,
		request.Id, request.OrgId, request.CreatedAt, request.ExpiresAt, request.CreatedBy, request.RedemptionTokenSha256Hash, request.EmailAddress, request.MembershipSubjectType, request.MembershipSubject,
	).Scan(&out.CreatedAt, &out.ExpiresAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert invitation")
	}
	return &out, nil
}

func (d *databaser) GetInvitation(ctx context.Context, optionalTx Tx, id uuid.UUID) (*Invitation, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := Invitation{Id: id}
	userDisplayName := opt.Empty[string]()
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT i.org_id, i.created_at, i.expires_at, i.created_by, i.redemption_token_hash, i.email_address, i.membership_subject_type, i.membership_subject, u.display_name, u.primary_email_address FROM invitations i LEFT JOIN users u ON i.created_by = u.id WHERE i.id = $1`,
		id,
	).Scan(&out.OrgId, &out.CreatedAt, &out.ExpiresAt, &out.CreatedBy, &out.RedemptionTokenSha256Hash, &out.EmailAddress, &out.MembershipSubjectType, &out.MembershipSubject, opt.Scan(&userDisplayName), opt.Scan(&out.CreatedByPrimaryEmailAddress)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("invitation not found")
		}
		return nil, errors.Wrap(err, "failed to get invitation")
	}
	out.CreatedByDisplayName = userDisplayName.Or(userid.GenerateDisplayNameForUserId(out.CreatedBy))
	return &out, nil
}

func (d *databaser) ListInvitations(ctx context.Context, optionalTx Tx, orgId string) ([]Invitation, error) {
	optionalTx = d.txOrDb(optionalTx)
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)

	if res, err := optionalTx.QueryContext(
		ctx,
		`SELECT i.id, i.created_at, i.expires_at, i.created_by, i.redemption_token_hash, i.email_address, i.membership_subject_type, i.membership_subject, u.display_name, u.primary_email_address FROM invitations i LEFT JOIN users u ON i.created_by = u.id WHERE i.org_id = $1 ORDER BY i.created_at`,
		orgId,
	); err != nil {
		return nil, errors.Wrap(err, "failed to list invitations")
	} else {
		defer func() {
			if err := res.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]Invitation, 0)
		for res.Next() {
			invitation := Invitation{OrgId: orgId}
			userDisplayName := opt.Empty[string]()
			if err := res.Scan(&invitation.Id, &invitation.CreatedAt, &invitation.ExpiresAt, &invitation.CreatedBy, &invitation.RedemptionTokenSha256Hash, &invitation.EmailAddress, &invitation.MembershipSubjectType, &invitation.MembershipSubject, opt.Scan(&userDisplayName), opt.Scan(&invitation.CreatedByPrimaryEmailAddress)); err != nil {
				return nil, errors.Wrap(err, "failed to scan invitation")
			}
			invitation.CreatedByDisplayName = userDisplayName.Or(userid.GenerateDisplayNameForUserId(invitation.CreatedBy))
			out = append(out, invitation)
		}
		if err := res.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate rows")
		}
		return out, nil
	}
}

func (d *databaser) DeleteInvitation(ctx context.Context, optionalTx Tx, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if res, err := optionalTx.ExecContext(ctx, `DELETE FROM invitations WHERE id = $1`, id); err != nil {
		return errors.Wrap(err, "failed to delete invitation")
	} else if rc, _ := res.RowsAffected(); rc == 0 {
		return NewErrNotFound("invitation not found")
	}
	return nil
}

// DeleteInvitationsForScimUser revokes pending invitations addressed to the
// user's current primary email or an email-shaped SCIM userName. An invitation
// is a bearer credential that creates a membership, so leaving it alive after
// SCIM deprovisioning would provide a route straight back into the organization.
func (d *databaser) DeleteInvitationsForScimUser(ctx context.Context, optionalTx Tx, orgId string, userId uuid.UUID, userName string) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	res, err := optionalTx.ExecContext(
		ctx,
		`DELETE FROM invitations i
		USING users u
		WHERE u.id = $2
		  AND i.org_id = $1
		  AND (
			LOWER(i.email_address) = LOWER(u.primary_email_address)
			OR (STRPOS($3, '@') > 1 AND LOWER(i.email_address) = LOWER($3))
		  )`,
		orgId, userId, userName,
	)
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete invitations for scim user")
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get deleted invitation count")
	}
	return rowsAffected, nil
}

func (d *databaser) DeleteExpiredInvitations(ctx context.Context, optionalTx Tx) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	rs, err := optionalTx.ExecContext(ctx, `DELETE FROM invitations WHERE expires_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete expired invitations")
	}

	rowsAffected, err := rs.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get rows affected")
	}

	return rowsAffected, nil
}
