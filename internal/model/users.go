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

type User struct {
	Id                  uuid.UUID
	DisplayName         string
	CreatedAt           time.Time
	LastLoggedInAt      *time.Time
	UserIdentities      map[UserIdentityProvider]string
	PrimaryEmailAddress opt.Opt[string]
	DismissedPrompts    []string
}

type UserIdentityProvider string

const (
	UserIdentityProviderDevice    = UserIdentityProvider("devicelogin")
	UserIdentityProviderGoogle    = UserIdentityProvider("google")
	UserIdentityProviderMicrosoft = UserIdentityProvider("microsoft")
	UserIdentityProviderScim      = UserIdentityProvider("scim")
	UserIdentityProviderSso       = UserIdentityProvider("sso")
	UserIdentityProviderTestUser  = UserIdentityProvider("testuser")
)

func (d *databaser) CreateUser(ctx context.Context, tx Tx, request *User) (*User, error) {
	if tx == nil {
		return nil, errors.New("tx is nil")
	}
	out := *request
	if err := tx.QueryRowContext(
		ctx,
		`INSERT INTO users (id, display_name, created_at, last_logged_in_at, primary_email_address) values ($1, $2, $3, $4, $5) returning created_at, last_logged_in_at`,
		request.Id,
		request.DisplayName,
		request.CreatedAt,
		request.LastLoggedInAt,
		request.PrimaryEmailAddress,
	).Scan(&out.CreatedAt, &out.LastLoggedInAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert user")
	}

	idProviders := make([]UserIdentityProvider, 0, len(request.UserIdentities))
	idProviderStrings := make([]string, 0, len(request.UserIdentities))
	for idProvider, id := range request.UserIdentities {
		idProviders = append(idProviders, idProvider)
		idProviderStrings = append(idProviderStrings, id)
	}

	if rs, err := tx.ExecContext(
		ctx,
		`INSERT INTO identities (provider, provider_user_id, user_id) SELECT unnest($1::identity_provider[]), unnest($2::text[]), $3`,
		pq.Array(idProviders), pq.Array(idProviderStrings), request.Id,
	); err != nil {
		return nil, errors.Wrap(err, "failed to insert user identities")
	} else if rc, _ := rs.RowsAffected(); int(rc) != len(request.UserIdentities) {
		return nil, errors.Errorf("failed to insert user identities - incorrect number of rows affected: %d != %d", rc, len(request.UserIdentities))
	}

	return &out, nil
}

func (d *databaser) GetUser(ctx context.Context, optionalTx Tx, id uuid.UUID) (*User, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := User{Id: id, UserIdentities: make(map[UserIdentityProvider]string), DismissedPrompts: make([]string, 0)}

	row := optionalTx.QueryRowContext(
		ctx,
		`SELECT
			u.id,
			u.display_name,
			u.created_at,
			u.last_logged_in_at,
			u.primary_email_address,
			COALESCE(
				json_object_agg(p.provider, p.provider_user_id)
				FILTER (WHERE p.user_id IS NOT NULL), '{}'
			) AS identities,
			COALESCE(
				json_agg(DISTINCT dp.id)
				FILTER (WHERE dp.id IS NOT NULL), '[]'
			) AS dismissed_prompt_ids
		FROM users u
		LEFT JOIN identities p ON u.id = p.user_id
		LEFT JOIN dismissed_prompts dp ON u.id = dp.user_id
		WHERE u.id = $1
		GROUP BY u.id`,
		id,
	)

	if err := row.Scan(&out.Id, &out.DisplayName, &out.CreatedAt, &out.LastLoggedInAt, opt.Scan(&out.PrimaryEmailAddress), asJson(&out.UserIdentities), asJson(&out.DismissedPrompts)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to scan user")
	}

	return &out, nil
}

// GetUsersByIds returns the core user records (no identities, no dismissed
// prompts) for the given ids in one query. Missing ids are simply absent from
// the result. Built for list endpoints that only need display name and email
// for many users — the SCIM /Users list used to call GetUser once per row.
func (d *databaser) GetUsersByIds(ctx context.Context, optionalTx Tx, ids []uuid.UUID) ([]User, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if len(ids) == 0 {
		return []User{}, nil
	}
	idStrings := make([]string, 0, len(ids))
	for _, id := range ids {
		idStrings = append(idStrings, id.String())
	}
	rs, err := optionalTx.QueryContext(
		ctx,
		`SELECT id, display_name, created_at, last_logged_in_at, primary_email_address FROM users WHERE id = ANY($1::uuid[])`,
		pq.Array(idStrings),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get users by ids")
	}
	defer func() {
		if err := rs.Close(); err != nil {
			logger.Error("failed to close row set", zap.Error(err))
		}
	}()
	out := make([]User, 0, len(ids))
	for rs.Next() {
		var item User
		if err := rs.Scan(&item.Id, &item.DisplayName, &item.CreatedAt, &item.LastLoggedInAt, opt.Scan(&item.PrimaryEmailAddress)); err != nil {
			return nil, errors.Wrap(err, "failed to scan user")
		}
		out = append(out, item)
	}
	if err := rs.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate users")
	}
	return out, nil
}

func (d *databaser) DeleteUser(ctx context.Context, optionalTx Tx, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return errors.Wrap(err, "failed to delete user")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return errors.Wrap(err, "failed to delete user - no rows affected")
	}
	return nil
}

func (d *databaser) GetUserIdByIdentity(ctx context.Context, optionalTx Tx, identity UserIdentityProvider, identityId string) (*uuid.UUID, error) {
	optionalTx = d.txOrDb(optionalTx)
	var outId uuid.UUID
	if err := optionalTx.QueryRowContext(ctx, `SELECT user_id FROM identities WHERE provider = $1 AND provider_user_id = $2`, identity, identityId).Scan(&outId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by identity")
	}
	return &outId, nil
}

func (d *databaser) UpdateUser(ctx context.Context, optionalTx Tx, request *User) (*User, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if err := optionalTx.QueryRowContext(
		ctx,
		`UPDATE users SET display_name = $2, last_logged_in_at = $3, primary_email_address = $4 WHERE id = $1 RETURNING last_logged_in_at`,
		request.Id, request.DisplayName, request.LastLoggedInAt, request.PrimaryEmailAddress,
	).Scan(&out.LastLoggedInAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to update user")
	}

	// NOTE: haven't implemented user identities update yet

	return &out, nil
}

func (d *databaser) DismissUserPrompt(ctx context.Context, optionalTx Tx, userId uuid.UUID, promptId string) error {
	optionalTx = d.txOrDb(optionalTx)
	if _, err := optionalTx.ExecContext(
		ctx,
		`INSERT INTO dismissed_prompts (id, user_id) VALUES ($1, $2) ON CONFLICT (id, user_id) DO NOTHING`,
		promptId, userId,
	); err != nil {
		return errors.Wrap(err, "failed to dismiss prompt")
	}
	return nil
}

func (d *databaser) FindUserByPrimaryEmail(ctx context.Context, optionalTx Tx, email string) (*User, error) {
	optionalTx = d.txOrDb(optionalTx)
	rows, err := optionalTx.QueryContext(
		ctx,
		`SELECT
			u.id,
			u.display_name,
			u.created_at,
			u.last_logged_in_at,
			u.primary_email_address,
			COALESCE(
				json_object_agg(p.provider, p.provider_user_id)
				FILTER (WHERE p.user_id IS NOT NULL), '{}'
			) AS identities,
			COALESCE(
				json_agg(DISTINCT dp.id)
				FILTER (WHERE dp.id IS NOT NULL), '[]'
			) AS dismissed_prompt_ids
		FROM users u
		LEFT JOIN identities p ON u.id = p.user_id
		LEFT JOIN dismissed_prompts dp ON u.id = dp.user_id
		WHERE LOWER(u.primary_email_address) = LOWER($1)
		GROUP BY u.id
		ORDER BY u.id
		LIMIT 2`,
		email,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find user by primary email")
	}
	defer func() { _ = rows.Close() }()

	var found *User
	for rows.Next() {
		if found != nil {
			return nil, NewErrConflict("multiple users already have this primary email")
		}
		out := User{UserIdentities: make(map[UserIdentityProvider]string), DismissedPrompts: make([]string, 0)}
		if err := rows.Scan(&out.Id, &out.DisplayName, &out.CreatedAt, &out.LastLoggedInAt, opt.Scan(&out.PrimaryEmailAddress), asJson(&out.UserIdentities), asJson(&out.DismissedPrompts)); err != nil {
			return nil, errors.Wrap(err, "failed to scan user by primary email")
		}
		found = &out
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate users by primary email")
	}
	if found == nil {
		return nil, NewErrNotFound("user not found")
	}
	return found, nil
}

// AddUserIdentity links an external identity to an existing user. It is
// idempotent: the identities primary key is (provider, provider_user_id), so
// re-linking the same key is a no-op, and a user may hold several identities of
// the same provider (e.g. one SCIM key per organization).
//
// This exists because UpdateUser deliberately does not persist
// User.UserIdentities, so mutating that map is not enough to attach an identity.
func (d *databaser) AddUserIdentity(ctx context.Context, optionalTx Tx, userId uuid.UUID, provider UserIdentityProvider, providerUserId string) error {
	optionalTx = d.txOrDb(optionalTx)
	var owner uuid.UUID
	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO identities (provider, provider_user_id, user_id) VALUES ($1, $2, $3)
			ON CONFLICT (provider, provider_user_id) DO UPDATE
			SET user_id = identities.user_id
			RETURNING user_id`,
		provider, providerUserId, userId,
	).Scan(&owner); err != nil {
		return errors.Wrap(err, "failed to add user identity")
	}
	if owner != userId {
		return NewErrConflict("external identity already belongs to another user")
	}
	return nil
}
