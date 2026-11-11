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
)

type SessionToken struct {
	Sha256Hash         []byte
	Provider           UserIdentityProvider
	UserId             uuid.UUID
	CreatedAt          time.Time
	ExpiresAt          time.Time
	LastActiveAt       time.Time
	CheckedAt          time.Time
	BrowserIdleTimeout time.Duration
	CLITokenTTL        time.Duration
	ClientIp           opt.Opt[string]
	ClientCity         opt.Opt[string]
	ClientRegion       opt.Opt[string]
}

func (d *databaser) CreateSessionToken(ctx context.Context, optionalTx Tx, request *SessionToken) (*SessionToken, error) {
	if optionalTx == nil {
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()
		out, err := d.CreateSessionToken(ctx, tx, request)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return out, nil
	}
	var cliTTL time.Duration
	if err := optionalTx.QueryRowContext(ctx, `SELECT COALESCE(cli_token_ttl_ns,$1) FROM installation_session_policy WHERE singleton FOR SHARE`, int64(request.ExpiresAt.Sub(request.CreatedAt))).Scan(&cliTTL); err != nil {
		return nil, err
	}

	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if request.Provider == UserIdentityProviderDevice {
		out.ExpiresAt = request.CreatedAt.Add(cliTTL)
	}
	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO session_tokens (sha256_hash, provider, user_id, created_at, expires_at, client_ip, client_city, client_region, last_active_at) values ($1, $2, $3, $4, $5, $6, $7, $8, statement_timestamp()) returning created_at, expires_at, last_active_at`,
		request.Sha256Hash, request.Provider, request.UserId, request.CreatedAt, out.ExpiresAt, request.ClientIp, request.ClientCity, request.ClientRegion,
	).Scan(&out.CreatedAt, &out.ExpiresAt, &out.LastActiveAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert session token")
	}
	return &out, nil
}

func (d *databaser) GetSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*SessionToken, error) {
	if optionalTx == nil {
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()
		out, err := d.GetSessionTokenByHash(ctx, tx, hash)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return out, nil
	}
	// Observe policy and credential after any policy transition commits. A
	// reader must not reject an old snapshot while its live session is being
	// extended atomically under the installation policy's exclusive lock.
	var revision int64
	if err := optionalTx.QueryRowContext(ctx, `SELECT revision FROM installation_session_policy WHERE singleton FOR SHARE`).Scan(&revision); err != nil {
		return nil, err
	}

	optionalTx = d.txOrDb(optionalTx)
	out := SessionToken{Sha256Hash: hash}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT user_id, provider, created_at, expires_at, client_ip, client_city, client_region, last_active_at, statement_timestamp(), COALESCE(browser_idle_timeout_ns,0), COALESCE(cli_token_ttl_ns,0) FROM session_tokens CROSS JOIN installation_session_policy WHERE singleton AND sha256_hash = $1`,
		hash,
	).Scan(&out.UserId, &out.Provider, &out.CreatedAt, &out.ExpiresAt, opt.Scan(&out.ClientIp), opt.Scan(&out.ClientCity), opt.Scan(&out.ClientRegion), &out.LastActiveAt, &out.CheckedAt, &out.BrowserIdleTimeout, &out.CLITokenTTL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("session token not found")
		}
		return nil, errors.Wrap(err, "failed to get session token")
	}
	return &out, nil
}

func (d *databaser) DeleteSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) error {
	optionalTx = d.txOrDb(optionalTx)
	if rs, err := optionalTx.ExecContext(ctx, `DELETE FROM session_tokens WHERE sha256_hash = $1`, hash); err != nil {
		return errors.Wrap(err, "failed to delete session token")
	} else if rc, _ := rs.RowsAffected(); rc == 0 {
		return NewErrNotFound("session token not found")
	}
	return nil
}

type ListSessionTokensParams struct {
	ExpiresAfter time.Time
}

func (d *databaser) ListSessionTokenByUserId(ctx context.Context, optionalTx Tx, userId uuid.UUID, params ListSessionTokensParams) ([]SessionToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)

	if rs, err := optionalTx.QueryContext(ctx, `SELECT sha256_hash, provider, created_at, expires_at, client_ip, client_city, client_region FROM session_tokens WHERE user_id = $1 AND expires_at > $2 ORDER BY created_at`, userId, params.ExpiresAfter); err != nil {
		return nil, errors.Wrap(err, "failed to list session tokens")
	} else {
		out := make([]SessionToken, 0)
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		for rs.Next() {
			item := SessionToken{UserId: userId}
			if err := rs.Scan(&item.Sha256Hash, &item.Provider, &item.CreatedAt, &item.ExpiresAt, opt.Scan(&item.ClientIp), opt.Scan(&item.ClientCity), opt.Scan(&item.ClientRegion)); err != nil {
				return nil, errors.Wrap(err, "failed to scan session token")
			}
			out = append(out, item)
		}
		if err := rs.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to iterate rows")
		}
		return out, nil
	}
}

func (d *databaser) DeleteSessionTokensByUserId(ctx context.Context, optionalTx Tx, userId uuid.UUID) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	rs, err := optionalTx.ExecContext(ctx, `DELETE FROM session_tokens WHERE user_id = $1`, userId)
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete session tokens by user id")
	}
	rc, _ := rs.RowsAffected()
	return rc, nil
}

func (d *databaser) DeleteExpiredSessionTokens(ctx context.Context, optionalTx Tx) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	rs, err := optionalTx.ExecContext(ctx, `DELETE FROM session_tokens WHERE expires_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete expired session tokens")
	}

	rowsAffected, err := rs.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get rows affected")
	}

	return rowsAffected, nil
}

// RecordBrowserSessionActivity renews only a still-live browser session. The
// row lock is acquired before checking time, including after a lock wait.
func (d *databaser) RecordBrowserSessionActivity(ctx context.Context, hash []byte, idleTimeout time.Duration) (*SessionToken, error) {
	out := SessionToken{Sha256Hash: hash}
	tx, err := d.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to start session activity transaction")
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(browser_idle_timeout_ns,$1) FROM installation_session_policy WHERE singleton FOR SHARE`, int64(idleTimeout)).Scan(&idleTimeout); err != nil {
		return nil, err
	}
	out.BrowserIdleTimeout = idleTimeout
	var lockedHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT sha256_hash FROM session_tokens WHERE sha256_hash=$1 FOR UPDATE`, hash).Scan(&lockedHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("live browser session not found")
		}
		return nil, errors.Wrap(err, "failed to lock browser session")
	}
	err = tx.QueryRowContext(ctx, `UPDATE session_tokens SET last_active_at = GREATEST(last_active_at, statement_timestamp())
        WHERE sha256_hash = $1 AND provider <> $3
          AND expires_at AT TIME ZONE 'UTC' > statement_timestamp()
          AND last_active_at + ($2 * interval '1 microsecond') > statement_timestamp()
        RETURNING user_id, provider, created_at, expires_at, last_active_at, statement_timestamp()`,
		hash, idleTimeout.Microseconds(), UserIdentityProviderDevice).Scan(&out.UserId, &out.Provider, &out.CreatedAt, &out.ExpiresAt, &out.LastActiveAt, &out.CheckedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, NewErrNotFound("live browser session not found")
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to record browser session activity")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit session activity")
	}
	return &out, nil
}
