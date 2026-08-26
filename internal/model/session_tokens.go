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
	Sha256Hash   []byte
	Provider     UserIdentityProvider
	UserId       uuid.UUID
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ClientIp     opt.Opt[string]
	ClientCity   opt.Opt[string]
	ClientRegion opt.Opt[string]
}

func (d *databaser) CreateSessionToken(ctx context.Context, optionalTx Tx, request *SessionToken) (*SessionToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO session_tokens (sha256_hash, provider, user_id, created_at, expires_at, client_ip, client_city, client_region) values ($1, $2, $3, $4, $5, $6, $7, $8) returning created_at, expires_at`,
		request.Sha256Hash, request.Provider, request.UserId, request.CreatedAt, request.ExpiresAt, request.ClientIp, request.ClientCity, request.ClientRegion,
	).Scan(&out.CreatedAt, &out.ExpiresAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert session token")
	}
	return &out, nil
}

func (d *databaser) GetSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*SessionToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := SessionToken{Sha256Hash: hash}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT user_id, created_at, expires_at, client_ip, client_city, client_region FROM session_tokens WHERE sha256_hash = $1`,
		hash,
	).Scan(&out.UserId, &out.CreatedAt, &out.ExpiresAt, opt.Scan(&out.ClientIp), opt.Scan(&out.ClientCity), opt.Scan(&out.ClientRegion)); err != nil {
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
