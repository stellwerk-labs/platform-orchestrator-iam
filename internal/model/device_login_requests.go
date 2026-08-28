package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

const (
	DeviceLoginRejected = "rejected"
	DeviceLoginAccepted = "accepted"
)

type DeviceLoginRequest struct {
	Id                         uuid.UUID
	VerificationCodeSha256Hash []byte
	CreatedAt                  time.Time
	ExpiresAt                  time.Time
	UserAgent                  string
	PollingTokenSha256Hash     []byte
	Decision                   *string
	DecidedBy                  *uuid.UUID
	ClientIp                   opt.Opt[string]
	ClientCity                 opt.Opt[string]
	ClientRegion               opt.Opt[string]
}

func (d *databaser) CreateDeviceLoginRequest(ctx context.Context, optionalTx Tx, request *DeviceLoginRequest) (*DeviceLoginRequest, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO device_login_requests (id, verification_code_hash, created_at, expires_at, user_agent, polling_token_hash, client_ip, client_city, client_region) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at, expires_at`,
		out.Id, out.VerificationCodeSha256Hash, out.CreatedAt, out.ExpiresAt, out.UserAgent, out.PollingTokenSha256Hash, out.ClientIp, out.ClientCity, out.ClientRegion,
	).Scan(&out.CreatedAt, &out.ExpiresAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert device login request")
	}
	return &out, nil
}

func (d *databaser) GetDeviceLoginRequest(ctx context.Context, optionalTx Tx, requestId uuid.UUID) (*DeviceLoginRequest, error) {
	optionalTx = d.txOrDb(optionalTx)

	out := DeviceLoginRequest{Id: requestId}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT verification_code_hash, created_at, expires_at, user_agent, polling_token_hash, decision, decided_by, client_ip, client_city, client_region FROM device_login_requests WHERE id = $1`,
		requestId,
	).Scan(&out.VerificationCodeSha256Hash, &out.CreatedAt, &out.ExpiresAt, &out.UserAgent, &out.PollingTokenSha256Hash, &out.Decision, &out.DecidedBy, opt.Scan(&out.ClientIp), opt.Scan(&out.ClientCity), opt.Scan(&out.ClientRegion)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("device login request not found")
		}
		return nil, errors.Wrap(err, "failed to get device login request")
	}

	return &out, nil
}

func (d *databaser) GetDeviceLoginRequestByCodeHash(ctx context.Context, optionalTx Tx, codeSha256Hash []byte) (*DeviceLoginRequest, error) {
	optionalTx = d.txOrDb(optionalTx)

	out := DeviceLoginRequest{VerificationCodeSha256Hash: codeSha256Hash}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT id, created_at, expires_at, user_agent, polling_token_hash, decision, decided_by, client_ip, client_city, client_region FROM device_login_requests WHERE verification_code_hash = $1`,
		codeSha256Hash,
	).Scan(&out.Id, &out.CreatedAt, &out.ExpiresAt, &out.UserAgent, &out.PollingTokenSha256Hash, &out.Decision, &out.DecidedBy, opt.Scan(&out.ClientIp), opt.Scan(&out.ClientCity), opt.Scan(&out.ClientRegion)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("device login request not found")
		}
		return nil, errors.Wrap(err, "failed to get device login request")
	}

	return &out, nil
}

func (d *databaser) UpdateDeviceLoginRequest(ctx context.Context, optionalTx Tx, request *DeviceLoginRequest) (*DeviceLoginRequest, error) {
	optionalTx = d.txOrDb(optionalTx)

	out := *request
	if r, err := optionalTx.ExecContext(
		ctx,
		`UPDATE device_login_requests SET decision = $2, decided_by = $3 WHERE id = $1`,
		request.Id, request.Decision, request.DecidedBy,
	); err != nil {
		return nil, errors.Wrap(err, "failed to update device login request")
	} else if rc, _ := r.RowsAffected(); rc == 0 {
		return nil, NewErrNotFound("device login request not found")
	}

	return &out, nil
}

// DeleteDeviceLoginRequestsDecidedBy removes every device-login request the
// given user has decided (accepted or rejected). An ACCEPTED request is a live
// credential: its poll path mints a fresh session token for DecidedBy, so
// deprovisioning must destroy it together with the user's session tokens or the
// device can log in as a user who no longer has any access. Rejected rows are
// just dead state and go with them. Pending rows are untouched — they carry no
// user yet, and accepting one requires an authenticated session the
// deprovisioned user no longer has.
func (d *databaser) DeleteDeviceLoginRequestsDecidedBy(ctx context.Context, optionalTx Tx, userId uuid.UUID) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	rs, err := optionalTx.ExecContext(ctx, `DELETE FROM device_login_requests WHERE decided_by = $1`, userId)
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete device login requests decided by user")
	}
	rc, _ := rs.RowsAffected()
	return rc, nil
}

func (d *databaser) DeleteDeviceLoginRequest(ctx context.Context, optionalTx Tx, requestId uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if r, err := optionalTx.ExecContext(ctx, `DELETE FROM device_login_requests WHERE id = $1`, requestId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NewErrNotFound("device login request not found")
		}
		return errors.Wrap(err, "failed to delete device login request")
	} else if rc, _ := r.RowsAffected(); rc == 0 {
		return NewErrNotFound("device login request not found")
	}
	return nil
}
