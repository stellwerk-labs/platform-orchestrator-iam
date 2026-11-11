package model

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrSettingsRevision = errors.New("installation settings changed; reload before saving")

type InstallationSessionPolicy struct {
	BrowserIdleTimeout time.Duration
	CLITokenTTL        time.Duration
	Revision           int64
	UpdatedAt          time.Time
	UpdatedBy          *uuid.UUID
	Source             string
}

func readSessionPolicy(ctx context.Context, tx Tx, browser, cli time.Duration, lock bool) (InstallationSessionPolicy, error) {
	query := `SELECT COALESCE(browser_idle_timeout_ns,$1),COALESCE(cli_token_ttl_ns,$2),revision,updated_at,updated_by,source FROM installation_session_policy WHERE singleton`
	if lock {
		query += " FOR UPDATE"
	}
	var out InstallationSessionPolicy
	err := tx.QueryRowContext(ctx, query, int64(browser), int64(cli)).Scan(&out.BrowserIdleTimeout, &out.CLITokenTTL, &out.Revision, &out.UpdatedAt, &out.UpdatedBy, &out.Source)
	return out, err
}

func ReadInstallationSessionPolicy(ctx context.Context, db Databaser, browser, cli time.Duration) (InstallationSessionPolicy, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return InstallationSessionPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return readSessionPolicy(ctx, tx, browser, cli, false)
}

// Apply policy under the exclusive settings lock. Renewals and session issuance
// take a shared lock first, so no old-policy write can race this transition.
func applySessionPolicy(ctx context.Context, tx Tx, old InstallationSessionPolicy, browser, cli time.Duration, actor *uuid.UUID, source string, revision int64) error {
	if browser < time.Second || cli < time.Second {
		return NewErrBadRequest("session durations must be at least 1s")
	}
	// Lock sessions before taking the transition's clock reading. A row-lock
	// wait must not turn an old statement timestamp into a revival window.
	var locked int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT sha256_hash FROM session_tokens ORDER BY sha256_hash FOR UPDATE) locked`).Scan(&locked); err != nil {
		return err
	}
	// Delete sessions expired under EITHER policy before lengthening anything.
	// This makes shorten/lengthen monotonic for expired credentials, even if no
	// request observed their original deadline while they sat idle.
	_, err := tx.ExecContext(ctx, `DELETE FROM session_tokens WHERE expires_at AT TIME ZONE 'UTC' <= statement_timestamp()
      OR (provider <> $1 AND last_active_at + ($2 * interval '1 microsecond') <= statement_timestamp())
      OR (provider <> $1 AND last_active_at + ($3 * interval '1 microsecond') <= statement_timestamp())
      OR (provider = $1 AND created_at AT TIME ZONE 'UTC' + ($4 * interval '1 microsecond') <= statement_timestamp())
      OR (provider = $1 AND created_at AT TIME ZONE 'UTC' + ($5 * interval '1 microsecond') <= statement_timestamp())`,
		UserIdentityProviderDevice, old.BrowserIdleTimeout.Microseconds(), browser.Microseconds(), old.CLITokenTTL.Microseconds(), cli.Microseconds())
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE session_tokens SET expires_at=created_at+($1 * interval '1 microsecond') WHERE provider=$2`, cli.Microseconds(), UserIdentityProviderDevice); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE installation_session_policy SET browser_idle_timeout_ns=$1,cli_token_ttl_ns=$2,revision=$3,updated_at=statement_timestamp(),updated_by=$4,source=$5 WHERE singleton`, int64(browser), int64(cli), revision, actor, source); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO installation_session_policy_events(revision,browser_idle_timeout_ns,cli_token_ttl_ns,changed_by,source) VALUES($1,$2,$3,$4,$5)`, revision, int64(browser), int64(cli), actor, source)
	return err
}

func UpdateInstallationSessionPolicy(ctx context.Context, db Databaser, actor uuid.UUID, revision int64, browser, cli, fallbackBrowser, fallbackCLI time.Duration) (InstallationSessionPolicy, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return InstallationSessionPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	old, err := readSessionPolicy(ctx, tx, fallbackBrowser, fallbackCLI, true)
	if err != nil {
		return InstallationSessionPolicy{}, err
	}
	if old.Revision != revision {
		return InstallationSessionPolicy{}, ErrSettingsRevision
	}
	if err := applySessionPolicy(ctx, tx, old, browser, cli, &actor, "api", revision+1); err != nil {
		return InstallationSessionPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return InstallationSessionPolicy{}, err
	}
	return ReadInstallationSessionPolicy(ctx, db, fallbackBrowser, fallbackCLI)
}

// Environment values bootstrap a fresh installation only. Explicit recovery
// resets use the same expiry pruning and audit trail as a runtime policy change.
func InitializeInstallationSessionPolicy(ctx context.Context, db Databaser, browser, cli time.Duration, reset bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	old, err := readSessionPolicy(ctx, tx, browser, cli, true)
	if err != nil {
		return err
	}
	var initialized bool
	if err := tx.QueryRowContext(ctx, `SELECT browser_idle_timeout_ns IS NOT NULL FROM installation_session_policy WHERE singleton`).Scan(&initialized); err != nil {
		return err
	}
	if initialized && !reset {
		return nil
	}
	revision := old.Revision
	if initialized {
		revision++
	}
	if err := applySessionPolicy(ctx, tx, old, browser, cli, nil, "bootstrap", revision); err != nil {
		return err
	}
	return tx.Commit()
}
