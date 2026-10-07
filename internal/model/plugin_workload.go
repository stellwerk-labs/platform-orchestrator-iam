package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// PluginWorkloadBinding maps one Kubernetes ServiceAccount of one issuer to
// the service user named by a plugin installation record.
type PluginWorkloadBinding struct {
	ID             uuid.UUID
	Issuer         string
	Namespace      string
	ServiceAccount string
	Audience       string
	ServiceUserID  uuid.UUID
	PluginID       string
	InstallationID uuid.UUID
	CreatedAt      time.Time
	CreatedBy      uuid.UUID
	// ServiceUserActive reports whether the bound service user still exists
	// within its expiry, the same rule IsAuthorizationSubjectActive applies.
	ServiceUserActive bool
}

// PluginWorkloadToken is an issued plugin workload token. Only its hash is stored.
type PluginWorkloadToken struct {
	Sha256Hash    []byte
	BindingID     uuid.UUID
	ServiceUserID uuid.UUID
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

const selectPluginWorkloadBindings = `
	SELECT b.id, b.issuer, b.namespace, b.service_account, b.audience, b.service_user_id,
		b.plugin_id, b.installation_id, b.created_at, b.created_by,
		sut.current_token_expires_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
	FROM plugin_workload_bindings b
	JOIN service_user_tokens sut ON sut.id = b.service_user_id
`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPluginWorkloadBinding(row rowScanner) (*PluginWorkloadBinding, error) {
	var binding PluginWorkloadBinding
	if err := row.Scan(&binding.ID, &binding.Issuer, &binding.Namespace, &binding.ServiceAccount, &binding.Audience,
		&binding.ServiceUserID, &binding.PluginID, &binding.InstallationID, &binding.CreatedAt, &binding.CreatedBy,
		&binding.ServiceUserActive); err != nil {
		return nil, err
	}
	return &binding, nil
}

func pluginWorkloadBindingResult(binding *PluginWorkloadBinding, err error) (*PluginWorkloadBinding, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, NewErrNotFound("plugin workload binding not found")
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to read plugin workload binding")
	}
	return binding, nil
}

func (d *databaser) CreatePluginWorkloadBinding(ctx context.Context, optionalTx Tx, binding PluginWorkloadBinding) (*PluginWorkloadBinding, error) {
	tx := d.txOrDb(optionalTx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO plugin_workload_bindings
			(id, issuer, namespace, service_account, audience, service_user_id, plugin_id, installation_id, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, binding.ID, binding.Issuer, binding.Namespace, binding.ServiceAccount, binding.Audience, binding.ServiceUserID,
		binding.PluginID, binding.InstallationID, binding.CreatedAt, binding.CreatedBy); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			switch pqErr.Constraint {
			case "plugin_workload_bindings_service_account":
				return nil, NewErrConflict("the ServiceAccount already has a plugin workload binding")
			case "plugin_workload_bindings_service_user":
				return nil, NewErrConflict("the service user already has a plugin workload binding")
			case "plugin_workload_bindings_service_user_fk":
				return nil, NewErrNotFound("service user not found")
			}
		}
		return nil, errors.Wrap(err, "failed to create plugin workload binding")
	}
	return d.GetPluginWorkloadBinding(ctx, tx, binding.ID)
}

func (d *databaser) GetPluginWorkloadBinding(ctx context.Context, optionalTx Tx, id uuid.UUID) (*PluginWorkloadBinding, error) {
	return pluginWorkloadBindingResult(scanPluginWorkloadBinding(
		d.txOrDb(optionalTx).QueryRowContext(ctx, selectPluginWorkloadBindings+`WHERE b.id = $1`, id),
	))
}

func (d *databaser) GetPluginWorkloadBindingForServiceAccount(ctx context.Context, optionalTx Tx, issuer, namespace, serviceAccount string) (*PluginWorkloadBinding, error) {
	return pluginWorkloadBindingResult(scanPluginWorkloadBinding(d.txOrDb(optionalTx).QueryRowContext(ctx,
		selectPluginWorkloadBindings+`WHERE b.issuer = $1 AND b.namespace = $2 AND b.service_account = $3`,
		issuer, namespace, serviceAccount,
	)))
}

func (d *databaser) GetPluginWorkloadBindingForServiceUser(ctx context.Context, optionalTx Tx, serviceUserID uuid.UUID) (*PluginWorkloadBinding, error) {
	return pluginWorkloadBindingResult(scanPluginWorkloadBinding(
		d.txOrDb(optionalTx).QueryRowContext(ctx, selectPluginWorkloadBindings+`WHERE b.service_user_id = $1`, serviceUserID),
	))
}

func (d *databaser) ListPluginWorkloadBindings(ctx context.Context, optionalTx Tx) ([]PluginWorkloadBinding, error) {
	return d.listPluginWorkloadBindings(ctx, optionalTx, "")
}

// ListPluginWorkloadBindingsForInstallation returns the bindings of one plugin installation.
func (d *databaser) ListPluginWorkloadBindingsForInstallation(ctx context.Context, optionalTx Tx, pluginID string, installationID uuid.UUID) ([]PluginWorkloadBinding, error) {
	return d.listPluginWorkloadBindings(ctx, optionalTx, `WHERE b.plugin_id = $1 AND b.installation_id = $2 `, pluginID, installationID)
}

func (d *databaser) listPluginWorkloadBindings(ctx context.Context, optionalTx Tx, where string, args ...any) ([]PluginWorkloadBinding, error) {
	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, selectPluginWorkloadBindings+where+`ORDER BY b.created_at, b.id`, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list plugin workload bindings")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close plugin workload binding rows", zap.Error(closeErr))
		}
	}()
	bindings := make([]PluginWorkloadBinding, 0)
	for rows.Next() {
		binding, err := scanPluginWorkloadBinding(rows)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan plugin workload binding")
		}
		bindings = append(bindings, *binding)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate plugin workload bindings")
	}
	return bindings, nil
}

// DeletePluginWorkloadBinding revokes a binding. Its issued tokens are deleted with it.
func (d *databaser) DeletePluginWorkloadBinding(ctx context.Context, optionalTx Tx, id uuid.UUID) error {
	result, err := d.txOrDb(optionalTx).ExecContext(ctx, `DELETE FROM plugin_workload_bindings WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, "failed to delete plugin workload binding")
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return NewErrNotFound("plugin workload binding not found")
	}
	return nil
}

// DisableServiceUserStaticToken replaces the static token hash with random
// bytes that are no token's hash. Identity, roles and expiry stay unchanged, so
// revoking a workload binding later cannot revive a previously issued static token.
func (d *databaser) DisableServiceUserStaticToken(ctx context.Context, optionalTx Tx, serviceUserID uuid.UUID) error {
	unusable := make([]byte, sha256.Size)
	if _, err := rand.Read(unusable); err != nil {
		return errors.Wrap(err, "failed to generate an unusable token hash")
	}
	result, err := d.txOrDb(optionalTx).ExecContext(ctx,
		`UPDATE service_user_tokens SET current_token_sha256_hash = $2 WHERE id = $1`, serviceUserID, unusable)
	if err != nil {
		return errors.Wrap(err, "failed to disable service user static token")
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return NewErrNotFound("service user not found")
	}
	return nil
}

func (d *databaser) CreatePluginWorkloadToken(ctx context.Context, optionalTx Tx, token PluginWorkloadToken) error {
	if _, err := d.txOrDb(optionalTx).ExecContext(ctx, `
		INSERT INTO plugin_workload_tokens (token_sha256_hash, binding_id, issued_at, expires_at)
		VALUES ($1, $2, $3, $4)
	`, token.Sha256Hash, token.BindingID, token.IssuedAt, token.ExpiresAt); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return NewErrNotFound("plugin workload binding not found")
		}
		return errors.Wrap(err, "failed to create plugin workload token")
	}
	return nil
}

// GetPluginWorkloadTokenByHash returns a token only while it is unexpired, its
// binding exists and the bound service user is active.
func (d *databaser) GetPluginWorkloadTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*PluginWorkloadToken, error) {
	token := PluginWorkloadToken{Sha256Hash: hash}
	if err := d.txOrDb(optionalTx).QueryRowContext(ctx, `
		SELECT t.binding_id, b.service_user_id, t.issued_at, t.expires_at
		FROM plugin_workload_tokens t
		JOIN plugin_workload_bindings b ON b.id = t.binding_id
		JOIN service_user_tokens sut ON sut.id = b.service_user_id
		WHERE t.token_sha256_hash = $1
		  AND t.expires_at > now()
		  AND sut.current_token_expires_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
	`, hash).Scan(&token.BindingID, &token.ServiceUserID, &token.IssuedAt, &token.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("plugin workload token not found")
		}
		return nil, errors.Wrap(err, "failed to get plugin workload token")
	}
	return &token, nil
}

func (d *databaser) DeleteExpiredPluginWorkloadTokens(ctx context.Context, optionalTx Tx) (int64, error) {
	result, err := d.txOrDb(optionalTx).ExecContext(ctx, `DELETE FROM plugin_workload_tokens WHERE expires_at <= now()`)
	if err != nil {
		return 0, errors.Wrap(err, "failed to delete expired plugin workload tokens")
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "failed to count deleted plugin workload tokens")
	}
	return deleted, nil
}
