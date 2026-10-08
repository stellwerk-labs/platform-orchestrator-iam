package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// ServiceUserScope says where a service user belongs.
type ServiceUserScope string

const (
	// ServiceUserScopeOrganization is a service user of exactly one
	// organization, with roles only there.
	ServiceUserScopeOrganization ServiceUserScope = "organization"
	// ServiceUserScopePlatform is a platform principal: no organization, no
	// roles, and no IAM authority in any organization.
	ServiceUserScopePlatform ServiceUserScope = "platform"
)

// PlatformPrincipal is a service user with scope platform. A plugin workload
// principal has no static token and acts only through its workload binding; a
// static-token principal (the Data Plane admission checker) holds one token
// and is never bound.
type PlatformPrincipal struct {
	ID          uuid.UUID
	DisplayName string
	// GeneratedAt and GeneratedBy record the creation or the last token
	// regeneration.
	GeneratedAt time.Time
	GeneratedBy uuid.UUID
	// CurrentTokenExpiresAt and CurrentTokenSha256Hash describe the static
	// token; both are nil for a plugin workload principal. The hash is written,
	// never read back.
	CurrentTokenExpiresAt  *time.Time
	CurrentTokenSha256Hash []byte
	// WorkloadBindingID names the binding of a bound plugin workload principal.
	WorkloadBindingID *uuid.UUID
}

// HoldsStaticToken reports whether the principal authenticates with a static token.
func (p PlatformPrincipal) HoldsStaticToken() bool {
	return p.CurrentTokenExpiresAt != nil
}

const selectPlatformPrincipals = `
	SELECT sut.id, sut.display_name, sut.generated_at, sut.generated_by, sut.current_token_expires_at, b.id
	FROM service_user_tokens sut
	LEFT JOIN plugin_workload_bindings b ON b.service_user_id = sut.id
	WHERE sut.scope = 'platform'
`

func scanPlatformPrincipal(row rowScanner) (*PlatformPrincipal, error) {
	var principal PlatformPrincipal
	var expiresAt sql.NullTime
	var bindingID uuid.NullUUID
	if err := row.Scan(&principal.ID, &principal.DisplayName, &principal.GeneratedAt, &principal.GeneratedBy, &expiresAt, &bindingID); err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		principal.CurrentTokenExpiresAt = &expiresAt.Time
	}
	if bindingID.Valid {
		principal.WorkloadBindingID = &bindingID.UUID
	}
	return &principal, nil
}

// CreatePlatformPrincipal inserts a platform principal. A principal without a
// token expiry and hash is a plugin workload principal.
func (d *databaser) CreatePlatformPrincipal(ctx context.Context, optionalTx Tx, principal PlatformPrincipal) (*PlatformPrincipal, error) {
	tx := d.txOrDb(optionalTx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO service_user_tokens
			(id, scope, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash)
		VALUES ($1, 'platform', NULL, $2, $3, $4, $5, $6)
	`, principal.ID, principal.DisplayName, principal.GeneratedAt, principal.GeneratedBy,
		principal.CurrentTokenExpiresAt, principal.CurrentTokenSha256Hash); err != nil {
		return nil, errors.Wrap(err, "failed to create platform principal")
	}
	return d.GetPlatformPrincipal(ctx, tx, principal.ID)
}

// GetPlatformPrincipal returns a platform principal. A service user of an
// organization is not found here.
func (d *databaser) GetPlatformPrincipal(ctx context.Context, optionalTx Tx, id uuid.UUID) (*PlatformPrincipal, error) {
	principal, err := scanPlatformPrincipal(d.txOrDb(optionalTx).QueryRowContext(ctx, selectPlatformPrincipals+`AND sut.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, NewErrNotFound("platform principal not found")
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to read platform principal")
	}
	return principal, nil
}
