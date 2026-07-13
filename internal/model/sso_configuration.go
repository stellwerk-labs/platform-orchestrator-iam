package model

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/pkg/errors"
)

type SsoConfiguration struct {
	OrgId         string
	ProviderOrgId string
}

func (d *databaser) GetSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string) (*SsoConfiguration, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := SsoConfiguration{OrgId: orgId}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT provider_org_id FROM sso_configuration WHERE org_id = $1`,
		orgId,
	).Scan(&out.ProviderOrgId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("sso configuration not found")
		}
		return nil, errors.Wrap(err, "failed to get sso configuration")
	}
	return &out, nil
}

func (d *databaser) UpsertSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string, request *SsoConfiguration) (*SsoConfiguration, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request

	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO sso_configuration (org_id, provider_org_id) VALUES ($1, $2)
		ON CONFLICT (org_id) DO UPDATE SET provider_org_id = EXCLUDED.provider_org_id
		RETURNING provider_org_id`,
		orgId, request.ProviderOrgId,
	).Scan(&out.ProviderOrgId); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Constraint == "unique_provider_org_id" {
			return nil, NewErrConflict(fmt.Sprintf("provider org id %s is used for another organization", request.ProviderOrgId))
		}
		return nil, errors.Wrap(err, "failed to insert org sso configuration")
	}

	return &out, nil
}
