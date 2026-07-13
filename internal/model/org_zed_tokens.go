package model

import (
	"context"
	"database/sql"

	"github.com/pkg/errors"
)

type OrgZedTokens struct {
	OrgId    string
	ZedToken string
}

func (d *databaser) UpsertOrgZedToken(ctx context.Context, optionalTx Tx, orgId string, request *OrgZedTokens) (*OrgZedTokens, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request

	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO org_zed_tokens (org_id, zed_token) VALUES ($1, $2)
		ON CONFLICT (org_id) DO UPDATE SET zed_token = EXCLUDED.zed_token
		RETURNING zed_token`,
		orgId, request.ZedToken,
	).Scan(&out.ZedToken); err != nil {
		return nil, errors.Wrap(err, "failed to insert org zed token")
	}

	return &out, nil
}

func (d *databaser) GetOrgZedToken(ctx context.Context, optionalTx Tx, orgId string) (*OrgZedTokens, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := OrgZedTokens{OrgId: orgId}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT
			zed_token
		FROM org_zed_tokens 
		WHERE org_id = $1`,
		orgId,
	).Scan(&out.ZedToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("org zed token not found")
		}
		return nil, errors.Wrap(err, "failed to get org zed token by id")
	}
	return &out, nil
}
