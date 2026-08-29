package model

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/pagination"
)

var serviceUsersPageTokenCodec = pagination.PageTokenCodec{Parts: 1}

const defaultServiceUsersPerPage = 100

type ServiceUserToken struct {
	Id                     uuid.UUID
	OrgId                  string
	DisplayName            string
	GeneratedAt            time.Time
	GeneratedBy            uuid.UUID
	CurrentTokenExpiresAt  time.Time
	CurrentTokenSha256Hash []byte
	ServiceUserRoles       []ServiceUserRole
}

func (d *databaser) CreateServiceUserToken(ctx context.Context, optionalTx Tx, orgId string, request *ServiceUserToken) (*ServiceUserToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request

	if err := optionalTx.QueryRowContext(
		ctx,
		`INSERT INTO service_user_tokens (id, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash) values ($1, $2, $3, $4, $5, $6, $7) returning current_token_expires_at, generated_at`,
		request.Id, orgId, request.DisplayName, request.GeneratedAt, request.GeneratedBy, request.CurrentTokenExpiresAt, request.CurrentTokenSha256Hash,
	).Scan(&out.CurrentTokenExpiresAt, &out.GeneratedAt); err != nil {
		return nil, errors.Wrap(err, "failed to insert service user token")
	}

	return &out, nil
}

func (d *databaser) GetServiceUserToken(ctx context.Context, optionalTx Tx, id uuid.UUID) (*ServiceUserToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	var roles json.RawMessage
	out := ServiceUserToken{Id: id}
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT
			sut.org_id,
			sut.display_name,
			sut.generated_at, 
			sut.generated_by, 
			sut.current_token_expires_at,
			sut.current_token_sha256_hash,
			JSON_AGG(
				JSON_BUILD_OBJECT(
					'role_id', sur.role_id
				)
			) FILTER (WHERE sur.role_id IS NOT NULL) as roles
		FROM service_user_tokens sut 
		LEFT JOIN service_user_roles sur ON sut.id = sur.service_user_id
		WHERE sut.id = $1
		GROUP BY sut.org_id, sut.display_name, sut.generated_at, sut.generated_by, sut.current_token_expires_at, sut.current_token_sha256_hash`,
		id,
	).Scan(&out.OrgId, &out.DisplayName, &out.GeneratedAt, &out.GeneratedBy, &out.CurrentTokenExpiresAt, &out.CurrentTokenSha256Hash, &roles); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("service user token not found")
		}
		return nil, errors.Wrap(err, "failed to get service user token by id")
	}
	if err := json.Unmarshal(roles, &out.ServiceUserRoles); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal service token roles")
	}
	return &out, nil
}

func (d *databaser) GetServiceUserTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*ServiceUserToken, error) {
	optionalTx = d.txOrDb(optionalTx)

	out := ServiceUserToken{CurrentTokenSha256Hash: hash}
	var roles json.RawMessage
	if err := optionalTx.QueryRowContext(
		ctx,
		`SELECT 
			sut.id,
			sut.org_id,
			sut.display_name,
			sut.generated_at,
			sut.generated_by,
			sut.current_token_expires_at,
			JSON_AGG(
				JSON_BUILD_OBJECT(
					'role_id', sur.role_id
				)
			) as roles 
		FROM service_user_tokens sut 
		LEFT JOIN service_user_roles sur ON sut.id = sur.service_user_id 
		WHERE sut.current_token_sha256_hash = $1
		GROUP BY sut.id, sut.display_name, sut.generated_at, sut.generated_by, sut.current_token_expires_at, sut.current_token_sha256_hash`,
		hash,
	).Scan(&out.Id, &out.OrgId, &out.DisplayName, &out.GeneratedAt, &out.GeneratedBy, &out.CurrentTokenExpiresAt, &roles); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NewErrNotFound("service user token not found")
		}
		return nil, errors.Wrap(err, "failed to get service user token by hash")
	}
	if err := json.Unmarshal(roles, &out.ServiceUserRoles); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal service token roles")
	}
	return &out, nil
}

type ListServiceUserTokensParams struct {
	OrgId     string
	PageToken string
	PerPage   int
}

func (d *databaser) ListServiceUserTokens(ctx context.Context, optionalTx Tx, params ListServiceUserTokensParams) ([]ServiceUserToken, string, error) {
	perPage := params.PerPage
	if perPage <= 0 {
		perPage = defaultServiceUsersPerPage
	}

	parts, err := serviceUsersPageTokenCodec.Parse(params.PageToken)
	if err != nil {
		return nil, "", NewErrBadRequest(err.Error())
	}

	var cursorId *uuid.UUID
	if parts[0] != "" {
		id, err := uuid.Parse(parts[0])
		if err != nil {
			return nil, "", NewErrBadRequest("invalid page token")
		}
		cursorId = &id
	}

	logger := hlogger.TraceScopedLoggerFromCtx(d.logger, ctx)
	optionalTx = d.txOrDb(optionalTx)
	if rows, err := optionalTx.QueryContext(ctx,
		`SELECT 
			sut.id,
			sut.display_name,
			sut.generated_at,
			sut.generated_by,
			sut.current_token_expires_at,
			sut.current_token_sha256_hash,
			JSON_AGG(
				JSON_BUILD_OBJECT(
					'role_id', sur.role_id,
					'scope', sur.scope
				)
			) as roles 
		FROM service_user_tokens sut 
		LEFT JOIN service_user_roles sur ON sut.id = sur.service_user_id 
		WHERE sut.org_id = $1
		AND ($2::uuid IS NULL OR sut.id > $2)
		GROUP BY sut.id, sut.display_name, sut.generated_at, sut.generated_by, sut.current_token_expires_at, sut.current_token_sha256_hash
		ORDER BY sut.id ASC
		LIMIT $3`, params.OrgId, cursorId, perPage+1); err != nil {
		return nil, "", errors.Wrap(err, "failed to list service user tokens")
	} else {
		defer func() {
			if err := rows.Close(); err != nil {
				logger.Error("failed to close row set", zap.Error(err))
			}
		}()
		out := make([]ServiceUserToken, 0)
		for rows.Next() {
			var roles json.RawMessage
			token := ServiceUserToken{OrgId: params.OrgId}
			if err := rows.Scan(&token.Id, &token.DisplayName, &token.GeneratedAt, &token.GeneratedBy, &token.CurrentTokenExpiresAt, &token.CurrentTokenSha256Hash, &roles); err != nil {
				return nil, "", errors.Wrap(err, "failed to scan service user token")
			}
			if err := json.Unmarshal(roles, &token.ServiceUserRoles); err != nil {
				return nil, "", errors.Wrap(err, "failed to unmarshal service token roles")
			}
			out = append(out, token)
		}
		if err := rows.Err(); err != nil {
			return nil, "", errors.Wrap(err, "failed to iterate rows")
		}

		var nextPageToken string
		if len(out) > perPage {
			last := out[perPage-1]
			nextPageToken = serviceUsersPageTokenCodec.Generate(last.Id.String())
			out = out[:perPage]
		}
		return out, nextPageToken, nil
	}
}

func (d *databaser) UpdateServiceUserToken(ctx context.Context, optionalTx Tx, request *ServiceUserToken) (*ServiceUserToken, error) {
	optionalTx = d.txOrDb(optionalTx)
	out := *request
	if err := optionalTx.QueryRowContext(
		ctx,
		`UPDATE service_user_tokens SET display_name = $1, generated_at = $2, generated_by = $3, current_token_expires_at = $4, current_token_sha256_hash = $5 WHERE id = $6 RETURNING generated_at, current_token_expires_at`,
		request.DisplayName, request.GeneratedAt, request.GeneratedBy, request.CurrentTokenExpiresAt, request.CurrentTokenSha256Hash, request.Id,
	).Scan(&out.GeneratedAt, &out.CurrentTokenExpiresAt); err != nil {
		return nil, errors.Wrap(err, "failed to update service user token")
	}
	return &out, nil
}

func (d *databaser) DeleteServiceUserToken(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error {
	optionalTx = d.txOrDb(optionalTx)
	if r, err := optionalTx.ExecContext(ctx, `DELETE FROM service_user_tokens WHERE org_id = $1 AND id = $2`, orgId, id); err != nil {
		return errors.Wrap(err, "failed to delete service user token")
	} else if rc, _ := r.RowsAffected(); rc == 0 {
		return NewErrNotFound("service user token not found")
	}
	return nil
}

func (d *databaser) BulkExpireAllServiceUserTokens(ctx context.Context, optionalTx Tx, orgId string) (int64, error) {
	optionalTx = d.txOrDb(optionalTx)
	if r, err := optionalTx.ExecContext(ctx, "UPDATE service_user_tokens SET current_token_expires_at = NOW() WHERE org_id = $1", orgId); err != nil {
		return 0, errors.Wrap(err, "failed to expire service user tokens")
	} else {
		rc, _ := r.RowsAffected()
		return rc, nil
	}
}
