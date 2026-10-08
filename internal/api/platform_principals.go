package api

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const serviceUsersMayNotIssuePlatformTokens = "service users may not issue static platform tokens"

// Platform principals belong to no organization and hold no role. Managing
// them is part of managing plugin identities, so every route requires the
// platform permission plugin_workload_binding_write. Issuing a static token
// additionally requires a user or IAM's internal system identity: like
// CreateServiceUser, a service user may not mint long-lived credentials.

func toAPIPlatformPrincipal(principal model.PlatformPrincipal) PlatformPrincipal {
	credential := PlatformPrincipalCredentialWorkload
	if principal.HoldsStaticToken() {
		credential = PlatformPrincipalCredentialStaticToken
	}
	return PlatformPrincipal{
		Id:                    principal.ID,
		DisplayName:           principal.DisplayName,
		Credential:            credential,
		GeneratedAt:           principal.GeneratedAt,
		GeneratedBy:           principal.GeneratedBy,
		CurrentTokenExpiresAt: principal.CurrentTokenExpiresAt,
		WorkloadBindingId:     principal.WorkloadBindingID,
	}
}

func toAPIPlatformPrincipalWithToken(principal model.PlatformPrincipal, token string) PlatformPrincipalWithToken {
	view := toAPIPlatformPrincipal(principal)
	return PlatformPrincipalWithToken{
		Id:                    view.Id,
		DisplayName:           view.DisplayName,
		Credential:            view.Credential,
		GeneratedAt:           view.GeneratedAt,
		GeneratedBy:           view.GeneratedBy,
		CurrentTokenExpiresAt: view.CurrentTokenExpiresAt,
		WorkloadBindingId:     view.WorkloadBindingId,
		Token:                 token,
	}
}

func (s *Server) ListPlatformPrincipals(ctx context.Context, _ ListPlatformPrincipalsRequestObject) (ListPlatformPrincipalsResponseObject, error) {
	if _, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite); err != nil {
		return nil, err
	}
	principals, err := s.Database.ListPlatformPrincipals(ctx, nil)
	if err != nil {
		return nil, err
	}
	items := make([]PlatformPrincipal, len(principals))
	for index, principal := range principals {
		items[index] = toAPIPlatformPrincipal(principal)
	}
	return ListPlatformPrincipals200JSONResponse{Items: items}, nil
}

func (s *Server) GetPlatformPrincipal(ctx context.Context, request GetPlatformPrincipalRequestObject) (GetPlatformPrincipalResponseObject, error) {
	if _, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite); err != nil {
		return nil, err
	}
	principal, err := s.Database.GetPlatformPrincipal(ctx, nil, request.PrincipalId)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return GetPlatformPrincipal404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	return GetPlatformPrincipal200JSONResponse(toAPIPlatformPrincipal(*principal)), nil
}

// CreatePlatformPrincipal creates a static-token platform principal, such as
// the Data Plane admission checker.
func (s *Server) CreatePlatformPrincipal(ctx context.Context, request CreatePlatformPrincipalRequestObject) (CreatePlatformPrincipalResponseObject, error) {
	operator, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite)
	if err != nil {
		return nil, err
	}
	if userid.IsServiceUser(operator) {
		return CreatePlatformPrincipal403JSONResponse{Generate403Response(serviceUsersMayNotIssuePlatformTokens)}, nil
	}
	if request.Body == nil {
		return CreatePlatformPrincipal400JSONResponse{Generate400Response("request body is required")}, nil
	}
	token := newStaticToken(request.Body.ExpiryInDays)
	principal, err := s.Database.CreatePlatformPrincipal(ctx, nil, model.PlatformPrincipal{
		ID: userid.NewServiceUserTokenId(), DisplayName: request.Body.DisplayName,
		GeneratedAt: token.generatedAt, GeneratedBy: operator,
		CurrentTokenExpiresAt: &token.expiresAt, CurrentTokenSha256Hash: token.sha256Hash,
	})
	if err != nil {
		return nil, err
	}
	s.platformPrincipalLogger(ctx, principal.ID, operator).Info("created static-token platform principal",
		zap.String("display_name", principal.DisplayName), zap.Timep("current_token_expires_at", principal.CurrentTokenExpiresAt))
	return CreatePlatformPrincipal201JSONResponse(toAPIPlatformPrincipalWithToken(*principal, token.value)), nil
}

// RegeneratePlatformPrincipal replaces the static token of a static-token
// platform principal. The previous token stops authenticating within the
// authentication cache TTL, like a regenerated service user token.
func (s *Server) RegeneratePlatformPrincipal(ctx context.Context, request RegeneratePlatformPrincipalRequestObject) (RegeneratePlatformPrincipalResponseObject, error) {
	operator, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite)
	if err != nil {
		return nil, err
	}
	if userid.IsServiceUser(operator) {
		return RegeneratePlatformPrincipal403JSONResponse{Generate403Response(serviceUsersMayNotIssuePlatformTokens)}, nil
	}
	if request.Body == nil {
		return RegeneratePlatformPrincipal400JSONResponse{Generate400Response("request body is required")}, nil
	}
	logger := s.platformPrincipalLogger(ctx, request.PrincipalId, operator)

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()
	principal, err := s.Database.GetPlatformPrincipal(ctx, tx, request.PrincipalId)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return RegeneratePlatformPrincipal404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	if !principal.HoldsStaticToken() {
		return RegeneratePlatformPrincipal409JSONResponse{Generate409Response("a plugin workload principal has no static token")}, nil
	}
	token := newStaticToken(request.Body.ExpiryInDays)
	principal.GeneratedAt, principal.GeneratedBy = token.generatedAt, operator
	principal.CurrentTokenExpiresAt, principal.CurrentTokenSha256Hash = &token.expiresAt, token.sha256Hash
	principal, err = s.Database.RegeneratePlatformPrincipalToken(ctx, tx, *principal)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return RegeneratePlatformPrincipal404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	logger.Info("regenerated platform principal token", zap.Timep("current_token_expires_at", principal.CurrentTokenExpiresAt))
	return RegeneratePlatformPrincipal200JSONResponse(toAPIPlatformPrincipalWithToken(*principal, token.value)), nil
}

// DeletePlatformPrincipal deletes a platform principal with its workload
// binding and issued workload tokens.
func (s *Server) DeletePlatformPrincipal(ctx context.Context, request DeletePlatformPrincipalRequestObject) (DeletePlatformPrincipalResponseObject, error) {
	operator, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite)
	if err != nil {
		return nil, err
	}
	err = s.Database.DeletePlatformPrincipal(ctx, nil, request.PrincipalId)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return DeletePlatformPrincipal404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	s.platformPrincipalLogger(ctx, request.PrincipalId, operator).Info("deleted platform principal")
	return DeletePlatformPrincipal204Response{}, nil
}

func (s *Server) platformPrincipalLogger(ctx context.Context, principal, operator uuid.UUID) *zap.Logger {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	return hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField()).
		With(zap.Stringer("platform_principal_id", principal), zap.Stringer("operator", operator))
}
