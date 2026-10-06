package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/plugincapabilities"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	invalidGrantErrorCode           = "invalid_grant"
	temporarilyUnavailableErrorCode = "temporarily_unavailable"
	maxPluginIDLength               = 200
)

// PluginWorkloadExchange is the configured v1alpha workload token exchange.
type PluginWorkloadExchange struct {
	Issuer   string
	Verifier *workloadidentity.Verifier
	TokenTTL time.Duration
}

// checkPlatformPermission authorizes platform-level operations. Platform
// permissions are granted by IAM configuration only, never by organization
// roles, and never to a plugin workload even if it was configured by mistake.
func (s *Server) checkPlatformPermission(ctx context.Context, permission string) (uuid.UUID, error) {
	subject, authErr := GetAuthenticatedUserIdOr401(ctx)
	if authErr != nil {
		return uuid.Nil, authErr
	}
	if subject != userid.InternalSystemUuid {
		denied := &herrors.PlatformOrchestratorError{
			StatusCode: http.StatusForbidden,
			Details: map[string]interface{}{
				failedChecksField: []ResourcePermissionCheck{{Resource: "platform", Permission: permission}},
			},
		}
		if !slices.Contains(s.PlatformPermissionHolders[permission], subject) {
			return uuid.Nil, denied
		}
		if active, err := s.Database.IsAuthorizationSubjectActive(ctx, nil, subject); err != nil {
			return uuid.Nil, err
		} else if !active {
			return uuid.Nil, denied
		}
		if bound, err := s.isPluginWorkload(ctx, nil, subject); err != nil {
			return uuid.Nil, err
		} else if bound {
			return uuid.Nil, denied
		}
	}
	if ids, ok := hlogger.GetPlatformOrchestratorIdsFromCtx(ctx); ok {
		ids.UserId = subject.String()
	}
	middleware.SetAuthAsserterChecked(ctx)
	return subject, nil
}

// pluginWorkloadBinding returns the binding of a service user, or nil when the
// principal is not a plugin workload.
func (s *Server) pluginWorkloadBinding(ctx context.Context, tx model.Tx, principal uuid.UUID) (*model.PluginWorkloadBinding, error) {
	if !userid.IsServiceUser(principal) {
		return nil, nil
	}
	binding, err := s.Database.GetPluginWorkloadBindingForServiceUser(ctx, tx, principal)
	if _, notFound := model.IsErrNotFound(err); notFound {
		return nil, nil
	}
	return binding, err
}

func (s *Server) isPluginWorkload(ctx context.Context, tx model.Tx, principal uuid.UUID) (bool, error) {
	binding, err := s.pluginWorkloadBinding(ctx, tx, principal)
	return binding != nil, err
}

func toAPIPluginWorkloadBinding(binding model.PluginWorkloadBinding) PluginWorkloadBinding {
	return PluginWorkloadBinding{
		Id:             binding.ID,
		Issuer:         binding.Issuer,
		Namespace:      binding.Namespace,
		ServiceAccount: binding.ServiceAccount,
		Audience:       binding.Audience,
		ServiceUserId:  binding.ServiceUserID,
		PluginId:       binding.PluginID,
		InstallationId: binding.InstallationID,
		CreatedAt:      binding.CreatedAt,
		CreatedBy:      binding.CreatedBy,
	}
}

func (s *Server) validatePluginWorkloadBinding(body *PluginWorkloadBindingCreateBody) string {
	switch {
	case body == nil:
		return "request body is required"
	case s.PluginWorkloadExchange == nil || body.Issuer != s.PluginWorkloadExchange.Issuer:
		return "issuer must be the configured plugin workload token issuer"
	case !workloadidentity.ValidServiceAccount(body.Namespace, body.ServiceAccount):
		return "namespace and service_account must name a Kubernetes ServiceAccount"
	case !workloadidentity.ValidAudience(body.Audience):
		return "audience must be 1 to 255 printable ASCII characters without spaces"
	case len(body.PluginId) > maxPluginIDLength || !plugincapabilities.ValidPluginID(body.PluginId):
		return "plugin_id must be an immutable plugin ID"
	}
	return ""
}

func (s *Server) CreatePluginWorkloadBinding(ctx context.Context, request CreatePluginWorkloadBindingRequestObject) (CreatePluginWorkloadBindingResponseObject, error) {
	operator, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite)
	if err != nil {
		return nil, err
	}
	if message := s.validatePluginWorkloadBinding(request.Body); message != "" {
		return CreatePluginWorkloadBinding400JSONResponse{Generate400Response(message)}, nil
	}
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	body := request.Body
	binding, err := s.Database.CreatePluginWorkloadBinding(ctx, tx, model.PluginWorkloadBinding{
		ID:             uuid.Must(uuid.NewV7()),
		Issuer:         body.Issuer,
		Namespace:      body.Namespace,
		ServiceAccount: body.ServiceAccount,
		Audience:       body.Audience,
		ServiceUserID:  body.ServiceUserId,
		PluginID:       body.PluginId,
		InstallationID: body.InstallationId,
		CreatedAt:      time.Now().UTC(),
		CreatedBy:      operator,
	})
	if conflict, ok := model.IsErrConflict(err); ok {
		return CreatePluginWorkloadBinding409JSONResponse{Generate409Response(conflict.Message)}, nil
	} else if notFound, ok := model.IsErrNotFound(err); ok {
		return CreatePluginWorkloadBinding400JSONResponse{Generate400Response(notFound.Message)}, nil
	} else if err != nil {
		return nil, err
	}
	if !binding.ServiceUserActive {
		return CreatePluginWorkloadBinding400JSONResponse{Generate400Response("service user is not active")}, nil
	}
	if !s.PluginWorkloadStaticTokens {
		if err := s.Database.DisableServiceUserStaticToken(ctx, tx, binding.ServiceUserID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	logger.Info("created plugin workload binding",
		zap.Stringer("binding_id", binding.ID), zap.Stringer("service_user_id", binding.ServiceUserID),
		zap.String("plugin_id", binding.PluginID), zap.String("namespace", binding.Namespace),
		zap.String("service_account", binding.ServiceAccount), zap.Bool("static_token_disabled", !s.PluginWorkloadStaticTokens))
	return CreatePluginWorkloadBinding201JSONResponse(toAPIPluginWorkloadBinding(*binding)), nil
}

func (s *Server) ListPluginWorkloadBindings(ctx context.Context, _ ListPluginWorkloadBindingsRequestObject) (ListPluginWorkloadBindingsResponseObject, error) {
	if _, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite); err != nil {
		return nil, err
	}
	bindings, err := s.Database.ListPluginWorkloadBindings(ctx, nil)
	if err != nil {
		return nil, err
	}
	items := make([]PluginWorkloadBinding, len(bindings))
	for index, binding := range bindings {
		items[index] = toAPIPluginWorkloadBinding(binding)
	}
	return ListPluginWorkloadBindings200JSONResponse{Items: items}, nil
}

func (s *Server) GetPluginWorkloadBinding(ctx context.Context, request GetPluginWorkloadBindingRequestObject) (GetPluginWorkloadBindingResponseObject, error) {
	if _, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite); err != nil {
		return nil, err
	}
	binding, err := s.Database.GetPluginWorkloadBinding(ctx, nil, request.BindingId)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return GetPluginWorkloadBinding404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	return GetPluginWorkloadBinding200JSONResponse(toAPIPluginWorkloadBinding(*binding)), nil
}

// DeletePluginWorkloadBinding revokes a binding. Issued tokens are deleted with
// it and workload tokens are never cached positively, so the next
// authentication with any of them fails.
func (s *Server) DeletePluginWorkloadBinding(ctx context.Context, request DeletePluginWorkloadBindingRequestObject) (DeletePluginWorkloadBindingResponseObject, error) {
	if _, err := s.checkPlatformPermission(ctx, sharedauthz.PermissionPluginWorkloadBindingWrite); err != nil {
		return nil, err
	}
	err := s.Database.DeletePluginWorkloadBinding(ctx, nil, request.BindingId)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return DeletePluginWorkloadBinding404JSONResponse{Generate404FromModelErr(notFound)}, nil
	} else if err != nil {
		return nil, err
	}
	s.Logger.Info("revoked plugin workload binding", zap.Stringer("binding_id", request.BindingId))
	return DeletePluginWorkloadBinding204Response{}, nil
}

// ExchangePluginWorkloadToken implements the v1alpha RFC 8693 exchange. The
// subject token is the credential, so the operation is exempt from gateway
// authentication. Every refusal returns the same invalid_grant answer; the
// reason is only logged.
func (s *Server) ExchangePluginWorkloadToken(ctx context.Context, request ExchangePluginWorkloadTokenRequestObject) (ExchangePluginWorkloadTokenResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())
	reject := func(reason error) ExchangePluginWorkloadTokenResponseObject {
		logger.Info("rejected plugin workload subject token", zap.Error(reason))
		return ExchangePluginWorkloadToken400JSONResponse{N400BadRequestJSONResponse{
			Error: invalidGrantErrorCode, Message: "the subject token cannot be exchanged",
		}}
	}

	exchange := s.PluginWorkloadExchange
	if exchange == nil {
		return ExchangePluginWorkloadToken404JSONResponse{Generate404Response("plugin workload token exchange is not configured")}, nil
	}
	body := request.Body
	if body == nil || !body.GrantType.Valid() || !body.SubjectTokenType.Valid() {
		return ExchangePluginWorkloadToken400JSONResponse{Generate400Response("a token-exchange grant with a JWT subject token is required")}, nil
	}

	claims, err := exchange.Verifier.Verify(ctx, body.SubjectToken)
	if errors.Is(err, workloadidentity.ErrKeysUnavailable) {
		logger.Error("plugin workload token verification keys are unavailable", zap.Error(err))
		return ExchangePluginWorkloadToken503JSONResponse{
			Error: temporarilyUnavailableErrorCode, Message: "the workload token issuer keys are unavailable",
		}, nil
	} else if err != nil {
		return reject(err), nil
	}
	logger = logger.With(zap.String("namespace", claims.Namespace), zap.String("service_account", claims.ServiceAccount))

	binding, err := s.Database.GetPluginWorkloadBindingForServiceAccount(ctx, nil, claims.Issuer, claims.Namespace, claims.ServiceAccount)
	if notFound, ok := model.IsErrNotFound(err); ok {
		return reject(notFound), nil
	} else if err != nil {
		return nil, err
	}
	if err := workloadidentity.MatchAudience(claims.Audience, binding.Audience); err != nil {
		return reject(err), nil
	}
	if !binding.ServiceUserActive {
		return reject(errors.New("the bound service user is not active")), nil
	}
	now := time.Now().UTC()
	lifetime, err := workloadidentity.IssuedLifetime(now, exchange.TokenTTL, claims.Expiry)
	if err != nil {
		return reject(err), nil
	}

	token, hash := workloadidentity.NewToken()
	err = s.Database.CreatePluginWorkloadToken(ctx, nil, model.PluginWorkloadToken{
		Sha256Hash: hash, BindingID: binding.ID, IssuedAt: now, ExpiresAt: now.Add(lifetime),
	})
	if notFound, ok := model.IsErrNotFound(err); ok {
		return reject(notFound), nil
	} else if err != nil {
		return nil, err
	}
	logger.Info("issued plugin workload token",
		zap.Stringer("binding_id", binding.ID), zap.Stringer("service_user_id", binding.ServiceUserID), zap.Duration("lifetime", lifetime))
	return ExchangePluginWorkloadToken200JSONResponse{
		Body: PluginWorkloadTokenExchangeResponse{
			AccessToken:     token,
			IssuedTokenType: PluginWorkloadIssuedTokenTypeAccessToken,
			TokenType:       PluginWorkloadTokenTypeBearer,
			ExpiresIn:       int(lifetime / time.Second),
		},
		Headers: ExchangePluginWorkloadToken200ResponseHeaders{CacheControl: "no-store"},
	}, nil
}
