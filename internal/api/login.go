package api

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

func (s *Server) LoginSession(ctx context.Context, request LoginSessionRequestObject) (LoginSessionResponseObject, error) {
	// TODO: reject request if user is logged in

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zap.String("provider", request.Body.Provider)).WithLazy(ids.AsLogField())

	providerType := model.UserIdentityProvider(request.Body.Provider)
	provider := s.UserIdentityProviders[providerType]
	if provider == nil {
		return LoginSession400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid provider")}, nil
	}

	iu, ok, err := provider.IdentifyUser(ctx, logger, request.Body.ProviderToken)
	if err != nil {
		// NOTE: for security / availability reasons we don't return a 400 vs 500 here we just log the error
		logger.Warn("failed to identify user", zap.Error(err))
	}
	if !ok {
		return LoginSession400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid provider token")}, nil
	}

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	// Check if we have an existing user with this identity
	existingUserId, err := s.Database.GetUserIdByIdentity(ctx, tx, providerType, iu.ProviderId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return LoginSession401JSONResponse{N401UnauthorizedJSONResponse: build401WithMessage("Bearer", "no such user")}, nil
		}
		return nil, errors.Wrap(err, "failed to get user id by identity")
	}

	user, err := s.Database.GetUser(ctx, tx, *existingUserId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user")
	}

	now := time.Now().UTC()
	user.LastLoggedInAt = &now

	// todo: potentially also update the display name if it has changed (microsoft)
	if iu.PrimaryEmailAddress != nil && user.PrimaryEmailAddress.Or("") != *iu.PrimaryEmailAddress {
		user.PrimaryEmailAddress = opt.OfRef(iu.PrimaryEmailAddress)
	}
	user, err = s.Database.UpdateUser(ctx, tx, user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update user")
	}

	logger.Info("creating session token", zap.String("user_id", user.Id.String()))
	rawToken, st := NewSessionToken(user.Id, providerType)
	st.ClientIp = opt.OfRef(request.Params.XClientIP)
	st.ClientRegion = opt.OfRef(request.Params.XClientRegion)
	st.ClientCity = opt.OfRef(request.Params.XClientCity)
	if st, err = s.Database.CreateSessionToken(ctx, tx, st); err != nil {
		return nil, errors.Wrap(err, "failed to create session token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	return LoginSession200JSONResponse{
		Body: User{
			CreatedAt:      user.CreatedAt,
			DisplayName:    user.DisplayName,
			Id:             user.Id,
			LastLoggedInAt: user.LastLoggedInAt,
			LoginProviders: slices.Sorted(func(yield func(string) bool) {
				for p := range user.UserIdentities {
					yield(string(p))
				}
			}),
			PrimaryEmailAddress: user.PrimaryEmailAddress.Ref(),
		},
		Headers: LoginSession200ResponseHeaders{
			SetCookie: s.generateSetCookieForToken(rawToken, st),
		},
	}, nil

}
