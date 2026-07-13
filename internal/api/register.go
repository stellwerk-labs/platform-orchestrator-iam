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

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func (s *Server) RegisterUser(ctx context.Context, request RegisterUserRequestObject) (RegisterUserResponseObject, error) {
	// TODO: reject request if user is logged in

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zap.String("provider", request.Body.Provider)).WithLazy(ids.AsLogField())

	providerType := model.UserIdentityProvider(request.Body.Provider)
	provider := s.UserIdentityProviders[providerType]
	if provider == nil {
		return RegisterUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid provider")}, nil
	}

	iu, ok, err := provider.IdentifyUser(ctx, logger, request.Body.ProviderToken)
	if err != nil {
		// NOTE: for security / availability reasons we don't return a 400 vs 500 here we just log the error
		logger.Warn("failed to identify user", zap.Error(err))
	}
	if !ok {
		return RegisterUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid provider token")}, nil
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

	var resultingUser model.User
	existingUserId, err := s.Database.GetUserIdByIdentity(ctx, tx, providerType, iu.ProviderId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); !ok {
			return nil, errors.Wrap(err, "failed to get user id by identity")
		}
	}

	now := time.Now().UTC()
	if existingUserId == nil {

		newUser := model.User{
			Id:                  userid.NewHumanUserId(),
			DisplayName:         opt.OfRef(iu.DisplayName).Or("Unnamed User"),
			PrimaryEmailAddress: opt.OfRef(iu.PrimaryEmailAddress),
			CreatedAt:           time.Now().UTC(),
			LastLoggedInAt:      &now,
			UserIdentities: map[model.UserIdentityProvider]string{
				providerType: iu.ProviderId,
			},
		}
		if user, err := s.Database.CreateUser(ctx, tx, &newUser); err != nil {
			return nil, errors.Wrap(err, "failed to create user")
		} else {
			resultingUser = *user
		}
		logger = logger.With(zap.String("user_id", resultingUser.Id.String()))
		logger.Info("registered new user")

	} else {

		if user, err := s.Database.GetUser(ctx, tx, *existingUserId); err != nil {
			return nil, errors.Wrap(err, "failed to get user")
		} else {
			user.LastLoggedInAt = &now
			if iu.PrimaryEmailAddress != nil && user.PrimaryEmailAddress.Or("") != *iu.PrimaryEmailAddress {
				user.PrimaryEmailAddress = opt.OfRef(iu.PrimaryEmailAddress)
			}
			if user, err = s.Database.UpdateUser(ctx, tx, user); err != nil {
				return nil, errors.Wrap(err, "failed to update user")
			}

			resultingUser = *user
		}

		logger = logger.With(zap.String("user_id", resultingUser.Id.String()))
		logger.Info("user identity already has an account")

	}

	logger.Info("creating session token", zap.String("user_id", resultingUser.Id.String()))
	rawToken, st := NewSessionToken(resultingUser.Id, providerType)
	st.ClientIp = opt.OfRef(request.Params.XClientIP)
	st.ClientRegion = opt.OfRef(request.Params.XClientRegion)
	st.ClientCity = opt.OfRef(request.Params.XClientCity)
	if st, err = s.Database.CreateSessionToken(ctx, tx, st); err != nil {
		return nil, errors.Wrap(err, "failed to create session token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	return RegisterUser202JSONResponse{
		Body: RegisteredUser{
			CreatedAt:             resultingUser.CreatedAt,
			DisplayName:           resultingUser.DisplayName,
			Id:                    resultingUser.Id,
			IdentityAlreadyExists: existingUserId != nil,
			LastLoggedInAt:        resultingUser.LastLoggedInAt,
			LoginProviders: slices.Sorted(func(yield func(string) bool) {
				for p := range resultingUser.UserIdentities {
					yield(string(p))
				}
			}),
			PrimaryEmailAddress: resultingUser.PrimaryEmailAddress.Ref(),
		},
		Headers: RegisterUser202ResponseHeaders{
			SetCookie: s.generateSetCookieForToken(rawToken, st),
		},
	}, nil
}
