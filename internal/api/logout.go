package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

// LogoutSession gets called from the frontend when a user wants to log out from their session and possibly log in as
// a different user. In general this means at least clearing the browser cookie, but we also attempt to revoke the
// login session too. The hash of the session token should be forwarded from the auth gateway.
func (s *Server) LogoutSession(ctx context.Context, request LogoutSessionRequestObject) (LogoutSessionResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	if request.Params.XTokenHash != nil {
		raw, err := base64.URLEncoding.DecodeString(*request.Params.XTokenHash)
		if err != nil {
			logger.Warn("invalid session token hash provided", zap.String("hash", *request.Params.XTokenHash), zap.Error(err))
			return nil, herrors.NewWithStatus(http.StatusBadRequest, "session token hash is invalid", nil)
		}

		if err := s.Database.DeleteSessionTokenByHash(ctx, nil, raw); err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				logger.Info("no-op logout - session token not found")
			} else {
				return nil, errors.Wrap(err, "failed to delete session token")
			}
		}
		logger.Info("session token deleted during log out")
	} else {
		logger.Warn("no-op logout - no session token hash provided")
	}

	return LogoutSession204Response{
		Headers: LogoutSession204ResponseHeaders{
			SetCookie: s.generateSetCookieForLogout(),
		},
	}, nil
}
