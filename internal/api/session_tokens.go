package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

const (
	SessionTokenEntropyBytes = 33
	SessionTokenExpiry       = 24 * time.Hour
	SessionTokenCookieName   = "session-token"
)

func EncodeSessionToken(raw []byte) string {
	return base64.URLEncoding.EncodeToString(raw)
}

func DecodeSessionToken(raw string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(raw)
}

func NewSessionToken(userId uuid.UUID, providerType model.UserIdentityProvider) (string, *model.SessionToken) {
	raw := make([]byte, SessionTokenEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		// panic if we can't get entropy
		panic(err)
	}
	hashSum := sha256.Sum256(raw)
	now := time.Now().UTC()
	return EncodeSessionToken(raw), &model.SessionToken{
		Sha256Hash: hashSum[:],
		Provider:   providerType,
		UserId:     userId,
		CreatedAt:  now,
		ExpiresAt:  now.Add(SessionTokenExpiry),
	}
}

func (s *Server) baseCookie() http.Cookie {
	// #nosec G124 -- all required security attributes are set explicitly below.
	return http.Cookie{
		Name: SessionTokenCookieName,
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#pathpath-value
		// The Path that must exist as a prefix. / must be set explicitly.
		Path: "/",
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#httponly
		// Javascript cannot access the cookie
		HttpOnly: true,
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#secure
		// Only sent on https requests
		Secure: true,
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
		// This might look weird, but we want this cookie to be present on _any_ request within Domain including
		// cross-site and same-site.
		SameSite: http.SameSiteNoneMode,
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#domaindomain-value
		// The cookie is available on this domain and all subdomains, a leading . is ignored and not required.
		Domain: s.SessionTokenCookieDomain,
	}
}

func (s *Server) generateSetCookieForToken(raw string, token *model.SessionToken) string {
	// #nosec G124 -- baseCookie sets Secure, HttpOnly, and SameSite.
	base := s.baseCookie()
	base.Value = raw
	base.Expires = token.ExpiresAt
	return base.String()
}

func (s *Server) generateSetCookieForLogout() string {
	// #nosec G124 -- baseCookie sets Secure, HttpOnly, and SameSite.
	base := s.baseCookie()
	base.MaxAge = -1
	return base.String()
}

func (s *Server) ListUserSessionTokens(ctx context.Context, request ListUserSessionTokensRequestObject) (ListUserSessionTokensResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkUserIdSelfAuthorization(ctx, uid, request.UserId); err != nil {
		return nil, err
	}

	page, err := s.Database.ListSessionTokenByUserId(ctx, nil, request.UserId, model.ListSessionTokensParams{ExpiresAfter: time.Now().UTC()})
	if err != nil {
		return nil, err
	}

	out := make([]UserSessionTokenSummary, len(page))
	for i, item := range page {
		out[i] = UserSessionTokenSummary{
			CreatedAt:    item.CreatedAt,
			ExpiresAt:    item.ExpiresAt,
			Hash:         base64.URLEncoding.EncodeToString(item.Sha256Hash),
			Provider:     string(item.Provider),
			ClientIp:     item.ClientIp.Ref(),
			ClientCity:   item.ClientCity.Ref(),
			ClientRegion: item.ClientRegion.Ref(),
		}
	}

	return ListUserSessionTokens200JSONResponse{Items: out}, nil
}

func (s *Server) RevokeUserSessionToken(ctx context.Context, request RevokeUserSessionTokenRequestObject) (RevokeUserSessionTokenResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkUserIdSelfAuthorization(ctx, uid, request.UserId); err != nil {
		return nil, err
	}

	raw, err := base64.URLEncoding.DecodeString(request.Hash)
	if err != nil {
		return RevokeUserSessionToken400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid hash")}, nil
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	t, err := s.Database.GetSessionTokenByHash(ctx, tx, raw)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return RevokeUserSessionToken404JSONResponse{N404NotFoundJSONResponse: Generate404Response("session token not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get session token")
	} else if t.UserId != request.UserId {
		return RevokeUserSessionToken404JSONResponse{N404NotFoundJSONResponse: Generate404Response("session token not found")}, nil
	}

	if err := s.Database.DeleteSessionTokenByHash(ctx, tx, raw); err != nil {
		return nil, errors.Wrap(err, "failed to delete session token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	return RevokeUserSessionToken204Response{}, nil
}
