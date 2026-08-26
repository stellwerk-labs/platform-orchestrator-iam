package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

const (
	// authenticationTokenCacheSize used for GetTokenByHashCache. Cache entries are small and don't last long
	// so we don't really expect this size to be hit.
	authenticationTokenCacheSize = 10_000
	// authenticationTokenCacheTTL is the ttl for GetTokenByHashCache. We need enough to spread out most frequent
	// user accesses.
	authenticationTokenCacheTTL = 60 * time.Second
	// authenticatedUserIdHeader is the header that provides the authenticated user id down to the backend services.
	authenticatedUserIdHeader = "From"
	// authenticatedUserIdTokenHashHeader is the header that provides the hash of the token which
	// supports certain IAM functions like logout.
	authenticatedUserIdTokenHashHeader = "X-Token-Hash" //nolint:gosec
)

var skipAuthenticationRegex = regexp.MustCompile(
	`^(` +
		// register and login obvious don't need to be authenticated yet
		`/auth/register|/auth/login|/auth/device|/auth/sso/login|/auth/sso/callback` +

		// exclude device logins
		`|/auth/device|/devicelogins/[^/]+/actions/poll` +

		// TODO: remove these once we have a different domain for the runners to hit
		`|(/orgs/[^/]+/deployments/[^/]+/results)` +
		`|(/orgs/[^/]+/deployments/[^/]+/bundle)` +

		// SCIM discovery documents are static and tenant-free, and RFC 7644 §4
		// allows them unauthenticated. Entra's SCIM validator probes them
		// without a token, so they have to clear ext-auth too — the handlers
		// being outside the SCIM auth middleware is not enough on its own,
		// because Envoy's ext-auth runs before the route.
		//
		// Enumerated deliberately: /Users and /Groups must never match here.
		`|(/scim/v2/orgs/[^/]+/ServiceProviderConfig)` +
		`|(/scim/v2/orgs/[^/]+/Schemas(/[^/]+)?)` +
		`|(/scim/v2/orgs/[^/]+/ResourceTypes(/[^/]+)?)` +
		`)$`,
)

// buildInternalAuthenticateWildcard is a proxy to InternalAuthenticate because the openapi defined routes do not allow
// wildcard path params.
func (s *Server) buildInternalAuthenticateWildcard(handler ServerInterface) echo.HandlerFunc {
	return func(c echo.Context) error {
		// There will be some paths that don't need authentication. Check for them and exclude them here. This is usually
		// just the login methods, but could be some other things too.
		if skipAuthenticationRegex.MatchString("/" + c.Param("*")) {
			c.Response().Header().Set(authenticatedUserIdHeader, uuid.Nil.String())
			return c.NoContent(http.StatusOK)
		}

		// Admin paths use a separate authentication flow based on the super user token env var.
		if strings.HasPrefix(c.Param("*"), "admin/") {
			return s.authenticateSuperUser(c)
		}

		var authHeader, cookieContents *string
		if v := c.Request().Header.Get("Authorization"); v != "" {
			authHeader = &v
		}
		if cookie, err := c.Cookie(SessionTokenCookieName); err == nil {
			cookieContents = &cookie.Value
		}

		return handler.InternalAuthenticate(c, InternalAuthenticateParams{
			Authorization: authHeader,
			SessionToken:  cookieContents,
		})
	}
}

// authenticateSuperUser handles authentication for /admin/ paths by comparing the bearer token hash
// against the configured SuperUserTokenHash.
func (s *Server) authenticateSuperUser(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		resp := build401(`Bearer`)
		c.Response().Header().Set("WWW-Authenticate", resp.Headers.WWWAuthenticate)
		return c.JSON(http.StatusUnauthorized, resp.Body)
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	if len(s.SuperUserTokenHash) == 0 {
		s.Logger.Debug("super user token rejected: feature disabled")
		resp := build401(`Bearer error="invalid_token"`)
		c.Response().Header().Set("WWW-Authenticate", resp.Headers.WWWAuthenticate)
		return c.JSON(http.StatusUnauthorized, resp.Body)
	}

	tokenHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(tokenHash[:], s.SuperUserTokenHash) != 1 {
		s.Logger.Debug("super user token rejected: hash mismatch")
		resp := build401(`Bearer error="invalid_token"`)
		c.Response().Header().Set("WWW-Authenticate", resp.Headers.WWWAuthenticate)
		return c.JSON(http.StatusUnauthorized, resp.Body)
	}

	s.Logger.Debug("super user authentication successful")
	c.Response().Header().Set(authenticatedUserIdHeader, userid.InternalSystemUuid.String())
	c.Response().Header().Set(authenticatedUserIdTokenHashHeader, base64.URLEncoding.EncodeToString(tokenHash[:]))
	return c.NoContent(http.StatusOK)
}

func build401(wwwAuthenticate string) N401UnauthorizedJSONResponse {
	return N401UnauthorizedJSONResponse{
		Body: Error{
			Error:   unauthorizedErrorCode,
			Message: http.StatusText(http.StatusUnauthorized),
		},
		Headers: N401UnauthorizedResponseHeaders{WWWAuthenticate: wwwAuthenticate},
	}
}

// InternalAuthenticate Endpoint to authenticate external requests and pass the user id and session token hash down
// to the backend services.
func (s *Server) InternalAuthenticate(ctx context.Context, request InternalAuthenticateRequestObject) (InternalAuthenticateResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	var tokenHashFromRequest [32]byte
	var isServiceUserToken bool
	{
		// Lookup the source of the token from either cookie or bearer token. We hash it immediately without letting
		// the value leak into the rest of the function.
		var token string
		if request.Params.SessionToken != nil {
			token = *request.Params.SessionToken
		} else if request.Params.Authorization != nil && strings.HasPrefix(*request.Params.Authorization, "Bearer ") {
			token = strings.TrimPrefix(*request.Params.Authorization, "Bearer ")
		} else {
			// If we never found the token anywhere, we can simply reject the request as unauthorized. We're under no obligation
			// to return any other errors or information.
			return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer`)}, nil
		}
		isServiceUserToken = strings.HasPrefix(token, ServiceUserTokenPrefix)
		rawToken, _ := DecodeSessionToken(strings.TrimPrefix(token, ServiceUserTokenPrefix))
		tokenHashFromRequest = sha256.Sum256(rawToken)
	}
	logger = logger.With(
		zap.Bool("is_service_user_token", isServiceUserToken),
		zap.String("token_hash", base64.URLEncoding.EncodeToString(tokenHashFromRequest[:])),
	)

	// NOTE: in the future when we need to authenticate service user tokens, we should ensure they have a predictable
	// prefix which indicates this use and allows us to skip immediately to that route.

	// Attempt to record hit stats
	defer func() {
		if lookups, misses, ok := s.TokenByHashCache.Stats(time.Minute); ok {
			hitRatio := float64(lookups-misses) / float64(lookups)
			logger.Info("authentication token cache stats", zap.Uint64("lookups", lookups), zap.Uint64("misses", misses), zap.Float64("hit_ratio", hitRatio))
		}
	}()

	// Now we attempt to match the incoming token hash against a session token and do this through our caching layer
	st, err := s.TokenByHashCache.GetTokenByHash(ctx, isServiceUserToken, tokenHashFromRequest[:])
	if err != nil {
		logger.Error("failed to lookup token", zap.Error(err))
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	} else if st == nil {
		logger.Debug("token not found")
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	} else if time.Now().After(st.ExpiresAt) {
		logger.Debug("token expired")
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	}

	// return our authentication request
	logger.Debug("authentication successful", zap.Stringer("user_id", st.UserId))
	return InternalAuthenticate200Response{
		Headers: InternalAuthenticate200ResponseHeaders{
			From:       st.UserId,
			XTokenHash: base64.URLEncoding.EncodeToString(tokenHashFromRequest[:]),
		},
	}, nil
}

// GetTokenByHashCache is used to cache the GetTokenByHash database call. We can't do this extra DB
// call on every request since this could easily be malicious traffic or old expired tokens.
type GetTokenByHashCache struct {
	inner model.Databaser
	cache *ccache.Cache
	ttl   time.Duration

	lookups         atomic.Uint64
	misses          atomic.Uint64
	lastStatsReport atomic.Value
}

type WrappedToken struct {
	UserId    uuid.UUID
	ExpiresAt time.Time
}

func NewGetTokenByHashCache(db model.Databaser) *GetTokenByHashCache {
	return &GetTokenByHashCache{
		inner: db,
		cache: ccache.New(ccache.Configure().MaxSize(authenticationTokenCacheSize)),
		ttl:   authenticationTokenCacheTTL,
	}
}

func (a *GetTokenByHashCache) GetTokenByHash(ctx context.Context, isServiceUserToken bool, tokenHash []byte) (*WrappedToken, error) {
	a.lookups.Add(1)
	item, err := a.cache.Fetch(hex.EncodeToString(tokenHash), a.ttl, func() (interface{}, error) {
		a.misses.Add(1)
		if isServiceUserToken {
			sut, err := a.inner.GetServiceUserTokenByHash(ctx, nil, tokenHash)
			if err != nil {
				if _, ok := model.IsErrNotFound(err); ok {
					// record a negative cache entry
					return &WrappedToken{}, nil
				}
				return nil, errors.Wrap(err, "failed to get service user token")
			}
			return &WrappedToken{UserId: sut.Id, ExpiresAt: sut.CurrentTokenExpiresAt}, nil
		} else {
			st, err := a.inner.GetSessionTokenByHash(ctx, nil, tokenHash)
			if err != nil {
				if _, ok := model.IsErrNotFound(err); ok {
					// record a negative cache entry
					return &WrappedToken{}, nil
				}
				return nil, errors.Wrap(err, "failed to get session token")
			}
			return &WrappedToken{UserId: st.UserId, ExpiresAt: st.ExpiresAt}, nil
		}
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch and cache token")
	}

	if v := item.Value().(*WrappedToken); v.UserId == uuid.Nil {
		// We can safely extend the lifetime of a negative cache entry since it won't spontaneously map to a new token.
		// We can't do the same for real entries because that would negate logout/session revocation - which would
		// be bad.
		item.Extend(a.ttl)
		// this is a negative cache entry - return it as nil (not found)
		return nil, nil
	} else {
		return v, nil
	}
}

// Stats will only return the stats if enough time has passed since the last request for them. This acts as a throttle
// or rate limit to avoid logging them too much.
// We could replace this with metrics if we care too in the future but its not worth the hassle yet.
func (a *GetTokenByHashCache) Stats(interval time.Duration) (lookups uint64, misses uint64, ok bool) {
	now := time.Now()
	if t := a.lastStatsReport.Load(); t == nil || now.Sub(t.(time.Time)) > interval {
		if a.lastStatsReport.CompareAndSwap(t, now) {
			return a.lookups.Load(), a.misses.Load(), true
		}
	}
	return 0, 0, false
}
