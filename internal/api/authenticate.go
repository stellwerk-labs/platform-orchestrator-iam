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
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity"
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

		// The plugin workload token exchange authenticates its caller with the
		// projected ServiceAccount token in the request body.
		`|/auth/plugin-workload-token` +
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
	return build401WithMessage(wwwAuthenticate, http.StatusText(http.StatusUnauthorized))
}

func build401WithMessage(wwwAuthenticate, message string) N401UnauthorizedJSONResponse {
	return N401UnauthorizedJSONResponse{
		Body: Error{
			Error:   unauthorizedErrorCode,
			Message: message,
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
	var kind tokenKind
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
		kind, tokenHashFromRequest = classifyToken(token)
	}
	logger = logger.With(
		zap.String("token_kind", string(kind)),
		zap.String("token_hash", base64.URLEncoding.EncodeToString(tokenHashFromRequest[:])),
	)

	// Attempt to record hit stats
	defer func() {
		if lookups, misses, ok := s.TokenByHashCache.Stats(time.Minute); ok {
			hitRatio := float64(lookups-misses) / float64(lookups)
			logger.Info("authentication token cache stats", zap.Uint64("lookups", lookups), zap.Uint64("misses", misses), zap.Float64("hit_ratio", hitRatio))
		}
	}()

	// Now we attempt to match the incoming token hash against a session token and do this through our caching layer
	st, err := s.TokenByHashCache.GetTokenByHash(ctx, kind, tokenHashFromRequest[:])
	if err != nil {
		logger.Error("failed to lookup token", zap.Error(err))
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	} else if st == nil {
		logger.Debug("token not found")
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	} else if time.Now().After(st.ExpiresAt) {
		logger.Debug("token expired")
		return InternalAuthenticate401JSONResponse{N401UnauthorizedJSONResponse: build401(`Cookie, Bearer error="invalid_token"`)}, nil
	} else if kind == tokenKindServiceUser && st.WorkloadBound && !s.PluginWorkloadStaticTokens {
		logger.Info("rejected static token of a workload-bound service user", zap.Stringer("user_id", st.UserId))
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
	// WorkloadBound marks a service user that has a plugin workload binding.
	WorkloadBound bool
}

// tokenKind selects the authoritative table and the caching rule of a credential.
type tokenKind string

const (
	tokenKindSession        tokenKind = "session"
	tokenKindServiceUser    tokenKind = "service-user"
	tokenKindPluginWorkload tokenKind = "plugin-workload"
)

func classifyToken(token string) (tokenKind, [32]byte) {
	switch {
	case strings.HasPrefix(token, ServiceUserTokenPrefix):
		raw, _ := DecodeSessionToken(strings.TrimPrefix(token, ServiceUserTokenPrefix))
		return tokenKindServiceUser, sha256.Sum256(raw)
	case strings.HasPrefix(token, workloadidentity.TokenPrefix):
		var hash [32]byte
		if parsed, ok := workloadidentity.HashToken(token); ok {
			copy(hash[:], parsed)
		}
		return tokenKindPluginWorkload, hash
	default:
		raw, _ := DecodeSessionToken(token)
		return tokenKindSession, sha256.Sum256(raw)
	}
}

func NewGetTokenByHashCache(db model.Databaser) *GetTokenByHashCache {
	return &GetTokenByHashCache{
		inner: db,
		cache: ccache.New(ccache.Configure().MaxSize(authenticationTokenCacheSize)),
		ttl:   authenticationTokenCacheTTL,
	}
}

func (a *GetTokenByHashCache) GetTokenByHash(ctx context.Context, kind tokenKind, tokenHash []byte) (*WrappedToken, error) {
	a.lookups.Add(1)
	// The token kind is part of the key deliberately. Service-user tokens use
	// the same random payload with an SU- wire prefix; sharing a hash-only cache
	// key let a warmed service-user entry authenticate the prefixless payload as
	// a human session.
	cacheKey := string(kind) + ":" + hex.EncodeToString(tokenHash)

	// A human session must stop authenticating as soon as its database row is
	// deleted. Positive session caching made logout and SCIM deprovisioning
	// continue to work for up to authenticationTokenCacheTTL, and a process-
	// local eviction would still be unsafe with multiple IAM replicas. Plugin
	// workload tokens follow the same rule, so revoking a binding or disabling
	// its service user rejects the next authentication. Keep negative entries to
	// absorb random/expired-token traffic, but read every valid token of these
	// kinds from the authoritative database.
	if kind != tokenKindServiceUser {
		if item := a.cache.Get(cacheKey); item != nil && !item.Expired() {
			if item.Value().(*WrappedToken).UserId == uuid.Nil {
				item.Extend(a.ttl)
				return nil, nil
			}
		}

		a.misses.Add(1)
		wrapped, err := a.lookupUncached(ctx, kind, tokenHash)
		if err != nil {
			return nil, err
		}
		if wrapped == nil || time.Now().After(wrapped.ExpiresAt) {
			a.cache.Set(cacheKey, &WrappedToken{}, a.ttl)
		}
		return wrapped, nil
	}

	item, err := a.cache.Fetch(cacheKey, a.ttl, func() (interface{}, error) {
		a.misses.Add(1)
		sut, err := a.inner.GetServiceUserTokenByHash(ctx, nil, tokenHash)
		if err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				// record a negative cache entry
				return &WrappedToken{}, nil
			}
			return nil, errors.Wrap(err, "failed to get service user token")
		}
		// The binding flag is cached with the entry: a binding created later
		// rejects this static token within authenticationTokenCacheTTL.
		_, err = a.inner.GetPluginWorkloadBindingForServiceUser(ctx, nil, sut.Id)
		if _, notFound := model.IsErrNotFound(err); err != nil && !notFound {
			return nil, errors.Wrap(err, "failed to check plugin workload binding")
		}
		return &WrappedToken{UserId: sut.Id, ExpiresAt: sut.CurrentTokenExpiresAt, WorkloadBound: err == nil}, nil
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

func (a *GetTokenByHashCache) lookupUncached(ctx context.Context, kind tokenKind, tokenHash []byte) (*WrappedToken, error) {
	if kind == tokenKindPluginWorkload {
		token, err := a.inner.GetPluginWorkloadTokenByHash(ctx, nil, tokenHash)
		if _, ok := model.IsErrNotFound(err); ok {
			return nil, nil
		} else if err != nil {
			return nil, errors.Wrap(err, "failed to get plugin workload token")
		}
		return &WrappedToken{UserId: token.ServiceUserID, ExpiresAt: token.ExpiresAt}, nil
	}
	st, err := a.inner.GetSessionTokenByHash(ctx, nil, tokenHash)
	if _, ok := model.IsErrNotFound(err); ok {
		return nil, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to get session token")
	}
	return &WrappedToken{UserId: st.UserId, ExpiresAt: st.ExpiresAt}, nil
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
