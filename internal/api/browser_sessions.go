package api

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

// BrowserSessionStatus contains deadlines, never credentials. Reading it does
// not renew a session, so polling and tab resumption cannot keep it alive.
type BrowserSessionStatus struct {
	IdleTimeoutMS int64     `json:"idle_timeout_ms"`
	UserID        uuid.UUID `json:"user_id"`
	ServerTime    time.Time `json:"server_time"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func browserSessionHash(c echo.Context) ([]byte, error) {
	cookie, err := c.Cookie(SessionTokenCookieName)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Browser session required")
	}
	raw, err := DecodeSessionToken(cookie.Value)
	if err != nil || len(raw) != SessionTokenEntropyBytes {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid browser session")
	}
	hash := sha256.Sum256(raw)
	return hash[:], nil
}

func (s *Server) browserSessionStatus(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	hash, err := browserSessionHash(c)
	if err != nil {
		return err
	}
	token, err := s.Database.GetSessionTokenByHash(c.Request().Context(), nil, hash)
	if _, missing := model.IsErrNotFound(err); missing {
		return echo.NewHTTPError(http.StatusUnauthorized, "Session expired")
	}
	if err != nil {
		return err
	}
	if token.Provider == model.UserIdentityProviderDevice {
		return echo.NewHTTPError(http.StatusUnauthorized, "Browser session required")
	}
	return s.writeBrowserSession(c, token)
}

func (s *Server) browserSessionActivity(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	// SameSite=None is intentional for the existing session cookie. Require the
	// configured Console origin and a non-simple header, not CORS alone.
	console, err := url.Parse(s.UiHostUrl)
	if err != nil || console.Host == "" || c.Request().Header.Get("Origin") != console.Scheme+"://"+console.Host || c.Request().Header.Get("X-Session-Activity") != "1" {
		return echo.NewHTTPError(http.StatusForbidden, "Console activity origin required")
	}
	hash, err := browserSessionHash(c)
	if err != nil {
		return err
	}
	token, err := s.Database.RecordBrowserSessionActivity(c.Request().Context(), hash, s.browserSessionIdleTimeout())
	if _, missing := model.IsErrNotFound(err); missing {
		return echo.NewHTTPError(http.StatusUnauthorized, "Session expired")
	}
	if err != nil {
		return err
	}
	return s.writeBrowserSession(c, token)
}

func (s *Server) writeBrowserSession(c echo.Context, token *model.SessionToken) error {
	expiry := s.sessionExpiresAt(token)
	if !token.CheckedAt.Before(expiry) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Session expired")
	}
	idle := token.BrowserIdleTimeout
	if idle <= 0 {
		idle = s.browserSessionIdleTimeout()
	}
	return c.JSON(http.StatusOK, BrowserSessionStatus{IdleTimeoutMS: idle.Milliseconds(), UserID: token.UserId, ServerTime: token.CheckedAt, ExpiresAt: expiry})
}
