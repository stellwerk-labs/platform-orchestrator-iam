//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func browserSessionFixture(t *testing.T, timeZone ...string) (*Server, *sql.DB, *echo.Echo, uuid.UUID) {
	t.Helper()
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "session_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); require.NoError(t, err) })
	zone := "UTC"
	if len(timeZone) > 0 {
		zone = timeZone[0]
	}
	connection += " options='-c search_path=" + schema + " -c timezone=" + zone + "'"
	// Keep the connection lifetime through cleanup. testing.T cancels its own
	// context before cleanup, which otherwise races the driver's Close.
	lifetime, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	store, err := model.NewDatabaser(lifetime, zap.NewNop(), connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	db, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	user := userid.NewHumanUserId()
	_, err = db.Exec(`INSERT INTO users(id,display_name,created_at) VALUES($1,'Session fixture',now())`, user)
	require.NoError(t, err)
	server := &Server{Database: store, Logger: zap.NewNop(), UiHostUrl: "https://console.example.test", TokenByHashCache: NewGetTokenByHashCache(store)}
	e := echo.New()
	server.MapRoutes(e)
	return server, db, e, user
}

func TestBrowserSessionLifecycleAndCLILifetime(t *testing.T) {
	s, db, e, user := browserSessionFixture(t)
	raw, token := s.newSessionToken(user, model.UserIdentityProviderGoogle)
	_, err := s.Database.CreateSessionToken(t.Context(), nil, token)
	require.NoError(t, err)
	call := func(method, path, credential, origin, activity string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: SessionTokenCookieName, Value: credential})
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Session-Activity", activity)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, req)
		return response
	}
	authenticate := func(credential string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/projects", nil)
		req.Header.Set("Authorization", "Bearer "+credential)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, req)
		require.Equal(t, want, response.Code, response.Body.String())
	}
	status := call("GET", "/auth/session", raw, "", "")
	require.Equal(t, 200, status.Code, status.Body.String())
	require.Equal(t, "no-store", status.Header().Get("Cache-Control"))
	var initial BrowserSessionStatus
	require.NoError(t, json.Unmarshal(status.Body.Bytes(), &initial))
	require.WithinDuration(t, initial.ServerTime.Add(15*time.Minute), initial.ExpiresAt, time.Second)
	var before, after time.Time
	require.NoError(t, db.QueryRow(`SELECT last_active_at FROM session_tokens WHERE sha256_hash=$1`, token.Sha256Hash).Scan(&before))
	for range 3 {
		require.Equal(t, 200, call("GET", "/auth/session", raw, "", "").Code)
		authenticate(raw, 200)
	}
	require.NoError(t, db.QueryRow(`SELECT last_active_at FROM session_tokens WHERE sha256_hash=$1`, token.Sha256Hash).Scan(&after))
	require.Equal(t, before, after, "background and auth requests must not renew activity")
	for _, origin := range []string{"", "null", "https://evil.example.test", "https://console.example.test.evil.test"} {
		require.Equal(t, 403, call("POST", "/auth/session/activity", raw, origin, "1").Code)
	}
	require.Equal(t, 403, call("POST", "/auth/session/activity", raw, s.UiHostUrl, "").Code)
	require.NoError(t, db.QueryRow(`SELECT last_active_at FROM session_tokens WHERE sha256_hash=$1`, token.Sha256Hash).Scan(&after))
	require.Equal(t, before, after)
	_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-interval '10 minutes' WHERE sha256_hash=$1`, token.Sha256Hash)
	require.NoError(t, err)
	require.Equal(t, 200, call("POST", "/auth/session/activity", raw, s.UiHostUrl, "1").Code)
	require.NoError(t, db.QueryRow(`SELECT last_active_at FROM session_tokens WHERE sha256_hash=$1`, token.Sha256Hash).Scan(&after))
	require.WithinDuration(t, time.Now(), after, time.Second)

	s.BrowserSessionIdleTimeout = 5 * time.Minute
	_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-interval '6 minutes' WHERE sha256_hash=$1`, token.Sha256Hash)
	require.NoError(t, err)
	authenticate(raw, 401) // Replaying the cookie as Bearer cannot escape the policy.
	require.Equal(t, 401, call("GET", "/auth/session", raw, "", "").Code)
	require.Equal(t, 401, call("POST", "/auth/session/activity", raw, s.UiHostUrl, "1").Code)
	// An idle denial must not negatively cache a concurrent, authoritative renewal.
	_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp() WHERE sha256_hash=$1`, token.Sha256Hash)
	require.NoError(t, err)
	authenticate(raw, 200)
	require.NoError(t, s.Database.DeleteSessionTokenByHash(t.Context(), nil, token.Sha256Hash))
	require.Equal(t, 401, call("POST", "/auth/session/activity", raw, s.UiHostUrl, "1").Code)
	authenticate(raw, 401)

	rawCLI, cli := s.newSessionToken(user, model.UserIdentityProviderDevice)
	require.Equal(t, 2*time.Hour, cli.ExpiresAt.Sub(cli.CreatedAt))
	_, err = s.Database.CreateSessionToken(t.Context(), nil, cli)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE session_tokens SET last_active_at=created_at-interval '1 day' WHERE sha256_hash=$1`, cli.Sha256Hash)
	require.NoError(t, err)
	authenticate(rawCLI, 200)
	require.Equal(t, 401, call("GET", "/auth/session", rawCLI, "", "").Code)
	require.Equal(t, 401, call("POST", "/auth/session/activity", rawCLI, s.UiHostUrl, "1").Code)
	s.CLISessionTokenTTL = 4 * time.Hour
	_, custom := s.newSessionToken(user, model.UserIdentityProviderDevice)
	require.Equal(t, 4*time.Hour, custom.ExpiresAt.Sub(custom.CreatedAt))
	// Configuration also caps legacy 24h device sessions; requests do not slide it.
	_, err = db.Exec(`UPDATE session_tokens SET created_at=statement_timestamp()-interval '5 hours', expires_at=statement_timestamp()+interval '1 day' WHERE sha256_hash=$1`, cli.Sha256Hash)
	require.NoError(t, err)
	authenticate(rawCLI, 401)
	require.Equal(t, 401, call("GET", "/auth/session", "invalid", "", "").Code)
}

func TestBrowserSessionCannotRenewAfterWaitingBeyondDeadline(t *testing.T) {
	s, db, _, user := browserSessionFixture(t)
	raw, token := s.newSessionToken(user, model.UserIdentityProviderGoogle)
	_ = raw
	_, err := s.Database.CreateSessionToken(t.Context(), nil, token)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-interval '14 minutes 59 seconds' WHERE sha256_hash=$1`, token.Sha256Hash)
	require.NoError(t, err)
	// A renewal blocked behind this transaction must check the clock after the
	// lock is released, not the transaction or request start time.
	result := make(chan error, 1)
	go func() {
		_, err := s.Database.RecordBrowserSessionActivity(t.Context(), token.Sha256Hash, 15*time.Minute)
		result <- err
	}()
	time.Sleep(1200 * time.Millisecond)
	require.NoError(t, tx.Commit())
	select {
	case err := <-result:
		_, missing := model.IsErrNotFound(err)
		require.True(t, missing, "expired session was renewed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not finish")
	}
}

func TestBrowserSessionUsesUTCWithNonUTCDatabase(t *testing.T) {
	for _, zone := range []string{"Pacific/Honolulu", "Asia/Tokyo"} {
		t.Run(zone, func(t *testing.T) {
			s, db, e, user := browserSessionFixture(t, zone)
			raw, token := s.newSessionToken(user, model.UserIdentityProviderGoogle)
			token.ExpiresAt = token.CreatedAt.Add(time.Minute)
			_, err := s.Database.CreateSessionToken(t.Context(), nil, token)
			require.NoError(t, err)
			req := httptest.NewRequest("POST", "/auth/session/activity", nil)
			req.AddCookie(&http.Cookie{Name: SessionTokenCookieName, Value: raw})
			req.Header.Set("Origin", s.UiHostUrl)
			req.Header.Set("X-Session-Activity", "1")
			response := httptest.NewRecorder()
			e.ServeHTTP(response, req)
			require.Equal(t, 200, response.Code, response.Body.String())
			var status BrowserSessionStatus
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &status))
			require.WithinDuration(t, token.ExpiresAt, status.ExpiresAt, time.Millisecond)
			_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-interval '16 minutes' WHERE sha256_hash=$1`, token.Sha256Hash)
			require.NoError(t, err)
			response = httptest.NewRecorder()
			e.ServeHTTP(response, req)
			require.Equal(t, 401, response.Code, response.Body.String())
		})
	}
}
