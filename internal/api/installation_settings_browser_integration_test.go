//go:build integration

package api

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
)

func TestInstallationSettingsConsoleWithRealDataPlaneAndIAM(t *testing.T) {
	driver := os.Getenv("PLATFORM_SETTINGS_BROWSER_DRIVER")
	if driver == "" {
		t.Skip("optional real Console/Data Plane/IAM qualification")
	}
	assets := os.Getenv("PLATFORM_SETTINGS_BROWSER_ASSETS")
	dp := os.Getenv("PLATFORM_SETTINGS_DP_SOURCE")
	require.NotEmpty(t, assets)
	require.NotEmpty(t, dp)
	s, db, e, writer := browserSessionFixture(t)
	reader, denied := userid.NewHumanUserId(), userid.NewHumanUserId()
	for _, user := range []uuid.UUID{reader, denied} {
		_, err := db.Exec(`INSERT INTO users(id,display_name,created_at) VALUES($1,'Settings fixture',now())`, user)
		require.NoError(t, err)
	}
	authorizer, err := authorization.New(t.Context(), s.Database)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	s.Authorizer = authorizer
	s.PlatformPermissionHolders = map[string][]uuid.UUID{settingsReadPermission: {writer, reader}, settingsWritePermission: {writer}, "plugin_manager_read": {writer}}
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour, false))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if strings.HasPrefix(c.Request().URL.Path, "/fixture/") || c.Request().URL.Path == "/internal/authorize" {
				return next(c)
			}
			var cookie *string
			if value, err := c.Cookie(SessionTokenCookieName); err == nil {
				cookie = &value.Value
			}
			response, err := s.InternalAuthenticate(c.Request().Context(), InternalAuthenticateRequestObject{Params: InternalAuthenticateParams{SessionToken: cookie}})
			if err != nil {
				return err
			}
			authenticated, ok := response.(InternalAuthenticate200Response)
			if !ok {
				return c.NoContent(401)
			}
			c.Request().Header.Set("From", authenticated.Headers.From.String())
			return next(c)
		}
	})
	e.Static("/fixture/assets", assets)
	e.GET("/fixture/session", func(c echo.Context) error {
		actor := writer
		switch c.QueryParam("role") {
		case "reader":
			actor = reader
		case "none":
			actor = denied
		}
		raw, token := s.newSessionToken(actor, model.UserIdentityProviderGoogle)
		if _, err := s.Database.CreateSessionToken(c.Request().Context(), nil, token); err != nil {
			return err
		}
		c.Response().Header().Set("Set-Cookie", s.generateSetCookieForToken(raw, token))
		return c.HTML(200, `<!doctype html><html lang="en"><body><div id="root"></div><script>window.env={BASE_URL:'',PRODUCT_NAME:'Platform Orchestrator'};</script><script type="module" src="/fixture/assets/settings-app.js"></script></body></html>`)
	})
	server := httptest.NewTLSServer(e)
	defer server.Close()
	s.UiHostUrl = server.URL
	directory := t.TempDir()
	ready := filepath.Join(directory, "peer-ready")
	ca := filepath.Join(directory, "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	ctx, cancel := context.WithTimeout(t.Context(), 85*time.Second)
	defer cancel()
	peer := exec.CommandContext(ctx, "go", "test", "-v", "-tags", "integration", "./internal/api", "-run", "^TestInstallationSettingsPeer$", "-count=1") // #nosec G204 -- explicit local integration-test source checkout.
	peer.Dir = dp
	peer.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.11", "PLATFORM_SETTINGS_PEER_READY="+ready, "PLATFORM_SETTINGS_CA_FILE="+ca, "PLATFORM_SETTINGS_IAM_URL="+server.URL)
	log, err := os.Create(filepath.Join(directory, "peer.log"))
	require.NoError(t, err)
	defer func() { require.NoError(t, log.Close()) }()
	peer.Stdout = log
	peer.Stderr = log
	require.NoError(t, peer.Start())
	defer func() {
		require.NoError(t, os.WriteFile(ready+".stop", nil, 0600))
		err := peer.Wait()
		if err != nil {
			output, _ := os.ReadFile(log.Name())
			t.Log(string(output))
		}
		require.NoError(t, err)
	}()
	require.Eventually(t, func() bool { _, err := os.Stat(ready); return err == nil }, 35*time.Second, 50*time.Millisecond)
	rawPeer, err := os.ReadFile(ready)
	require.NoError(t, err)
	target, err := url.Parse(string(rawPeer))
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	e.Any("/platform-settings/deployments", echo.WrapHandler(proxy))
	cpSource := os.Getenv("PLATFORM_SETTINGS_CP_SOURCE")
	require.NotEmpty(t, cpSource)
	cpReady := filepath.Join(directory, "cp-ready")
	cp := exec.CommandContext(ctx, "go", "test", "-v", "-tags", "integration", "./internal/api", "-run", "^TestMaintenanceBrowserPeer$", "-count=1")
	cp.Dir = cpSource
	cp.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.11", "PLATFORM_SETTINGS_CP_READY="+cpReady, "PLATFORM_SETTINGS_CA_FILE="+ca, "PLATFORM_SETTINGS_IAM_URL="+server.URL, "PLATFORM_SETTINGS_DP_URL="+string(rawPeer))
	cpLog, err := os.Create(filepath.Join(directory, "cp.log"))
	require.NoError(t, err)
	defer cpLog.Close() //nolint:errcheck
	cp.Stdout, cp.Stderr = cpLog, cpLog
	require.NoError(t, cp.Start())
	defer func() {
		require.NoError(t, os.WriteFile(cpReady+".stop", nil, 0600))
		err := cp.Wait()
		if err != nil {
			raw, _ := os.ReadFile(cpLog.Name())
			t.Log(string(raw))
		}
		require.NoError(t, err)
	}()
	require.Eventually(t, func() bool { _, err := os.Stat(cpReady); return err == nil }, 30*time.Second, 50*time.Millisecond)
	rawCP, err := os.ReadFile(cpReady)
	require.NoError(t, err)
	cpTarget, err := url.Parse(string(rawCP))
	require.NoError(t, err)
	cpProxy := httputil.NewSingleHostReverseProxy(cpTarget)
	e.Any("/platform-settings/maintenance-status", echo.WrapHandler(cpProxy))
	e.Any("/plugin-installations", echo.WrapHandler(cpProxy))
	e.Any("/plugin-packages", echo.WrapHandler(cpProxy))
	command := exec.CommandContext(ctx, "node", driver) // #nosec G204 -- explicit local Console test driver.
	command.Env = append(os.Environ(), "PLATFORM_SETTINGS_BROWSER_URL="+server.URL)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	require.NoError(t, err)
}
