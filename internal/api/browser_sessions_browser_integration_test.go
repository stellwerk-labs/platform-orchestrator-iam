//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stretchr/testify/require"
)

// Optional cross-repository qualification uses the real Console controller and
// real PostgreSQL-backed handlers. It does not replace normal backend tests.
func TestBrowserSessionConsoleInput(t *testing.T) {
	driver := os.Getenv("SESSION_BROWSER_DRIVER")
	if driver == "" {
		t.Skip("SESSION_BROWSER_DRIVER names the Console live test driver")
	}
	assets := os.Getenv("SESSION_BROWSER_ASSETS")
	require.NotEmpty(t, assets)
	s, _, e, user := browserSessionFixture(t)
	s.BrowserSessionIdleTimeout = 4 * time.Second
	if os.Getenv("SESSION_BROWSER_POLICY_REFRESH") == "1" {
		s.BrowserSessionIdleTimeout = 2 * time.Minute
	}
	if os.Getenv("SESSION_BROWSER_MINIMUM") == "1" {
		s.BrowserSessionIdleTimeout = time.Second
	}
	e.File("/controller.js", filepath.Join(assets, "controller.js"))
	e.File("/mask.js", filepath.Join(assets, "mask.js"))
	const page = `<!doctype html><html><body><input id="input" aria-label="Activity"><script type="module">
    import { startBrowserSession, SessionRejectedError } from '/controller.js';
    window.activityRequests=0;
    window.sessionState='starting';
    window.controller=startBrowserSession({
      request: async (activity, signal) => {
        if(activity) window.activityRequests++;
        const response=await fetch(activity ? '/auth/session/activity' : '/auth/session', {
          method: activity ? 'POST' : 'GET', signal,
          headers: activity ? {'X-Session-Activity':'1'} : {},
        });
        if(response.status===401) throw new SessionRejectedError();
        if(!response.ok) throw new Error('Session request failed');
        return response.json();
      },
      onChecking:()=>window.sessionState='checking',
      onActive:()=>window.sessionState='active',
      onExpired:()=>window.sessionState='expired',
    });
    </script></body></html>`
	e.GET("/fixture", func(c echo.Context) error { return c.HTML(http.StatusOK, page) })
	e.GET("/fixture/new-session", func(c echo.Context) error {
		raw, token := s.newSessionToken(user, model.UserIdentityProviderGoogle)
		if _, err := s.Database.CreateSessionToken(c.Request().Context(), nil, token); err != nil {
			return err
		}
		c.Response().Header().Set("Set-Cookie", s.generateSetCookieForToken(raw, token))
		return c.Redirect(http.StatusFound, "/fixture")
	})
	e.POST("/fixture/policy", func(c echo.Context) error {
		_, err := model.UpdateInstallationSessionPolicy(c.Request().Context(), s.Database, user, 1, time.Second, 2*time.Hour, s.browserSessionIdleTimeout(), s.cliSessionTokenTTL())
		if err != nil {
			return err
		}
		return c.NoContent(204)
	})
	server := httptest.NewTLSServer(e)
	defer server.Close()
	s.UiHostUrl = server.URL
	plugin := echo.New()
	plugin.Static("/assets", assets)
	plugin.GET("/:name", func(c echo.Context) error {
		name := c.Param("name")
		if name != "rollouts" && name != "drift" {
			return c.NoContent(404)
		}
		return c.HTML(200, fmt.Sprintf(`<!doctype html><html><body><input id="plugin-input" aria-label="Plugin input"><script type="module">
          import {reportSessionInput} from '/assets/%s.js';
          window.addEventListener('message', event => {
            if(event.origin !== %q || event.source !== window.parent || event.ports.length !== 1) return;
            reportSessionInput(event.ports[0], event.data.nonce);
          });
        </script></body></html>`, name, server.URL))
	})
	pluginServer := httptest.NewTLSServer(plugin)
	defer pluginServer.Close()
	plugins, err := json.Marshal([]string{pluginServer.URL + "/rollouts", pluginServer.URL + "/drift"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", driver) // #nosec G204 -- explicit local integration-test driver, not production input.
	command.Env = append(os.Environ(), "SESSION_BROWSER_URL="+server.URL, "SESSION_BROWSER_PLUGINS="+string(plugins))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	require.NoError(t, err)
}
