package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const maximumSettingsBodyBytes = 1024

const settingsReadPermission = "platform_settings_read"
const settingsWritePermission = "platform_settings_write"

func (s *Server) installationSettingsCaller(c echo.Context, permission string) (uuid.UUID, error) {
	actor, err := uuid.Parse(c.Request().Header.Get("From"))
	if err != nil || actor == uuid.Nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	if !userid.IsHumanUser(actor) || actor == userid.InternalSystemUuid {
		return uuid.Nil, echo.NewHTTPError(http.StatusForbidden, "A platform settings operator is required")
	}
	held, err := s.holdsPlatformPermission(c.Request().Context(), actor, permission)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Platform authorization unavailable").SetInternal(err)
	}
	if !held {
		return uuid.Nil, echo.NewHTTPError(http.StatusForbidden, "The platform permission "+permission+" is required")
	}
	return actor, nil
}

type installationSessionPolicyResponse struct {
	BrowserIdleTimeout string     `json:"browser_idle_timeout"`
	CLITokenTTL        string     `json:"cli_token_ttl"`
	Revision           int64      `json:"revision"`
	UpdatedAt          time.Time  `json:"updated_at"`
	UpdatedBy          *uuid.UUID `json:"updated_by"`
	Source             string     `json:"source"`
}

func writeSessionPolicy(c echo.Context, value model.InstallationSessionPolicy) error {
	c.Response().Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
	return c.JSON(http.StatusOK, installationSessionPolicyResponse{BrowserIdleTimeout: value.BrowserIdleTimeout.String(), CLITokenTTL: value.CLITokenTTL.String(), Revision: value.Revision, UpdatedAt: value.UpdatedAt, UpdatedBy: value.UpdatedBy, Source: value.Source})
}

func (s *Server) getInstallationSessionPolicy(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	if _, err := s.installationSettingsCaller(c, settingsReadPermission); err != nil {
		return err
	}
	value, err := model.ReadInstallationSessionPolicy(c.Request().Context(), s.Database, s.browserSessionIdleTimeout(), s.cliSessionTokenTTL())
	if err != nil {
		return err
	}
	return writeSessionPolicy(c, value)
}

func (s *Server) putInstallationSessionPolicy(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	actor, err := s.installationSettingsCaller(c, settingsWritePermission)
	if err != nil {
		return err
	}
	var body struct {
		BrowserIdleTimeout string `json:"browser_idle_timeout"`
		CLITokenTTL        string `json:"cli_token_ttl"`
	}
	revision, err := decodeSettingsMutation(c, s.UiHostUrl, &body)
	if err != nil {
		return err
	}

	browser, err := time.ParseDuration(body.BrowserIdleTimeout)
	if err != nil || browser < time.Second {
		return echo.NewHTTPError(http.StatusBadRequest, "browser_idle_timeout must be a Go duration of at least 1s")
	}
	cli, err := time.ParseDuration(body.CLITokenTTL)
	if err != nil || cli < time.Second {
		return echo.NewHTTPError(http.StatusBadRequest, "cli_token_ttl must be a Go duration of at least 1s")
	}
	value, err := model.UpdateInstallationSessionPolicy(c.Request().Context(), s.Database, actor, revision, browser, cli, s.browserSessionIdleTimeout(), s.cliSessionTokenTTL())
	if errors.Is(err, model.ErrSettingsRevision) {
		return echo.NewHTTPError(http.StatusPreconditionFailed, err.Error())
	}
	if err != nil {
		return err
	}
	return writeSessionPolicy(c, value)
}

func parseSettingsRevision(value string) (int64, error) {
	if value == "" {
		return 0, echo.NewHTTPError(http.StatusPreconditionRequired, "If-Match is required; read settings before changing them")
	}
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "If-Match must contain the quoted settings revision")
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 1 {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "Invalid settings revision")
	}
	return revision, nil
}

func decodeSettingsMutation(c echo.Context, uiHost string, value any) (int64, error) {
	if _, cookie := c.Cookie("session-token"); cookie == nil {
		console, err := url.Parse(uiHost)
		if err != nil || console.Host == "" || c.Request().Header.Get("Origin") != console.Scheme+"://"+console.Host {
			return 0, echo.NewHTTPError(http.StatusForbidden, "The exact Console origin is required")
		}
	}
	revision, err := parseSettingsRevision(c.Request().Header.Get("If-Match"))
	if err != nil {
		return 0, err
	}
	media, _, err := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return 0, echo.NewHTTPError(http.StatusUnsupportedMediaType, "application/json is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, maximumSettingsBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "A valid settings object is required")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "One JSON object is required")
	}
	return revision, nil
}
