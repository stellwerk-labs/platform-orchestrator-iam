package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/golib/hecho"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

const (
	badRequestErrorCode   = "HTTP-400"
	unauthorizedErrorCode = "HTTP-401"
	forbiddenErrorCode    = "HTTP-403"
	notFoundErrorCode     = "HTTP-404"
)

func Generate400Response(message string) N400BadRequestJSONResponse {
	return N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: message}
}

func (resp N400BadRequestJSONResponse) WithDetails(details *map[string]interface{}) N400BadRequestJSONResponse {
	resp.Details = details
	return resp
}

func Generate400FromModelErr(e model.ErrBadRequest) N400BadRequestJSONResponse {
	return Generate400Response(e.Message)
}

func Generate409Response(message string) N409ConflictJSONResponse {
	return N409ConflictJSONResponse{Error: "HTTP-409", Message: message}
}

func Generate403Response(message string) N403ForbiddenJSONResponse {
	return N403ForbiddenJSONResponse{Error: forbiddenErrorCode, Message: message}
}

func Generate404Response(message string) N404NotFoundJSONResponse {
	return N404NotFoundJSONResponse{Error: notFoundErrorCode, Message: message}
}

func Generate404FromModelErr(e model.ErrNotFound) N404NotFoundJSONResponse {
	return Generate404Response(e.Message)
}

// GetAuthenticatedUserId retrieves the human or service users id from the authenticated From HTTP header.
func GetAuthenticatedUserId(ctx context.Context) (uuid.UUID, error) {
	return uuid.Parse(hecho.GetUserID(ctx))
}

// GetAuthenticatedUserIdOr401 is the same as GetAuthenticatedUserId but returns a useful http 401 error
func GetAuthenticatedUserIdOr401(ctx context.Context) (uuid.UUID, *echo.HTTPError) {
	if u, err := GetAuthenticatedUserId(ctx); err == nil {
		return u, nil
	}
	return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized)
}

func zapDeviceLoginRequest(reqId uuid.UUID) zap.Field {
	return zap.Stringer("po-device-login-id", reqId)
}
