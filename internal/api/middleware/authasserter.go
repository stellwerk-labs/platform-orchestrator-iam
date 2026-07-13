package middleware

import (
	"context"
	"regexp"

	"github.com/labstack/echo/v4"
	strictecho "github.com/oapi-codegen/runtime/strictmiddleware/echo"
	"github.com/pkg/errors"
)

type contextKey string

const authAsserterContextKey = contextKey("github.com/stellwerk-labs/platform-orchestrator-iam/auth-checked")

type authAsserterPayload struct {
	checked bool
}

// NewAuthAsserter helps to assert that all public API methods authorized the request.
// The function must end up calling SetAuthAsserterChecked.
func NewAuthAsserter(skipOperationPattern *regexp.Regexp) strictecho.StrictEchoMiddlewareFunc {
	return func(f strictecho.StrictEchoHandlerFunc, operationID string) strictecho.StrictEchoHandlerFunc {
		return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
			// skip this asserter if it's an internal operation
			if skipOperationPattern.MatchString(operationID) {
				return f(ctx, request)
			}

			payload := &authAsserterPayload{}
			// inject a reference to the auth asserter payload into the request context
			ctx.SetRequest(ctx.Request().WithContext(context.WithValue(ctx.Request().Context(), authAsserterContextKey, payload)))
			r, err := f(ctx, request)
			if err == nil {
				if !payload.checked {
					return nil, errors.New("all public API methods must authorize the request")
				}
			}
			return r, err
		}
	}
}

func SetAuthAsserterChecked(ctx context.Context) {
	if payload, ok := ctx.Value(authAsserterContextKey).(*authAsserterPayload); ok {
		payload.checked = true
	}
}
