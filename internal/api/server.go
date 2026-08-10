package api

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hmessaging"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/identity"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/emailprovider"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider"
)

//go:generate go tool oapi-codegen --config=oapi-codegen.cfg.yaml --exclude-tags not-implemented ../../openapi/spec.yaml

type Server struct {
	Database model.Databaser
	Logger   *zap.Logger
	CpClient cpclient.ClientWithResponsesInterface

	SessionTokenCookieDomain string
	UserIdentityProviders    map[model.UserIdentityProvider]identity.Provider
	TokenByHashCache         *GetTokenByHashCache

	UiHostUrl          string
	EmailProvider      emailprovider.Provider
	SsoProvider        ssoprovider.Provider
	SsoCallbackUrlPath string
	SsoStateSecret     string

	SpiceDB   spicedb.SpiceDB
	Publisher hmessaging.Publisher

	SuperUserTokenHash []byte
}

func (s *Server) MapRoutes(e *echo.Echo) {
	apiHandler := NewStrictHandler(s, []StrictMiddlewareFunc{
		hecho.OperationIdCollectorMiddleware,
		hecho.BuildContextTimeoutMiddlewareWithDuration(time.Second * 30),
		hecho.AuthMiddleware("userIdHeader.Scopes"),
		middleware.NewAuthAsserter(regexp.MustCompile(`^(Internal.*|RegisterUser|LoginSession|LogoutSession|TemporaryLogin|Logout)$`)),
	})
	RegisterHandlers(e, apiHandler)

	buildInfo, _ := debug.ReadBuildInfo()
	e.GET("/alive", func(c echo.Context) error {
		return c.String(200, fmt.Sprintf("%s %s", buildInfo.Main.Path, buildInfo.Main.Version))
	})
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"app":     buildInfo.Main.Path,
			"version": buildInfo.Main.Version,
			"status":  "OK",
		})
	})

	// Internal wildcard auth handlers. We MUST still have this handler so that we can skip authN for login and device
	// paths.
	e.Any("/internal/authenticate/*", s.buildInternalAuthenticateWildcard(apiHandler))
}

func OpenApiValidatorSkipper(c echo.Context) bool {
	return hecho.DefaultOAIValidationSkipper(c) || c.Path() == "/internal/authenticate/*"
}

// StrictServerInterface is the interface that your Server implementation should generate methods for.
// This line should fail if you're missing some methods. If you want to add methods to the specification, without
// implementing them, consider tagging them with the "not-implemented" tag.
var _ StrictServerInterface = (*Server)(nil)

// MustDecodeOpenApiSpec returns the value from decodeSpec via the cached value in rawSpec and panics if there was an error.
func MustDecodeOpenApiSpec() []byte {
	if b, err := rawSpec(); err != nil {
		panic(err)
	} else {
		return b
	}
}
