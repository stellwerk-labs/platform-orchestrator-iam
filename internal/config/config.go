package config

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// Configuration ...
type Configuration struct {
	Port int `env:"PORT" validate:"required"`

	DatabaseName     string `env:"DATABASE_NAME" validate:"required"`
	DatabaseUser     string `env:"DATABASE_USER" validate:"required"`
	DatabasePassword string `env:"DATABASE_PASSWORD" validate:"required"`
	DatabaseHost     string `env:"DATABASE_HOST"`
	DatabasePort     string `env:"DATABASE_PORT"`

	ControlPlaneUrl string `env:"CONTROL_PLANE_URL" validate:"required"`

	SessionTokenCookieDomain    string `env:"SESSION_TOKEN_COOKIE_DOMAIN" validate:"required"`
	TestUserProviderAgeIdentity string `env:"TEST_USER_PROVIDER_AGE_IDENTITY"`
	UiHostUrl                   string `env:"UI_HOST_URL" validate:"required"`

	// AllowedGoogleClientIds is used to restrict the oauth idtokens that can be used to login to an account backed
	// by google oauth. See the google oauth identity provider.
	AllowedGoogleClientIds string `env:"ALLOWED_GOOGLE_CLIENT_IDS"`

	// Same here: sets the allowed client IDs for Microsoft oauth identity provider.
	AllowedMicrosoftClientIds string `env:"ALLOWED_MICROSOFT_CLIENT_IDS"`

	// SendGridApiKey enables SendGrid to send invites. If not set, invites are disabled.
	SendGridApiKey        string `env:"SENDGRID_API_KEY"`
	SendGridSenderName    string `env:"SENDGRID_SENDER_NAME"`
	SendGridSenderAddress string `env:"SENDGRID_SENDER_ADDRESS"`

	ProductName string `env:"PRODUCT_NAME"`

	ShutdownDelay time.Duration `env:"SHUTDOWN_DELAY"`
	OTELEnabled   bool          `env:"OTEL_ENABLE"`
	LogLevel      string        `env:"LOG_LEVEL"`

	ExpiredDataCleanupInterval time.Duration `env:"EXPIRED_DATA_CLEANUP_INTERVAL" default:"5m"`

	SpiceDBUrl          string `env:"SPICEDB_URL" validate:"required,url"`
	SpiceDBPreSharedKey string `env:"SPICEDB_PRE_SHARED_KEY" validate:"required"`

	// AmqpConnectionString should be an AMQP url like "amqp://%s:%s@%s:%d/%s"
	AmqpConnectionString string `env:"AMQP_CONNECTION_STRING" validate:"omitempty,url"`

	// Alternatively, separate env vars can be set for AMQP connection
	AmpqHost     string `env:"AMQP_HOST"`
	AmpqPort     string `env:"AMQP_PORT, default=5672"`
	AmpqVhost    string `env:"AMQP_VHOST"`
	AmpqUsername string `env:"AMQP_USERNAME"`
	AmpqPassword string `env:"AMQP_PASSWORD"`

	WorkosApiKey       string `env:"WORKOS_API_KEY"`
	WorkosClientId     string `env:"WORKOS_CLIENT_ID"`
	SsoCallbackUrlPath string `env:"SSO_CALLBACK_URL_PATH"`
	SsoStateSecret     string `env:"SSO_STATE_SECRET"`

	KeycloakUrl          string `env:"KEYCLOAK_URL"`
	KeycloakInternalUrl  string `env:"KEYCLOAK_INTERNAL_URL"`
	KeycloakRealm        string `env:"KEYCLOAK_REALM"`
	KeycloakClientId     string `env:"KEYCLOAK_CLIENT_ID"`
	KeycloakClientSecret string `env:"KEYCLOAK_CLIENT_SECRET"`

	// SuperUserToken enables the global super user identity when set. The token is compared via sha256 hash.
	SuperUserToken string `env:"SUPER_USER_TOKEN"`
}

func (c *Configuration) GetAmqpConnectionString() (string, error) {
	if c.AmqpConnectionString != "" {
		return c.AmqpConnectionString, nil
	}
	if c.AmpqHost == "" {
		return "", errors.New("AMQP_HOST or AMQP_CONNECTION_STRING is not set")
	}
	if c.AmpqVhost == "" {
		return "", errors.New("AMQP_VHOST or AMQP_CONNECTION_STRING is not set")
	}
	if c.AmpqUsername == "" {
		return "", errors.New("AMQP_USERNAME or AMQP_CONNECTION_STRING is not set")
	}
	if c.AmpqPassword == "" {
		return "", errors.New("AMQP_PASSWORD or AMQP_CONNECTION_STRING is not set")
	}
	return fmt.Sprintf("amqp://%s:%s@%s:%s/%s", c.AmpqUsername, c.AmpqPassword, c.AmpqHost, c.AmpqPort, c.AmpqVhost), nil
}
