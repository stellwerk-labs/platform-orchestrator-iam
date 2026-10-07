package config

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
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

	// ApiHostUrl is the externally reachable base URL of this API (scheme and
	// host, e.g. https://api.example.com). It pins the absolute URLs the server
	// emits (SCIM meta.location) instead of reflecting the client-controlled
	// Host header. Optional: when unset, absolute URLs fall back to a validated
	// request Host.
	ApiHostUrl string `env:"API_HOST_URL" validate:"omitempty,url"`

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

	NatsURL              string `env:"NATS_URL" validate:"required,url"`
	NatsToken            string `env:"NATS_TOKEN"`
	NatsCredentialsFile  string `env:"NATS_CREDENTIALS_FILE"`
	NatsNKeySeedFile     string `env:"NATS_NKEY_SEED_FILE"`
	NatsCAFile           string `env:"NATS_CA_FILE"`
	NatsClientCertFile   string `env:"NATS_CLIENT_CERT_FILE"`
	NatsClientKeyFile    string `env:"NATS_CLIENT_KEY_FILE"`
	NatsTLSServerName    string `env:"NATS_TLS_SERVER_NAME"`
	NatsStreamReplicas   int    `env:"NATS_STREAM_REPLICAS, default=1" validate:"min=1,max=5"`
	NatsBootstrapStreams bool   `env:"NATS_BOOTSTRAP_STREAMS, default=false"`

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

	// PluginWorkloadTokenIssuer enables the v1alpha plugin workload token
	// exchange for projected ServiceAccount tokens of this cluster issuer.
	// Without it the exchange answers 404 and no workload binding can be created.
	PluginWorkloadTokenIssuer string `env:"PLUGIN_WORKLOAD_TOKEN_ISSUER" validate:"omitempty,url"`
	// PluginWorkloadJWKSFile is an operator-supplied JWKS used instead of the
	// URL, for clusters where IAM cannot reach the API server.
	PluginWorkloadJWKSFile      string `env:"PLUGIN_WORKLOAD_JWKS_FILE"`
	PluginWorkloadJWKSURL       string `env:"PLUGIN_WORKLOAD_JWKS_URL, default=https://kubernetes.default.svc/openid/v1/jwks" validate:"omitempty,url"`
	PluginWorkloadJWKSCAFile    string `env:"PLUGIN_WORKLOAD_JWKS_CA_FILE, default=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"`
	PluginWorkloadJWKSTokenFile string `env:"PLUGIN_WORKLOAD_JWKS_TOKEN_FILE, default=/var/run/secrets/kubernetes.io/serviceaccount/token"`
	// PluginWorkloadTokenTTL is the lifetime of issued workload tokens, never
	// longer than the subject token's remaining lifetime.
	PluginWorkloadTokenTTL time.Duration `env:"PLUGIN_WORKLOAD_TOKEN_TTL, default=15m" validate:"min=1m,max=15m"`
	// PluginWorkloadBindingWriters are the principals holding the platform-level
	// plugin_workload_binding_write permission, typically the installation controller.
	PluginWorkloadBindingWriters []string `env:"PLUGIN_WORKLOAD_BINDING_WRITERS" validate:"dive,uuid"`
	// PluginManagerReaders and PluginManagerWriters are the users holding the
	// platform-level plugin_manager_read and plugin_manager_write permissions
	// of the Core Plugin Manager. Writers also read.
	PluginManagerReaders []string `env:"PLUGIN_MANAGER_READERS" validate:"dive,uuid"`
	PluginManagerWriters []string `env:"PLUGIN_MANAGER_WRITERS" validate:"dive,uuid"`
	// PluginWorkloadStaticTokenAdapter names the transitional adapter version
	// that keeps static tokens of workload-bound service users usable. Off when empty.
	PluginWorkloadStaticTokenAdapter string `env:"PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER" validate:"omitempty,oneof=v1alpha"`
}

// PlatformPermissionHolders returns the principals holding each platform-level
// permission. Plugin Manager holders must be users: plugin workloads
// authenticate as service users, so a service user, the internal system
// identity or the nil UUID is refused and IAM does not start.
func (c *Configuration) PlatformPermissionHolders() (map[string][]uuid.UUID, error) {
	bindingWriters, err := parsePrincipals(c.PluginWorkloadBindingWriters)
	if err != nil {
		return nil, err
	}
	readers, err := parsePrincipals(c.PluginManagerReaders)
	if err != nil {
		return nil, err
	}
	writers, err := parsePrincipals(c.PluginManagerWriters)
	if err != nil {
		return nil, err
	}
	for _, holder := range slices.Concat(readers, writers) {
		if holder == uuid.Nil || holder == userid.InternalSystemUuid || userid.IsServiceUser(holder) {
			return nil, fmt.Errorf("plugin manager permission holder %s must be a user, never a service user or the internal system identity", holder)
		}
	}
	return map[string][]uuid.UUID{
		sharedauthz.PermissionPluginWorkloadBindingWrite: bindingWriters,
		sharedauthz.PermissionPluginManagerRead:          slices.Concat(readers, writers),
		sharedauthz.PermissionPluginManagerWrite:         writers,
	}, nil
}

func parsePrincipals(values []string) ([]uuid.UUID, error) {
	principals := make([]uuid.UUID, len(values))
	for index, value := range values {
		principal, err := uuid.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("invalid platform permission principal %q: %w", value, err)
		}
		principals[index] = principal
	}
	return principals, nil
}
