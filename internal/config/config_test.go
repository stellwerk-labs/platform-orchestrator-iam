package config

import (
	"os"
	"testing"
	"time"

	"github.com/stellwerk-labs/golib/hconfig"
)

var pluginWorkloadEnvironment = []string{
	"PLUGIN_WORKLOAD_TOKEN_ISSUER", "PLUGIN_WORKLOAD_JWKS_FILE", "PLUGIN_WORKLOAD_JWKS_URL",
	"PLUGIN_WORKLOAD_JWKS_CA_FILE", "PLUGIN_WORKLOAD_JWKS_TOKEN_FILE", "PLUGIN_WORKLOAD_TOKEN_TTL",
	"PLUGIN_WORKLOAD_BINDING_WRITERS", "PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER",
}

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"PORT":                        "8080",
		"DATABASE_NAME":               "iam",
		"DATABASE_USER":               "iam",
		"DATABASE_PASSWORD":           "secret",
		"CONTROL_PLANE_URL":           "http://control-plane:8080",
		"SESSION_TOKEN_COOKIE_DOMAIN": "localhost",
		"UI_HOST_URL":                 "http://localhost:8080",
		"NATS_URL":                    "nats://nats:4222",
	} {
		t.Setenv(key, value)
	}
}

func unsetEnvironment(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		value, exists := os.LookupEnv(key)
		requireNoError(t, os.Unsetenv(key))
		t.Cleanup(func() {
			if exists {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
}

func TestConfigurationLoadsNATSDefaults(t *testing.T) {
	setRequiredEnvironment(t)
	unsetEnvironment(t, "NATS_STREAM_REPLICAS", "NATS_BOOTSTRAP_STREAMS")

	var cfg Configuration
	requireNoError(t, hconfig.LoadConfigWithoutRetag(&cfg))
	if cfg.NatsStreamReplicas != 1 {
		t.Fatalf("expected one NATS stream replica by default, got %d", cfg.NatsStreamReplicas)
	}
	if cfg.NatsBootstrapStreams {
		t.Fatal("NATS stream bootstrap must be disabled by default")
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationNATSFields(t *testing.T) {
	cfg := Configuration{ // #nosec G101 -- test-only configuration contains no usable credentials.
		NatsURL:              "tls://nats.example.test:4222",
		NatsToken:            t.Name(),
		NatsCredentialsFile:  "/var/run/secrets/nats/client.creds",
		NatsNKeySeedFile:     "/var/run/secrets/nats/client.nk",
		NatsCAFile:           "/var/run/secrets/nats/ca.crt",
		NatsClientCertFile:   "/var/run/secrets/nats/tls.crt",
		NatsClientKeyFile:    "/var/run/secrets/nats/tls.key",
		NatsTLSServerName:    "nats.example.test",
		NatsStreamReplicas:   3,
		NatsBootstrapStreams: true,
	}

	if cfg.NatsURL != "tls://nats.example.test:4222" {
		t.Fatalf("unexpected NATS URL %q", cfg.NatsURL)
	}
	if cfg.NatsCredentialsFile == "" || cfg.NatsCAFile == "" {
		t.Fatal("credential and CA paths must be retained")
	}
	if cfg.NatsToken == "" || cfg.NatsNKeySeedFile == "" || cfg.NatsClientCertFile == "" || cfg.NatsClientKeyFile == "" {
		t.Fatal("authentication and mTLS fields must be retained")
	}
	if cfg.NatsTLSServerName != "nats.example.test" || cfg.NatsStreamReplicas != 3 || !cfg.NatsBootstrapStreams {
		t.Fatal("TLS server name, stream replication, and bootstrap setting must be retained")
	}
}

func TestConfigurationPluginWorkloadExchangeIsOffWithInClusterKeyDefaults(t *testing.T) {
	setRequiredEnvironment(t)
	unsetEnvironment(t, pluginWorkloadEnvironment...)

	var cfg Configuration
	requireNoError(t, hconfig.LoadConfigWithoutRetag(&cfg))
	if cfg.PluginWorkloadTokenIssuer != "" || cfg.PluginWorkloadJWKSFile != "" {
		t.Fatal("the workload token exchange must be disabled by default")
	}
	if cfg.PluginWorkloadJWKSURL != "https://kubernetes.default.svc/openid/v1/jwks" ||
		cfg.PluginWorkloadJWKSCAFile != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" ||
		cfg.PluginWorkloadJWKSTokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Fatalf("unexpected in-cluster JWKS defaults: %q %q %q", cfg.PluginWorkloadJWKSURL, cfg.PluginWorkloadJWKSCAFile, cfg.PluginWorkloadJWKSTokenFile)
	}
	if cfg.PluginWorkloadTokenTTL != 15*time.Minute {
		t.Fatalf("expected a 15 minute token TTL by default, got %s", cfg.PluginWorkloadTokenTTL)
	}
	if len(cfg.PluginWorkloadBindingWriters) != 0 || cfg.PluginWorkloadStaticTokenAdapter != "" {
		t.Fatal("no binding writer and no static-token adapter may be configured by default")
	}
}

func TestConfigurationLoadsPluginWorkloadSettings(t *testing.T) {
	setRequiredEnvironment(t)
	unsetEnvironment(t, pluginWorkloadEnvironment...)
	t.Setenv("PLUGIN_WORKLOAD_TOKEN_ISSUER", "https://kubernetes.default.svc.cluster.local")
	t.Setenv("PLUGIN_WORKLOAD_JWKS_FILE", "/etc/stellwerk/plugin-workload/jwks.json")
	t.Setenv("PLUGIN_WORKLOAD_TOKEN_TTL", "5m")
	t.Setenv("PLUGIN_WORKLOAD_BINDING_WRITERS", "0199a0c1-1d6e-72f1-8000-000000000001,0199a0c1-1d6e-72f2-8000-000000000002")
	t.Setenv("PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER", "v1alpha")

	var cfg Configuration
	requireNoError(t, hconfig.LoadConfigWithoutRetag(&cfg))
	if cfg.PluginWorkloadTokenIssuer != "https://kubernetes.default.svc.cluster.local" || cfg.PluginWorkloadJWKSFile != "/etc/stellwerk/plugin-workload/jwks.json" {
		t.Fatal("issuer and static JWKS file must be retained")
	}
	if cfg.PluginWorkloadTokenTTL != 5*time.Minute {
		t.Fatalf("unexpected token TTL %s", cfg.PluginWorkloadTokenTTL)
	}
	if len(cfg.PluginWorkloadBindingWriters) != 2 || cfg.PluginWorkloadStaticTokenAdapter != "v1alpha" {
		t.Fatalf("unexpected writers %v or adapter %q", cfg.PluginWorkloadBindingWriters, cfg.PluginWorkloadStaticTokenAdapter)
	}
}

func TestConfigurationRejectsUnsafePluginWorkloadSettings(t *testing.T) {
	for name, setting := range map[string][2]string{
		"ttl above 15 minutes":       {"PLUGIN_WORKLOAD_TOKEN_TTL", "16m"},
		"ttl below one minute":       {"PLUGIN_WORKLOAD_TOKEN_TTL", "30s"},
		"unversioned adapter switch": {"PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER", "true"},
		"unknown adapter version":    {"PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER", "v1"},
		"writer that is not a uuid":  {"PLUGIN_WORKLOAD_BINDING_WRITERS", "installation-controller"},
		"issuer that is not a url":   {"PLUGIN_WORKLOAD_TOKEN_ISSUER", "kubernetes"},
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredEnvironment(t)
			unsetEnvironment(t, pluginWorkloadEnvironment...)
			t.Setenv(setting[0], setting[1])

			var cfg Configuration
			if err := hconfig.LoadConfigWithoutRetag(&cfg); err == nil {
				t.Fatalf("%s=%q must be rejected", setting[0], setting[1])
			}
		})
	}
}
