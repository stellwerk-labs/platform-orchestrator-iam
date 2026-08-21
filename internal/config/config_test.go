package config

import (
	"os"
	"testing"

	"github.com/stellwerk-labs/golib/hconfig"
)

func TestConfigurationLoadsNATSDefaults(t *testing.T) {
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
	for _, key := range []string{"NATS_STREAM_REPLICAS", "NATS_BOOTSTRAP_STREAMS"} {
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
