package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorizationmigration"
)

func TestExpectedFingerprintFromReport(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	report := authorizationmigration.Report{
		Phase:         authorizationmigration.PhasePreflight,
		SchemaVersion: authorizationmigration.LegacySchemaVersion,
		PolicySHA256:  digest,
		Ready:         true,
	}
	contents, err := json.Marshal(report)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "preflight.json")
	require.NoError(t, os.WriteFile(path, contents, 0o600))

	actual, err := expectedFingerprint(commonOptions{preflightReport: path})
	require.NoError(t, err)
	require.Equal(t, digest, actual)
}

func TestExpectedFingerprintRejectsFailedReport(t *testing.T) {
	report := authorizationmigration.Report{
		Phase:         authorizationmigration.PhasePreflight,
		SchemaVersion: authorizationmigration.LegacySchemaVersion,
		PolicySHA256:  strings.Repeat("ab", 32),
		Ready:         false,
	}
	contents, err := json.Marshal(report)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "preflight.json")
	require.NoError(t, os.WriteFile(path, contents, 0o600))

	_, err = expectedFingerprint(commonOptions{preflightReport: path})
	require.ErrorContains(t, err, "not a successful legacy-schema report")
}

func TestExpectedFingerprintRejectsMismatch(t *testing.T) {
	report := authorizationmigration.Report{
		Phase:         authorizationmigration.PhasePreflight,
		SchemaVersion: authorizationmigration.LegacySchemaVersion,
		PolicySHA256:  strings.Repeat("ab", 32),
		Ready:         true,
	}
	contents, err := json.Marshal(report)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "preflight.json")
	require.NoError(t, os.WriteFile(path, contents, 0o600))

	_, err = expectedFingerprint(commonOptions{preflightReport: path, policySHA256: strings.Repeat("cd", 32)})
	require.ErrorContains(t, err, "does not match")
}

func TestResolveDatabaseURLFromIAMEnvironment(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_NAME", "iam database")
	t.Setenv("DATABASE_USER", "iam-user")
	t.Setenv("DATABASE_PASSWORD", "it's secret")
	t.Setenv("DATABASE_HOST", "postgres")
	t.Setenv("DATABASE_PORT", "5432")
	t.Setenv("DATABASE_SSLMODE", "require")

	connectionString, err := resolveDatabaseURL("")
	require.NoError(t, err)
	require.Contains(t, connectionString, "dbname='iam database'")
	require.Contains(t, connectionString, `password='it\'s secret'`)
	require.Contains(t, connectionString, "sslmode='require'")
}

func TestValidateReport(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	require.NoError(t, validateReport(authorizationmigration.Report{Ready: true, PolicySHA256: digest}, digest))
	require.Error(t, validateReport(authorizationmigration.Report{Ready: false, PolicySHA256: digest}, digest))
	require.Error(t, validateReport(authorizationmigration.Report{Ready: true, PolicySHA256: strings.Repeat("cd", 32)}, digest))
}
