package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorizationmigration"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"
)

const usage = `Usage:
  authorization-migrate preflight [options]
  authorization-migrate apply --control-plane-url URL (--preflight-report FILE | --policy-sha256 SHA256) [options]
  authorization-migrate verify [(--preflight-report FILE | --policy-sha256 SHA256)] [options]
  authorization-migrate rollback --confirm-no-rbac-writes (--preflight-report FILE | --policy-sha256 SHA256) [options]

Database options default to DATABASE_URL or the IAM DATABASE_* environment variables.
Every command emits a machine-readable JSON report and exits non-zero when a check fails.
`

const (
	commandApply    = "apply"
	commandRollback = "rollback"
)

type commonOptions struct {
	databaseURL     string
	output          string
	preflightReport string
	policySHA256    string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := run(ctx, logger, os.Args[1], os.Args[2:]); err != nil {
		logger.Error("authorization migration failed", zap.Error(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *zap.Logger, command string, arguments []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	options := commonOptions{}
	flags.StringVar(&options.databaseURL, "database-url", "", "PostgreSQL connection string (defaults to DATABASE_URL or DATABASE_* variables)")
	flags.StringVar(&options.output, "output", "-", "write the JSON report to this file, or - for stdout")
	flags.StringVar(&options.preflightReport, "preflight-report", "", "pre-upgrade JSON report used to guard apply, verify, or rollback")
	flags.StringVar(&options.policySHA256, "policy-sha256", "", "expected pre-upgrade policy SHA-256 when a report file is not mounted")

	var controlPlaneURL string
	var confirmNoWrites bool
	if command == commandApply {
		flags.StringVar(&controlPlaneURL, "control-plane-url", os.Getenv("CONTROL_PLANE_URL"), "control-plane base URL used to rebuild resource ancestry")
	}
	if command == commandRollback {
		flags.BoolVar(&confirmNoWrites, "confirm-no-rbac-writes", false, "confirm IAM is stopped and no RBAC writes occurred after cutover")
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if command != "preflight" && command != commandApply && command != "verify" && command != commandRollback {
		fmt.Fprint(os.Stderr, usage)
		return errors.Errorf("unknown command %q", command)
	}

	connectionString, err := resolveDatabaseURL(options.databaseURL)
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return errors.Wrap(err, "failed to create PostgreSQL client")
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(4)
	if err := db.PingContext(ctx); err != nil {
		return errors.Wrap(err, "failed to connect to PostgreSQL")
	}

	switch command {
	case "preflight":
		report, inspectErr := authorizationmigration.Inspect(ctx, db, authorizationmigration.PhasePreflight)
		if err := writeReport(options.output, report); err != nil {
			return err
		}
		if inspectErr != nil {
			return inspectErr
		}
		if !report.Ready {
			return errors.New("preflight checks failed")
		}
		return nil
	case commandApply:
		if controlPlaneURL == "" {
			return errors.New("--control-plane-url or CONTROL_PLANE_URL is required")
		}
		expected, err := expectedFingerprint(options)
		if err != nil {
			return err
		}
		report, err := apply(ctx, logger, db, connectionString, controlPlaneURL, expected)
		if writeErr := writeReport(options.output, report); writeErr != nil {
			return writeErr
		}
		return err
	case "verify":
		expected, err := optionalFingerprint(options)
		if err != nil {
			return err
		}
		report, inspectErr := authorizationmigration.Inspect(ctx, db, authorizationmigration.PhaseVerify)
		if inspectErr == nil && !report.Ready {
			inspectErr = errors.New("verify checks failed")
		} else if inspectErr == nil && expected != "" {
			inspectErr = validateReport(report, expected)
		}
		if err := writeReport(options.output, report); err != nil {
			return err
		}
		return inspectErr
	case commandRollback:
		if !confirmNoWrites {
			return errors.New("rollback requires --confirm-no-rbac-writes")
		}
		expected, err := expectedFingerprint(options)
		if err != nil {
			return err
		}
		report, err := rollback(ctx, logger, db, expected)
		if writeErr := writeReport(options.output, report); writeErr != nil {
			return writeErr
		}
		return err
	default:
		return errors.Errorf("unsupported command %q", command)
	}
}

func apply(ctx context.Context, logger *zap.Logger, db *sql.DB, connectionString, controlPlaneURL, expected string) (authorizationmigration.Report, error) {
	cp, err := cpclient.NewClientWithResponses(controlPlaneURL,
		cpclient.WithHTTPClient(http.DefaultClient),
		cpclient.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("From", userid.InternalSystemUuid.String())
			return nil
		}),
	)
	if err != nil {
		return authorizationmigration.Report{}, errors.Wrap(err, "failed to create control-plane client")
	}
	database, report, err := authorizationmigration.Upgrade(ctx, logger, db, connectionString, cp, expected)
	if err != nil {
		return report, err
	}
	defer func() { _ = database.Close() }()
	return report, validateReport(report, expected)
}

func rollback(ctx context.Context, logger *zap.Logger, db *sql.DB, expected string) (authorizationmigration.Report, error) {
	version, err := authorizationmigration.CurrentVersion(ctx, db)
	if err != nil {
		return authorizationmigration.Report{}, err
	}
	if version != authorizationmigration.CasbinSchemaVersion {
		return authorizationmigration.Report{}, errors.Errorf("rollback requires schema version %d, found %d", authorizationmigration.CasbinSchemaVersion, version)
	}
	current, err := authorizationmigration.Inspect(ctx, db, authorizationmigration.PhaseVerify)
	if err != nil {
		return current, err
	}
	if current.PolicySHA256 != expected {
		return current, errors.Errorf("RBAC policy changed after cutover: expected %s, found %s; restore the database backup instead", expected, current.PolicySHA256)
	}
	if err := model.MigrateDownTo(ctx, logger, db, authorizationmigration.LegacySchemaVersion); err != nil {
		return current, errors.Wrap(err, "failed to roll database back to the SpiceDB schema")
	}
	legacy, err := authorizationmigration.Inspect(ctx, db, authorizationmigration.PhasePreflight)
	if err == nil {
		err = validateReport(legacy, expected)
	}
	return legacy, err
}

func validateReport(report authorizationmigration.Report, expected string) error {
	if !report.Ready {
		return errors.Errorf("%s checks failed", report.Phase)
	}
	if report.PolicySHA256 != expected {
		return errors.Errorf("authorization data changed: expected policy SHA-256 %s, found %s", expected, report.PolicySHA256)
	}
	return nil
}

func expectedFingerprint(options commonOptions) (string, error) {
	expected, err := optionalFingerprint(options)
	if err != nil {
		return "", err
	}
	if expected == "" {
		return "", errors.New("a valid --preflight-report or --policy-sha256 is required")
	}
	return expected, nil
}

func optionalFingerprint(options commonOptions) (string, error) {
	expected := options.policySHA256
	if options.preflightReport != "" {
		contents, err := os.ReadFile(options.preflightReport)
		if err != nil {
			return "", errors.Wrap(err, "failed to read preflight report")
		}
		var report authorizationmigration.Report
		if err := json.Unmarshal(contents, &report); err != nil {
			return "", errors.Wrap(err, "failed to parse preflight report")
		}
		if !report.Ready || report.Phase != authorizationmigration.PhasePreflight || report.SchemaVersion != authorizationmigration.LegacySchemaVersion {
			return "", errors.New("preflight report is not a successful legacy-schema report")
		}
		if expected != "" && expected != report.PolicySHA256 {
			return "", errors.New("--policy-sha256 does not match --preflight-report")
		}
		expected = report.PolicySHA256
	}
	if expected == "" {
		return "", nil
	}
	if len(expected) != sha256HexLength || strings.Trim(expected, "0123456789abcdefABCDEF") != "" {
		return "", errors.New("invalid --preflight-report or --policy-sha256")
	}
	return strings.ToLower(expected), nil
}

const sha256HexLength = 64

func resolveDatabaseURL(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if fromEnvironment := os.Getenv("DATABASE_URL"); fromEnvironment != "" {
		return fromEnvironment, nil
	}
	required := []string{"DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "DATABASE_PORT"}
	values := make(map[string]string, len(required))
	for _, name := range required {
		values[name] = os.Getenv(name)
		if values[name] == "" {
			return "", errors.Errorf("%s is required when DATABASE_URL is not set", name)
		}
	}
	sslMode := os.Getenv("DATABASE_SSLMODE")
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf("dbname=%s user=%s password=%s host=%s port=%s connect_timeout=5 sslmode=%s",
		quoteConnectionValue(values["DATABASE_NAME"]),
		quoteConnectionValue(values["DATABASE_USER"]),
		quoteConnectionValue(values["DATABASE_PASSWORD"]),
		quoteConnectionValue(values["DATABASE_HOST"]),
		quoteConnectionValue(values["DATABASE_PORT"]),
		quoteConnectionValue(sslMode),
	), nil
}

func quoteConnectionValue(value string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), "'", `\'`) + "'"
}

func writeReport(path string, report authorizationmigration.Report) error {
	contents, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to encode migration report")
	}
	contents = append(contents, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(contents)
		return err
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return errors.Wrap(err, "failed to write migration report")
	}
	return nil
}
