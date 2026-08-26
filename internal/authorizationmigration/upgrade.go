package authorizationmigration

import (
	"context"
	"database/sql"

	"github.com/pkg/errors"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

const authorizationMigrationLockID int64 = 0x5354454c4c574552

type migrationState struct {
	policySHA256 string
	reconciled   bool
}

// Upgrade serializes startup migrations across replicas, validates legacy
// authorization data, migrates the schema, rebuilds resource ancestry, and
// verifies the result before returning a database suitable for serving IAM
// traffic. It is safe to retry after an interrupted reconciliation.
func Upgrade(
	ctx context.Context,
	logger *zap.Logger,
	rawDB *sql.DB,
	connectionString string,
	cp cpclient.ClientWithResponsesInterface,
	expectedPolicySHA256 string,
) (model.Databaser, Report, error) {
	report := Report{}
	lockConnection, err := rawDB.Conn(ctx)
	if err != nil {
		return nil, report, errors.Wrap(err, "failed to reserve authorization migration connection")
	}
	defer func() { _ = lockConnection.Close() }()
	if _, err := lockConnection.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, authorizationMigrationLockID); err != nil {
		return nil, report, errors.Wrap(err, "failed to acquire authorization migration lock")
	}
	defer func() {
		if _, unlockErr := lockConnection.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, authorizationMigrationLockID); unlockErr != nil {
			logger.Error("failed to release authorization migration lock", zap.Error(unlockErr))
		}
	}()

	version, err := CurrentVersion(ctx, rawDB)
	if err != nil {
		return nil, report, err
	}
	effectiveExpected := expectedPolicySHA256

	switch {
	case version == 0:
		logger.Info("initializing fresh IAM database")
		if err := model.MigrateUp(ctx, logger, rawDB); err != nil {
			return nil, report, errors.Wrap(err, "failed to initialize IAM database")
		}
	case version == LegacySchemaVersion:
		report, err = Inspect(ctx, rawDB, PhasePreflight)
		if err != nil {
			return nil, report, err
		}
		if !report.Ready {
			return nil, report, errors.New("automatic SpiceDB migration preflight failed")
		}
		if effectiveExpected != "" && effectiveExpected != report.PolicySHA256 {
			return nil, report, errors.Errorf("authorization data changed: expected policy SHA-256 %s, found %s", effectiveExpected, report.PolicySHA256)
		}
		effectiveExpected = report.PolicySHA256
		logger.Info("automatically upgrading SpiceDB authorization data", zap.Int64("schema_version", version))
		if err := model.MigrateUp(ctx, logger, rawDB); err != nil {
			return nil, report, errors.Wrap(err, "failed to apply Casbin database migrations")
		}
	case version >= 1 && version < LegacySchemaVersion:
		return nil, report, errors.Errorf("automatic Casbin upgrade requires schema version %d; found %d, so upgrade to IAM v2.0.1 first", LegacySchemaVersion, version)
	case version >= LegacySchemaVersion && version < CasbinSchemaVersion:
		logger.Info("finishing interrupted Casbin authorization migration", zap.Int64("schema_version", version))
		if err := model.MigrateUp(ctx, logger, rawDB); err != nil {
			return nil, report, errors.Wrap(err, "failed to finish Casbin database migrations")
		}
	case version > model.MaxMigrationVersion():
		return nil, report, errors.Errorf("database schema version %d is newer than this binary's latest migration %d", version, model.MaxMigrationVersion())
	}

	database, err := model.NewDatabaser(ctx, logger, connectionString)
	if err != nil {
		return nil, report, errors.Wrap(err, "failed to open migrated IAM database")
	}
	closeOnError := func(upgradeErr error) (model.Databaser, Report, error) {
		if closeErr := database.Close(); closeErr != nil {
			logger.Error("failed to close IAM database after migration error", zap.Error(closeErr))
		}
		return nil, report, upgradeErr
	}

	state, err := loadMigrationState(ctx, rawDB)
	if err != nil {
		return closeOnError(err)
	}
	report, err = Inspect(ctx, rawDB, PhaseVerify)
	if err != nil {
		return closeOnError(err)
	}
	if state.reconciled && expectedPolicySHA256 == "" && report.Ready {
		logger.Info("authorization database is ready", zap.Int64("schema_version", report.SchemaVersion))
		return database, report, nil
	}
	if state.reconciled && expectedPolicySHA256 == "" {
		effectiveExpected = report.PolicySHA256
	}
	if effectiveExpected == "" {
		effectiveExpected = state.policySHA256
	}
	if effectiveExpected == "" {
		effectiveExpected = report.PolicySHA256
	}
	if report.PolicySHA256 != effectiveExpected {
		return closeOnError(errors.Errorf("authorization data changed during migration: expected policy SHA-256 %s, found %s", effectiveExpected, report.PolicySHA256))
	}
	if state.policySHA256 == "" {
		if err := storeMigrationFingerprint(ctx, rawDB, effectiveExpected); err != nil {
			return closeOnError(err)
		}
	}

	if !state.reconciled || !report.Ready {
		reconciled, reconcileErr := Reconcile(ctx, logger, rawDB, database, cp)
		if reconcileErr != nil {
			return closeOnError(reconcileErr)
		}
		report, err = Inspect(ctx, rawDB, PhaseVerify)
		report.Reconciled = &reconciled
		if err != nil {
			return closeOnError(err)
		}
		if !report.Ready {
			return closeOnError(errors.New("Casbin authorization verification failed after reconciliation"))
		}
		if report.PolicySHA256 != effectiveExpected {
			return closeOnError(errors.Errorf("authorization data changed during reconciliation: expected policy SHA-256 %s, found %s", effectiveExpected, report.PolicySHA256))
		}
		if err := markMigrationReconciled(ctx, rawDB); err != nil {
			return closeOnError(err)
		}
	}

	logger.Info("authorization database is ready", zap.Int64("schema_version", CasbinSchemaVersion))
	return database, report, nil
}

func CurrentVersion(ctx context.Context, db *sql.DB) (int64, error) {
	var tableName sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.goose_db_version')::text`).Scan(&tableName); err != nil {
		return 0, errors.Wrap(err, "failed to locate database migration history")
	}
	if !tableName.Valid {
		return 0, nil
	}
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil {
		return 0, errors.Wrap(err, "failed to read current database migration version")
	}
	return version, nil
}

func loadMigrationState(ctx context.Context, db *sql.DB) (migrationState, error) {
	state := migrationState{}
	var policySHA256 sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT policy_sha256, reconciled FROM authorization_migration_state WHERE singleton`).Scan(&policySHA256, &state.reconciled); err != nil {
		return state, errors.Wrap(err, "failed to read authorization migration state")
	}
	if policySHA256.Valid {
		state.policySHA256 = policySHA256.String
	}
	return state, nil
}

func storeMigrationFingerprint(ctx context.Context, db *sql.DB, policySHA256 string) error {
	_, err := db.ExecContext(ctx, `UPDATE authorization_migration_state SET policy_sha256 = $1 WHERE singleton`, policySHA256)
	return errors.Wrap(err, "failed to store authorization migration fingerprint")
}

func markMigrationReconciled(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE authorization_migration_state SET reconciled = true, reconciled_at = now() WHERE singleton`)
	return errors.Wrap(err, "failed to mark authorization migration as reconciled")
}
