package integrationtests

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

// scimMigrationTables are the tables introduced by 000032_scim.sql and
// 000033_scim_group_role_mappings.sql, in no particular order.
var scimMigrationTables = []string{
	"scim_users",
	"scim_groups",
	"scim_group_members",
	"scim_group_role_mappings",
	"scim_managed_memberships",
}

// preScimMigrationVersion is the migration the SCIM feature builds on top of;
// rolling back to it must undo 000033 and 000032.
const preScimMigrationVersion = 31

// TestScimMigrationRollback executes the `-- +goose Down` blocks of the SCIM
// migrations, which no other test (and no deployment) ever runs. A broken Down
// means an operator cannot roll back a bad release. The dance runs in a
// scratch SCHEMA (the test user may not create databases): every migration in
// this repo uses unqualified names, so pinning search_path to the scratch
// schema replays the full history — including its own goose_db_version —
// without touching the tables the parallel tests depend on.
func TestScimMigrationRollback(t *testing.T) {
	t.Parallel()

	connStr := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connStr, "DATABASE_URL must be set")

	admin, err := sql.Open("postgres", connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })

	scratchName := "scim_migration_test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = admin.ExecContext(t.Context(), "CREATE SCHEMA "+scratchName)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA IF EXISTS " + scratchName + " CASCADE")
	})

	// search_path holds ONLY the scratch schema, so goose cannot see the main
	// schema's goose_db_version and skip the replay.
	db, err := sql.Open("postgres", connStr+" options='-c search_path="+scratchName+"'")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	logger := zap.NewNop()
	ctx := t.Context()

	tableExists := func(t *testing.T, table string) bool {
		t.Helper()
		var regclass *string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT to_regclass($1)", scratchName+"."+table).Scan(&regclass))
		return regclass != nil
	}

	require.NoError(t, model.MigrateUp(ctx, logger, db), "initial migrate up")
	for _, table := range scimMigrationTables {
		require.True(t, tableExists(t, table), "table %s must exist after migrate up", table)
	}

	require.NoError(t, model.MigrateDownTo(ctx, logger, db, preScimMigrationVersion), "migrate down past the scim migrations")
	for _, table := range scimMigrationTables {
		assert.False(t, tableExists(t, table), "table %s must be gone after rollback", table)
	}

	// Postgres cannot remove enum values, so 000032's Down intentionally leaves
	// the 'scim' identity_provider in place (documented in the migration).
	var enumCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pg_enum e
		 JOIN pg_type ty ON ty.oid = e.enumtypid
		 JOIN pg_namespace ns ON ns.oid = ty.typnamespace
		 WHERE ns.nspname = $1 AND ty.typname = 'identity_provider' AND e.enumlabel = 'scim'`,
		scratchName).Scan(&enumCount))
	assert.Equal(t, 1, enumCount, "the 'scim' enum value must survive the rollback")

	// And the round trip: migrating up again must succeed on the post-rollback
	// state (the enum value still existing must not trip the re-run).
	require.NoError(t, model.MigrateUp(ctx, logger, db), "migrate up again after rollback")
	for _, table := range scimMigrationTables {
		assert.True(t, tableExists(t, table), "table %s must be back after re-migrating up", table)
	}

	var version int64
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1").Scan(&version))
	assert.GreaterOrEqual(t, version, int64(33), "database must be back at (or beyond) the scim migrations")
}
