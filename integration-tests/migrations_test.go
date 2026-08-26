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

// newScratchSchemaDb opens a connection whose search_path holds ONLY a fresh
// scratch schema, so goose cannot see the main schema's goose_db_version and
// replays the full migration history without touching the tables the parallel
// tests depend on. The schema is dropped on cleanup.
func newScratchSchemaDb(t *testing.T, prefix string) (*sql.DB, string) {
	t.Helper()
	connStr := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connStr, "DATABASE_URL must be set")

	admin, err := sql.Open("postgres", connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })

	scratchName := prefix + strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = admin.ExecContext(t.Context(), "CREATE SCHEMA "+scratchName)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA IF EXISTS " + scratchName + " CASCADE")
	})

	db, err := sql.Open("postgres", connStr+" options='-c search_path="+scratchName+"'")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, scratchName
}

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
// rolling back to it must undo 000034, 000033, and 000032.
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

	db, scratchName := newScratchSchemaDb(t, "scim_migration_test_")

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
	assert.GreaterOrEqual(t, version, int64(34), "database must be back at (or beyond) the scim migrations")
}

// TestScimCaseCollisionMigrationFailsLoudly pins the operator-facing failure
// mode of 000035: rows that differ only in case (legal before, duplicates
// after) must abort the migration with a message that lists the colliding
// rows, instead of erroring out on the index build. After the operator
// resolves them, the migration must complete and enforce case-insensitive
// uniqueness from then on.
func TestScimCaseCollisionMigrationFailsLoudly(t *testing.T) {
	t.Parallel()

	db, _ := newScratchSchemaDb(t, "scim_case_migration_test_")
	logger := zap.NewNop()
	ctx := t.Context()

	// Stage the world as it was BEFORE case-insensitive uniqueness.
	require.NoError(t, model.MigrateUpTo(ctx, logger, db, 34), "migrate up to the pre-case-folding version")

	mustInsertUser := func(userId uuid.UUID, name string) {
		_, err := db.ExecContext(ctx,
			`INSERT INTO users (id, display_name, created_at) VALUES ($1, $2, now())`, userId, name)
		require.NoError(t, err)
	}
	mustInsertScimUser := func(userName string, deleted bool) {
		userId := uuid.New()
		mustInsertUser(userId, userName)
		var deletedAt *string
		if deleted {
			s := "2026-01-01T00:00:00Z"
			deletedAt = &s
		}
		_, err := db.ExecContext(ctx,
			`INSERT INTO scim_users (id, org_id, user_id, user_name, active, created_at, updated_at, deleted_at)
			 VALUES ($1, 'case-org', $2, $3, true, now(), now(), $4)`,
			uuid.New(), userId, userName, deletedAt)
		require.NoError(t, err)
	}
	mustInsertScimGroup := func(displayName string) uuid.UUID {
		id := uuid.New()
		_, err := db.ExecContext(ctx,
			`INSERT INTO scim_groups (id, org_id, display_name, created_at, updated_at)
			 VALUES ($1, 'case-org', $2, now(), now())`, id, displayName)
		require.NoError(t, err)
		return id
	}

	// Live case-collisions in both tables, plus a tombstoned user that folds to
	// the same name — tombstones are exempt and must NOT trip the check.
	mustInsertScimUser("Alice@Example.com", false)
	mustInsertScimUser("alice@example.com", false)
	mustInsertScimUser("ALICE@EXAMPLE.COM", true)
	collidingGroupId := mustInsertScimGroup("Engineering")
	mustInsertScimGroup("engineering")

	err := model.MigrateUp(ctx, logger, db)
	require.Error(t, err, "migration must refuse to build the case-insensitive index over colliding rows")
	assert.Contains(t, err.Error(), "differ only in userName case", "the error must explain the problem")
	assert.Contains(t, err.Error(), "alice@example.com", "the error must name the colliding rows")

	// Resolve the user collision only; the group collision must still block.
	_, err = db.ExecContext(ctx, `DELETE FROM scim_users WHERE user_name = 'alice@example.com'`)
	require.NoError(t, err)
	err = model.MigrateUp(ctx, logger, db)
	require.Error(t, err, "the group collision must still block the migration")
	assert.Contains(t, err.Error(), "differ only in displayName case")
	assert.Contains(t, err.Error(), "engineering")

	// Resolve the group collision too; now the migration must complete.
	_, err = db.ExecContext(ctx, `DELETE FROM scim_groups WHERE id = $1`, collidingGroupId)
	require.NoError(t, err)
	require.NoError(t, model.MigrateUp(ctx, logger, db), "migration must succeed once the collisions are resolved")

	// And from here on, case-insensitive uniqueness is enforced by the database.
	userId := uuid.New()
	mustInsertUser(userId, "dupe probe")
	_, err = db.ExecContext(ctx,
		`INSERT INTO scim_users (id, org_id, user_id, user_name, active, created_at, updated_at)
		 VALUES ($1, 'case-org', $2, 'aLiCe@ExAmPlE.cOm', true, now(), now())`,
		uuid.New(), userId)
	require.ErrorContains(t, err, "unique_scim_user_name", "a case-variant duplicate userName must violate the unique index")
	_, err = db.ExecContext(ctx,
		`INSERT INTO scim_groups (id, org_id, display_name, created_at, updated_at)
		 VALUES ($1, 'case-org', 'ENGINEERING', now(), now())`, uuid.New())
	assert.ErrorContains(t, err, "unique_scim_group_name", "a case-variant duplicate displayName must violate the unique index")
}
