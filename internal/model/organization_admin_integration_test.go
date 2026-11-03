//go:build integration

package model

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCanonicalOrganizationAdminRequiresExactCurrentMembership(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "canonical_admin_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); require.NoError(t, err) })
	pool, err := sql.Open("postgres", connection+" options='-c search_path="+schema+"'")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	require.NoError(t, MigrateUp(t.Context(), zap.NewNop(), pool))
	db := &databaser{DB: pool, logger: zap.NewNop()}
	actor := userid.NewHumanUserId()
	role := uuid.New()
	custom := uuid.New()
	membership := uuid.New()
	_, err = pool.Exec(`INSERT INTO users(id,display_name,created_at) VALUES($1,'Admin fixture',now())`, actor)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	err = db.SeedRoles(t.Context(), tx, "org-a", []Role{{Id: role, DisplayName: "Admin", CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, IsSystem: true, BuiltinKey: "admin", Permissions: []string{"manage_all"}}})
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	_, err = pool.Exec(`INSERT INTO memberships(id,created_at,user_id,org_id,subject_type,subject,role,scope) VALUES($1,now(),$2,'org-a','role',$3,$4,'')`, membership, actor, role.String(), role)
	require.NoError(t, err)
	check := func(org string, want bool) {
		t.Helper()
		got, err := IsOrganizationAdmin(t.Context(), db, org, actor)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	check("org-a", true)
	check("org-b", false)
	_, err = pool.Exec(`UPDATE memberships SET scope='project:example' WHERE id=$1`, membership)
	require.NoError(t, err)
	check("org-a", false)
	_, err = pool.Exec(`UPDATE memberships SET scope='' WHERE id=$1`, membership)
	require.NoError(t, err)
	_, err = pool.Exec(`UPDATE roles SET display_name='Renamed immutable Admin' WHERE id=$1`, role)
	require.NoError(t, err)
	check("org-a", true)
	_, err = pool.Exec(`UPDATE roles SET builtin_key=NULL WHERE id=$1`, role)
	require.ErrorContains(t, err, "immutable")
	_, err = pool.Exec(`INSERT INTO roles(id,org_id,display_name,created_at,permissions) VALUES($1,'org-a','Admin',now(),ARRAY['manage_all'])`, custom)
	require.NoError(t, err)
	_, err = pool.Exec(`UPDATE memberships SET role=$2,subject=$3 WHERE id=$1`, membership, custom, custom.String())
	require.NoError(t, err)
	check("org-a", false)
	_, err = pool.Exec(`UPDATE memberships SET role=$2,subject=$3 WHERE id=$1`, membership, role, role.String())
	require.NoError(t, err)
	check("org-a", true)
	_, err = pool.Exec(`DELETE FROM memberships WHERE id=$1`, membership)
	require.NoError(t, err)
	check("org-a", false)
	for _, id := range []uuid.UUID{uuid.Nil, userid.InternalSystemUuid, uuid.New()} {
		allowed, err := IsOrganizationAdmin(t.Context(), db, "org-a", id)
		require.NoError(t, err)
		require.False(t, allowed)
	}
}

func TestCanonicalRoleMigrationClassifiesOnlySeedEvidenceAndRefusesLoss(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "canonical_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); require.NoError(t, err) })
	pool, err := sql.Open("postgres", connection+" options='-c search_path="+schema+"'")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	require.NoError(t, MigrateUpTo(t.Context(), zap.NewNop(), pool, 38))
	seeded, custom, modified := uuid.New(), uuid.New(), uuid.New()
	_, err = pool.Exec(`INSERT INTO roles(id,org_id,display_name,created_at,created_by,permissions,is_system) VALUES($1,'seeded','Admin',now(),'ffffffff-ffff-ffff-ffff-ffffffffffff',ARRAY['manage_all'],true),($2,'custom','Admin',now(),$4,ARRAY['manage_all'],true),($3,'modified','Admin',now(),'ffffffff-ffff-ffff-ffff-ffffffffffff',ARRAY['manage_all','read_all'],true)`, seeded, custom, modified, uuid.New())
	require.NoError(t, err)
	require.NoError(t, MigrateUp(t.Context(), zap.NewNop(), pool))
	var key sql.NullString
	require.NoError(t, pool.QueryRow(`SELECT builtin_key FROM roles WHERE id=$1`, seeded).Scan(&key))
	require.True(t, key.Valid)
	require.Equal(t, "admin", key.String)
	for _, id := range []uuid.UUID{custom, modified} {
		require.NoError(t, pool.QueryRow(`SELECT builtin_key FROM roles WHERE id=$1`, id).Scan(&key))
		require.False(t, key.Valid)
	}
	require.ErrorContains(t, MigrateDownTo(t.Context(), zap.NewNop(), pool, 38), "canonical built-in role identities")
	require.NoError(t, MigrateUp(t.Context(), zap.NewNop(), pool))
	require.NoError(t, pool.QueryRow(`SELECT builtin_key FROM roles WHERE id=$1`, seeded).Scan(&key))
	require.Equal(t, "admin", key.String)
}
