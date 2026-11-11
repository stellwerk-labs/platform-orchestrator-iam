//go:build integration

package model

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSessionActivityMigrationDoesNotReviveLegacySessions(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "session_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); require.NoError(t, err) })
	pool, err := sql.Open("postgres", connection+" options='-c timezone=Pacific/Honolulu -c search_path="+schema+"'")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	require.NoError(t, MigrateUpTo(t.Context(), zap.NewNop(), pool, 39))
	user := uuid.New()
	_, err = pool.Exec(`INSERT INTO users(id,display_name,created_at) VALUES($1,'Legacy session fixture',now())`, user)
	require.NoError(t, err)
	_, err = pool.Exec(`INSERT INTO session_tokens(sha256_hash,provider,user_id,created_at,expires_at) VALUES(decode(repeat('11',32),'hex'),'google',$1,statement_timestamp()-interval '1 hour',statement_timestamp()+interval '23 hours')`, user)
	require.NoError(t, err)
	require.NoError(t, MigrateUp(t.Context(), zap.NewNop(), pool))
	var created, active time.Time
	require.NoError(t, pool.QueryRow(`SELECT created_at,last_active_at FROM session_tokens`).Scan(&created, &active))
	require.True(t, created.Equal(active), "migration changed the activity instant")
	require.True(t, active.Add(15*time.Minute).Before(time.Now()))
	require.NoError(t, MigrateDownTo(t.Context(), zap.NewNop(), pool, 39))
	require.NoError(t, MigrateUp(t.Context(), zap.NewNop(), pool))
	require.NoError(t, pool.QueryRow(`SELECT created_at,last_active_at FROM session_tokens`).Scan(&created, &active))
	require.True(t, created.Equal(active), "migration changed the activity instant")
}
