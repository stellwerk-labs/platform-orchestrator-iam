//go:build integration

package model

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPluginCapabilitiesAreDurableAndUnregistrationInvalidatesThem(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection, "DATABASE_URL must name an isolated local PostgreSQL test database")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "plugin_capability_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE") })
	db, err := sql.Open("postgres", connection+" options='-c search_path="+schema+"'")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, MigrateUp(ctx, zap.NewNop(), db))
	store := &databaser{DB: db, logger: zap.NewNop()}
	_, err = db.ExecContext(ctx, `
		INSERT INTO plugin_capabilities
			(org_id, plugin_id, id, display_name, description, category, level, scopes)
		VALUES
			('plugin-org', 'dev.example', 'plugin.dev.example.reader.read', 'Read', 'Read plugin state.', 'Plugin', 'read', ARRAY['organization'])
	`)
	require.Error(t, err, "database must reject an ambiguous dotted local capability name")

	const orgID = "plugin-org"
	const pluginID = "dev.stellwerk.progressive-rollouts"
	capability := PluginCapability{
		OrgID: orgID, PluginID: pluginID, ID: "plugin." + pluginID + ".rollout-read",
		DisplayName: "View rollouts", Description: "View rollout state.", Category: "Progressive rollouts",
		Level: sharedauthz.PermissionLevelRead, Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization},
	}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, ReplacePluginCapabilities(ctx, tx, orgID, pluginID, []PluginCapability{capability}))
	require.NoError(t, tx.Commit())
	listed, err := store.ListPluginCapabilities(ctx, nil, orgID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, capability.ID, listed[0].ID)
	_, err = db.ExecContext(ctx, `INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id)
		VALUES ('organization:' || $1, 'organization', $1, $1)`, orgID)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($2, $1, 'Plugin role', now(), ARRAY[$3])`, orgID, uuid.New(), capability.ID)
	require.NoError(t, err)
	check := AuthorizationPermissionCheck{Resource: "organization:" + orgID, Permission: capability.ID}
	known, err := store.ListKnownAuthorizationPermissions(ctx, nil, []AuthorizationPermissionCheck{check})
	require.NoError(t, err)
	require.Equal(t, []AuthorizationPermissionCheck{check}, known)

	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, ReplacePluginCapabilities(ctx, tx, orgID, pluginID, nil))
	require.NoError(t, tx.Commit())
	listed, err = store.ListPluginCapabilities(ctx, nil, orgID)
	require.NoError(t, err)
	require.Empty(t, listed)
	known, err = store.ListKnownAuthorizationPermissions(ctx, nil, []AuthorizationPermissionCheck{check})
	require.NoError(t, err)
	require.Empty(t, known, "a stale role entry must not keep an unregistered plugin capability valid")
}
