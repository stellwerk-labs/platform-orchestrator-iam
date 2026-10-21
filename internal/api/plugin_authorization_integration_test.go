//go:build integration

package api

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestRegisteredPluginCapabilitiesAreKnownBeforeRoleAssignment(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection, "DATABASE_URL must name an isolated local PostgreSQL test database")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "plugin_authorization_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE")
		require.NoError(t, cleanupErr)
	})
	scopedConnection := fmt.Sprintf("%s options='-c search_path=%s'", connection, schema)
	store, err := model.NewDatabaser(ctx, zap.NewNop(), scopedConnection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	raw, err := sql.Open("postgres", scopedConnection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })

	const orgID = "plugin-org"
	const pluginID = "dev.stellwerk.progressive-rollouts"
	const readPermission = "plugin." + pluginID + ".rollout-read"
	const environmentPermission = "plugin." + pluginID + ".rollout-approve-environment"
	const projectPermission = "plugin." + pluginID + ".rollout-approve-project"
	_, err = raw.ExecContext(ctx, `INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
		VALUES ('organization:plugin-org', 'organization', 'plugin-org', $1, NULL),
		       ('project:test', 'project', 'test', $1, 'organization:plugin-org'),
		       ('env:test', 'env', 'test', $1, 'project:test'),
		       ('organization:other', 'organization', 'other', 'other', NULL)`, orgID)
	require.NoError(t, err)
	capabilities := []model.PluginCapability{
		{ID: readPermission, DisplayName: "Read rollouts", Description: "Read rollout state.", Category: "Rollouts", Level: sharedauthz.PermissionLevelRead,
			Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization}},
		{ID: environmentPermission, DisplayName: "Approve environments", Description: "Approve one environment.", Category: "Rollouts", Level: sharedauthz.PermissionLevelWrite,
			Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeEnvironment}},
		{ID: projectPermission, DisplayName: "Approve projects", Description: "Approve one project.", Category: "Rollouts", Level: sharedauthz.PermissionLevelWrite,
			Scopes: []sharedauthz.PermissionScope{sharedauthz.PermissionScopeProject}},
	}
	replace := func(capabilities []model.PluginCapability) {
		t.Helper()
		tx, beginErr := store.BeginTx(ctx, nil)
		require.NoError(t, beginErr)
		t.Cleanup(func() { _ = tx.Rollback() })
		require.NoError(t, model.ReplacePluginCapabilities(ctx, tx, orgID, pluginID, capabilities))
		require.NoError(t, tx.Commit())
	}
	replace(capabilities)
	actor := userid.NewHumanUserId()
	otherActor := userid.NewHumanUserId()
	_, err = raw.ExecContext(ctx, `INSERT INTO users (id, display_name, created_at)
		VALUES ($1, 'Admin actor', now()), ($2, 'Other actor', now())`, actor, otherActor)
	require.NoError(t, err)
	assign := func(subject uuid.UUID, name string, permission string) {
		t.Helper()
		roleID := uuid.New()
		_, insertErr := raw.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
			VALUES ($1, $2, $3, now(), ARRAY[$4])`, roleID, orgID, name, permission)
		require.NoError(t, insertErr)
		_, insertErr = raw.ExecContext(ctx, `INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role)
			VALUES ($1, now(), $2, $3, 'role', $4::text, $4::uuid)`, uuid.New(), subject, orgID, roleID)
		require.NoError(t, insertErr)
	}
	assign(actor, "Admin", authorization.PermissionManageAll)
	authorizer, err := authorization.New(ctx, store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	server := &Server{Database: store, Authorizer: authorizer}
	actorContext := context.WithValue(ctx, hecho.ContextKeyUserID, actor.String())
	catalogue, err := server.ListPermissions(actorContext, ListPermissionsRequestObject{OrgId: orgID})
	require.NoError(t, err)
	definitions, ok := catalogue.(ListPermissions200JSONResponse)
	require.True(t, ok)
	permissionIDs := make([]string, 0, len(definitions.Items))
	for _, definition := range definitions.Items {
		permissionIDs = append(permissionIDs, definition.Id)
	}
	require.Contains(t, permissionIDs, readPermission)
	check := func(subject uuid.UUID, resource, permission string, valid, allowed bool) {
		t.Helper()
		body := CheckPermissionsJSONRequestBody{{Resource: resource, Permission: permission}}
		actorContext := context.WithValue(ctx, hecho.ContextKeyUserID, subject.String())
		response, checkErr := server.CheckPermissions(actorContext, CheckPermissionsRequestObject{Body: &body})
		require.NoError(t, checkErr)
		if valid {
			result, ok := response.(CheckPermissions200JSONResponse)
			require.True(t, ok, "registered permission should be valid: %s on %s, got %T", permission, resource, response)
			require.Len(t, result.Items, 1)
			require.Equal(t, allowed, result.Items[0].Allowed)
		} else {
			_, rejected := response.(CheckPermissions400JSONResponse)
			require.True(t, rejected, "permission should be invalid: %s on %s", permission, resource)
		}
		internalAllowed, failed, checkErr := server.InternalAuthorizeInner(ctx, InternalAuthorizeBody{
			UserId: subject, Checks: []ResourcePermissionCheck{{Resource: resource, Permission: permission}},
		})
		require.NoError(t, checkErr)
		require.Equal(t, allowed, internalAllowed)
		if allowed {
			require.Empty(t, failed)
		} else {
			require.Len(t, failed, 1)
		}
	}
	check(actor, "organization:plugin-org", readPermission, true, true)
	check(actor, "env:test", environmentPermission, true, true)
	check(actor, "project:test", projectPermission, true, true)
	check(otherActor, "organization:plugin-org", readPermission, true, false)
	check(actor, "project:test", readPermission, false, false)
	check(actor, "env:test", readPermission, false, false)
	check(actor, "organization:plugin-org", environmentPermission, false, false)
	check(actor, "env:test", projectPermission, false, false)
	check(actor, "organization:other", readPermission, false, false)
	check(actor, "env:missing", environmentPermission, false, false)
	check(actor, "organization:plugin-org", "plugin."+pluginID+".unregistered", false, false)
	check(actor, "organization:plugin-org", "customer_unassigned", false, false)

	assign(otherActor, "Viewer", authorization.PermissionReadAll)
	require.NoError(t, authorizer.ReloadPolicy())
	check(otherActor, "organization:plugin-org", readPermission, true, false)
	assign(otherActor, "Plugin reader", readPermission)
	assign(otherActor, "Custom permission", "customer_permission")
	require.NoError(t, authorizer.ReloadPolicy())
	check(otherActor, "organization:plugin-org", readPermission, true, true)
	check(otherActor, "env:test", sharedauthz.PermissionModuleVersionUnpin, true, false)
	check(otherActor, "organization:plugin-org", "customer_permission", true, true)
	check(actor, "organization:plugin-org", "customer_permission", true, true)
	check(actor, "organization:other", "customer_permission", false, false)

	replace(nil)
	require.NoError(t, authorizer.ReloadPolicy())
	check(actor, "organization:plugin-org", readPermission, false, false)
	check(otherActor, "organization:plugin-org", readPermission, false, false)
}
