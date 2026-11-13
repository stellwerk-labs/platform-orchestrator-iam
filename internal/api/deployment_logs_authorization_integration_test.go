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

func TestDeploymentLogsAuthorizationUsesDedicatedScopedGrant(t *testing.T) {
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

	const permission = sharedauthz.PermissionDeploymentLogsRead
	_, err = raw.ExecContext(ctx, `INSERT INTO authorization_resources(resource,resource_type,resource_id,org_id,parent_resource) VALUES
 ('organization:acme','organization','acme','acme',NULL),
 ('project:p','project','p','acme','organization:acme'),
 ('env:a','env','a','acme','project:p'),
 ('env:b','env','b','acme','project:p'),
 ('organization:foreign','organization','foreign','foreign',NULL),
 ('env:foreign','env','foreign','foreign','organization:foreign')`)
	require.NoError(t, err)

	adminActor, adminRole := userid.NewHumanUserId(), uuid.New()
	_, err = raw.ExecContext(ctx, `INSERT INTO users(id,display_name,created_at) VALUES($1,'Admin',now())`, adminActor)
	require.NoError(t, err)
	tx, err := store.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, store.SeedRoles(ctx, tx, "acme", []model.Role{{Id: adminRole, DisplayName: "Admin", CreatedAt: time.Now(), CreatedBy: userid.InternalSystemUuid, IsSystem: true, BuiltinKey: "admin", Permissions: []string{authorization.PermissionManageAll}}}))
	require.NoError(t, tx.Commit())
	_, err = raw.ExecContext(ctx, `INSERT INTO memberships(id,created_at,user_id,org_id,subject_type,subject,role) VALUES($1,now(),$2,'acme','role',$3::text,$3::uuid)`, uuid.New(), adminActor, adminRole)
	require.NoError(t, err)
	authorizer, err := authorization.New(ctx, store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	server := &Server{Database: store, Authorizer: authorizer, Logger: zap.NewNop()}
	adminContext := context.WithValue(ctx, hecho.ContextKeyUserID, adminActor.String())
	allowed, _, err := server.InternalAuthorizeInner(ctx, InternalAuthorizeBody{UserId: adminActor, Checks: []ResourcePermissionCheck{{Resource: "env:a", Permission: permission}}})
	require.NoError(t, err)
	require.True(t, allowed, "canonical Admin inherits plaintext log access")
	type assignment struct {
		grant, scope       string
		allowedA, allowedB bool
	}
	for _, scenario := range []assignment{
		{authorization.PermissionReadAll, "", false, false},
		{authorization.PermissionWriteAll, "", false, false},
		{sharedauthz.PermissionDeploymentRead, "", false, false},
		{authorization.PermissionManageAll, "", true, true},
		{permission, "", true, true},
		{permission, "project:p", true, true},
		{permission, "env:a", true, false},
	} {
		actor := userid.NewHumanUserId()
		_, err = raw.ExecContext(ctx, `INSERT INTO users(id,display_name,created_at) VALUES($1,'Reader',now());`, actor)
		require.NoError(t, err)
		roleBody := RoleWriteBody{DisplayName: uuid.NewString(), Permissions: []string{scenario.grant}}
		created, err := server.CreateRole(adminContext, CreateRoleRequestObject{OrgId: "acme", Body: &roleBody})
		require.NoError(t, err)
		role, ok := created.(CreateRole201JSONResponse)
		require.True(t, ok, "permission accepted through real role API: %s", scenario.grant)
		_, err = raw.ExecContext(ctx, `INSERT INTO memberships(id,created_at,user_id,org_id,subject_type,subject,role,scope) VALUES($1,now(),$2,'acme','role',$3::text,$3::uuid,$4)`, uuid.New(), actor, role.Id, scenario.scope)
		require.NoError(t, err)
		require.NoError(t, authorizer.ReloadPolicy())
		for _, target := range []struct {
			resource string
			allowed  bool
		}{{"env:a", scenario.allowedA}, {"env:b", scenario.allowedB}, {"env:foreign", false}} {
			allowed, _, err := server.InternalAuthorizeInner(ctx, InternalAuthorizeBody{UserId: actor, Checks: []ResourcePermissionCheck{{Resource: target.resource, Permission: permission}}})
			require.NoError(t, err)
			require.Equal(t, target.allowed, allowed, "grant %s scope %s resource %s", scenario.grant, scenario.scope, target.resource)
		}
		actorContext := context.WithValue(ctx, hecho.ContextKeyUserID, actor.String())
		body := CheckPermissionsJSONRequestBody{{Resource: "env:a", Permission: permission}}
		response, err := server.CheckPermissions(actorContext, CheckPermissionsRequestObject{Body: &body})
		require.NoError(t, err)
		result, ok := response.(CheckPermissions200JSONResponse)
		require.True(t, ok)
		require.Equal(t, scenario.allowedA, result.Items[0].Allowed)
	}
}
