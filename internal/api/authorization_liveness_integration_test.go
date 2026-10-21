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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestInternalAuthorizeChecksAuthoritativeSubjectLivenessBeforeCachedPolicy(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection, "DATABASE_URL must name an isolated local PostgreSQL test database")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	schema := "authorization_liveness_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
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

	const orgID = "liveness-org"
	roleID := uuid.New()
	humanID := userid.NewHumanUserId()
	expiringServiceID := userid.NewServiceUserTokenId()
	deletedServiceID := userid.NewServiceUserTokenId()
	now := time.Now().UTC()
	_, err = raw.ExecContext(ctx, `INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id)
		VALUES ('organization:' || $1, 'organization', $1, $1)`, orgID)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($1, $2, 'Liveness reader', $3, ARRAY['read'])`, roleID, orgID, now.Add(-2*time.Hour))
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO users (id, display_name, created_at)
		VALUES ($1, 'Human actor', $2)`, humanID, now.Add(-2*time.Hour))
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role)
		VALUES ($1, $2, $3, $4, 'role', $5::text, $5::uuid)`, uuid.New(), now.Add(-2*time.Hour), humanID, orgID, roleID)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO service_user_tokens
			(id, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash)
		VALUES
			($1, $2, 'Expiring actor', $3, $4, $5, decode(repeat('11', 32), 'hex')),
			($6, $2, 'Deleted actor', $3, $4, $5, decode(repeat('22', 32), 'hex'))`,
		expiringServiceID, orgID, now.Add(-2*time.Hour), humanID, now.Add(time.Hour), deletedServiceID)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
		VALUES ($1, $2, $3, $4), ($5, $2, $3, $4)`,
		expiringServiceID, orgID, roleID, now.Add(-2*time.Hour), deletedServiceID)
	require.NoError(t, err)

	authorizer, err := authorization.New(ctx, store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	server := &Server{Database: store, Authorizer: authorizer}
	check := ResourcePermissionCheck{Resource: "organization:" + orgID, Permission: "read"}
	authorize := func(subjectID uuid.UUID) bool {
		t.Helper()
		allowed, _, authorizeErr := server.InternalAuthorizeInner(ctx, InternalAuthorizeBody{
			UserId: subjectID, Checks: []ResourcePermissionCheck{check},
		})
		require.NoError(t, authorizeErr)
		return allowed
	}

	require.True(t, authorize(humanID))
	require.True(t, authorize(expiringServiceID))
	require.True(t, authorize(deletedServiceID))

	_, err = raw.ExecContext(ctx, `
		UPDATE service_user_tokens
		SET current_token_expires_at = $2
		WHERE id = $1
	`, expiringServiceID, now.Add(-time.Hour))
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `DELETE FROM service_user_tokens WHERE id = $1`, deletedServiceID)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, humanID)
	require.NoError(t, err)

	require.False(t, authorize(expiringServiceID), "expired service actor must be denied despite its cached role")
	require.False(t, authorize(deletedServiceID), "deleted service actor must be denied despite its cached role")
	require.False(t, authorize(humanID), "deleted human actor must be denied despite its cached role")
}
