//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

func TestRolelessServiceUserCanBeRetrievedAndRegenerated(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection, "DATABASE_URL must name an isolated local PostgreSQL test database")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	schema := "service_user_roleless_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	serviceID := uuid.New()
	actorID := uuid.New()
	oldHash := bytes.Repeat([]byte{0x42}, sha256.Size)
	now := time.Now().UTC()
	_, err = raw.ExecContext(ctx, `INSERT INTO service_user_tokens
		(id, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash)
		VALUES ($1, 'roleless-org', 'Roleless plugin backend', $2, $3, $4, $5)`,
		serviceID, now.Add(-time.Hour), actorID, now.Add(time.Hour), oldHash)
	require.NoError(t, err)

	service, err := store.GetServiceUserToken(ctx, nil, serviceID)
	require.NoError(t, err)
	require.Empty(t, service.ServiceUserRoles)
	byHash, err := store.GetServiceUserTokenByHash(ctx, nil, oldHash)
	require.NoError(t, err)
	require.Equal(t, serviceID, byHash.Id)
	require.Empty(t, byHash.ServiceUserRoles)
	listed, _, err := store.ListServiceUserTokens(ctx, nil, model.ListServiceUserTokensParams{OrgId: "roleless-org"})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Empty(t, listed[0].ServiceUserRoles)

	newToken := RegenerateServiceUserToken(service, 7)
	service.GeneratedBy = actorID
	updated, err := store.UpdateServiceUserToken(ctx, nil, service)
	require.NoError(t, err)
	require.Equal(t, serviceID, updated.Id)
	require.Empty(t, updated.ServiceUserRoles)
	require.True(t, updated.CurrentTokenExpiresAt.After(now.Add(6*24*time.Hour)))

	rawToken, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(newToken, ServiceUserTokenPrefix))
	require.NoError(t, err)
	newHash := sha256.Sum256(rawToken)
	byHash, err = store.GetServiceUserTokenByHash(ctx, nil, newHash[:])
	require.NoError(t, err)
	require.Equal(t, serviceID, byHash.Id)
	require.Empty(t, byHash.ServiceUserRoles)
}
