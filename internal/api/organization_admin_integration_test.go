//go:build integration

package api

import (
	"database/sql"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/adminapi"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCanonicalAdminOptionalAPIUsesRealIAMMembership(t *testing.T) {
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "canonical_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); require.NoError(t, err) })
	db, err := model.NewDatabaser(t.Context(), zap.NewNop(), connection+" options='-c search_path="+schema+"'")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	actor := userid.NewHumanUserId()
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	_, err = db.CreateUser(t.Context(), tx, &model.User{Id: actor, DisplayName: "Canonical Admin", CreatedAt: time.Now()})
	require.NoError(t, err)
	roles, err := SeedBuiltinOrgRoles(t.Context(), zap.NewNop(), db, tx, "org-a")
	require.NoError(t, err)
	role := roles[0].Id
	membership := uuid.New()
	_, err = tx.ExecContext(t.Context(), `INSERT INTO memberships(id,created_at,user_id,org_id,subject_type,subject,role,scope) VALUES($1,now(),$2,'org-a','role',$3,$4,'')`, membership, actor, role.String(), role)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	router, err := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{AppName: "canonical-api-test", Logger: zap.NewNop(), OpenAPIRawSchema: MustDecodeOpenApiSpec(), OpenAPISkipperFn: OpenApiValidatorSkipper})
	require.NoError(t, err)
	(&Server{Database: db, Logger: zap.NewNop()}).MapRoutes(router)
	httpServer := httptest.NewServer(router)
	t.Cleanup(httpServer.Close)
	client, err := adminapi.NewClientWithResponses(httpServer.URL)
	require.NoError(t, err)
	response, err := client.InternalIsOrganizationAdminWithResponse(t.Context(), "org-a", actor)
	require.NoError(t, err)
	require.NotNil(t, response.JSON200, string(response.Body))
	require.True(t, response.JSON200.Allowed)
	response, err = client.InternalIsOrganizationAdminWithResponse(t.Context(), "org-b", actor)
	require.NoError(t, err)
	require.NotNil(t, response.JSON200, string(response.Body))
	require.False(t, response.JSON200.Allowed)
	tx, err = db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `DELETE FROM memberships WHERE id=$1`, membership)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	response, err = client.InternalIsOrganizationAdminWithResponse(t.Context(), "org-a", actor)
	require.NoError(t, err)
	require.NotNil(t, response.JSON200, string(response.Body))
	require.False(t, response.JSON200.Allowed)
}
