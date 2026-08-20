package integrationtests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

const (
	DefaultAdminRoleName    = "Admin"
	DefaultDeployerRoleName = "Deployer"
	DefaultViewerRoleName   = "Viewer"
)

var testHttpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if strings.HasSuffix(host, ".localhost") {
				address = net.JoinHostPort("127.0.0.1", port)
			}
			dialer := &net.Dialer{
				Timeout: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, address)
		},
	},
}

func mustServerURL(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("SERVER_URL"))
	require.NoError(t, err)
	require.NotEmpty(t, u.Host, "SERVER_URL must be set")
	return u.String()
}

func mustInternalServerURL(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("INTERNAL_SERVER_URL"))
	require.NoError(t, err)
	require.NotEmpty(t, u.Host, "INTERNAL_SERVER_URL must be set")
	return u.String()
}

func MustInternalControlPlaneClient(t *testing.T) cpclient.ClientWithResponsesInterface {
	u, err := url.Parse(os.Getenv("INTERNAL_CP_URL"))
	require.NoError(t, err)
	require.NotEmpty(t, u.Host, "INTERNAL_CP_URL must be set")
	client, err := cpclient.NewClientWithResponses(u.String(), cpclient.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("From", "x")
		if !strings.HasPrefix(req.URL.Path, "/internal") {
			return fmt.Errorf("path %s is not internal - MustControlPlaneClient required", req.URL.Path)
		}
		return nil
	}))
	require.NoError(t, err)
	return client
}

func MustControlPlaneClient(t *testing.T) cpclient.ClientWithResponsesInterface {
	u, err := url.Parse(os.Getenv("SERVER_URL"))
	require.NoError(t, err)
	require.NotEmpty(t, u.Host, "SERVER_URL must be set")
	client, err := cpclient.NewClientWithResponses(u.String(), cpclient.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("From", "ffffffff-ffff-ffff-ffff-ffffffffffff")
		if strings.HasPrefix(req.URL.Path, "/internal") {
			return fmt.Errorf("path %s is internal - MustInternalControlPlaneClient client required", req.URL.Path)
		}
		return nil
	}), cpclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	return client
}

type TestUser struct {
	ProviderId  string `json:"ProviderId,omitempty"`
	DisplayName string `json:"DisplayName,omitempty"`
	Email       string `json:"PrimaryEmailAddress,omitempty"`
}

func MustGenerateTestUserTokenWith(t *testing.T, tu TestUser) string {
	t.Helper()
	ageRecipient, err := age.ParseX25519Recipient(os.Getenv("TEST_USER_IDENTITY_RECIPIENT"))
	require.NoError(t, err)
	buff := new(bytes.Buffer)
	bw := base64.NewEncoder(base64.StdEncoding, buff)
	aw, _ := age.Encrypt(bw, ageRecipient)
	_ = json.NewEncoder(aw).Encode(tu)
	_ = aw.Close()
	_ = bw.Close()
	return buff.String()
}

func MustGenerateTestUserToken(t *testing.T) string {
	t.Helper()
	return MustGenerateTestUserTokenWith(t, TestUser{
		ProviderId:  rand.Text(),
		DisplayName: "bob.smith",
		Email:       "bob.smith@example.com",
	})
}

func MustRegisterTestUser(client serverclient.ClientWithResponsesInterface, t *testing.T) serverclient.RegisteredUser {
	r, err := client.RegisterUserWithResponse(context.Background(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
		Provider:      "testuser",
		ProviderToken: MustGenerateTestUserToken(t),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	return *r.JSON202
}

func MustCreateTestOrg(client cpclient.ClientWithResponsesInterface, t *testing.T) cpclient.InternalOrganization {
	orgId := "test-" + uuid.New().String()
	r, err := client.CreateInternalOrganizationWithResponse(context.Background(), cpclient.CreateInternalOrganizationJSONRequestBody{
		Id: ptr(orgId),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	return *r.JSON201
}

func MustCreateProject(t *testing.T, cpClient cpclient.ClientWithResponsesInterface, orgId string, projectId string) *cpclient.Project {
	t.Helper()
	res, err := cpClient.CreateProjectWithResponse(t.Context(), orgId, cpclient.CreateProjectJSONRequestBody{Id: projectId})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, res.StatusCode(), "failed to create project: %s", string(res.Body))
	return res.JSON201
}

func MustCreateEnv(t *testing.T, cpClient cpclient.ClientWithResponsesInterface, orgId string, projectId string, envId string) *cpclient.Environment {
	t.Helper()
	{
		res, err := cpClient.CreateEnvironmentTypeWithResponse(t.Context(), orgId, cpclient.EnvironmentTypeCreateBody{Id: "development"})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, res.StatusCode(), "failed to create environment type: %s", string(res.Body))
	}
	res, err := cpClient.CreateEnvironmentWithResponse(t.Context(), orgId, projectId, cpclient.CreateEnvironmentJSONRequestBody{Id: envId, EnvTypeId: "development"})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, res.StatusCode())
	return res.JSON201
}

func MustObtainRoleIdByName(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId, roleName string) uuid.UUID {
	t.Helper()
	r, err := client.ListRolesWithResponse(t.Context(), orgId, &serverclient.ListRolesParams{}, WithInternalUserId)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	for _, role := range r.JSON200.Items {
		if role.DisplayName == roleName {
			return role.Id
		}
	}
	t.Fatalf("role with name %s not found in org %s", roleName, orgId)
	return uuid.Nil
}

func MustAddUserToOrgWithRoleAndEnsurePermissions(client serverclient.ClientWithResponsesInterface, t *testing.T, orgId string, userId, roleId uuid.UUID) serverclient.OrgMembership {
	r, err := client.InternalCreateOrgMembershipWithResponse(context.Background(), orgId, serverclient.InternalCreateOrgMembershipJSONRequestBody{
		UserId:      userId,
		SubjectType: serverclient.SubjectTypeRole,
		Subject:     roleId.String(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))

	// The policy is read directly from PostgreSQL, so this should be visible immediately.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{authz.CanReadOrgCheck(orgId)}, WithAuthenticatedUserId(userId))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), "unexpected status %d %s", resp.StatusCode(), string(resp.Body))
		require.Equal(collect, []serverclient.ResourcePermissionCheckResultItem{{
			Allowed:         true,
			PermissionCheck: authz.CanReadOrgCheck(orgId),
		}}, resp.JSON200.Items)
	}, time.Second*30, time.Second*3, "user did not get proper permissions in time")

	return *r.JSON201
}

func WithInternalUserId(ctx context.Context, req *http.Request) error {
	req.Header.Set("From", "ffffffff-ffff-ffff-ffff-ffffffffffff")
	return nil
}

func WithAuthenticatedUserId(u uuid.UUID) func(ctx context.Context, req *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("From", u.String())
		return nil
	}
}

func MustDatabase(t *testing.T) model.Databaser {
	t.Helper()
	connStr := os.Getenv("DATABASE_URL")

	logger, _ := zap.NewDevelopment()
	db, err := model.NewDatabaser(context.Background(), logger, connStr)
	require.NoError(t, err)
	return db
}

func ptr(s string) *string { return &s }
