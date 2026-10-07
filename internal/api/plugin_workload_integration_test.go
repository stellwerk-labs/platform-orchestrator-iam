//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/config"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/plugincapabilities"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity/workloadidentitytest"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	workloadOrg            = "workload-org"
	workloadPluginID       = "dev.stellwerk.progressive-rollouts"
	workloadNamespace      = "stellwerk-plugins"
	workloadServiceAccount = "progressive-rollouts-runtime"
	workloadAudience       = "stellwerk-iam-plugin-workload"
)

type workloadFixture struct {
	ctx      context.Context
	raw      *sql.DB
	server   *Server
	issuer   *workloadidentitytest.Issuer
	plugin   uuid.UUID
	operator uuid.UUID
	other    uuid.UUID
	// pluginStaticToken is the plugin service user's static token before binding.
	pluginStaticToken string
}

// newWorkloadFixture builds a real store, Casbin authorizer and issuer. The
// plugin and operator service users both hold plugin_registration_write in
// the organization; only the operator holds the platform binding permission.
func newWorkloadFixture(t *testing.T) *workloadFixture {
	t.Helper()
	connection := os.Getenv("DATABASE_URL")
	require.NotEmpty(t, connection, "DATABASE_URL must name an isolated local PostgreSQL test database")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	admin, err := sql.Open("postgres", connection)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := "plugin_workload_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	fixture := &workloadFixture{
		ctx: ctx, raw: raw, issuer: workloadidentitytest.NewIssuer(t),
		plugin: userid.NewServiceUserTokenId(), operator: userid.NewServiceUserTokenId(), other: userid.NewServiceUserTokenId(),
	}
	_, err = raw.ExecContext(ctx, `INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id)
		VALUES ('organization:' || $1, 'organization', $1, $1)`, workloadOrg)
	require.NoError(t, err)
	roleID := uuid.New()
	_, err = raw.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($1, $2, 'Plugin registration', now(), ARRAY[$3])`, roleID, workloadOrg, sharedauthz.PermissionPluginRegistrationWrite)
	require.NoError(t, err)
	now := time.Now().UTC()
	for _, serviceUser := range []uuid.UUID{fixture.plugin, fixture.operator, fixture.other} {
		raw33 := make([]byte, ServiceUserTokenEntropyBytes)
		_, err := rand.Read(raw33)
		require.NoError(t, err)
		hash := sha256.Sum256(raw33)
		if serviceUser == fixture.plugin {
			fixture.pluginStaticToken = EncodeServiceUserToken(raw33)
		}
		_, err = raw.ExecContext(ctx, `INSERT INTO service_user_tokens
			(id, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash)
			VALUES ($1, $2, 'Workload fixture', $3, $4, $5, $6)`,
			serviceUser, workloadOrg, now.Add(-2*time.Hour), userid.InternalSystemUuid, now.Add(30*24*time.Hour), hash[:])
		require.NoError(t, err)
		_, err = raw.ExecContext(ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
			VALUES ($1, $2, $3, now())`, serviceUser, workloadOrg, roleID)
		require.NoError(t, err)
	}

	authorizer, err := authorization.New(ctx, store)
	require.NoError(t, err)
	t.Cleanup(authorizer.Close)
	keys := workloadidentity.NewKeySet(workloadidentity.HTTPKeySource(fixture.issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), time.Now)
	fixture.server = &Server{
		Database: store, Authorizer: authorizer, Logger: zaptest.NewLogger(t), TokenByHashCache: NewGetTokenByHashCache(store),
		PluginCapabilities: &plugincapabilities.Registry{Database: store, Reloader: authorizer},
		PluginWorkloadExchange: &PluginWorkloadExchange{
			Issuer: fixture.issuer.URL, Verifier: workloadidentity.NewVerifier(fixture.issuer.URL, keys, time.Now), TokenTTL: workloadidentity.MaxTokenLifetime,
		},
		PlatformPermissionHolders: map[string][]uuid.UUID{sharedauthz.PermissionPluginWorkloadBindingWrite: {fixture.operator}},
	}
	return fixture
}

func (f *workloadFixture) as(principal uuid.UUID) context.Context {
	return context.WithValue(f.ctx, hecho.ContextKeyUserID, principal.String())
}

func (f *workloadFixture) bindingBody() *PluginWorkloadBindingCreateBody {
	return &PluginWorkloadBindingCreateBody{
		Issuer: f.issuer.URL, Namespace: workloadNamespace, ServiceAccount: workloadServiceAccount, Audience: workloadAudience,
		ServiceUserId: f.plugin, PluginId: workloadPluginID, InstallationId: uuid.New(),
	}
}

func (f *workloadFixture) createBinding(t *testing.T, body *PluginWorkloadBindingCreateBody) CreatePluginWorkloadBindingResponseObject {
	t.Helper()
	response, err := f.server.CreatePluginWorkloadBinding(f.as(f.operator), CreatePluginWorkloadBindingRequestObject{Body: body})
	require.NoError(t, err)
	return response
}

// authenticate uses a fresh cache, so the result reflects the database and
// not an entry the existing 60 second cache may still hold.
func (f *workloadFixture) authenticate(t *testing.T, token string) (uuid.UUID, bool) {
	t.Helper()
	f.server.TokenByHashCache = NewGetTokenByHashCache(f.server.Database)
	bearer := "Bearer " + token
	response, err := f.server.InternalAuthenticate(f.ctx, InternalAuthenticateRequestObject{Params: InternalAuthenticateParams{Authorization: &bearer}})
	require.NoError(t, err)
	if success, ok := response.(InternalAuthenticate200Response); ok {
		return success.Headers.From, true
	}
	require.IsType(t, InternalAuthenticate401JSONResponse{}, response)
	return uuid.Nil, false
}

func (f *workloadFixture) exchange(t *testing.T, claims workloadidentitytest.Claims) ExchangePluginWorkloadTokenResponseObject {
	t.Helper()
	response, err := f.server.ExchangePluginWorkloadToken(f.ctx, ExchangePluginWorkloadTokenRequestObject{Body: &PluginWorkloadTokenExchangeRequest{
		GrantType:        PluginWorkloadTokenExchangeGrantType,
		SubjectToken:     f.issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims),
		SubjectTokenType: PluginWorkloadSubjectTokenTypeJWT,
	}})
	require.NoError(t, err)
	return response
}

func (f *workloadFixture) validClaims() workloadidentitytest.Claims {
	return f.issuer.ValidClaims(time.Now(), workloadNamespace, workloadServiceAccount, workloadAudience)
}

func (f *workloadFixture) exchangeToken(t *testing.T) string {
	t.Helper()
	response := f.exchange(t, f.validClaims())
	issued, ok := response.(ExchangePluginWorkloadToken200JSONResponse)
	require.True(t, ok, "exchange failed: %#v", response)
	return issued.Body.AccessToken
}

func (f *workloadFixture) regenerate(t *testing.T) RegenerateServiceUserResponseObject {
	t.Helper()
	response, err := f.server.RegenerateServiceUser(f.as(userid.InternalSystemUuid), RegenerateServiceUserRequestObject{
		OrgId: workloadOrg, ServiceUserId: f.plugin, Body: &ServiceUserRegenerateBody{ExpiryInDays: 30},
	})
	require.NoError(t, err)
	return response
}

func (f *workloadFixture) registerCapabilities(t *testing.T, principal uuid.UUID, pluginID string) ReplacePluginCapabilitiesResponseObject {
	t.Helper()
	response, err := f.server.ReplacePluginCapabilities(f.as(principal), ReplacePluginCapabilitiesRequestObject{
		OrgId: workloadOrg, PluginId: pluginID, Body: &PluginCapabilityRegistrationBody{Capabilities: []PluginCapabilityRegistration{{
			Name: "rollout-read", DisplayName: "Read rollouts", Description: "Read rollout state.", Category: "Rollouts",
			Level: PluginCapabilityRegistrationLevelRead, Scopes: []PluginCapabilityRegistrationScopes{PluginCapabilityRegistrationScopesOrganization},
		}}},
	})
	require.NoError(t, err)
	return response
}

func TestPluginWorkloadBindingIsPlatformOperatorOnlyAndUnique(t *testing.T) {
	f := newWorkloadFixture(t)

	_, err := f.server.CreatePluginWorkloadBinding(f.as(f.other), CreatePluginWorkloadBindingRequestObject{Body: f.bindingBody()})
	require.Error(t, err, "an organization service user without the platform permission must be refused")

	foreignIssuer := f.bindingBody()
	foreignIssuer.Issuer = "https://other-cluster.example.test"
	require.IsType(t, CreatePluginWorkloadBinding400JSONResponse{}, f.createBinding(t, foreignIssuer))

	created, ok := f.createBinding(t, f.bindingBody()).(CreatePluginWorkloadBinding201JSONResponse)
	require.True(t, ok)
	require.Equal(t, f.operator, created.CreatedBy)
	require.Equal(t, f.plugin, created.ServiceUserId)

	sameServiceAccount := f.bindingBody()
	sameServiceAccount.ServiceUserId = f.other
	require.IsType(t, CreatePluginWorkloadBinding409JSONResponse{}, f.createBinding(t, sameServiceAccount))
	sameServiceUser := f.bindingBody()
	sameServiceUser.ServiceAccount = "another-runtime"
	require.IsType(t, CreatePluginWorkloadBinding409JSONResponse{}, f.createBinding(t, sameServiceUser))
	unknownServiceUser := f.bindingBody()
	unknownServiceUser.ServiceUserId = userid.NewServiceUserTokenId()
	unknownServiceUser.ServiceAccount = "unknown-runtime"
	require.IsType(t, CreatePluginWorkloadBinding400JSONResponse{}, f.createBinding(t, unknownServiceUser))

	listed, err := f.server.ListPluginWorkloadBindings(f.as(f.operator), ListPluginWorkloadBindingsRequestObject{})
	require.NoError(t, err)
	require.Len(t, listed.(ListPluginWorkloadBindings200JSONResponse).Items, 1)

	// The bound plugin principal never gains platform authority, even when listed as a holder.
	f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginWorkloadBindingWrite] = []uuid.UUID{f.operator, f.plugin}
	_, err = f.server.ListPluginWorkloadBindings(f.as(f.plugin), ListPluginWorkloadBindingsRequestObject{})
	require.Error(t, err)
}

func TestPluginWorkloadExchangeAuthenticatesTheBoundServiceUserUntilRevocation(t *testing.T) {
	f := newWorkloadFixture(t)
	subject, ok := f.authenticate(t, f.pluginStaticToken)
	require.True(t, ok)
	require.Equal(t, f.plugin, subject)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()), "no binding yet")

	created := f.createBinding(t, f.bindingBody()).(CreatePluginWorkloadBinding201JSONResponse)

	// Production mode: the bound service user holds no static token any more.
	_, ok = f.authenticate(t, f.pluginStaticToken)
	require.False(t, ok, "the static token of a workload-bound service user must not authenticate")
	require.IsType(t, RegenerateServiceUser409JSONResponse{}, f.regenerate(t))

	response := f.exchange(t, f.validClaims())
	issued, ok := response.(ExchangePluginWorkloadToken200JSONResponse)
	require.True(t, ok, "exchange failed: %#v", response)
	require.True(t, strings.HasPrefix(issued.Body.AccessToken, workloadidentity.TokenPrefix))
	require.Equal(t, "no-store", issued.Headers.CacheControl)
	require.Equal(t, PluginWorkloadTokenTypeBearer, issued.Body.TokenType)
	require.Equal(t, PluginWorkloadIssuedTokenTypeAccessToken, issued.Body.IssuedTokenType)
	require.LessOrEqual(t, issued.Body.ExpiresIn, 600, "an exchanged token never outlives its ten minute subject token")
	subject, ok = f.authenticate(t, issued.Body.AccessToken)
	require.True(t, ok)
	require.Equal(t, f.plugin, subject)

	wrongAudience := f.validClaims()
	wrongAudience.Audience = []string{"https://kubernetes.default.svc"}
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, wrongAudience))
	extraAudience := f.validClaims()
	extraAudience.Audience = append(extraAudience.Audience, "https://kubernetes.default.svc")
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, extraAudience))
	unbound := f.issuer.ValidClaims(time.Now(), workloadNamespace, "other-runtime", workloadAudience)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, unbound))

	// Expired workload tokens stop authenticating and are cleaned up.
	expiring := f.exchangeToken(t)
	hash, ok := workloadidentity.HashToken(expiring)
	require.True(t, ok)
	_, err := f.raw.ExecContext(f.ctx, `UPDATE plugin_workload_tokens
		SET issued_at = now() - interval '20 minutes', expires_at = now() - interval '10 minutes'
		WHERE token_sha256_hash = $1`, hash)
	require.NoError(t, err)
	_, ok = f.authenticate(t, expiring)
	require.False(t, ok)
	deleted, err := f.server.Database.DeleteExpiredPluginWorkloadTokens(f.ctx, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	// Disabling the service user denies the next authentication and new exchanges.
	beforeDisable := f.exchangeToken(t)
	_, err = f.raw.ExecContext(f.ctx, `UPDATE service_user_tokens SET current_token_expires_at = $2 WHERE id = $1`,
		f.plugin, time.Now().UTC().Add(-time.Minute))
	require.NoError(t, err)
	_, ok = f.authenticate(t, beforeDisable)
	require.False(t, ok)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()))
	_, err = f.raw.ExecContext(f.ctx, `UPDATE service_user_tokens SET current_token_expires_at = $2 WHERE id = $1`,
		f.plugin, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)

	// Revoking the binding denies the next authentication without waiting for a cache.
	beforeRevocation := f.exchangeToken(t)
	f.server.TokenByHashCache = NewGetTokenByHashCache(f.server.Database)
	bearer := "Bearer " + beforeRevocation
	warmed, err := f.server.InternalAuthenticate(f.ctx, InternalAuthenticateRequestObject{Params: InternalAuthenticateParams{Authorization: &bearer}})
	require.NoError(t, err)
	require.IsType(t, InternalAuthenticate200Response{}, warmed)
	revoked, err := f.server.DeletePluginWorkloadBinding(f.as(f.operator), DeletePluginWorkloadBindingRequestObject{BindingId: created.Id})
	require.NoError(t, err)
	require.IsType(t, DeletePluginWorkloadBinding204Response{}, revoked)
	afterRevocation, err := f.server.InternalAuthenticate(f.ctx, InternalAuthenticateRequestObject{Params: InternalAuthenticateParams{Authorization: &bearer}})
	require.NoError(t, err)
	require.IsType(t, InternalAuthenticate401JSONResponse{}, afterRevocation, "the same cache must not keep a revoked workload token alive")
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()))

	// The disabled static token stays dead after revocation; a new one can be issued again.
	_, ok = f.authenticate(t, f.pluginStaticToken)
	require.False(t, ok)
	require.IsType(t, RegenerateServiceUser200JSONResponse{}, f.regenerate(t))
}

func TestPluginWorkloadRegistersCapabilitiesOnlyForItsOwnPlugin(t *testing.T) {
	f := newWorkloadFixture(t)
	require.IsType(t, CreatePluginWorkloadBinding201JSONResponse{}, f.createBinding(t, f.bindingBody()))

	require.IsType(t, ReplacePluginCapabilities204Response{}, f.registerCapabilities(t, f.plugin, workloadPluginID))
	require.IsType(t, ReplacePluginCapabilities403JSONResponse{}, f.registerCapabilities(t, f.plugin, "dev.stellwerk.other-plugin"))
	require.IsType(t, ReplacePluginCapabilities403JSONResponse{}, f.registerCapabilities(t, f.plugin, workloadPluginID+".nested"))
	require.IsType(t, ReplacePluginCapabilities204Response{}, f.registerCapabilities(t, f.operator, "dev.stellwerk.other-plugin"),
		"an unbound operator principal keeps authority over every plugin")
}

func TestTransitionalStaticTokenAdapterKeepsStaticTokensOfBoundServiceUsers(t *testing.T) {
	f := newWorkloadFixture(t)
	f.server.PluginWorkloadStaticTokens = true
	require.IsType(t, CreatePluginWorkloadBinding201JSONResponse{}, f.createBinding(t, f.bindingBody()))

	subject, ok := f.authenticate(t, f.pluginStaticToken)
	require.True(t, ok)
	require.Equal(t, f.plugin, subject)
	subject, ok = f.authenticate(t, f.exchangeToken(t))
	require.True(t, ok)
	require.Equal(t, f.plugin, subject)

	// Switching the adapter off rejects the retained static token as well.
	f.server.PluginWorkloadStaticTokens = false
	_, ok = f.authenticate(t, f.pluginStaticToken)
	require.False(t, ok)
	require.IsType(t, RegenerateServiceUser409JSONResponse{}, f.regenerate(t))
}

func (f *workloadFixture) authorize(t *testing.T, subject uuid.UUID, checks ...ResourcePermissionCheck) []ResourcePermissionCheck {
	t.Helper()
	response, err := f.server.InternalAuthorize(f.ctx, InternalAuthorizeRequestObject{Body: &InternalAuthorizeBody{UserId: subject, Checks: checks}})
	require.NoError(t, err)
	if _, allowed := response.(InternalAuthorize204Response); allowed {
		return nil
	}
	denied, ok := response.(InternalAuthorize403JSONResponse)
	require.True(t, ok, "unexpected authorize response %#v", response)
	return (*denied.Details)[failedChecksField].([]ResourcePermissionCheck)
}

func TestPlatformAuthorizeGrantsPluginManagerPermissionsOnlyToConfiguredUsers(t *testing.T) {
	f := newWorkloadFixture(t)
	reader, writer, outsider := userid.NewHumanUserId(), userid.NewHumanUserId(), userid.NewHumanUserId()
	_, err := f.raw.ExecContext(f.ctx, `INSERT INTO users (id, display_name, created_at)
		VALUES ($1, 'Reader', now()), ($2, 'Writer', now()), ($3, 'Outsider', now())`, reader, writer, outsider)
	require.NoError(t, err)
	holders, err := (&config.Configuration{
		PluginWorkloadBindingWriters: []string{f.operator.String()},
		PluginManagerReaders:         []string{reader.String()},
		PluginManagerWriters:         []string{writer.String()},
	}).PlatformPermissionHolders()
	require.NoError(t, err)
	f.server.PlatformPermissionHolders = holders
	read := ResourcePermissionCheck{Resource: sharedauthz.PlatformResource, Permission: sharedauthz.PermissionPluginManagerRead}
	write := ResourcePermissionCheck{Resource: sharedauthz.PlatformResource, Permission: sharedauthz.PermissionPluginManagerWrite}

	require.Empty(t, f.authorize(t, reader, read))
	require.Equal(t, []ResourcePermissionCheck{write}, f.authorize(t, reader, read, write), "a reader never writes")
	require.Empty(t, f.authorize(t, writer, read, write), "writers also read")
	require.Equal(t, []ResourcePermissionCheck{read, write}, f.authorize(t, outsider, read, write))
	require.Equal(t, []ResourcePermissionCheck{read}, f.authorize(t, userid.InternalSystemUuid, read), "the internal system identity holds no platform permission here")
	require.Equal(t, []ResourcePermissionCheck{{Resource: sharedauthz.PlatformResource, Permission: sharedauthz.PermissionPluginWorkloadBindingWrite}},
		f.authorize(t, writer, ResourcePermissionCheck{Resource: sharedauthz.PlatformResource, Permission: sharedauthz.PermissionPluginWorkloadBindingWrite}),
		"each platform permission has its own holders")
	require.Equal(t, []ResourcePermissionCheck{{Resource: sharedauthz.PlatformResource, Permission: "plugin_manager_admin"}},
		f.authorize(t, writer, ResourcePermissionCheck{Resource: sharedauthz.PlatformResource, Permission: "plugin_manager_admin"}))

	// Organization roles never grant a platform permission, and a platform
	// holder gains nothing in an organization; both checks are decided in one call.
	orgCheck := ResourcePermissionCheck{Resource: "organization:" + workloadOrg, Permission: sharedauthz.PermissionPluginRegistrationWrite}
	require.Equal(t, []ResourcePermissionCheck{read}, f.authorize(t, f.operator, orgCheck, read))
	require.Equal(t, []ResourcePermissionCheck{orgCheck}, f.authorize(t, writer, orgCheck, read))

	// A plugin workload never holds a platform permission, even when listed.
	f.createBinding(t, f.bindingBody())
	f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginManagerRead] = append(f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginManagerRead], f.plugin)
	require.Equal(t, []ResourcePermissionCheck{read}, f.authorize(t, f.plugin, read))

	// A subject can ask for its own platform permissions.
	body := []ResourcePermissionCheck{write, orgCheck, read}
	checked, err := f.server.CheckPermissions(f.as(reader), CheckPermissionsRequestObject{Body: &body})
	require.NoError(t, err)
	require.Equal(t, CheckPermissions200JSONResponse{Items: []ResourcePermissionCheckResultItem{
		{PermissionCheck: write, Allowed: false}, {PermissionCheck: orgCheck, Allowed: false}, {PermissionCheck: read, Allowed: true},
	}}, checked)
}
