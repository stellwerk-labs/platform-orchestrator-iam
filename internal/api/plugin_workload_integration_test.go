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
	"github.com/lib/pq"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/herrors"
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
	legacyServiceAccount   = "legacy-runtime"
	workloadAudience       = "stellwerk-iam-plugin-workload"
)

type workloadFixture struct {
	ctx        context.Context
	raw        *sql.DB
	server     *Server
	authorizer *authorization.CasbinAuthorizer
	issuer     *workloadidentitytest.Issuer
	// operator and other are organization service users holding
	// plugin_registration_write; only the operator holds the platform binding
	// permission.
	operator uuid.UUID
	other    uuid.UUID
	// legacy is a role-less organization service user. Bindings of such users
	// predate platform principals; tests store them through the model because
	// the API now refuses to create them.
	legacy            uuid.UUID
	legacyStaticToken string
	// admin is a human holding the Admin role of workloadOrg.
	admin  uuid.UUID
	roleID uuid.UUID
}

// newWorkloadFixture builds a real store, Casbin authorizer and issuer.
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
		operator: userid.NewServiceUserTokenId(), other: userid.NewServiceUserTokenId(), legacy: userid.NewServiceUserTokenId(),
		admin: userid.NewHumanUserId(), roleID: uuid.New(),
	}
	_, err = raw.ExecContext(ctx, `INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id)
		VALUES ('organization:' || $1, 'organization', $1, $1)`, workloadOrg)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($1, $2, 'Plugin registration', now(), ARRAY[$3])`, fixture.roleID, workloadOrg, sharedauthz.PermissionPluginRegistrationWrite)
	require.NoError(t, err)
	adminRole := uuid.New()
	_, err = raw.ExecContext(ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($1, $2, $3, now(), ARRAY[$4])`, adminRole, workloadOrg, RoleAdmin, PermissionsManageAll)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO users (id, display_name, created_at) VALUES ($1, 'Organization admin', now())`, fixture.admin)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role)
		VALUES ($1, now(), $2, $3, 'role', $4::text, $4::uuid)`, uuid.New(), fixture.admin, workloadOrg, adminRole)
	require.NoError(t, err)
	now := time.Now().UTC()
	for _, serviceUser := range []uuid.UUID{fixture.operator, fixture.other, fixture.legacy} {
		raw33 := make([]byte, ServiceUserTokenEntropyBytes)
		_, err := rand.Read(raw33)
		require.NoError(t, err)
		hash := sha256.Sum256(raw33)
		if serviceUser == fixture.legacy {
			fixture.legacyStaticToken = EncodeServiceUserToken(raw33)
		}
		_, err = raw.ExecContext(ctx, `INSERT INTO service_user_tokens
			(id, org_id, display_name, generated_at, generated_by, current_token_expires_at, current_token_sha256_hash)
			VALUES ($1, $2, 'Workload fixture', $3, $4, $5, $6)`,
			serviceUser, workloadOrg, now.Add(-2*time.Hour), userid.InternalSystemUuid, now.Add(30*24*time.Hour), hash[:])
		require.NoError(t, err)
		if serviceUser != fixture.legacy {
			_, err = raw.ExecContext(ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
				VALUES ($1, $2, $3, now())`, serviceUser, workloadOrg, fixture.roleID)
			require.NoError(t, err)
		}
	}

	fixture.authorizer, err = authorization.New(ctx, store)
	require.NoError(t, err)
	t.Cleanup(fixture.authorizer.Close)
	keys := workloadidentity.NewKeySet(workloadidentity.HTTPKeySource(fixture.issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), time.Now)
	fixture.server = &Server{
		Database: store, Authorizer: fixture.authorizer, Logger: zaptest.NewLogger(t), TokenByHashCache: NewGetTokenByHashCache(store),
		PluginCapabilities: &plugincapabilities.Registry{Database: store, Reloader: fixture.authorizer},
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

// bindingBody creates a new platform principal for the plugin workload.
func (f *workloadFixture) bindingBody() *PluginWorkloadBindingCreateBody {
	return &PluginWorkloadBindingCreateBody{
		Issuer: f.issuer.URL, Namespace: workloadNamespace, ServiceAccount: workloadServiceAccount, Audience: workloadAudience,
		PlatformPrincipal: &PluginWorkloadPrincipalCreateBody{DisplayName: "progressive-rollouts"}, PluginId: workloadPluginID, InstallationId: uuid.New(),
	}
}

// rebindingBody names an existing platform principal instead of creating one.
func (f *workloadFixture) rebindingBody(principal uuid.UUID) *PluginWorkloadBindingCreateBody {
	body := f.bindingBody()
	body.PlatformPrincipal, body.ServiceUserId = nil, &principal
	return body
}

func (f *workloadFixture) createBinding(t *testing.T, body *PluginWorkloadBindingCreateBody) CreatePluginWorkloadBindingResponseObject {
	t.Helper()
	response, err := f.server.CreatePluginWorkloadBinding(f.as(f.operator), CreatePluginWorkloadBindingRequestObject{Body: body})
	require.NoError(t, err)
	return response
}

func (f *workloadFixture) bind(t *testing.T, body *PluginWorkloadBindingCreateBody) PluginWorkloadBinding {
	t.Helper()
	created, ok := f.createBinding(t, body).(CreatePluginWorkloadBinding201JSONResponse)
	require.True(t, ok, "binding refused")
	return PluginWorkloadBinding(created)
}

// bindLegacy stores a binding of an organization service user as IAM created
// them before platform principals existed.
func (f *workloadFixture) bindLegacy(t *testing.T, serviceUser uuid.UUID) *model.PluginWorkloadBinding {
	t.Helper()
	binding, err := f.server.Database.CreatePluginWorkloadBinding(f.ctx, nil, model.PluginWorkloadBinding{
		ID: uuid.Must(uuid.NewV7()), Issuer: f.issuer.URL, Namespace: workloadNamespace, ServiceAccount: legacyServiceAccount,
		Audience: workloadAudience, ServiceUserID: serviceUser, PluginID: workloadPluginID, InstallationID: uuid.New(),
		CreatedAt: time.Now().UTC(), CreatedBy: f.operator,
	})
	require.NoError(t, err)
	require.Equal(t, model.ServiceUserScopeOrganization, binding.ServiceUserScope)
	return binding
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
	return f.claimsFor(workloadServiceAccount)
}

func (f *workloadFixture) claimsFor(serviceAccount string) workloadidentitytest.Claims {
	return f.issuer.ValidClaims(time.Now(), workloadNamespace, serviceAccount, workloadAudience)
}

func (f *workloadFixture) exchangeToken(t *testing.T) string {
	t.Helper()
	return f.exchangeTokenFor(t, workloadServiceAccount)
}

func (f *workloadFixture) exchangeTokenFor(t *testing.T, serviceAccount string) string {
	t.Helper()
	response := f.exchange(t, f.claimsFor(serviceAccount))
	issued, ok := response.(ExchangePluginWorkloadToken200JSONResponse)
	require.True(t, ok, "exchange failed: %#v", response)
	return issued.Body.AccessToken
}

// regenerate regenerates a service user through the organization route.
func (f *workloadFixture) regenerate(t *testing.T, serviceUser uuid.UUID) RegenerateServiceUserResponseObject {
	t.Helper()
	response, err := f.server.RegenerateServiceUser(f.as(userid.InternalSystemUuid), RegenerateServiceUserRequestObject{
		OrgId: workloadOrg, ServiceUserId: serviceUser, Body: &ServiceUserRegenerateBody{ExpiryInDays: 30},
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

func requireForbidden(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	var forbidden *herrors.PlatformOrchestratorError
	require.ErrorAs(t, err, &forbidden, msgAndArgs...)
	require.Equal(t, http.StatusForbidden, forbidden.StatusCode, msgAndArgs...)
}

func (f *workloadFixture) active(t *testing.T, principal uuid.UUID) bool {
	t.Helper()
	active, err := f.server.Database.IsAuthorizationSubjectActive(f.ctx, nil, principal)
	require.NoError(t, err)
	return active
}

func (f *workloadFixture) platformPrincipalCount(t *testing.T) int {
	t.Helper()
	var count int
	require.NoError(t, f.raw.QueryRowContext(f.ctx, `SELECT count(*) FROM service_user_tokens WHERE scope = 'platform'`).Scan(&count))
	return count
}

func TestPluginWorkloadBindingIsPlatformOperatorOnlyAndUnique(t *testing.T) {
	f := newWorkloadFixture(t)

	_, err := f.server.CreatePluginWorkloadBinding(f.as(f.other), CreatePluginWorkloadBindingRequestObject{Body: f.bindingBody()})
	requireForbidden(t, err, "an organization service user without the platform permission must be refused")
	_, err = f.server.CreatePluginWorkloadBinding(f.as(f.admin), CreatePluginWorkloadBindingRequestObject{Body: f.bindingBody()})
	requireForbidden(t, err, "an organization admin holds no platform permission")

	foreignIssuer := f.bindingBody()
	foreignIssuer.Issuer = "https://other-cluster.example.test"
	require.IsType(t, CreatePluginWorkloadBinding400JSONResponse{}, f.createBinding(t, foreignIssuer))
	both := f.bindingBody()
	both.ServiceUserId = &f.legacy
	require.Equal(t, CreatePluginWorkloadBinding400JSONResponse{Generate400Response("exactly one of platform_principal and service_user_id is required")}, f.createBinding(t, both))
	neither := f.bindingBody()
	neither.PlatformPrincipal = nil
	require.IsType(t, CreatePluginWorkloadBinding400JSONResponse{}, f.createBinding(t, neither))
	require.Zero(t, f.platformPrincipalCount(t), "a refused request creates no principal")

	created := f.bind(t, f.bindingBody())
	require.Equal(t, f.operator, created.CreatedBy)
	require.Equal(t, ServiceUserScopePlatform, created.ServiceUserScope)
	require.True(t, userid.IsServiceUser(created.ServiceUserId), "a platform principal keeps the service user identity variant")
	principal, err := f.server.Database.GetPlatformPrincipal(f.ctx, nil, created.ServiceUserId)
	require.NoError(t, err)
	require.Equal(t, "progressive-rollouts", principal.DisplayName)
	require.Equal(t, f.operator, principal.GeneratedBy)
	require.False(t, principal.HoldsStaticToken(), "a plugin workload principal has no static token")
	require.Equal(t, created.Id, *principal.WorkloadBindingID)

	sameServiceAccount := f.bindingBody()
	require.IsType(t, CreatePluginWorkloadBinding409JSONResponse{}, f.createBinding(t, sameServiceAccount))
	samePrincipal := f.rebindingBody(created.ServiceUserId)
	samePrincipal.ServiceAccount = "another-runtime"
	require.IsType(t, CreatePluginWorkloadBinding409JSONResponse{}, f.createBinding(t, samePrincipal))
	require.Equal(t, 1, f.platformPrincipalCount(t), "a refused binding rolls its new principal back")

	unknown := f.rebindingBody(userid.NewServiceUserTokenId())
	unknown.ServiceAccount = "unknown-runtime"
	require.IsType(t, CreatePluginWorkloadBinding400JSONResponse{}, f.createBinding(t, unknown))
	// An organization service user is no plugin identity any more, with or
	// without roles.
	for _, serviceUser := range []uuid.UUID{f.legacy, f.other} {
		organizationUser := f.rebindingBody(serviceUser)
		organizationUser.ServiceAccount = "organization-runtime"
		require.Equal(t, CreatePluginWorkloadBinding400JSONResponse{Generate400Response("service_user_id must name a platform principal; create one with platform_principal")},
			f.createBinding(t, organizationUser))
	}

	listed, err := f.server.ListPluginWorkloadBindings(f.as(f.operator), ListPluginWorkloadBindingsRequestObject{})
	require.NoError(t, err)
	require.Equal(t, []PluginWorkloadBinding{created}, listed.(ListPluginWorkloadBindings200JSONResponse).Items)

	// The bound plugin principal never gains platform authority, even when listed as a holder.
	f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginWorkloadBindingWrite] = []uuid.UUID{f.operator, created.ServiceUserId}
	_, err = f.server.ListPluginWorkloadBindings(f.as(created.ServiceUserId), ListPluginWorkloadBindingsRequestObject{})
	requireForbidden(t, err)
}

func TestPluginWorkloadExchangeAuthenticatesTheBoundServiceUserUntilRevocation(t *testing.T) {
	f := newWorkloadFixture(t)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()), "no binding yet")

	created := f.bind(t, f.bindingBody())
	principal := created.ServiceUserId
	require.True(t, f.active(t, principal), "a plugin workload principal is active while it exists")
	require.IsType(t, RegenerateServiceUser404JSONResponse{}, f.regenerate(t, principal), "no organization route issues it a static token")

	response := f.exchange(t, f.validClaims())
	issued, ok := response.(ExchangePluginWorkloadToken200JSONResponse)
	require.True(t, ok, "exchange failed: %#v", response)
	require.True(t, strings.HasPrefix(issued.Body.AccessToken, workloadidentity.TokenPrefix))
	require.Equal(t, "no-store", issued.Headers.CacheControl)
	require.Equal(t, PluginWorkloadTokenTypeBearer, issued.Body.TokenType)
	require.Equal(t, PluginWorkloadIssuedTokenTypeAccessToken, issued.Body.IssuedTokenType)
	require.LessOrEqual(t, issued.Body.ExpiresIn, 600, "an exchanged token never outlives its ten minute subject token")
	subject, ok := f.authenticate(t, issued.Body.AccessToken)
	require.True(t, ok)
	require.Equal(t, principal, subject)

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

	// The principal outlives its binding without any credential; binding it
	// again restores the same identity, so Core's installation record stays valid.
	unboundPrincipal, err := f.server.Database.GetPlatformPrincipal(f.ctx, nil, principal)
	require.NoError(t, err)
	require.Nil(t, unboundPrincipal.WorkloadBindingID)
	_, ok = f.authenticate(t, beforeRevocation)
	require.False(t, ok, "a new binding never revives tokens of the revoked one")
	rebound := f.bind(t, f.rebindingBody(principal))
	require.Equal(t, principal, rebound.ServiceUserId)
	require.Equal(t, ServiceUserScopePlatform, rebound.ServiceUserScope)
	_, ok = f.authenticate(t, beforeRevocation)
	require.False(t, ok, "a new binding never revives tokens of the revoked one")
	subject, ok = f.authenticate(t, f.exchangeToken(t))
	require.True(t, ok)
	require.Equal(t, principal, subject)
}

func TestPluginWorkloadRegistersCapabilitiesOnlyForItsOwnPlugin(t *testing.T) {
	f := newWorkloadFixture(t)
	principal := f.bind(t, f.bindingBody()).ServiceUserId

	// A platform principal holds no role, so it registers capabilities for no
	// plugin, not even its own: Core registers them for every enabled
	// organization. Operators keep their authority over every plugin.
	for _, pluginID := range []string{workloadPluginID, "dev.stellwerk.other-plugin", workloadPluginID + ".nested"} {
		_, err := f.server.ReplacePluginCapabilities(f.as(principal), ReplacePluginCapabilitiesRequestObject{
			OrgId: workloadOrg, PluginId: pluginID, Body: &PluginCapabilityRegistrationBody{},
		})
		requireForbidden(t, err, pluginID)
	}
	require.IsType(t, ReplacePluginCapabilities204Response{}, f.registerCapabilities(t, f.operator, workloadPluginID))
	require.IsType(t, ReplacePluginCapabilities204Response{}, f.registerCapabilities(t, f.operator, "dev.stellwerk.other-plugin"),
		"an unbound operator principal keeps authority over every plugin")
	require.IsType(t, ReplacePluginCapabilities204Response{}, f.registerCapabilities(t, userid.InternalSystemUuid, workloadPluginID),
		"Core registers capabilities per organization as IAM's internal system identity")
}

func TestTransitionalStaticTokenAdapterKeepsStaticTokensOfBoundServiceUsers(t *testing.T) {
	f := newWorkloadFixture(t)
	f.server.PluginWorkloadStaticTokens = true
	binding := f.bindLegacy(t, f.legacy)

	subject, ok := f.authenticate(t, f.legacyStaticToken)
	require.True(t, ok)
	require.Equal(t, f.legacy, subject)
	subject, ok = f.authenticate(t, f.exchangeTokenFor(t, legacyServiceAccount))
	require.True(t, ok)
	require.Equal(t, f.legacy, subject)

	// Switching the adapter off rejects the retained static token as well.
	f.server.PluginWorkloadStaticTokens = false
	_, ok = f.authenticate(t, f.legacyStaticToken)
	require.False(t, ok)
	require.IsType(t, RegenerateServiceUser409JSONResponse{}, f.regenerate(t, f.legacy))
	subject, ok = f.authenticate(t, f.exchangeTokenFor(t, legacyServiceAccount))
	require.True(t, ok, "the existing binding of an organization service user keeps exchanging")
	require.Equal(t, f.legacy, subject)

	// After revocation the service user is an ordinary one again.
	_, err := f.server.DeletePluginWorkloadBinding(f.as(f.operator), DeletePluginWorkloadBindingRequestObject{BindingId: binding.ID})
	require.NoError(t, err)
	require.IsType(t, RegenerateServiceUser200JSONResponse{}, f.regenerate(t, f.legacy))
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
	plugin := f.bind(t, f.bindingBody()).ServiceUserId
	f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginManagerRead] = append(f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginManagerRead], plugin)
	require.Equal(t, []ResourcePermissionCheck{read}, f.authorize(t, plugin, read))

	// A subject can ask for its own platform permissions.
	body := []ResourcePermissionCheck{write, orgCheck, read}
	checked, err := f.server.CheckPermissions(f.as(reader), CheckPermissionsRequestObject{Body: &body})
	require.NoError(t, err)
	require.Equal(t, CheckPermissions200JSONResponse{Items: []ResourcePermissionCheckResultItem{
		{PermissionCheck: write, Allowed: false}, {PermissionCheck: orgCheck, Allowed: false}, {PermissionCheck: read, Allowed: true},
	}}, checked)
}

func TestInternalBindingLookupReturnsExactlyTheInstallationsBindings(t *testing.T) {
	f := newWorkloadFixture(t)
	lookup := func(pluginID string, installationID uuid.UUID) []PluginWorkloadBinding {
		t.Helper()
		response, err := f.server.InternalListPluginWorkloadBindings(f.ctx, InternalListPluginWorkloadBindingsRequestObject{
			Params: InternalListPluginWorkloadBindingsParams{PluginId: pluginID, InstallationId: installationID},
		})
		require.NoError(t, err)
		return response.(InternalListPluginWorkloadBindings200JSONResponse).Items
	}
	body := f.bindingBody()
	require.Empty(t, lookup(workloadPluginID, body.InstallationId))
	created := f.bind(t, body)
	other := f.bindingBody()
	other.ServiceAccount = "other-runtime"
	otherCreated := f.bind(t, other)
	require.NotEqual(t, created.ServiceUserId, otherCreated.ServiceUserId, "every binding request creates its own principal")

	found := lookup(workloadPluginID, body.InstallationId)
	require.Equal(t, []PluginWorkloadBinding{created}, found)
	require.Equal(t, ServiceUserScopePlatform, found[0].ServiceUserScope, "Core learns that the installation's identity is a platform principal")
	require.Equal(t, []PluginWorkloadBinding{otherCreated}, lookup(workloadPluginID, other.InstallationId))
	require.Empty(t, lookup("dev.stellwerk.other-plugin", body.InstallationId), "the plugin ID must match as well")

	legacy := f.bindLegacy(t, f.legacy)
	legacyFound := lookup(workloadPluginID, legacy.InstallationID)
	require.Len(t, legacyFound, 1)
	require.Equal(t, f.legacy, legacyFound[0].ServiceUserId)
	require.Equal(t, ServiceUserScopeOrganization, legacyFound[0].ServiceUserScope, "a binding that predates platform principals says so")

	_, err := f.server.DeletePluginWorkloadBinding(f.as(f.operator), DeletePluginWorkloadBindingRequestObject{BindingId: created.Id})
	require.NoError(t, err)
	require.Empty(t, lookup(workloadPluginID, body.InstallationId), "a revoked binding is gone at once")
}

// The platform principal belongs to no organization and holds no role, so it
// has no IAM authority anywhere; the database cannot even store a role for it.
func TestPlatformPrincipalHasNoAuthorityInAnyOrganization(t *testing.T) {
	f := newWorkloadFixture(t)
	principal := f.bind(t, f.bindingBody()).ServiceUserId
	subject, ok := f.authenticate(t, f.exchangeToken(t))
	require.True(t, ok)
	require.Equal(t, principal, subject)

	organization := "organization:" + workloadOrg
	checks := []ResourcePermissionCheck{
		{Resource: organization, Permission: "member"},
		{Resource: organization, Permission: "read"},
		{Resource: organization, Permission: sharedauthz.PermissionPluginRegistrationWrite},
		{Resource: organization, Permission: sharedauthz.PermissionServiceUserRead},
		{Resource: sharedauthz.PlatformResource, Permission: sharedauthz.PermissionPluginWorkloadBindingWrite},
	}
	require.ElementsMatch(t, checks, f.authorize(t, principal, checks...))
	// The self check knows no "member" alias; it asks for the other four.
	ownChecks := checks[1:]
	checked, err := f.server.CheckPermissions(f.as(principal), CheckPermissionsRequestObject{Body: &ownChecks})
	require.NoError(t, err)
	require.Len(t, checked.(CheckPermissions200JSONResponse).Items, len(ownChecks))
	for _, item := range checked.(CheckPermissions200JSONResponse).Items {
		require.False(t, item.Allowed, "%+v", item.PermissionCheck)
	}
	_, err = f.server.GetCurrentUser(f.as(principal), GetCurrentUserRequestObject{})
	require.Error(t, err, "a platform principal is no user and has no organization memberships")
	_, err = f.server.ListServiceUsers(f.as(principal), ListServiceUsersRequestObject{OrgId: workloadOrg})
	requireForbidden(t, err)

	_, err = f.raw.ExecContext(f.ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
		VALUES ($1, $2, $3, now())`, principal, workloadOrg, f.roleID)
	var pqErr *pq.Error
	require.ErrorAs(t, err, &pqErr)
	require.Equal(t, "service_user_roles_service_user_org", pqErr.Constraint, "a role row needs the service user's own organization")
	_, err = f.raw.ExecContext(f.ctx, `INSERT INTO roles (id, org_id, display_name, created_at, permissions)
		VALUES ($1, 'other-org', 'Foreign', now(), ARRAY['manage_all'])`, uuid.New())
	require.NoError(t, err)
	_, err = f.raw.ExecContext(f.ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
		SELECT $1, org_id, id, now() FROM roles WHERE org_id = 'other-org'`, f.legacy)
	require.ErrorAs(t, err, &pqErr)
	require.Equal(t, "service_user_roles_service_user_org", pqErr.Constraint, "nor can an organization service user hold a role of another organization")
	_, err = f.raw.ExecContext(f.ctx, `UPDATE service_user_tokens SET org_id = $2 WHERE id = $1`, principal, workloadOrg)
	require.ErrorAs(t, err, &pqErr)
	require.Equal(t, "service_user_tokens_scope", pqErr.Constraint, "a platform principal never joins an organization")
	_, err = f.raw.ExecContext(f.ctx, `UPDATE service_user_tokens SET current_token_sha256_hash = $2 WHERE id = $1`, principal, make([]byte, sha256.Size))
	require.ErrorAs(t, err, &pqErr)
	require.Equal(t, "service_user_tokens_scope", pqErr.Constraint, "a plugin workload principal never holds a static token")
}

// An organization admin manages the organization's service users; the
// platform principal is none of them.
func TestOrganizationAdminsCannotSeeOrChangeAPlatformPrincipal(t *testing.T) {
	f := newWorkloadFixture(t)
	principal := f.bind(t, f.bindingBody()).ServiceUserId

	listed, err := f.server.ListServiceUsers(f.as(f.admin), ListServiceUsersRequestObject{OrgId: workloadOrg})
	require.NoError(t, err)
	var ids []uuid.UUID
	for _, item := range listed.(ListServiceUsers200JSONResponse).Items {
		ids = append(ids, item.Id)
	}
	require.ElementsMatch(t, []uuid.UUID{f.operator, f.other, f.legacy}, ids)

	regenerated, err := f.server.RegenerateServiceUser(f.as(f.admin), RegenerateServiceUserRequestObject{
		OrgId: workloadOrg, ServiceUserId: principal, Body: &ServiceUserRegenerateBody{ExpiryInDays: 30},
	})
	require.NoError(t, err)
	require.IsType(t, RegenerateServiceUser404JSONResponse{}, regenerated)
	replaced, err := f.server.ReplaceServiceUserRoles(f.as(f.admin), ReplaceServiceUserRolesRequestObject{
		OrgId: workloadOrg, ServiceUserId: principal, Body: &ReplaceServiceUserRolesJSONRequestBody{Roles: []ServiceUserRole{{Id: f.roleID}}},
	})
	require.NoError(t, err)
	require.IsType(t, ReplaceServiceUserRoles404JSONResponse{}, replaced)
	deleted, err := f.server.DeleteServiceUser(f.as(f.admin), DeleteServiceUserRequestObject{OrgId: workloadOrg, ServiceUserId: principal})
	require.NoError(t, err)
	require.IsType(t, DeleteServiceUser404JSONResponse{}, deleted)
	for _, call := range []func() error{
		func() error {
			_, err := f.server.ListPluginWorkloadBindings(f.as(f.admin), ListPluginWorkloadBindingsRequestObject{})
			return err
		},
		func() error {
			_, err := f.server.CreatePluginWorkloadBinding(f.as(f.admin), CreatePluginWorkloadBindingRequestObject{Body: f.rebindingBody(principal)})
			return err
		},
	} {
		requireForbidden(t, call(), "binding management is a platform permission")
	}

	require.True(t, f.active(t, principal))
	subject, ok := f.authenticate(t, f.exchangeToken(t))
	require.True(t, ok, "nothing an organization admin did reached the principal")
	require.Equal(t, principal, subject)
}

// Removing an organization's access expires its service users, including an
// organization service user bound before platform principals existed. The
// platform principal belongs to no organization and keeps serving.
func TestOrganizationAccessRemovalLeavesPlatformPrincipalsActive(t *testing.T) {
	f := newWorkloadFixture(t)
	principal := f.bind(t, f.bindingBody()).ServiceUserId
	f.bindLegacy(t, f.legacy)
	platformToken := f.exchangeToken(t)
	legacyToken := f.exchangeTokenFor(t, legacyServiceAccount)

	removed, err := f.server.InternalRemoveAccessFromOrg(f.ctx, InternalRemoveAccessFromOrgRequestObject{OrgId: workloadOrg})
	require.NoError(t, err)
	require.IsType(t, InternalRemoveAccessFromOrg204Response{}, removed)

	_, ok := f.authenticate(t, legacyToken)
	require.False(t, ok, "the organization service user is expired with its organization")
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.claimsFor(legacyServiceAccount)))
	require.False(t, f.active(t, f.legacy))

	require.True(t, f.active(t, principal))
	subject, ok := f.authenticate(t, platformToken)
	require.True(t, ok, "a token issued before the removal keeps authenticating")
	require.Equal(t, principal, subject)
	subject, ok = f.authenticate(t, f.exchangeToken(t))
	require.True(t, ok, "and the principal keeps exchanging")
	require.Equal(t, principal, subject)
}

// A plugin workload holds no role. A service user bound before platform
// principals existed may hold one, for example the Admin role that creating
// it without a roles field assigns. It gets no workload credential while it
// holds a role, and no role can be assigned to it while it is bound.
func TestServiceUsersHoldingRolesGetNoWorkloadCredential(t *testing.T) {
	f := newWorkloadFixture(t)
	f.server.PluginWorkloadStaticTokens = true

	created, err := f.server.CreateServiceUser(f.as(f.admin), CreateServiceUserRequestObject{
		OrgId: workloadOrg, Body: &ServiceUserCreateBody{DisplayName: "plugin without roles field", ExpiryInDays: 30},
	})
	require.NoError(t, err)
	defaultAdmin := created.(CreateServiceUser201JSONResponse)
	require.Len(t, defaultAdmin.Roles, 1, "the public default stays: no roles field means the Admin role")
	binding := f.bindLegacy(t, defaultAdmin.Id)
	read, err := f.server.Database.GetPluginWorkloadBinding(f.ctx, nil, binding.ID)
	require.NoError(t, err)
	require.True(t, read.ServiceUserHoldsRoles)

	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.claimsFor(legacyServiceAccount)),
		"an Admin service user never becomes a plugin workload")
	_, ok := f.authenticate(t, defaultAdmin.Token)
	require.False(t, ok, "the static-token adapter never keeps the token of a bound role holder")
	replaced, err := f.server.ReplaceServiceUserRoles(f.as(f.admin), ReplaceServiceUserRolesRequestObject{
		OrgId: workloadOrg, ServiceUserId: defaultAdmin.Id, Body: &ReplaceServiceUserRolesJSONRequestBody{Roles: []ServiceUserRole{{Id: f.roleID}}},
	})
	require.NoError(t, err)
	require.Equal(t, ReplaceServiceUserRoles409JSONResponse{N409ConflictJSONResponse: Generate409Response("the service user is bound to a plugin workload and cannot hold roles")}, replaced)

	// After revocation it is an ordinary organization service user again.
	_, err = f.server.DeletePluginWorkloadBinding(f.as(f.operator), DeletePluginWorkloadBindingRequestObject{BindingId: binding.ID})
	require.NoError(t, err)
	subject, ok := f.authenticate(t, defaultAdmin.Token)
	require.True(t, ok)
	require.Equal(t, defaultAdmin.Id, subject)
	replaced, err = f.server.ReplaceServiceUserRoles(f.as(f.admin), ReplaceServiceUserRolesRequestObject{
		OrgId: workloadOrg, ServiceUserId: defaultAdmin.Id, Body: &ReplaceServiceUserRolesJSONRequestBody{Roles: []ServiceUserRole{{Id: f.roleID}}},
	})
	require.NoError(t, err)
	require.IsType(t, ReplaceServiceUserRoles200JSONResponse{}, replaced)
}

// A role that reaches a bound service user by any path stops the workload
// tokens issued before it at the next request.
func TestARoleStopsWorkloadTokensIssuedBeforeIt(t *testing.T) {
	f := newWorkloadFixture(t)
	f.server.PluginWorkloadStaticTokens = true
	f.bindLegacy(t, f.legacy)
	issued := f.exchangeTokenFor(t, legacyServiceAccount)
	subject, ok := f.authenticate(t, issued)
	require.True(t, ok)
	require.Equal(t, f.legacy, subject)
	subject, ok = f.authenticate(t, f.legacyStaticToken)
	require.True(t, ok, "the adapter keeps the static token of a role-less bound service user")
	require.Equal(t, f.legacy, subject)

	_, err := f.raw.ExecContext(f.ctx, `INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at)
		VALUES ($1, $2, $3, now())`, f.legacy, workloadOrg, f.roleID)
	require.NoError(t, err)
	_, ok = f.authenticate(t, issued)
	require.False(t, ok)
	_, ok = f.authenticate(t, f.legacyStaticToken)
	require.False(t, ok)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.claimsFor(legacyServiceAccount)))

	_, err = f.raw.ExecContext(f.ctx, `DELETE FROM service_user_roles WHERE service_user_id = $1`, f.legacy)
	require.NoError(t, err)
	subject, ok = f.authenticate(t, f.exchangeTokenFor(t, legacyServiceAccount))
	require.True(t, ok, "without the role the binding serves again")
	require.Equal(t, f.legacy, subject)
}

// Each installation has its own principal; revoking one binding stops exactly
// that principal at its next request.
func TestBindingRevocationStopsOnlyThatPlatformPrincipal(t *testing.T) {
	f := newWorkloadFixture(t)
	first := f.bind(t, f.bindingBody())
	secondBody := f.bindingBody()
	secondBody.ServiceAccount = "second-runtime"
	second := f.bind(t, secondBody)
	firstToken, secondToken := f.exchangeToken(t), f.exchangeTokenFor(t, "second-runtime")

	foreign := f.rebindingBody(first.ServiceUserId)
	foreign.ServiceAccount, foreign.InstallationId = "third-runtime", second.InstallationId
	require.IsType(t, CreatePluginWorkloadBinding409JSONResponse{}, f.createBinding(t, foreign),
		"a bound principal cannot gain a binding to another installation")

	_, err := f.server.DeletePluginWorkloadBinding(f.as(f.operator), DeletePluginWorkloadBindingRequestObject{BindingId: first.Id})
	require.NoError(t, err)
	_, ok := f.authenticate(t, firstToken)
	require.False(t, ok)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()))
	subject, ok := f.authenticate(t, secondToken)
	require.True(t, ok, "the other installation's principal is untouched")
	require.Equal(t, second.ServiceUserId, subject)
}
