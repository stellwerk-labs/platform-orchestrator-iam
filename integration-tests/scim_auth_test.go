package integrationtests

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// scimProxyBaseURL returns the SCIM base URL for an org routed through the
// reverse proxy at SERVER_URL. The proxy mirrors the production Envoy route
// (see score.yaml), so requests here prove the externally reachable path,
// not just the container-to-container one.
func scimProxyBaseURL(t *testing.T, orgId string) string {
	t.Helper()
	return fmt.Sprintf("%s/scim/v2/orgs/%s", mustServerURL(t), orgId)
}

// extAuthDo replays what Envoy's ext-auth filter does: POST the original path
// under /internal/authenticate with the client's Authorization header, then
// read the identity headers off the response.
func extAuthDo(t *testing.T, path, bearerToken string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, mustInternalServerURL(t)+"/internal/authenticate"+path, nil)
	require.NoError(t, err)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := testHttpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, body
}

// mustCreateProvisioningRole creates a custom role holding exactly the two
// provisioning permissions, mirroring what an IDP integration gets in production.
func mustCreateProvisioningRole(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId string, adminId uuid.UUID) uuid.UUID {
	t.Helper()
	r, err := client.CreateRoleWithResponse(t.Context(), orgId, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Provisioner",
		Permissions: []string{authz.PermissionProvisioningRead, authz.PermissionProvisioningWrite},
	}, WithAuthenticatedUserId(adminId))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, r.StatusCode(), "create provisioner role: %s", string(r.Body))
	return r.JSON201.Id
}

// waitForProvisioningPerms blocks until Casbin grants the principal both
// provisioning permissions on the org.
func waitForProvisioningPerms(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId string, principalId uuid.UUID) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
			authz.OrgCheck(orgId, authz.PermissionProvisioningRead),
			authz.OrgCheck(orgId, authz.PermissionProvisioningWrite),
		}, WithAuthenticatedUserId(principalId))
		require.NoError(t, err)
		if !assert.Equal(c, http.StatusOK, resp.StatusCode(), "check perms: %s", string(resp.Body)) {
			return
		}
		assert.Equal(c, []serverclient.ResourcePermissionCheckResultItem{
			{Allowed: true, PermissionCheck: authz.OrgCheck(orgId, authz.PermissionProvisioningRead)},
			{Allowed: true, PermissionCheck: authz.OrgCheck(orgId, authz.PermissionProvisioningWrite)},
		}, resp.JSON200.Items)
	}, 30*time.Second, 500*time.Millisecond, "principal %s did not get provisioning permissions in org %s in time", principalId, orgId)
}

// mustScimOrgWithAdmin creates an org and an admin user for it.
func mustScimOrgWithAdmin(t *testing.T, client, internalClient serverclient.ClientWithResponsesInterface) (orgId string, adminId uuid.UUID) {
	t.Helper()
	cpInternalClient := MustInternalControlPlaneClient(t)
	org := MustCreateTestOrg(cpInternalClient, t)
	admin := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, admin.Id, adminRoleId)
	return org.Id, admin.Id
}

// mustProvisioningCaller registers a fresh user, binds it to a provisioning
// role in the org, and waits for policy propagation.
func mustProvisioningCaller(t *testing.T, client, internalClient serverclient.ClientWithResponsesInterface, orgId string, adminId uuid.UUID) uuid.UUID {
	t.Helper()
	roleId := mustCreateProvisioningRole(t, client, orgId, adminId)
	caller := MustRegisterTestUser(client, t)
	m, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), orgId,
		serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      caller.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     roleId.String(),
		})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, m.StatusCode(), "add provisioning caller membership: %s", string(m.Body))
	waitForProvisioningPerms(t, client, orgId, caller.Id)
	return caller.Id
}

// mustAssertScimErrorEnvelope decodes the body as a SCIM Error (RFC 7644 §3.12)
// and asserts the schemas urn and status match.
func mustAssertScimErrorEnvelope(t *testing.T, body []byte, expectedStatus int) {
	t.Helper()
	var envelope struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), "decode SCIM error from: %s", string(body))
	assert.Contains(t, envelope.Schemas, "urn:ietf:params:scim:api:messages:2.0:Error")
	assert.Equal(t, fmt.Sprintf("%d", expectedStatus), envelope.Status)
}

// TestScimServiceUserTokenAuth exercises the real token → identity path that
// the existing SCIM tests skip by injecting the From header directly. This is
// the exact contract Envoy's ext-auth filter depends on: it POSTs the original
// path under /internal/authenticate with the client's bearer token and forwards
// the resulting From / X-Token-Hash headers to the backend.
func TestScimServiceUserTokenAuth(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	provRoleId := mustCreateProvisioningRole(t, client, orgId, adminId)

	// A real service user bound to the provisioning role, with a real SU- token.
	var su serverclient.ServiceUserWithToken
	{
		r, err := client.CreateServiceUserWithResponse(t.Context(), orgId, serverclient.ServiceUserCreateBody{
			DisplayName:  "scim-provisioner",
			ExpiryInDays: 14,
			Roles:        &[]serverclient.ServiceUserRole{{Id: provRoleId}},
		}, WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "create service user: %s", string(r.Body))
		su = *r.JSON201
		require.Regexp(t, "^SU-.+", su.Token)
	}
	waitForProvisioningPerms(t, client, orgId, su.Id)

	scimPath := fmt.Sprintf("/scim/v2/orgs/%s/Users", orgId)

	t.Run("valid SU token yields 200 with From and X-Token-Hash headers", func(t *testing.T) {
		status, headers, body := extAuthDo(t, scimPath, su.Token)
		require.Equal(t, http.StatusOK, status, "body: %s", string(body))
		assert.Equal(t, su.Id.String(), headers.Get("From"), "From header must carry the service user id")
		assert.NotEmpty(t, headers.Get("X-Token-Hash"), "X-Token-Hash header must be set")
	})

	// The discovery documents are meant to be readable without a token. That is
	// decided at the ext-auth boundary, not in the handler: Envoy calls
	// /internal/authenticate before the route, so a handler placed outside the
	// SCIM auth middleware still 401s in production unless the path is
	// allow-listed here. Testing the handler directly cannot see this.
	t.Run("discovery clears ext-auth without any token", func(t *testing.T) {
		for _, res := range []string{"ServiceProviderConfig", "Schemas", "ResourceTypes"} {
			path := fmt.Sprintf("/scim/v2/orgs/%s/%s", orgId, res)
			status, headers, body := extAuthDo(t, path, "")
			assert.Equal(t, http.StatusOK, status, "%s must not require a token: %s", res, string(body))
			assert.Equal(t, uuid.Nil.String(), headers.Get("From"),
				"%s is anonymous, so the principal must be the nil uuid", res)
		}
	})

	t.Run("Users and Groups still require a token at ext-auth", func(t *testing.T) {
		for _, res := range []string{"Users", "Groups"} {
			path := fmt.Sprintf("/scim/v2/orgs/%s/%s", orgId, res)
			status, _, body := extAuthDo(t, path, "")
			assert.Equal(t, http.StatusUnauthorized, status,
				"%s must never be reachable anonymously: %s", res, string(body))
		}
	})

	t.Run("discovery is readable through the proxy with no Authorization header", func(t *testing.T) {
		// End to end, the way Entra's validator probes it.
		status, body := scimDo(t, http.MethodGet, scimProxyBaseURL(t, orgId)+"/ServiceProviderConfig", nil, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			var cfg struct {
				Patch struct{ Supported bool } `json:"patch"`
			}
			require.NoError(t, json.Unmarshal(body, &cfg))
			assert.True(t, cfg.Patch.Supported, "ServiceProviderConfig must be the real document")
		}
	})

	t.Run("unknown SU token yields 401", func(t *testing.T) {
		// Syntactically valid (SU- prefix + url-safe base64) but never issued.
		unknownToken := "SU-" + base64.URLEncoding.EncodeToString(randomBytes(33))
		status, _, body := extAuthDo(t, scimPath, unknownToken)
		assert.Equal(t, http.StatusUnauthorized, status, "body: %s", string(body))
	})

	t.Run("expired SU token yields 401", func(t *testing.T) {
		// Expiry is the failure mode operators actually hit: the token exists
		// and is otherwise valid, but its current_token_expires_at has passed.
		// A dedicated service user keeps the shared one usable, and its token
		// is never authenticated before being expired, so the 60s
		// GetTokenByHashCache cannot hold a stale not-yet-expired entry.
		r, err := client.CreateServiceUserWithResponse(t.Context(), orgId, serverclient.ServiceUserCreateBody{
			DisplayName:  "scim-provisioner-expired",
			ExpiryInDays: 14,
			Roles:        &[]serverclient.ServiceUserRole{{Id: provRoleId}},
		}, WithAuthenticatedUserId(adminId))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, r.StatusCode(), "create expiring service user: %s", string(r.Body))
		expiring := *r.JSON201

		db := MustDatabase(t)
		defer func() { _ = db.Close() }()
		token, err := db.GetServiceUserToken(t.Context(), nil, expiring.Id)
		require.NoError(t, err)
		// The table enforces current_token_expires_at > generated_at, so the
		// generation time moves back with the expiry.
		token.GeneratedAt = time.Now().UTC().Add(-2 * time.Hour)
		token.CurrentTokenExpiresAt = time.Now().UTC().Add(-time.Hour)
		_, err = db.UpdateServiceUserToken(t.Context(), nil, token)
		require.NoError(t, err)

		status, _, body := extAuthDo(t, scimPath, expiring.Token)
		assert.Equal(t, http.StatusUnauthorized, status, "expired token must be rejected; body: %s", string(body))
	})

	t.Run("SCIM token must not reach admin routes", func(t *testing.T) {
		// admin/ paths authenticate against the super user token hash, never
		// against service user tokens.
		status, _, body := extAuthDo(t, "/admin"+scimPath, su.Token)
		assert.Equal(t, http.StatusUnauthorized, status, "body: %s", string(body))
	})

	t.Run("principal from a real token can drive SCIM provisioning", func(t *testing.T) {
		// The chain Envoy composes: authenticate resolved the SU token to an
		// identity, and that identity (via From) is authorized for SCIM writes.
		userName := "scim-token-auth-" + uuid.New().String()[:8]
		suId := su.Id
		status, body := scimDo(t, http.MethodPost, scimProxyBaseURL(t, orgId)+"/Users", &suId, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
		})
		if assert.Equal(t, http.StatusCreated, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.Equal(t, userName, u.UserName)
			assert.True(t, u.Active)
		}
	})
}

// TestScimCrossOrgIsolation proves tenancy at the request level: a principal
// authorized in one org can neither list nor read SCIM resources of another,
// and a SCIM id never leaks across org boundaries.
func TestScimCrossOrgIsolation(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgAId, adminAId := mustScimOrgWithAdmin(t, client, internalClient)
	orgBId, adminBId := mustScimOrgWithAdmin(t, client, internalClient)

	callerA := mustProvisioningCaller(t, client, internalClient, orgAId, adminAId)
	callerB := mustProvisioningCaller(t, client, internalClient, orgBId, adminBId)

	t.Run("principal authorized in A only gets 403 in B", func(t *testing.T) {
		status, body := scimDo(t, http.MethodGet, scimProxyBaseURL(t, orgBId)+"/Users", &callerA, nil)
		assert.Equal(t, http.StatusForbidden, status, "body: %s", string(body))
	})

	// Provision a user in A and try to read it through B.
	var scimIdFromA uuid.UUID
	{
		userName := "scim-iso-" + uuid.New().String()[:8] + "@test.example"
		status, body := scimDo(t, http.MethodPost, scimProxyBaseURL(t, orgAId)+"/Users", &callerA, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
		})
		require.Equal(t, http.StatusCreated, status, "provision user in A: %s", string(body))
		u := mustDecodeScimUser(t, body)
		scimIdFromA = uuid.MustParse(u.Id)
	}

	t.Run("SCIM id from A yields 404 in B with a SCIM error envelope", func(t *testing.T) {
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Users/%s", scimProxyBaseURL(t, orgBId), scimIdFromA), &callerB, nil)
		if assert.Equal(t, http.StatusNotFound, status, "body: %s", string(body)) {
			mustAssertScimErrorEnvelope(t, body, http.StatusNotFound)
		}
	})

	// The cross-tenant guard in insertScimGroupMembers: org A's SCIM user id is a
	// real, existing id — B must refuse it exactly like a nonexistent one, both
	// at group create and at member add.
	t.Run("SCIM user from A cannot become a member of B's group", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, scimProxyBaseURL(t, orgBId)+"/Groups", &callerB, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: "iso-group-" + uuid.New().String()[:8],
		})
		require.Equal(t, http.StatusCreated, status, "create group in B: %s", string(body))
		groupId := mustDecodeScimGroup(t, body).Id

		status, body = scimDo(t, http.MethodPost, scimProxyBaseURL(t, orgBId)+"/Groups", &callerB, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: "iso-group-" + uuid.New().String()[:8],
			Members:     []map[string]string{{"value": scimIdFromA.String()}},
		})
		assert.Equal(t, http.StatusBadRequest, status, "cross-org member on group create must be a 400: %s", string(body))

		status, body = scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", scimProxyBaseURL(t, orgBId), groupId), &callerB, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "add", Path: "members", Value: []map[string]string{{"value": scimIdFromA.String()}}},
			},
		})
		assert.Equal(t, http.StatusBadRequest, status, "cross-org member add must be a 400: %s", string(body))

		status, body = scimDo(t, http.MethodGet, fmt.Sprintf("%s/Groups/%s", scimProxyBaseURL(t, orgBId), groupId), &callerB, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			g := mustDecodeScimGroup(t, body)
			assert.Empty(t, g.Members, "the foreign member must not have been stored")
		}
	})
}

// TestScimMultiOrgDeprovisioning mirrors the real customer shape: the same
// person is provisioned into a sandbox org and a production org (same email,
// distinct externalId per org), resolving to ONE global user. Deactivation in
// one org must only strip that org's membership; sessions are revoked only
// once the person has no memberships left anywhere.
func TestScimMultiOrgDeprovisioning(t *testing.T) {
	t.Parallel()

	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	sandboxOrgId, sandboxAdminId := mustScimOrgWithAdmin(t, client, internalClient)
	prodOrgId, prodAdminId := mustScimOrgWithAdmin(t, client, internalClient)

	sandboxCaller := mustProvisioningCaller(t, client, internalClient, sandboxOrgId, sandboxAdminId)
	prodCaller := mustProvisioningCaller(t, client, internalClient, prodOrgId, prodAdminId)

	initialSandboxCount := countOrgMembers(t, client, sandboxOrgId, sandboxAdminId)
	initialProdCount := countOrgMembers(t, client, prodOrgId, prodAdminId)

	// The same person in both orgs: identical userName/email, distinct externalId.
	email := "jane.doe-" + uuid.New().String()[:8] + "@test.example"
	provision := func(t *testing.T, orgId string, caller uuid.UUID, externalId string) uuid.UUID {
		t.Helper()
		status, body := scimDo(t, http.MethodPost, scimProxyBaseURL(t, orgId)+"/Users", &caller, testScimUserBody{
			Schemas:    []string{testScimUserSchema},
			UserName:   email,
			ExternalId: externalId,
			Active:     true,
			Emails:     []testScimEmail{{Value: email, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision in %s: %s", orgId, string(body))
		u := mustDecodeScimUser(t, body)
		require.True(t, u.Active)
		return uuid.MustParse(u.Id)
	}
	sandboxScimId := provision(t, sandboxOrgId, sandboxCaller, "ext-sandbox-"+uuid.New().String()[:8])
	prodScimId := provision(t, prodOrgId, prodCaller, "ext-prod-"+uuid.New().String()[:8])

	// Resolve both SCIM rows to the underlying global user and verify they are
	// the SAME person, not two records that happen to share an email.
	var globalUserId uuid.UUID
	t.Run("both orgs resolve to the same global user", func(t *testing.T) {
		sandboxRow, err := db.GetScimUser(t.Context(), nil, sandboxOrgId, sandboxScimId)
		require.NoError(t, err)
		prodRow, err := db.GetScimUser(t.Context(), nil, prodOrgId, prodScimId)
		require.NoError(t, err)
		require.Equal(t, sandboxRow.UserId, prodRow.UserId, "same email must resolve to one global user")
		globalUserId = sandboxRow.UserId

		assert.Equal(t, initialSandboxCount+1, countOrgMembers(t, client, sandboxOrgId, sandboxAdminId))
		assert.Equal(t, initialProdCount+1, countOrgMembers(t, client, prodOrgId, prodAdminId))

		memberships, err := db.ListMemberships(t.Context(), nil, model.ListMembershipsParams{UserId: &globalUserId})
		require.NoError(t, err)
		orgIds := make([]string, 0, len(memberships))
		for _, m := range memberships {
			orgIds = append(orgIds, m.OrgId)
		}
		assert.ElementsMatch(t, []string{sandboxOrgId, prodOrgId}, orgIds)
	})
	require.NotEqual(t, uuid.Nil, globalUserId, "global user id must be resolved before deprovisioning")

	// Give the person a live session, as if they had logged in via SSO. This is
	// what deprovisioning must eventually revoke.
	sessionHash := sha256.Sum256(randomBytes(33))
	now := time.Now().UTC()
	_, err = db.CreateSessionToken(t.Context(), nil, &model.SessionToken{
		Sha256Hash: sessionHash[:],
		Provider:   model.UserIdentityProviderSso,
		UserId:     globalUserId,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	})
	require.NoError(t, err)

	deactivate := func(t *testing.T, orgId string, caller, scimId uuid.UUID) {
		t.Helper()
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", scimProxyBaseURL(t, orgId), scimId), &caller, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "replace", Path: "active", Value: false},
			},
		})
		require.Equal(t, http.StatusOK, status, "deactivate in %s: %s", orgId, string(body))
		u := mustDecodeScimUser(t, body)
		require.False(t, u.Active)
	}

	t.Run("deactivation in sandbox leaves prod untouched", func(t *testing.T) {
		deactivate(t, sandboxOrgId, sandboxCaller, sandboxScimId)

		assert.Equal(t, initialSandboxCount, countOrgMembers(t, client, sandboxOrgId, sandboxAdminId), "sandbox membership must be gone")
		assert.Equal(t, initialProdCount+1, countOrgMembers(t, client, prodOrgId, prodAdminId), "prod membership must survive")

		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Users/%s", scimProxyBaseURL(t, prodOrgId), prodScimId), &prodCaller, nil)
		if assert.Equal(t, http.StatusOK, status, "body: %s", string(body)) {
			u := mustDecodeScimUser(t, body)
			assert.True(t, u.Active, "prod SCIM record must still be active")
		}

		sessions, err := db.ListSessionTokenByUserId(t.Context(), nil, globalUserId, model.ListSessionTokensParams{})
		require.NoError(t, err)
		assert.Len(t, sessions, 1, "session must survive while the user still belongs to prod")
	})

	t.Run("deactivation in prod removes the last membership and revokes sessions", func(t *testing.T) {
		deactivate(t, prodOrgId, prodCaller, prodScimId)

		assert.Equal(t, initialProdCount, countOrgMembers(t, client, prodOrgId, prodAdminId), "prod membership must be gone")

		memberships, err := db.ListMemberships(t.Context(), nil, model.ListMembershipsParams{UserId: &globalUserId})
		require.NoError(t, err)
		assert.Empty(t, memberships, "user must have no memberships anywhere")

		sessions, err := db.ListSessionTokenByUserId(t.Context(), nil, globalUserId, model.ListSessionTokensParams{})
		require.NoError(t, err)
		assert.Empty(t, sessions, "session tokens must be revoked with the last membership")
	})
}
