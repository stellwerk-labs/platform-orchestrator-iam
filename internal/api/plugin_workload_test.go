package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity/workloadidentitytest"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestPluginWorkloadTokenExchangeIsExemptFromGatewayAuthentication(t *testing.T) {
	require.True(t, skipAuthenticationRegex.MatchString("/auth/plugin-workload-token"))
	for _, path := range []string{
		"/auth/plugin-workload-token/extra",
		"/auth/plugin-workload-tokens",
		"/plugin-workload-bindings",
		"/plugin-workload-bindings/0199a0c1-1d6e-72f1-8000-000000000001",
		"/orgs/acme/auth/plugin-workload-token",
	} {
		require.False(t, skipAuthenticationRegex.MatchString(path), path)
	}
}

func TestClassifyTokenKeepsWorkloadServiceUserAndSessionTokensApart(t *testing.T) {
	workloadToken, workloadHash := workloadidentity.NewToken()
	kind, hash := classifyToken(workloadToken)
	require.Equal(t, tokenKindPluginWorkload, kind)
	require.Equal(t, workloadHash, hash[:])

	kind, hash = classifyToken(egServiceUserToken)
	require.Equal(t, tokenKindServiceUser, kind)
	require.Equal(t, egTokenHash, hash[:])

	kind, hash = classifyToken(egSessionToken)
	require.Equal(t, tokenKindSession, kind)
	require.Equal(t, egTokenHash, hash[:])

	kind, hash = classifyToken(workloadidentity.TokenPrefix + "malformed")
	require.Equal(t, tokenKindPluginWorkload, kind)
	require.Equal(t, [32]byte{}, hash, "a malformed workload token must not hash to a real token")
}

func TestPluginWorkloadContractValidatesRequestsAgainstTheGeneratedSchema(t *testing.T) {
	spec, err := GetSwagger()
	require.NoError(t, err)

	exchange := spec.Components.Schemas["PluginWorkloadTokenExchangeRequest"].Value
	validExchange := func() map[string]any {
		return map[string]any{ // #nosec G101 -- RFC 8693 type URNs and a placeholder subject token, no credential.
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      "header.payload.signature",
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		}
	}
	require.NoError(t, exchange.VisitJSON(validExchange()))
	for name, mutate := range map[string]func(map[string]any){
		"unknown field":    func(body map[string]any) { body["audience"] = "other" },
		"other grant type": func(body map[string]any) { body["grant_type"] = "client_credentials" },
		"access token subject": func(body map[string]any) {
			body["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
		},
		"empty subject token":   func(body map[string]any) { body["subject_token"] = "" },
		"missing subject type":  func(body map[string]any) { delete(body, "subject_token_type") },
		"missing grant type":    func(body map[string]any) { delete(body, "grant_type") },
		"missing subject token": func(body map[string]any) { delete(body, "subject_token") },
	} {
		t.Run("exchange/"+name, func(t *testing.T) {
			body := validExchange()
			mutate(body)
			require.Error(t, exchange.VisitJSON(body))
		})
	}

	binding := spec.Components.Schemas["PluginWorkloadBindingCreateBody"].Value
	validBinding := func() map[string]any {
		return map[string]any{
			"issuer":          "https://kubernetes.default.svc.cluster.local",
			"namespace":       "stellwerk-plugins",
			"service_account": "progressive-rollouts-runtime",
			"audience":        "stellwerk-iam-plugin-workload",
			"service_user_id": "0199a0c1-1d6e-72f2-8000-000000000001",
			"plugin_id":       "dev.stellwerk.progressive-rollouts",
			"installation_id": "0199a0c1-1d6e-7000-8000-000000000002",
		}
	}
	require.NoError(t, binding.VisitJSON(validBinding()))
	for name, mutate := range map[string]func(map[string]any){
		"uppercase namespace":        func(body map[string]any) { body["namespace"] = "Plugins" },
		"dotted namespace":           func(body map[string]any) { body["namespace"] = "plugins.v1" },
		"service account with colon": func(body map[string]any) { body["service_account"] = "runtime:other" },
		"audience with space":        func(body map[string]any) { body["audience"] = "two words" },
		"uppercase plugin id":        func(body map[string]any) { body["plugin_id"] = "Dev.Stellwerk" },
		"unknown field":              func(body map[string]any) { body["permissions"] = []any{"manage_all"} },
		"missing installation id":    func(body map[string]any) { delete(body, "installation_id") },
		"missing exchange audience":  func(body map[string]any) { delete(body, "audience") },
		"oversized service account":  func(body map[string]any) { body["service_account"] = strings.Repeat("a", 254) },
		"namespace beyond label size": func(body map[string]any) {
			body["namespace"] = "a234567890123456789012345678901234567890123456789012345678901234"
		},
	} {
		t.Run("binding/"+name, func(t *testing.T) {
			body := validBinding()
			mutate(body)
			require.Error(t, binding.VisitJSON(body))
		})
	}

	regenerate := spec.Paths.Value("/orgs/{orgId}/service-users/{serviceUserId}/actions/regenerate").Post
	require.NotNil(t, regenerate.Responses.Value("409"), "regeneration documents the refusal for workload-bound service users")
	require.Empty(t, spec.Paths.Value("/auth/plugin-workload-token").Post.Security, "the exchange needs no prior authentication")
	for _, path := range []string{"/plugin-workload-bindings", "/plugin-workload-bindings/{bindingId}"} {
		for method, operation := range spec.Paths.Value(path).Operations() {
			require.NotNil(t, operation.Security, "%s %s must require an authenticated principal", method, path)
		}
	}
}

func TestExchangeRefusesSubjectTokensBeforeReadingAnyBinding(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	keys := workloadidentity.NewKeySet(workloadidentity.HTTPKeySource(issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), time.Now)
	// No Database: every refusal below must happen during verification.
	server := &Server{Logger: zaptest.NewLogger(t), PluginWorkloadExchange: &PluginWorkloadExchange{
		Issuer: issuer.URL, Verifier: workloadidentity.NewVerifier(issuer.URL, keys, time.Now), TokenTTL: workloadidentity.MaxTokenLifetime,
	}}
	exchange := func(subjectToken string) ExchangePluginWorkloadTokenResponseObject {
		response, err := server.ExchangePluginWorkloadToken(t.Context(), ExchangePluginWorkloadTokenRequestObject{Body: &PluginWorkloadTokenExchangeRequest{
			GrantType: PluginWorkloadTokenExchangeGrantType, SubjectToken: subjectToken, SubjectTokenType: PluginWorkloadSubjectTokenTypeJWT,
		}})
		require.NoError(t, err)
		return response
	}

	claims := issuer.ValidClaims(time.Now(), "plugins", "runtime", "stellwerk-iam-plugin-workload")
	claims.Issuer = "https://other-cluster.example.test"
	require.Equal(t, ExchangePluginWorkloadToken400JSONResponse{N400BadRequestJSONResponse{
		Error: invalidGrantErrorCode, Message: "the subject token cannot be exchanged",
	}}, exchange(issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims)))

	expired := issuer.ValidClaims(time.Now().Add(-time.Hour), "plugins", "runtime", "stellwerk-iam-plugin-workload")
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, exchange(issuer.Sign(t, workloadidentitytest.DefaultKeyID, expired)))

	response, err := server.ExchangePluginWorkloadToken(t.Context(), ExchangePluginWorkloadTokenRequestObject{Body: &PluginWorkloadTokenExchangeRequest{
		GrantType: "client_credentials", SubjectToken: "x", SubjectTokenType: PluginWorkloadSubjectTokenTypeJWT,
	}})
	require.NoError(t, err)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, response)
}

func TestExchangeReportsUnavailableIssuerKeysAsTemporary(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	issuer.SetJWKSStatus(http.StatusServiceUnavailable)
	keys := workloadidentity.NewKeySet(workloadidentity.HTTPKeySource(issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), time.Now)
	server := &Server{Logger: zaptest.NewLogger(t), PluginWorkloadExchange: &PluginWorkloadExchange{
		Issuer: issuer.URL, Verifier: workloadidentity.NewVerifier(issuer.URL, keys, time.Now), TokenTTL: workloadidentity.MaxTokenLifetime,
	}}

	claims := issuer.ValidClaims(time.Now(), "plugins", "runtime", "stellwerk-iam-plugin-workload")
	response, err := server.ExchangePluginWorkloadToken(t.Context(), ExchangePluginWorkloadTokenRequestObject{Body: &PluginWorkloadTokenExchangeRequest{
		GrantType: PluginWorkloadTokenExchangeGrantType, SubjectToken: issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims), SubjectTokenType: PluginWorkloadSubjectTokenTypeJWT,
	}})
	require.NoError(t, err)
	require.Equal(t, ExchangePluginWorkloadToken503JSONResponse{
		Error: temporarilyUnavailableErrorCode, Message: "the workload token issuer keys are unavailable",
	}, response)
}

func TestExchangeIsNotFoundWithoutAConfiguredIssuer(t *testing.T) {
	server := &Server{Logger: zaptest.NewLogger(t)}
	response, err := server.ExchangePluginWorkloadToken(t.Context(), ExchangePluginWorkloadTokenRequestObject{})
	require.NoError(t, err)
	require.IsType(t, ExchangePluginWorkloadToken404JSONResponse{}, response)
}

func TestPluginWorkloadRoutesEnforceAuthenticationAndPlatformPermission(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	keys := workloadidentity.NewKeySet(workloadidentity.HTTPKeySource(issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), time.Now)
	listed := userid.NewServiceUserTokenId()
	// No Database: every request below is decided before any lookup.
	server := &Server{
		Logger: zaptest.NewLogger(t),
		PluginWorkloadExchange: &PluginWorkloadExchange{
			Issuer: issuer.URL, Verifier: workloadidentity.NewVerifier(issuer.URL, keys, time.Now), TokenTTL: workloadidentity.MaxTokenLifetime,
		},
		PlatformPermissionHolders: map[string][]uuid.UUID{sharedauthz.PermissionPluginWorkloadBindingWrite: {listed}},
	}
	echoServer, err := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{
		AppName: "test", Logger: zaptest.NewLogger(t), OpenAPIRawSchema: MustDecodeOpenApiSpec(), OpenAPISkipperFn: OpenApiValidatorSkipper,
	})
	require.NoError(t, err)
	server.MapRoutes(echoServer)
	serve := func(method, path, from, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if from != "" {
			request.Header.Set("From", from)
		}
		response := httptest.NewRecorder()
		echoServer.ServeHTTP(response, request)
		return response
	}

	bindingPath := "/plugin-workload-bindings/" + uuid.NewString()
	createBody := `{"issuer":"` + issuer.URL + `","namespace":"plugins","service_account":"runtime","audience":"stellwerk-iam-plugin-workload",` +
		`"service_user_id":"` + userid.NewServiceUserTokenId().String() + `","plugin_id":"dev.stellwerk.progressive-rollouts","installation_id":"` + uuid.NewString() + `"}`
	requests := []struct{ method, path, body string }{
		{http.MethodGet, "/plugin-workload-bindings", ""},
		{http.MethodPost, "/plugin-workload-bindings", createBody},
		{http.MethodGet, bindingPath, ""},
		{http.MethodDelete, bindingPath, ""},
	}
	for _, request := range requests {
		require.Equal(t, http.StatusUnauthorized, serve(request.method, request.path, "", request.body).Code, "%s %s without principal", request.method, request.path)
	}
	for name, principal := range map[string]string{
		"organization service user": userid.NewServiceUserTokenId().String(),
		"human":                     userid.NewHumanUserId().String(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, request := range requests {
				require.Equal(t, http.StatusForbidden, serve(request.method, request.path, principal, request.body).Code, "%s %s", request.method, request.path)
			}
		})
	}

	exchangeBody := `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","subject_token":"`
	response := serve(http.MethodPost, "/auth/plugin-workload-token", "", exchangeBody+`not-a-jwt"}`)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Contains(t, response.Body.String(), invalidGrantErrorCode)
	response = serve(http.MethodPost, "/auth/plugin-workload-token", "", exchangeBody+`x","audience":"other"}`)
	require.Equal(t, http.StatusBadRequest, response.Code, "unknown RFC 8693 parameters are rejected by the contract")
	require.NotContains(t, response.Body.String(), invalidGrantErrorCode)
}

func TestInternalPlatformRoutesHonourTheirContract(t *testing.T) {
	// No Database: every request below is decided before any lookup.
	server := &Server{Logger: zaptest.NewLogger(t), PlatformPermissionHolders: map[string][]uuid.UUID{}}
	echoServer, err := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{
		AppName: "test", Logger: zaptest.NewLogger(t), OpenAPIRawSchema: MustDecodeOpenApiSpec(), OpenAPISkipperFn: OpenApiValidatorSkipper,
	})
	require.NoError(t, err)
	server.MapRoutes(echoServer)
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("From", userid.InternalSystemUuid.String())
		response := httptest.NewRecorder()
		echoServer.ServeHTTP(response, request)
		return response
	}

	authorize := func(resource string) *httptest.ResponseRecorder {
		return serve(http.MethodPost, "/internal/authorize",
			`{"user_id":"`+userid.InternalSystemUuid.String()+`","checks":[{"resource":"`+resource+`","permission":"plugin_manager_read"}]}`)
	}
	response := authorize(sharedauthz.PlatformResource)
	require.Equal(t, http.StatusForbidden, response.Code, "the internal system identity is not a configured holder")
	require.JSONEq(t, `[{"resource":"platform","permission":"plugin_manager_read"}]`, failedChecksJSON(t, response.Body.Bytes()))
	for _, resource := range []string{"platforms", "platform:plugins", "Platform"} {
		require.Equal(t, http.StatusBadRequest, authorize(resource).Code, resource)
	}

}

func failedChecksJSON(t *testing.T, body []byte) string {
	t.Helper()
	var decoded struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))
	return string(decoded.Details[failedChecksField])
}
