package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/plugincapabilities"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
)

type recordingPluginCapabilityRegistry struct {
	orgID       string
	pluginID    string
	definitions []plugincapabilities.Definition
}

func (r *recordingPluginCapabilityRegistry) Replace(_ context.Context, orgID, pluginID string, definitions []plugincapabilities.Definition) error {
	r.orgID, r.pluginID, r.definitions = orgID, pluginID, definitions
	return nil
}

func TestReplacePluginCapabilitiesRequiresFixedRegistrationPermission(t *testing.T) {
	_, server, finish := MockServer(t)
	defer finish()

	serviceUserID := userid.NewServiceUserTokenId()
	MockAuthorizationFailure(server, serviceUserID, orgId)
	recorder := &recordingPluginCapabilityRegistry{}
	server.PluginCapabilities = recorder
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, serviceUserID.String())

	response, err := server.ReplacePluginCapabilities(ctx, pluginCapabilityRequest())
	require.Error(t, err)
	require.Nil(t, response)
	require.Empty(t, recorder.pluginID)
}

func TestReplacePluginCapabilitiesUsesAuthorizedInstallationNamespace(t *testing.T) {
	_, server, finish := MockServer(t)
	defer finish()

	serviceUserID := userid.NewServiceUserTokenId()
	MockAuthorizationSuccess(server, serviceUserID, orgId, sharedauthz.PermissionPluginRegistrationWrite)
	recorder := &recordingPluginCapabilityRegistry{}
	server.PluginCapabilities = recorder
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, serviceUserID.String())

	response, err := server.ReplacePluginCapabilities(ctx, pluginCapabilityRequest())
	require.NoError(t, err)
	require.IsType(t, ReplacePluginCapabilities204Response{}, response)
	require.Equal(t, orgId, recorder.orgID)
	require.Equal(t, "dev.stellwerk.rollouts", recorder.pluginID)
	require.Equal(t, "rollout-approve", recorder.definitions[0].Name)
	require.Equal(t, sharedauthz.PermissionLevelWrite, recorder.definitions[0].Level)
	require.Equal(t, []sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization}, recorder.definitions[0].Scopes)
}

func TestReplacePluginCapabilitiesRouteUsesGatewayAuthenticatedIdentity(t *testing.T) {
	echoServer, server, finish := MockServer(t)
	defer finish()

	serviceUserID := userid.NewServiceUserTokenId()
	MockAuthorizationSuccess(server, serviceUserID, orgId, sharedauthz.PermissionPluginRegistrationWrite)
	recorder := &recordingPluginCapabilityRegistry{}
	server.PluginCapabilities = recorder
	request := httptest.NewRequest(http.MethodPut, "/orgs/"+orgId+"/plugins/dev.stellwerk.rollouts/capabilities", strings.NewReader(`{
		"capabilities":[{"name":"rollout-approve","display_name":"Approve rollout","description":"Approve a rollout.","category":"Progressive rollouts","level":"write","scopes":["organization"]}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("From", serviceUserID.String())
	response := httptest.NewRecorder()

	echoServer.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())
	require.Equal(t, "dev.stellwerk.rollouts", recorder.pluginID)
}

func TestReplacePluginCapabilitiesRouteRejectsAmbiguousDottedLocalName(t *testing.T) {
	echoServer, server, finish := MockServer(t)
	defer finish()

	serviceUserID := userid.NewServiceUserTokenId()
	recorder := &recordingPluginCapabilityRegistry{}
	server.PluginCapabilities = recorder
	request := httptest.NewRequest(http.MethodPut, "/orgs/"+orgId+"/plugins/dev.example/capabilities", strings.NewReader(`{
		"capabilities":[{"name":"reader.read","display_name":"Read","description":"Read plugin state.","category":"Plugin","level":"read","scopes":["organization"]}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("From", serviceUserID.String())
	response := httptest.NewRecorder()

	echoServer.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Empty(t, recorder.pluginID)
}

func pluginCapabilityRequest() ReplacePluginCapabilitiesRequestObject {
	return ReplacePluginCapabilitiesRequestObject{
		OrgId: orgId, PluginId: "dev.stellwerk.rollouts",
		Body: &PluginCapabilityRegistrationBody{Capabilities: []PluginCapabilityRegistration{{
			Name: "rollout-approve", DisplayName: "Approve rollout", Description: "Approve a rollout.",
			Category: "Progressive rollouts", Level: PluginCapabilityRegistrationLevelWrite,
			Scopes: []PluginCapabilityRegistrationScopes{PluginCapabilityRegistrationScopesOrganization},
		}}},
	}
}
