package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests go through the full Echo route stack (MapRoutes), not the
// handlers directly, because the property under test lives in the middleware
// wiring: discovery endpoints must be reachable with NO From header (RFC 7644
// §4; Entra's SCIM Validator probes them without a token), while every Users
// and Groups route keeps demanding authentication.

func TestScimDiscovery_UnauthenticatedAccessAllowed(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	paths := []string{
		"/scim/v2/orgs/test-org/ServiceProviderConfig",
		"/scim/v2/orgs/test-org/Schemas",
		"/scim/v2/orgs/test-org/Schemas/" + scimSchemaIdUser,
		"/scim/v2/orgs/test-org/ResourceTypes",
		"/scim/v2/orgs/test-org/ResourceTypes/" + scimResourceTypeUser,
	}
	for _, path := range paths {
		// No From header at all — the request is anonymous.
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "discovery path %s must not require auth; body: %s", path, rec.Body.String())
	}
}

func TestScimUsersAndGroups_StillRequireAuthentication(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	requests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/scim/v2/orgs/test-org/Users"},
		{http.MethodPost, "/scim/v2/orgs/test-org/Users"},
		{http.MethodGet, fmt.Sprintf("/scim/v2/orgs/test-org/Users/%s", "00000000-0000-0000-0000-000000000001")},
		{http.MethodGet, "/scim/v2/orgs/test-org/Groups"},
		{http.MethodPost, "/scim/v2/orgs/test-org/Groups"},
		{http.MethodDelete, fmt.Sprintf("/scim/v2/orgs/test-org/Groups/%s", "00000000-0000-0000-0000-000000000001")},
	}
	for _, r := range requests {
		req := httptest.NewRequest(r.method, r.path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s must 401 without a From header", r.method, r.path) {
			var errBody scimError
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody), "401 must carry a SCIM error envelope")
			assert.Equal(t, "401", errBody.Status)
		}
	}
}
