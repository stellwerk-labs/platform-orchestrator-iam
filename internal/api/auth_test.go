package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCheckPermissions(t *testing.T) {
	t.Run("successful permission check with multiple permissions", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()

		uid := userid.NewHumanUserId()
		ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

		checks := []ResourcePermissionCheck{
			{Permission: "read", Resource: "organization:" + orgId},
			{Permission: "write", Resource: "organization:" + orgId},
		}

		s.Database.(*mockmodel.MockDatabaser).EXPECT().
			GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
			Return(nil, nil).Times(1)

		s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
			HasSubjectPermissionOnObj(gomock.Any(), spicedb.ObjectTypeUser, uid.String(), "read", spicedb.ObjectTypeOrg, orgId, gomock.Any()).
			Return(true, nil).Times(1)

		s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
			CheckBulkPermissions(gomock.Any(), gomock.Any()).
			Return([]*v1.CheckBulkPermissionsPair{
				{
					Request: &v1.CheckBulkPermissionsRequestItem{
						Permission: "read",
						Resource:   &v1.ObjectReference{ObjectType: "org", ObjectId: orgId},
					},
					Response: &v1.CheckBulkPermissionsPair_Item{
						Item: &v1.CheckBulkPermissionsResponseItem{
							Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
						},
					},
				},
				{
					Request: &v1.CheckBulkPermissionsRequestItem{
						Permission: "write",
						Resource:   &v1.ObjectReference{ObjectType: "org", ObjectId: orgId},
					},
					Response: &v1.CheckBulkPermissionsPair_Item{
						Item: &v1.CheckBulkPermissionsResponseItem{
							Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION,
						},
					},
				},
			}, nil).Times(1)

		r, err := s.CheckPermissions(ctx, CheckPermissionsRequestObject{
			Body: &checks,
		})
		require.NoError(t, err)

		resp, ok := r.(CheckPermissions200JSONResponse)
		require.True(t, ok)
		require.Len(t, resp.Items, 2)
		require.Equal(t, "read", resp.Items[0].PermissionCheck.Permission)
		require.Equal(t, "organization:"+orgId, resp.Items[0].PermissionCheck.Resource)
		require.True(t, resp.Items[0].Allowed)
		require.Equal(t, "write", resp.Items[1].PermissionCheck.Permission)
		require.Equal(t, "organization:"+orgId, resp.Items[1].PermissionCheck.Resource)
		require.False(t, resp.Items[1].Allowed)
	})

	t.Run("empty body returns 400", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()

		uid := userid.NewHumanUserId()
		ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

		emptyChecks := []ResourcePermissionCheck{}
		r, err := s.CheckPermissions(ctx, CheckPermissionsRequestObject{
			Body: &emptyChecks,
		})
		require.NoError(t, err)

		resp, ok := r.(CheckPermissions400JSONResponse)
		require.True(t, ok)
		require.Equal(t, "At least one permission check is required", resp.Message)
	})

	t.Run("nil body returns 400", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()

		uid := userid.NewHumanUserId()
		ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

		r, err := s.CheckPermissions(ctx, CheckPermissionsRequestObject{
			Body: nil,
		})
		require.NoError(t, err)

		resp, ok := r.(CheckPermissions400JSONResponse)
		require.True(t, ok)
		require.Equal(t, "At least one permission check is required", resp.Message)
	})

	t.Run("invalid resource format returns 400", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()

		uid := userid.NewHumanUserId()
		ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

		s.Database.(*mockmodel.MockDatabaser).EXPECT().
			GetOrgZedToken(gomock.Any(), gomock.Nil(), gomock.Any()).
			Return(nil, nil).
			Times(1)

		s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
			HasSubjectPermissionOnObj(gomock.Any(), spicedb.ObjectTypeUser, uid.String(), "read", spicedb.ObjectTypeOrg, orgId, gomock.Any()).
			Return(true, nil).
			Times(1)

		checks := []ResourcePermissionCheck{
			{Permission: "read", Resource: "invalid-format"},
		}

		r, err := s.CheckPermissions(ctx, CheckPermissionsRequestObject{
			Body: &checks,
		})
		require.NoError(t, err)

		resp, ok := r.(CheckPermissions400JSONResponse)
		require.True(t, ok)
		require.Contains(t, resp.Message, "Invalid resource format")
		require.Contains(t, resp.Message, "invalid-format")
	})

	t.Run("spicedb error is returned", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()

		uid := userid.NewHumanUserId()
		ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

		checks := []ResourcePermissionCheck{
			{Permission: "read", Resource: "organization:" + orgId},
		}

		s.Database.(*mockmodel.MockDatabaser).EXPECT().
			GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
			Return(nil, nil).Times(1)

		s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
			HasSubjectPermissionOnObj(gomock.Any(), spicedb.ObjectTypeUser, uid.String(), "read", spicedb.ObjectTypeOrg, orgId, gomock.Any()).
			Return(true, nil).Times(1)

		expectedErr := echo.NewHTTPError(http.StatusInternalServerError, "spicedb connection error")
		s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
			CheckBulkPermissions(gomock.Any(), gomock.Any()).
			Return(nil, expectedErr).Times(1)

		_, err := s.CheckPermissions(ctx, CheckPermissionsRequestObject{
			Body: &checks,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to check bulk permissions")
	})
}

func TestCheckPermissions_PermissionValidation(t *testing.T) {
	tests := []struct {
		name           string
		permission     string
		expectedStatus int
	}{
		// Valid permissions (3-64 chars, starts with lowercase, ends with lowercase/digit)
		{name: "valid simple permission", permission: "read", expectedStatus: http.StatusOK},
		{name: "valid permission with underscore", permission: "can_read", expectedStatus: http.StatusOK},
		{name: "valid permission with digits", permission: "read123", expectedStatus: http.StatusOK},
		{name: "valid permission with underscore and digits", permission: "can_read_v2", expectedStatus: http.StatusOK},
		{name: "valid minimum length (3 chars)", permission: "abc", expectedStatus: http.StatusOK},
		{name: "valid long permission", permission: "this_is_a_very_long_permission_name_that_is_still_valid_here12", expectedStatus: http.StatusOK},

		// Invalid permissions
		{name: "invalid empty permission", permission: "", expectedStatus: http.StatusBadRequest},
		{name: "invalid too short (1 char)", permission: "a", expectedStatus: http.StatusBadRequest},
		{name: "invalid too short (2 chars)", permission: "ab", expectedStatus: http.StatusBadRequest},
		{name: "invalid starts with digit", permission: "1read", expectedStatus: http.StatusBadRequest},
		{name: "invalid starts with underscore", permission: "_read", expectedStatus: http.StatusBadRequest},
		{name: "invalid ends with underscore", permission: "read_", expectedStatus: http.StatusBadRequest},
		{name: "invalid contains uppercase", permission: "Read", expectedStatus: http.StatusBadRequest},
		{name: "invalid contains hyphen", permission: "can-read", expectedStatus: http.StatusBadRequest},
		{name: "invalid contains space", permission: "can read", expectedStatus: http.StatusBadRequest},
		{name: "invalid contains special char", permission: "read!", expectedStatus: http.StatusBadRequest},
		{name: "invalid too long (65 chars)", permission: "this_is_a_very_long_permission_name_that_exceeds_the_maximum_len1", expectedStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, s, fin := MockServer(t)
			defer fin()
			s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

			uid := userid.NewHumanUserId()

			// Only set up mocks for valid permission cases that will pass validation
			if tt.expectedStatus == http.StatusOK {
				s.Database.(*mockmodel.MockDatabaser).EXPECT().
					GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
					Return(nil, nil).Times(1)

				s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
					HasSubjectPermissionOnObj(gomock.Any(), spicedb.ObjectTypeUser, uid.String(), tt.permission, spicedb.ObjectTypeOrg, orgId, gomock.Any()).
					Return(true, nil).Times(1)

				s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
					CheckBulkPermissions(gomock.Any(), gomock.Any()).
					Return([]*v1.CheckBulkPermissionsPair{
						{
							Request: &v1.CheckBulkPermissionsRequestItem{
								Permission: tt.permission,
								Resource:   &v1.ObjectReference{ObjectType: "org", ObjectId: orgId},
							},
							Response: &v1.CheckBulkPermissionsPair_Item{
								Item: &v1.CheckBulkPermissionsResponseItem{
									Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
								},
							},
						},
					}, nil).Times(1)
			}

			body := `[{"permission":"` + tt.permission + `","resource":"organization:` + orgId + `"}]`

			req := httptest.NewRequest(http.MethodPost, "/auth/check-permissions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("From", uid.String())

			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)
			assert.Equal(t, tt.expectedStatus, resp.Code, "unexpected status for permission %q: %s", tt.permission, resp.Body.String())
		})
	}
}

func TestCheckPermissions_ResourceValidation(t *testing.T) {
	tests := []struct {
		name           string
		resource       string
		expectedStatus int
	}{
		// Valid resources (object ID allows: a-zA-Z0-9/_|\-=+)
		{name: "valid organization", resource: "organization:my-org", expectedStatus: http.StatusOK},
		{name: "valid organization with numbers", resource: "organization:my-polished-crow-1290", expectedStatus: http.StatusOK},
		{name: "valid project with uuid", resource: "project:01234567-89ab-cdef-0123-456789abcdef", expectedStatus: http.StatusOK},
		{name: "valid env with uuid", resource: "env:01234567-89ab-cdef-0123-456789abcdef", expectedStatus: http.StatusOK},
		{name: "valid with underscore", resource: "organization:my_org", expectedStatus: http.StatusOK},
		{name: "valid with slash", resource: "organization:my/org", expectedStatus: http.StatusOK},
		{name: "valid with pipe", resource: "organization:my|org", expectedStatus: http.StatusOK},
		{name: "valid with equals", resource: "organization:my=org", expectedStatus: http.StatusOK},
		{name: "valid with plus", resource: "organization:my+org", expectedStatus: http.StatusOK},
		{name: "valid with uppercase", resource: "organization:My-Org", expectedStatus: http.StatusOK},

		// Invalid resources
		{name: "invalid empty object id", resource: "organization:", expectedStatus: http.StatusBadRequest},
		{name: "invalid resource type", resource: "invalid:my-org", expectedStatus: http.StatusBadRequest},
		{name: "invalid no colon", resource: "organizationmy-org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with space", resource: "organization:my org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with @", resource: "organization:my@org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with !", resource: "organization:my!org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with #", resource: "organization:my#org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with %", resource: "organization:my%org", expectedStatus: http.StatusBadRequest},
		{name: "invalid with &", resource: "organization:my&org", expectedStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, s, fin := MockServer(t)
			defer fin()
			s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

			uid := userid.NewHumanUserId()

			// Only set up mocks for valid resource cases that will pass validation
			if tt.expectedStatus == http.StatusOK {
				s.Database.(*mockmodel.MockDatabaser).EXPECT().
					GetOrgZedToken(gomock.Any(), gomock.Nil(), gomock.Any()).
					Return(nil, nil).Times(1)

				s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
					HasSubjectPermissionOnObj(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(true, nil).Times(1)

				s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
					CheckBulkPermissions(gomock.Any(), gomock.Any()).
					Return([]*v1.CheckBulkPermissionsPair{
						{
							Request: &v1.CheckBulkPermissionsRequestItem{
								Permission: "read",
								Resource:   &v1.ObjectReference{ObjectType: "org", ObjectId: "test"},
							},
							Response: &v1.CheckBulkPermissionsPair_Item{
								Item: &v1.CheckBulkPermissionsResponseItem{
									Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
								},
							},
						},
					}, nil).Times(1)
			}

			body := `[{"permission":"read","resource":"` + tt.resource + `"}]`

			req := httptest.NewRequest(http.MethodPost, "/auth/check-permissions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("From", uid.String())

			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)
			assert.Equal(t, tt.expectedStatus, resp.Code, "unexpected status for resource %q: %s", tt.resource, resp.Body.String())
		})
	}
}
