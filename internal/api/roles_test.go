package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	usererrors "github.com/stellwerk-labs/platform-orchestrator-iam/internal/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestGetRole_NotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()

	MockAuthorizationSuccess(s, userId, orgId, "read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).Return(nil, model.NewErrNotFound("role not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.GetRole(ctx, GetRoleRequestObject{
		OrgId:  orgId,
		RoleId: roleId,
	})
	require.NoError(t, err)
	require.Equal(t, GetRole404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, r)
}

func TestGetRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	role := &model.Role{
		Id:          roleId,
		OrgId:       orgId,
		DisplayName: "Role 1",
		CreatedAt:   time.Now(),
		CreatedBy:   userId,
		Permissions: []string{"manage_all", "read_all"},
	}

	MockAuthorizationSuccess(s, userId, orgId, "read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).Return(role, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.GetRole(ctx, GetRoleRequestObject{
		OrgId:  orgId,
		RoleId: roleId,
	})
	require.NoError(t, err)
	require.Equal(t, GetRole200JSONResponse{
		Id:          role.Id,
		DisplayName: role.DisplayName,
		CreatedAt:   role.CreatedAt,
		CreatedBy:   role.CreatedBy,
		Permissions: role.Permissions,
	}, r)
}

func TestListRoles_empty(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	MockAuthorizationSuccess(s, userId, orgId, "read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return([]model.Role{}, nil)
	var seededRoles []model.Role
	s.Database.(*mockmodel.MockDatabaser).EXPECT().SeedRoles(gomock.Any(), gomock.Not(nil), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, roles []model.Role) error {
			seededRoles = roles
			return nil
		})
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ListRoles(ctx, ListRolesRequestObject{
		OrgId: orgId,
	})
	require.NoError(t, err)
	require.Len(t, seededRoles, 3)
	require.Equal(t, ListRoles200JSONResponse{Items: []Role{
		{
			Id:          seededRoles[0].Id,
			DisplayName: seededRoles[0].DisplayName,
			CreatedAt:   seededRoles[0].CreatedAt,
			CreatedBy:   seededRoles[0].CreatedBy,
			Permissions: seededRoles[0].Permissions,
			IsSystem:    true,
		},
		{
			Id:          seededRoles[1].Id,
			DisplayName: seededRoles[1].DisplayName,
			CreatedAt:   seededRoles[1].CreatedAt,
			CreatedBy:   seededRoles[1].CreatedBy,
			Permissions: seededRoles[1].Permissions,
			IsSystem:    true,
		},
		{
			Id:          seededRoles[2].Id,
			DisplayName: seededRoles[2].DisplayName,
			CreatedAt:   seededRoles[2].CreatedAt,
			CreatedBy:   seededRoles[2].CreatedBy,
			Permissions: seededRoles[2].Permissions,
			IsSystem:    true,
		},
	}}, r)
}

func TestListRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	role1 := model.Role{
		Id:          uuid.New(),
		OrgId:       orgId,
		DisplayName: "Admin",
		CreatedAt:   time.Now().Add(-time.Hour),
		CreatedBy:   userId,
		Permissions: []string{"manage_all"},
	}
	role2 := model.Role{
		Id:          uuid.New(),
		OrgId:       orgId,
		DisplayName: "Viewer",
		CreatedAt:   time.Now(),
		CreatedBy:   userId,
		Permissions: []string{"read_all"},
	}
	MockAuthorizationSuccess(s, userId, orgId, "read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return([]model.Role{role1, role2}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ListRoles(ctx, ListRolesRequestObject{
		OrgId: orgId,
	})
	require.NoError(t, err)
	require.Equal(t, ListRoles200JSONResponse{
		Items: []Role{
			{
				Id:          role1.Id,
				DisplayName: role1.DisplayName,
				CreatedAt:   role1.CreatedAt,
				CreatedBy:   role1.CreatedBy,
				Permissions: role1.Permissions,
			},
			{
				Id:          role2.Id,
				DisplayName: role2.DisplayName,
				CreatedAt:   role2.CreatedAt,
				CreatedBy:   role2.CreatedBy,
				Permissions: role2.Permissions,
			},
		},
	}, r)

}

func TestCreateRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	MockAuthorizationSuccess(s, userId, orgId, "manage")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateRole(gomock.Any(), nil, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, role *model.Role) (*model.Role, error) {
			require.Equal(t, orgId, role.OrgId)
			require.Equal(t, "Release Operator", role.DisplayName)
			require.Equal(t, []string{"deployment_cancel", "write_all"}, role.Permissions)
			require.False(t, role.IsSystem)
			return role, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	response, err := s.CreateRole(ctx, CreateRoleRequestObject{OrgId: orgId, Body: &RoleWriteBody{
		DisplayName: " Release Operator ",
		Permissions: []string{"write_all", "deployment_cancel", "write_all"},
	}})
	require.NoError(t, err)
	created, ok := response.(CreateRole201JSONResponse)
	require.True(t, ok)
	require.Equal(t, "Release Operator", created.DisplayName)
	require.Equal(t, []string{"deployment_cancel", "write_all"}, created.Permissions)
	require.False(t, created.IsSystem)
}

func TestUpdateSystemRoleIsRejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	MockAuthorizationSuccess(s, userId, orgId, "manage")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).
		Return(&model.Role{Id: roleId, OrgId: orgId, DisplayName: RoleAdmin, IsSystem: true}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	response, err := s.UpdateRole(ctx, UpdateRoleRequestObject{OrgId: orgId, RoleId: roleId, Body: &RoleWriteBody{
		DisplayName: "Changed Admin", Permissions: []string{"read_all"},
	}})
	require.NoError(t, err)
	_, conflict := response.(UpdateRole409JSONResponse)
	require.True(t, conflict)
}

func TestDeleteCustomRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	MockAuthorizationSuccess(s, userId, orgId, "manage")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetRole(gomock.Any(), nil, orgId, roleId).
		Return(&model.Role{Id: roleId, OrgId: orgId, DisplayName: "Auditor"}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteRole(gomock.Any(), nil, orgId, roleId).Return(nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	response, err := s.DeleteRole(ctx, DeleteRoleRequestObject{OrgId: orgId, RoleId: roleId})
	require.NoError(t, err)
	require.Equal(t, DeleteRole204Response{}, response)
}

func TestIsScopeValidForRole(t *testing.T) {
	stringPtr := func(s string) *string { return &s }

	tests := []struct {
		name          string
		scope         *string
		setupMock     func(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
		expectedValid bool
		expectError   bool
		errorType     string // "user" or "system"
	}{
		{
			name:          "nil scope is valid",
			scope:         nil,
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: true,
			expectError:   false,
		},
		{
			name:          "empty scope is valid",
			scope:         stringPtr(""),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: true,
			expectError:   false,
		},
		{
			name:  "valid project scope",
			scope: stringPtr("project:" + uuid.New().String()),
			setupMock: func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {
				m.EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, gomock.Any()).
					Return(&cpclient.GetInternalProjectByUuidResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
						JSON200:      &cpclient.Project{},
					}, nil)
			},
			expectedValid: true,
			expectError:   false,
		},
		{
			name:  "valid environment scope",
			scope: stringPtr("env:" + uuid.New().String()),
			setupMock: func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {
				m.EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, gomock.Any()).
					Return(&cpclient.GetInternalEnvironmentByUuidResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
						JSON200:      &cpclient.Environment{},
					}, nil)
			},
			expectedValid: true,
			expectError:   false,
		},
		{
			name:          "invalid scope - missing colon",
			scope:         stringPtr("project"),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - too many colons",
			scope:         stringPtr("project:id:extra"),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - invalid resource kind",
			scope:         stringPtr("organization:" + uuid.New().String()),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - invalid UUID",
			scope:         stringPtr("project:not-a-uuid"),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - empty resource kind",
			scope:         stringPtr(":" + uuid.New().String()),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - empty UUID",
			scope:         stringPtr("project:"),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:          "invalid scope - valid UUID but missing resource kind",
			scope:         stringPtr(uuid.New().String()),
			setupMock:     func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:  "project not found",
			scope: stringPtr("project:" + uuid.New().String()),
			setupMock: func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {
				m.EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, gomock.Any()).
					Return(&cpclient.GetInternalProjectByUuidResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					}, nil)
			},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:  "environment not found",
			scope: stringPtr("env:" + uuid.New().String()),
			setupMock: func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {
				m.EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, gomock.Any()).
					Return(&cpclient.GetInternalEnvironmentByUuidResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					}, nil)
			},
			expectedValid: false,
			expectError:   true,
			errorType:     "user",
		},
		{
			name:  "project API error",
			scope: stringPtr("project:" + uuid.New().String()),
			setupMock: func(m *mockplatformorchestratorcp.MockClientWithResponsesInterface) {
				m.EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, gomock.Any()).
					Return(&cpclient.GetInternalProjectByUuidResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusInternalServerError},
					}, nil)
			},
			expectedValid: false,
			expectError:   true,
			errorType:     "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCpClient := mockplatformorchestratorcp.NewMockClientWithResponsesInterface(ctrl)
			tt.setupMock(mockCpClient)

			result, err := isScopeValidForRole(t.Context(), tt.scope, orgId, mockCpClient)

			require.Equal(t, tt.expectedValid, result)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorType == "user" {
					var userErr *usererrors.UserError
					require.ErrorAs(t, err, &userErr, "expected user error but got: %v", err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
