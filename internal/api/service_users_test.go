package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestListServiceUsers_Paginates(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()
	perPage := 2
	pageToken := uuid.NewString()
	nextPageToken := uuid.NewString()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListServiceUserTokens(gomock.Any(), nil, model.ListServiceUserTokensParams{
		OrgId:     orgId,
		PageToken: pageToken,
		PerPage:   perPage,
	}).Return([]model.ServiceUserToken{{
		Id:                    serviceUserId,
		DisplayName:           "automation",
		GeneratedAt:           now,
		GeneratedBy:           userId,
		CurrentTokenExpiresAt: now.Add(24 * time.Hour),
		ServiceUserRoles: []model.ServiceUserRole{{
			RoleId: roleId,
			Scope:  "project:example",
		}},
	}}, nextPageToken, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	response, err := s.ListServiceUsers(ctx, ListServiceUsersRequestObject{
		OrgId: orgId,
		Params: ListServiceUsersParams{
			PerPage: &perPage,
			Page:    &pageToken,
		},
	})
	require.NoError(t, err)
	require.Equal(t, ListServiceUsers200JSONResponse{
		Items: []ServiceUserSummary{{
			Id:                    serviceUserId,
			DisplayName:           "automation",
			GeneratedAt:           now,
			GeneratedBy:           userId,
			CurrentTokenExpiresAt: now.Add(24 * time.Hour),
			Roles: []ServiceUserRole{{
				Id:    roleId,
				Scope: ref.Ref("project:example"),
			}},
		}},
		NextPageToken: &nextPageToken,
	}, response)
}

func TestListServiceUsers_InvalidPageToken(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	pageToken := "invalid"

	MockAuthorizationSuccess(s, userId, orgId, "service_user_read")
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListServiceUserTokens(gomock.Any(), nil, model.ListServiceUserTokensParams{
		OrgId:     orgId,
		PageToken: pageToken,
	}).Return(nil, "", model.NewErrBadRequest("invalid page token"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	response, err := s.ListServiceUsers(ctx, ListServiceUsersRequestObject{
		OrgId: orgId,
		Params: ListServiceUsersParams{
			Page: &pageToken,
		},
	})
	require.Error(t, err)
	require.Nil(t, response)
}

func TestCreateServiceUser_NotOrgMember(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	MockAuthorizationFailure(s, userId, orgId)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.Error(t, err)
}

func TestCreateServiceUser_ServiceUserCannotCreateServiceUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, serviceUserId, orgId, "service_user_write")

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, serviceUserId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.NoError(t, err)
	require.Equal(t, CreateServiceUser400JSONResponse{N400BadRequestJSONResponse: Generate400Response("service users may not create service users")}, r)
}

func TestCreateServiceUser_Success_WithDefaultAdminRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	now := time.Now().UTC()

	existingRoles := []model.Role{
		{
			Id:          uuid.New(),
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   now,
			CreatedBy:   userId,
			Permissions: []string{"manage_all"},
		},
		{
			Id:          uuid.New(),
			OrgId:       orgId,
			DisplayName: RoleViewer,
			CreatedAt:   now,
			CreatedBy:   userId,
			Permissions: []string{"read_all"},
		},
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(existingRoles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, existingRoles[0].Id, roles[0].RoleId)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.NoError(t, err)

	response, ok := r.(CreateServiceUser201JSONResponse)
	require.True(t, ok)
	require.Equal(t, "Test Service User", response.DisplayName)
	require.Equal(t, userId, response.GeneratedBy)
	require.NotEmpty(t, response.Token)
	require.Equal(t, ServiceUserTokenPrefix, response.Token[:3])
}

func TestCreateServiceUser_Success_WithSeededRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	var seededRoles []model.Role

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().SeedRoles(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, roles []model.Role) error {
			seededRoles = roles
			return nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			adminRole := getRoleByDisplayName(seededRoles, RoleAdmin)
			require.NotNil(t, adminRole)
			require.Equal(t, adminRole.Id, roles[0].RoleId)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.NoError(t, err)
	require.IsType(t, CreateServiceUser201JSONResponse{}, r)
}

func TestCreateServiceUser_Success_WithCustomRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	customRoleId := uuid.New()

	customRoles := []ServiceUserRole{
		{Id: customRoleId},
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, customRoleId, roles[0].RoleId)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)
	require.IsType(t, CreateServiceUser201JSONResponse{}, r)
}

func TestCreateServiceUser_RoleNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	nonExistentRoleId := uuid.New()

	customRoles := []ServiceUserRole{
		{Id: nonExistentRoleId},
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(model.NewErrNotFound("role not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)
	require.Equal(t, CreateServiceUser409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, r)
}

func TestCreateServiceUser_DatabaseError_CreateToken(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		Return(nil, fmt.Errorf("database error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create service user token")
}

func TestCreateServiceUser_DatabaseError_ListRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(nil, fmt.Errorf("database error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list roles")
}

func TestDeleteServiceUser_NotOrgMember(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	MockAuthorizationFailure(s, userId, orgId)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.DeleteServiceUser(ctx, DeleteServiceUserRequestObject{
		OrgId:         orgId,
		ServiceUserId: userid.NewServiceUserTokenId(),
	})
	require.Error(t, err)
}

func TestDeleteServiceUser_ServiceUserNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteServiceUserToken(gomock.Any(), gomock.Any(), orgId, serviceUserId).
		Return(model.NewErrNotFound("service user not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.DeleteServiceUser(ctx, DeleteServiceUserRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
	})
	require.NoError(t, err)
	require.Equal(t, DeleteServiceUser404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, r)
}

func TestDeleteServiceUser_DeleteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteServiceUserToken(gomock.Any(), gomock.Any(), orgId, serviceUserId).
		Return(fmt.Errorf("delete error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.DeleteServiceUser(ctx, DeleteServiceUserRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to delete service user token")
}

func TestDeleteServiceUser_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteServiceUserToken(gomock.Any(), gomock.Any(), orgId, serviceUserId).
		Return(nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.DeleteServiceUser(ctx, DeleteServiceUserRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
	})
	require.NoError(t, err)
	require.Equal(t, DeleteServiceUser204Response{}, r)
}

func TestCreateServiceUser_NilScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()

	customRoles := []ServiceUserRole{
		{Id: roleId, Scope: nil}, // nil scope should be valid
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId, roles[0].RoleId)
			require.Empty(t, roles[0].Scope, "scope should not be set for nil scope")
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)

	response, ok := r.(CreateServiceUser201JSONResponse)
	require.True(t, ok)
	require.Equal(t, "Test Service User", response.DisplayName)
	require.Len(t, response.Roles, 1)
	require.Empty(t, response.Roles[0].Scope)
}

func TestCreateServiceUser_InvalidScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	invalidScope := "invalid-scope-format"

	customRoles := []ServiceUserRole{
		{Id: roleId, Scope: &invalidScope}, // Invalid scope format
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)

	badRequestResponse, ok := r.(CreateServiceUser400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "invalid scope")
	require.Contains(t, badRequestResponse.Message, invalidScope)
}

func TestCreateServiceUser_ValidProjectScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	projectId := uuid.New()
	validScope := "project:" + projectId.String()

	customRoles := []ServiceUserRole{
		{Id: roleId, Scope: &validScope}, // Valid project scope
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	// Mock CP client project validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId, roles[0].RoleId)
			require.Equal(t, validScope, roles[0].Scope)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)

	response, ok := r.(CreateServiceUser201JSONResponse)
	require.True(t, ok)
	require.Equal(t, "Test Service User", response.DisplayName)
	require.Len(t, response.Roles, 1)
	require.NotNil(t, response.Roles[0].Scope)
	require.Equal(t, validScope, *response.Roles[0].Scope)
}

func TestCreateServiceUser_ValidEnvironmentScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	envId := uuid.New()
	validScope := "env:" + envId.String()

	customRoles := []ServiceUserRole{
		{Id: roleId, Scope: &validScope}, // Valid environment scope
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	// Mock CP client environment validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, envId).
		Return(&cpclient.GetInternalEnvironmentByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId, roles[0].RoleId)
			require.Equal(t, validScope, roles[0].Scope)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)

	response, ok := r.(CreateServiceUser201JSONResponse)
	require.True(t, ok)
	require.Equal(t, "Test Service User", response.DisplayName)
	require.Len(t, response.Roles, 1)
	require.NotNil(t, response.Roles[0].Scope)
	require.Equal(t, validScope, *response.Roles[0].Scope)
}

func TestCreateServiceUser_ProjectNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	projectId := uuid.New()
	validScope := "project:" + projectId.String()

	customRoles := []ServiceUserRole{
		{Id: roleId, Scope: &validScope},
	}

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	// Mock CP client project not found
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserToken(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, token *model.ServiceUserToken) (*model.ServiceUserToken, error) {
			return token, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.CreateServiceUser(ctx, CreateServiceUserRequestObject{
		OrgId: orgId,
		Body: &CreateServiceUserJSONRequestBody{
			DisplayName:  "Test Service User",
			ExpiryInDays: 30,
			Roles:        &customRoles,
		},
	})
	require.NoError(t, err)

	badRequestResponse, ok := r.(CreateServiceUser400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "project in the scope")
	require.Contains(t, badRequestResponse.Message, "does not exist")
	require.Contains(t, badRequestResponse.Message, validScope)
}

func TestReplaceServiceUserRoles_NotOrgAdmin(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationFailure(s, userId, orgId)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: uuid.New()},
			},
		},
	})
	require.Error(t, err)
}

func TestReplaceServiceUserRoles_ServiceUserNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(nil, model.NewErrNotFound("service user not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: uuid.New()},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, ReplaceServiceUserRoles404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, r)
}

func TestReplaceServiceUserRoles_ServiceUserInDifferentOrg(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	differentOrgId := "different-org"

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(&model.ServiceUserToken{
			Id:                     serviceUserId,
			OrgId:                  differentOrgId, // Different org
			DisplayName:            "Test Service User",
			GeneratedAt:            time.Now().UTC(),
			GeneratedBy:            userId,
			CurrentTokenExpiresAt:  time.Now().UTC().Add(30 * 24 * time.Hour),
			CurrentTokenSha256Hash: []byte("hash"),
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: uuid.New()},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, ReplaceServiceUserRoles404JSONResponse{N404NotFoundJSONResponse: Generate404Response("service user not found")}, r)
}

func TestReplaceServiceUserRoles_Success_SingleRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(2), nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, serviceUserId, roles[0].ServiceUserId)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId, roles[0].RoleId)
			require.Empty(t, roles[0].Scope)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId},
			},
		},
	})
	require.NoError(t, err)

	response, ok := r.(ReplaceServiceUserRoles200JSONResponse)
	require.True(t, ok)
	require.Equal(t, serviceUserId, response.Id)
	require.Equal(t, "Test Service User", response.DisplayName)
	require.Equal(t, userId, response.GeneratedBy)
	require.Len(t, response.Roles, 1)
	require.Equal(t, roleId, response.Roles[0].Id)
	require.Empty(t, response.Roles[0].Scope)
}

func TestReplaceServiceUserRoles_Success_MultipleRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId1 := uuid.New()
	roleId2 := uuid.New()
	projectId := uuid.New()
	projectScope := "project:" + projectId.String()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	// Mock project validation for scoped role
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 2)
			require.Equal(t, serviceUserId, roles[0].ServiceUserId)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId1, roles[0].RoleId)
			require.Empty(t, roles[0].Scope)

			require.Equal(t, serviceUserId, roles[1].ServiceUserId)
			require.Equal(t, orgId, roles[1].OrgId)
			require.Equal(t, roleId2, roles[1].RoleId)
			require.Equal(t, projectScope, roles[1].Scope)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId1},
				{Id: roleId2, Scope: &projectScope},
			},
		},
	})
	require.NoError(t, err)

	response, ok := r.(ReplaceServiceUserRoles200JSONResponse)
	require.True(t, ok)
	require.Len(t, response.Roles, 2)
	require.Equal(t, roleId1, response.Roles[0].Id)
	require.Empty(t, response.Roles[0].Scope)
	require.Equal(t, roleId2, response.Roles[1].Id)
	require.NotNil(t, response.Roles[1].Scope)
	require.Equal(t, projectScope, *response.Roles[1].Scope)
}

func TestReplaceServiceUserRoles_RoleNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(model.NewErrNotFound("role not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, ReplaceServiceUserRoles409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, r)
}

func TestReplaceServiceUserRoles_InvalidScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	invalidScope := "invalid-scope-format"
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId, Scope: &invalidScope},
			},
		},
	})
	require.NoError(t, err)

	badRequestResponse, ok := r.(ReplaceServiceUserRoles400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "invalid scope")
	require.Contains(t, badRequestResponse.Message, invalidScope)
}

func TestReplaceServiceUserRoles_ProjectNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	projectId := uuid.New()
	projectScope := "project:" + projectId.String()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	// Mock project not found
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId, Scope: &projectScope},
			},
		},
	})
	require.NoError(t, err)

	badRequestResponse, ok := r.(ReplaceServiceUserRoles400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "project in the scope")
	require.Contains(t, badRequestResponse.Message, "does not exist")
}

func TestReplaceServiceUserRoles_ValidEnvironmentScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	envId := uuid.New()
	envScope := "env:" + envId.String()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(0), nil)

	// Mock environment validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, envId).
		Return(&cpclient.GetInternalEnvironmentByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{},
		}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, roles []model.ServiceUserRole) error {
			require.Len(t, roles, 1)
			require.Equal(t, serviceUserId, roles[0].ServiceUserId)
			require.Equal(t, orgId, roles[0].OrgId)
			require.Equal(t, roleId, roles[0].RoleId)
			require.Equal(t, envScope, roles[0].Scope)
			return nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId, Scope: &envScope},
			},
		},
	})
	require.NoError(t, err)

	response, ok := r.(ReplaceServiceUserRoles200JSONResponse)
	require.True(t, ok)
	require.Len(t, response.Roles, 1)
	require.Equal(t, roleId, response.Roles[0].Id)
	require.NotNil(t, response.Roles[0].Scope)
	require.Equal(t, envScope, *response.Roles[0].Scope)
}

func TestReplaceServiceUserRoles_BulkDeleteError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(0), fmt.Errorf("database error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId},
			},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to delete existing service user roles")
}

func TestReplaceServiceUserRoles_CreateRolesError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(fmt.Errorf("database error"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	_, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId},
			},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create service user roles")
}

func TestReplaceServiceUserRoles_DuplicateRoleConflict(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	serviceUserId := userid.NewServiceUserTokenId()
	roleId := uuid.New()
	now := time.Now().UTC()

	MockAuthorizationSuccess(s, userId, orgId, "service_user_write")

	serviceUser := &model.ServiceUserToken{
		Id:                     serviceUserId,
		OrgId:                  orgId,
		DisplayName:            "Test Service User",
		GeneratedAt:            now,
		GeneratedBy:            userId,
		CurrentTokenExpiresAt:  now.Add(30 * 24 * time.Hour),
		CurrentTokenSha256Hash: []byte("hash"),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserToken(gomock.Any(), gomock.Any(), serviceUserId).
		Return(serviceUser, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), gomock.Any(), model.BulkDeleteServiceUserRolesParams{
		ServiceUserId: opt.Of(serviceUserId),
		OrgId:         opt.Of(orgId),
	}).Return(int64(1), nil)

	// Simulate duplicate key constraint violation
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateServiceUserRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(model.NewErrConflict("duplicate service user role"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	r, err := s.ReplaceServiceUserRoles(ctx, ReplaceServiceUserRolesRequestObject{
		OrgId:         orgId,
		ServiceUserId: serviceUserId,
		Body: &ReplaceServiceUserRolesJSONRequestBody{
			Roles: []ServiceUserRole{
				{Id: roleId},
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, ReplaceServiceUserRoles409JSONResponse{N409ConflictJSONResponse: Generate409Response("duplicate service user role")}, r)
}
