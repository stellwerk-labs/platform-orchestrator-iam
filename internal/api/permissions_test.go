package api

import (
	"context"
	"net/http"
	"testing"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	projectId = "test-project"
	envId     = "test-environment"
)

func TestListProjectUsers_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	// Role IDs that will be returned by the database
	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// User IDs that have various permissions
	adminUser := uuid.New()
	deployerUser := uuid.New()
	viewerUser := uuid.New()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	// Mock database to return zed token
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: "test-token"}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups for different permission levels
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: adminUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: deployerUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: viewerUser.String()}}, "next-cursor", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)

	require.Len(t, result.Items, 3)
	require.NotNil(t, result.NextPageToken)
	require.Equal(t, "next-cursor", *result.NextPageToken)

	// Verify users are sorted and have correct roles
	userRoleMap := make(map[uuid.UUID]uuid.UUID)
	for _, item := range result.Items {
		userRoleMap[item.Id] = item.SubjectId
	}

	require.Equal(t, adminRoleId, userRoleMap[adminUser])
	require.Equal(t, deployerRoleId, userRoleMap[deployerUser])
	require.Equal(t, viewerRoleId, userRoleMap[viewerUser])
}

func TestListProjectUsers_WithPagination(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()
	cursor := "test-cursor"

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups with pagination cursor
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		Params: ListProjectUsersParams{
			Page: ref.Ref(cursor),
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)
	require.Empty(t, result.Items)
	require.Nil(t, result.NextPageToken)
}

func TestListProjectUsers_WithTypeFilter_User(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Create a mix of human users and service users
	humanUser1 := userid.NewHumanUserId()
	humanUser2 := userid.NewHumanUserId()
	serviceUser1 := userid.NewServiceUserTokenId()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning both human and service users
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser2.String()}}, "", nil)

	userTypeFilter := ListProjectUsersParamsTypeUser
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		Params: ListProjectUsersParams{
			Type: &userTypeFilter,
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)

	// Should only return human users, not service users
	require.Len(t, result.Items, 2)
	for _, item := range result.Items {
		require.Equal(t, UserWithRoleTypeUser, item.Type)
	}
}

func TestListProjectUsers_WithTypeFilter_ServiceUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Create a mix of human users and service users
	humanUser := userid.NewHumanUserId()
	serviceUser1 := userid.NewServiceUserTokenId()
	serviceUser2 := userid.NewServiceUserTokenId()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning both human and service users
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser2.String()}}, "", nil)

	serviceUserTypeFilter := ListProjectUsersParamsTypeServiceUser
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		Params: ListProjectUsersParams{
			Type: &serviceUserTypeFilter,
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)

	// Should only return service users, not human users
	require.Len(t, result.Items, 2)
	for _, item := range result.Items {
		require.Equal(t, UserWithRoleTypeServiceUser, item.Type)
	}
}

func TestListProjectUsers_ProjectNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectId := "non-existent-project"

	// Mock CP client to return 404
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers404JSONResponse)
	require.True(t, ok)
	require.Equal(t, "project not found", result.Message)
}

func TestListProjectUsers_InsufficientPermissions(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock user does NOT have permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(false, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers403JSONResponse)
	require.True(t, ok)
	require.Equal(t, "insufficient permissions to view project users as user can't view project", result.Message)
}

func TestListProjectUsers_EmptyResult(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning no subjects
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)
	require.Empty(t, result.Items)
	require.Nil(t, result.NextPageToken)
}

func TestListProjectUsers_RolePriority(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	projectUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// User that appears in all three permission levels - should get admin role
	userWithMultipleRoles := uuid.New()

	// Mock CP client to return project
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetProjectWithResponse(gomock.Any(), orgId, projectId).
		Return(&cpclient.GetProjectResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Project{Uuid: projectUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view project
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeProject, projectUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups - same user appears in all three levels
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeProject, projectUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListProjectUsers(ctx, ListProjectUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListProjectUsers200JSONResponse)
	require.True(t, ok)

	require.Len(t, result.Items, 1)
	// User should have admin role (highest priority)
	require.Equal(t, adminRoleId, result.Items[0].SubjectId)
	require.Equal(t, userWithMultipleRoles, result.Items[0].Id)
}

func TestListEnvironmentUsers_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	// Role IDs that will be returned by the database
	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// User IDs that have various permissions
	adminUser := uuid.New()
	deployerUser := uuid.New()
	viewerUser := uuid.New()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	// Mock database to return zed token
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: "test-token"}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups for different permission levels
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: adminUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: deployerUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, "", "test-token").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: viewerUser.String()}}, "next-cursor", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)

	require.Len(t, result.Items, 3)
	require.NotNil(t, result.NextPageToken)
	require.Equal(t, "next-cursor", *result.NextPageToken)

	// Verify users are sorted and have correct roles
	userRoleMap := make(map[uuid.UUID]uuid.UUID)
	for _, item := range result.Items {
		userRoleMap[item.Id] = item.SubjectId
	}

	require.Equal(t, adminRoleId, userRoleMap[adminUser])
	require.Equal(t, deployerRoleId, userRoleMap[deployerUser])
	require.Equal(t, viewerRoleId, userRoleMap[viewerUser])
}

func TestListEnvironmentUsers_WithPagination(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()
	cursor := "test-cursor"

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups with pagination cursor
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, cursor, "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
		Params: ListEnvironmentUsersParams{
			Page: ref.Ref(cursor),
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)
	require.Empty(t, result.Items)
	require.Nil(t, result.NextPageToken)
}

func TestListEnvironmentUsers_WithTypeFilter_User(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Create a mix of human users and service users
	humanUser1 := userid.NewHumanUserId()
	humanUser2 := userid.NewHumanUserId()
	serviceUser1 := userid.NewServiceUserTokenId()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning both human and service users
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser2.String()}}, "", nil)

	userTypeFilter := ListEnvironmentUsersParamsTypeUser
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
		Params: ListEnvironmentUsersParams{
			Type: &userTypeFilter,
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)

	// Should only return human users, not service users
	require.Len(t, result.Items, 2)
	for _, item := range result.Items {
		require.Equal(t, UserWithRoleTypeUser, item.Type)
	}
}

func TestListEnvironmentUsers_WithTypeFilter_ServiceUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Create a mix of human users and service users
	humanUser := userid.NewHumanUserId()
	serviceUser1 := userid.NewServiceUserTokenId()
	serviceUser2 := userid.NewServiceUserTokenId()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning both human and service users
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser1.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: humanUser.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: serviceUser2.String()}}, "", nil)

	serviceUserTypeFilter := ListEnvironmentUsersParamsTypeServiceUser
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
		Params: ListEnvironmentUsersParams{
			Type: &serviceUserTypeFilter,
		},
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)

	// Should only return service users, not human users
	require.Len(t, result.Items, 2)
	for _, item := range result.Items {
		require.Equal(t, UserWithRoleTypeServiceUser, item.Type)
	}
}

func TestListEnvironmentUsers_EnvironmentNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envId := "non-existent-env"

	// Mock CP client to return 404
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers404JSONResponse)
	require.True(t, ok)
	require.Equal(t, "environment not found", result.Message)
}

func TestListEnvironmentUsers_InsufficientPermissions(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock user does NOT have permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(false, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers403JSONResponse)
	require.True(t, ok)
	require.Equal(t, "insufficient permissions to view environment users as user can't view environment", result.Message)
}

func TestListEnvironmentUsers_EmptyResult(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups returning no subjects
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)
	require.Empty(t, result.Items)
	require.Nil(t, result.NextPageToken)
}

func TestListEnvironmentUsers_RolePriority(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	envUuid := uuid.New()

	adminRoleId := uuid.New()
	deployerRoleId := uuid.New()
	viewerRoleId := uuid.New()

	// User that appears in all three permission levels - should get admin role
	userWithMultipleRoles := uuid.New()

	// Mock CP client to return environment
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetEnvironmentWithResponse(gomock.Any(), orgId, projectId, envId).
		Return(&cpclient.GetEnvironmentResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Environment{Uuid: envUuid},
		}, nil)

	// Mock database to return roles
	roles := []model.Role{
		{Id: adminRoleId, DisplayName: RoleAdmin},
		{Id: deployerRoleId, DisplayName: RoleDeployer},
		{Id: viewerRoleId, DisplayName: RoleViewer},
	}
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Any(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock user has permission to view environment
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(gomock.Any(), spicedb.SubjectTypeUser, userId.String(), spicedb.PermissionRead, spicedb.ObjectTypeEnv, envUuid.String(), "").
		Return(true, nil)

	// Mock SpiceDB lookups - same user appears in all three levels
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionManage, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionWrite, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		LookupSubjects(gomock.Any(), spicedb.ObjectTypeEnv, envUuid.String(), spicedb.PermissionRead, "", "").
		Return([]*v1.ResolvedSubject{{SubjectObjectId: userWithMultipleRoles.String()}}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	resp, err := s.ListEnvironmentUsers(ctx, ListEnvironmentUsersRequestObject{
		OrgId:     orgId,
		ProjectId: projectId,
		EnvId:     envId,
	})

	require.NoError(t, err)
	result, ok := resp.(ListEnvironmentUsers200JSONResponse)
	require.True(t, ok)

	require.Len(t, result.Items, 1)
	// User should have admin role (highest priority)
	require.Equal(t, adminRoleId, result.Items[0].SubjectId)
	require.Equal(t, userWithMultipleRoles, result.Items[0].Id)
}
