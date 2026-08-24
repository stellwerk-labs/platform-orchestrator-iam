package api

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"

	platformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

var (
	orgId        string = "test-org"
	invalidScope string = "invalid-scope-format"
)

func TestInternalCreateOrgMembership_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	expectedMembership := &model.Membership{
		Id:          uuid.New(),
		CreatedAt:   time.Now().UTC(),
		OrgId:       orgId,
		UserId:      userId,
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     uuid.New().String(),
		Role:        opt.Of(uuid.MustParse(uuid.New().String())),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			membership.Id = expectedMembership.Id
			membership.CreatedAt = expectedMembership.CreatedAt
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     expectedMembership.Subject,
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)
	require.Equal(t, userId, successResponse.UserId)
	require.Equal(t, user.DisplayName, successResponse.UserDisplayName)
	require.Equal(t, user.PrimaryEmailAddress.Ref(), successResponse.UserPrimaryEmailAddress)
}

func TestInternalCreateOrgMembership_UserNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(nil, model.NewErrNotFound("user not found"))

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     uuid.New().String(),
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	conflictResponse, ok := response.(InternalCreateOrgMembership409JSONResponse)
	require.True(t, ok)
	require.Equal(t, "user not found", conflictResponse.Message)
}

func TestInternalCreateOrgMembership_VirtualGroupOwners(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	adminRoleId := uuid.New()
	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: RoleAdmin,
			Permissions: []string{PermissionsManageAll},
		},
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Not(nil), orgId).Return(roles, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			// Verify that subject was converted to admin role ID
			require.Equal(t, adminRoleId.String(), membership.Subject)
			require.Equal(t, model.MembershipSubjectTypeRole, membership.SubjectType)
			val, err := membership.Role.Value()
			require.NoError(t, err)
			require.Equal(t, adminRoleId, val)
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeVirtualGroup,
			Subject:     model.MembershipSubjectOrganizationOwners,
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	_, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)
}

func TestInternalCreateOrgMembership_VirtualGroupOwners_NoRoles_SeedRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Not(nil), orgId).Return([]model.Role{}, nil)

	var seededRoles []model.Role
	s.Database.(*mockmodel.MockDatabaser).EXPECT().SeedRoles(gomock.Any(), gomock.Not(nil), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, _ string, roles []model.Role) error {
			seededRoles = roles
			return nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			// Find the admin role from seeded roles
			var adminRole *model.Role
			for i := range seededRoles {
				if seededRoles[i].DisplayName == RoleAdmin {
					adminRole = &seededRoles[i]
					break
				}
			}
			require.NotNil(t, adminRole)
			require.Equal(t, adminRole.Id.String(), membership.Subject)
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeVirtualGroup,
			Subject:     model.MembershipSubjectOrganizationOwners,
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	_, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)

	// Verify roles were seeded correctly
	require.Len(t, seededRoles, 3)
	for _, roleName := range []string{RoleAdmin, RoleViewer, RoleDeployer} {
		require.True(t, slices.ContainsFunc(seededRoles, func(rl model.Role) bool {
			return rl.DisplayName == roleName
		}))
	}

}

func TestInternalCreateOrgMembership_NilScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	roleId := uuid.New()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	// Mock create membership - verify nil scope is passed
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			require.Empty(t, membership.Scope, "scope should be empty string for nil scope")
			membership.Id = uuid.New()
			membership.CreatedAt = time.Now().UTC()
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     roleId.String(),
			Scope:       nil, // nil scope should be valid
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)
	require.Equal(t, userId, successResponse.UserId)
}

func TestInternalCreateOrgMembership_InvalidScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	roleId := uuid.New()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     roleId.String(),
			Scope:       &invalidScope, // Invalid scope format
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	badRequestResponse, ok := response.(InternalCreateOrgMembership400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "invalid scope")
	require.Contains(t, badRequestResponse.Message, invalidScope)
}

func TestInternalCreateOrgMembership_ValidProjectScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	roleId := uuid.New()
	projectId := uuid.New()
	validScope := "project:" + projectId.String()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	// Mock CP client project validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&platformorchestratorcp.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &platformorchestratorcp.Project{},
		}, nil)

	// Mock create membership - verify scope is set
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			require.Equal(t, validScope, membership.Scope)
			membership.Id = uuid.New()
			membership.CreatedAt = time.Now().UTC()
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     roleId.String(),
			Scope:       &validScope, // Valid project scope
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)
	require.Equal(t, userId, successResponse.UserId)
}

func TestInternalCreateOrgMembership_ValidEnvironmentScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	roleId := uuid.New()
	envId := uuid.New()
	validScope := "env:" + envId.String()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	// Mock CP client environment validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalEnvironmentByUuidWithResponse(gomock.Any(), orgId, envId).
		Return(&platformorchestratorcp.GetInternalEnvironmentByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &platformorchestratorcp.Environment{},
		}, nil)

	// Mock create membership - verify scope is set
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			require.Equal(t, validScope, membership.Scope)
			membership.Id = uuid.New()
			membership.CreatedAt = time.Now().UTC()
			return membership, nil
		})

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     roleId.String(),
			Scope:       &validScope, // Valid environment scope
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(InternalCreateOrgMembership201JSONResponse)
	require.True(t, ok)
	require.Equal(t, userId, successResponse.UserId)
}

func TestInternalCreateOrgMembership_ProjectNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := uuid.New()
	roleId := uuid.New()
	projectId := uuid.New()
	validScope := "project:" + projectId.String()

	user := &model.User{
		Id:                  userId,
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).
		Return(&platformorchestratorcp.GetInternalOrganizationResponse{HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &platformorchestratorcp.InternalOrganization{Id: orgId}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), userId).Return(user, nil)

	// Mock CP client project not found
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&platformorchestratorcp.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	ctx := context.Background()
	request := InternalCreateOrgMembershipRequestObject{
		OrgId: orgId,
		Body: &InternalCreateOrgMembershipJSONRequestBody{
			UserId:      userId,
			SubjectType: SubjectTypeRole,
			Subject:     roleId.String(),
			Scope:       &validScope,
		},
	}

	response, err := s.InternalCreateOrgMembership(ctx, request)
	require.NoError(t, err)

	badRequestResponse, ok := response.(InternalCreateOrgMembership400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "project in the scope")
	require.Contains(t, badRequestResponse.Message, "does not exist")
	require.Contains(t, badRequestResponse.Message, validScope)
}

func TestListOrgMemberships_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	membership1 := model.MembershipWithUserMetadata{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      uuid.New(),
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserDisplayName:         "User 1",
		UserPrimaryEmailAddress: opt.Of("user1@example.com"),
	}

	membership2 := model.MembershipWithUserMetadata{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      uuid.New(),
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserDisplayName:         "User 2",
		UserPrimaryEmailAddress: opt.Of("user2@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_read")

	// Mock membership list
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMemberships(gomock.Any(), nil, model.ListMembershipsParams{OrgId: &orgId}).
		Return([]model.MembershipWithUserMetadata{membership1, membership2}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ListOrgMembershipsRequestObject{OrgId: orgId}

	response, err := s.ListOrgMemberships(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(ListOrgMemberships200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 2)

	require.Equal(t, membership1.Id, successResponse.Items[0].Id)
	require.Equal(t, membership1.UserDisplayName, successResponse.Items[0].UserDisplayName)
	require.Equal(t, membership2.Id, successResponse.Items[1].Id)
	require.Equal(t, membership2.UserDisplayName, successResponse.Items[1].UserDisplayName)
}

func TestListUserMemberships_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	membership1 := model.MembershipWithUserMetadata{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       "org-1",
			UserId:      userId,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
	}

	membership2 := model.MembershipWithUserMetadata{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       "org-2",
			UserId:      userId,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMemberships(gomock.Any(), nil, model.ListMembershipsParams{UserId: &userId}).
		Return([]model.MembershipWithUserMetadata{membership1, membership2}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ListUserMembershipsRequestObject{UserId: userId}

	response, err := s.ListUserMemberships(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(ListUserMemberships200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 2)

	require.Equal(t, membership1.Id, successResponse.Items[0].Id)
	require.Equal(t, membership1.OrgId, successResponse.Items[0].OrgId)
	require.Equal(t, membership2.Id, successResponse.Items[1].Id)
	require.Equal(t, membership2.OrgId, successResponse.Items[1].OrgId)
}

func TestDeleteOrgMembership_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	membershipId := uuid.New()
	roleId := uuid.New()
	membership := &model.Membership{
		Id:          membershipId,
		OrgId:       orgId,
		UserId:      uuid.New(),
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     roleId.String(),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetRole(gomock.Any(), gomock.Any(), orgId, roleId).Return(&model.Role{
		Id:          roleId,
		DisplayName: RoleAdmin,
		Permissions: []string{PermissionsManageAll},
	}, nil).AnyTimes()

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{OrgId: &orgId, SubjectType: &membership.SubjectType, Subject: &membership.Subject}).
		Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{OrgId: orgId, UserId: userId}}, {Membership: model.Membership{OrgId: orgId, UserId: userid.NewHumanUserId()}}}, nil).Times(1)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetMembership(gomock.Any(), gomock.Any(), membershipId).
		Return(membership, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		DeleteMembership(gomock.Any(), gomock.Any(), membershipId).
		Return(nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := DeleteOrgMembershipRequestObject{
		OrgId:        orgId,
		MembershipId: membershipId,
	}

	response, err := s.DeleteOrgMembership(ctx, request)
	require.NoError(t, err)

	_, ok := response.(DeleteOrgMembership204Response)
	require.True(t, ok)
}

func TestDeleteOrgMembership_MembershipNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	membershipId := uuid.New()

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock membership not found
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetMembership(gomock.Any(), gomock.Any(), membershipId).
		Return(nil, model.NewErrNotFound("membership not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := DeleteOrgMembershipRequestObject{
		OrgId:        orgId,
		MembershipId: membershipId,
	}

	response, err := s.DeleteOrgMembership(ctx, request)
	require.NoError(t, err)

	notFoundResponse, ok := response.(DeleteOrgMembership404JSONResponse)
	require.True(t, ok)
	require.Equal(t, "membership not found", notFoundResponse.Message)
}

func TestDeleteOrgMembership_CannotDeleteLastAdmin(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	membershipId := uuid.New()
	roleId := uuid.New()
	role := &model.Role{
		Id:          roleId,
		DisplayName: RoleAdmin,
		Permissions: []string{PermissionsManageAll},
	}
	membership := &model.Membership{
		Id:          membershipId,
		OrgId:       orgId,
		UserId:      uuid.New(),
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     roleId.String(),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock get membership
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetMembership(gomock.Any(), gomock.Any(), membershipId).
		Return(membership, nil)

	// Mock get role
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetRole(gomock.Any(), gomock.Any(), orgId, roleId).
		Return(role, nil)

	// Mock list memberships for admin role check - return only this membership
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
			OrgId:       &orgId,
			SubjectType: &membership.SubjectType,
			Subject:     &membership.Subject,
		}).
		Return([]model.MembershipWithUserMetadata{{Membership: *membership}}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := DeleteOrgMembershipRequestObject{
		OrgId:        orgId,
		MembershipId: membershipId,
	}

	response, err := s.DeleteOrgMembership(ctx, request)
	require.NoError(t, err)

	conflictResponse, ok := response.(DeleteOrgMembership409JSONResponse)
	require.True(t, ok)
	require.Equal(t, "cannot delete the only remaining admin membership", conflictResponse.Message)
}

func TestSeedAdminViewerRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	tx := &mockmodel.MockTxWithCommit{}
	// Mock SeedRoles call
	var seededRoles []model.Role
	s.Database.(*mockmodel.MockDatabaser).EXPECT().SeedRoles(gomock.Any(), tx, orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, _ string, roles []model.Role) error {
			seededRoles = roles
			return nil
		})

	ctx := context.Background()
	roles, err := s.seedBuiltinOrgRoles(ctx, s.Logger, tx, orgId)
	require.NoError(t, err)

	require.Len(t, roles, 3)
	require.Len(t, seededRoles, 3)

	// Verify admin role
	adminRole := getRoleByDisplayName(roles, RoleAdmin)
	require.NotNil(t, adminRole)
	require.Equal(t, RoleAdmin, adminRole.DisplayName)
	require.Contains(t, adminRole.Permissions, PermissionsManageAll)
	require.Equal(t, userid.InternalSystemUuid, adminRole.CreatedBy)

	// Verify viewer role
	viewerRole := getRoleByDisplayName(roles, RoleViewer)
	require.NotNil(t, viewerRole)
	require.Equal(t, RoleViewer, viewerRole.DisplayName)
	require.Contains(t, viewerRole.Permissions, PermissionsReadAll)
	require.Equal(t, userid.InternalSystemUuid, viewerRole.CreatedBy)
}

func TestReplaceOrgUserMemberships_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	roleId1 := uuid.New()
	roleId2 := uuid.New()

	targetUser := &model.User{
		Id:                  uuid.New(),
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock existing memberships check (user is member of org)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUser.Id,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUser.Id,
		},
		UserDisplayName:         targetUser.DisplayName,
		UserPrimaryEmailAddress: targetUser.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUser.Id), OrgId: opt.Of(orgId)}).Return(int64(2), nil)

	// Mock create new memberships
	expectedMembership1 := &model.Membership{
		Id:          uuid.New(),
		CreatedAt:   time.Now().UTC(),
		OrgId:       orgId,
		UserId:      targetUser.Id,
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     roleId1.String(),
		Role:        opt.Of(roleId1),
	}

	expectedMembership2 := &model.Membership{
		Id:          uuid.New(),
		CreatedAt:   time.Now().UTC(),
		OrgId:       orgId,
		UserId:      targetUser.Id,
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     roleId2.String(),
		Role:        opt.Of(roleId2),
	}

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			if membership.Subject == roleId1.String() {
				membership.Id = expectedMembership1.Id
				membership.CreatedAt = expectedMembership1.CreatedAt
			} else {
				membership.Id = expectedMembership2.Id
				membership.CreatedAt = expectedMembership2.CreatedAt
			}
			return membership, nil
		}).Times(2)

	// Prepare request
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUser.Id,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId1.String(),
				},
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId2.String(),
				},
			},
		},
	}

	// Call replace memberships
	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(ReplaceOrgUserMemberships200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 2)
	require.Equal(t, orgId, successResponse.Items[0].OrgId)
	require.Equal(t, orgId, successResponse.Items[1].OrgId)
}

func TestReplaceOrgUserMemberships_UserNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	targetUserId := uuid.New()

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock user not found (no memberships)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUserId,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUserId,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     uuid.New().String(),
				},
			},
		},
	}

	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	notFoundResponse, ok := response.(ReplaceOrgUserMemberships404JSONResponse)
	require.True(t, ok)
	require.Equal(t, "user not found", notFoundResponse.Message)
}

func TestReplaceOrgUserMemberships_RoleNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	targetUserId := uuid.New()
	roleId := uuid.New()

	user := &model.User{
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock existing memberships check (user is member of org)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUserId,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUserId,
		},
		UserDisplayName:         user.DisplayName,
		UserPrimaryEmailAddress: user.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUserId), OrgId: opt.Of(orgId)}).Return(int64(0), nil)

	// Mock create membership fails with role not found
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, model.NewErrNotFound("role not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUserId,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId.String(),
				},
			},
		},
	}

	// Call replace memberships
	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	conflictResponse, ok := response.(ReplaceOrgUserMemberships409JSONResponse)
	require.True(t, ok)
	require.Equal(t, "role not found in the organization", conflictResponse.Message)
}

func TestReplaceOrgUserMemberships_CannotModifyOwnMemberships(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Prepare request
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: userId, // Same as authenticated user
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     uuid.New().String(),
				},
			},
		},
	}

	// Call replace memberships
	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	conflictResponse, ok := response.(ReplaceOrgUserMemberships409JSONResponse)
	require.True(t, ok)
	require.Equal(t, "cannot modify your own memberships", conflictResponse.Message)
}

func TestReplaceOrgUserMemberships_NilScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	targetUser := &model.User{
		Id:                  uuid.New(),
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock existing memberships check
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUser.Id,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUser.Id,
		},
		UserDisplayName:         targetUser.DisplayName,
		UserPrimaryEmailAddress: targetUser.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUser.Id), OrgId: opt.Of(orgId)}).Return(int64(1), nil)

	// Mock create new membership with nil scope
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			// Verify scope is empty (nil was passed)
			require.Empty(t, membership.Scope)
			membership.Id = uuid.New()
			membership.CreatedAt = time.Now().UTC()
			return membership, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUser.Id,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId.String(),
					Scope:       nil, // nil scope should be valid
				},
			},
		},
	}

	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(ReplaceOrgUserMemberships200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 1)
}

func TestReplaceOrgUserMemberships_InvalidScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	targetUser := &model.User{
		Id:                  uuid.New(),
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock existing memberships check
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUser.Id,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUser.Id,
		},
		UserDisplayName:         targetUser.DisplayName,
		UserPrimaryEmailAddress: targetUser.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUser.Id), OrgId: opt.Of(orgId)}).Return(int64(1), nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUser.Id,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId.String(),
					Scope:       &invalidScope, // Invalid scope format
				},
			},
		},
	}

	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	badRequestResponse, ok := response.(ReplaceOrgUserMemberships400JSONResponse)
	require.True(t, ok)
	require.Contains(t, badRequestResponse.Message, "invalid scope")
	require.Contains(t, badRequestResponse.Message, invalidScope)
}

func TestReplaceOrgUserMemberships_ValidScope(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	roleId := uuid.New()
	projectId := uuid.New()
	validScope := "project:" + projectId.String()

	targetUser := &model.User{
		Id:                  uuid.New(),
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock CP client project validation
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().GetInternalProjectByUuidWithResponse(gomock.Any(), orgId, projectId).
		Return(&platformorchestratorcp.GetInternalProjectByUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &platformorchestratorcp.Project{},
		}, nil)

	// Mock existing memberships check
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUser.Id,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUser.Id,
		},
		UserDisplayName:         targetUser.DisplayName,
		UserPrimaryEmailAddress: targetUser.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUser.Id), OrgId: opt.Of(orgId)}).Return(int64(1), nil)

	// Mock create new membership with valid scope
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, membership *model.Membership) (*model.Membership, error) {
			// Verify scope is set correctly
			require.Equal(t, validScope, membership.Scope)
			membership.Id = uuid.New()
			membership.CreatedAt = time.Now().UTC()
			return membership, nil
		})

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUser.Id,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId.String(),
					Scope:       &validScope, // Valid scope: project:<uuid>
				},
			},
		},
	}

	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	successResponse, ok := response.(ReplaceOrgUserMemberships200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 1)
	require.Equal(t, orgId, successResponse.Items[0].OrgId)
}

func TestReplaceOrgUserMemberships_DuplicateMembershipConflict(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	targetUserId := uuid.New()
	roleId := uuid.New()

	user := &model.User{
		DisplayName:         "Test User",
		PrimaryEmailAddress: opt.Of("test@example.com"),
	}

	// Mock authorization check
	MockAuthorizationSuccess(s, userId, orgId, "membership_write")

	// Mock existing memberships check (user is member of org)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &targetUserId,
		OrgId:  &orgId,
	}).Return([]model.MembershipWithUserMetadata{{
		Membership: model.Membership{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: targetUserId,
		},
		UserDisplayName:         user.DisplayName,
		UserPrimaryEmailAddress: user.PrimaryEmailAddress,
	}}, nil)

	// Mock delete existing memberships
	s.Database.(*mockmodel.MockDatabaser).EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{UserId: opt.Of(targetUserId), OrgId: opt.Of(orgId)}).Return(int64(0), nil)

	// Mock create membership fails with duplicate conflict
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, model.NewErrConflict("duplicate membership"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userId.String())
	request := ReplaceOrgUserMembershipsRequestObject{
		OrgId:  orgId,
		UserId: targetUserId,
		Body: &ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []UserMembershipRequest{
				{
					SubjectType: SubjectTypeRole,
					Subject:     roleId.String(),
				},
			},
		},
	}

	// Call replace memberships
	response, err := s.ReplaceOrgUserMemberships(ctx, request)
	require.NoError(t, err)

	conflictResponse, ok := response.(ReplaceOrgUserMemberships409JSONResponse)
	require.True(t, ok)
	require.Equal(t, "membership conflict", conflictResponse.Message)
}

func TestGetRoleByDisplayName(t *testing.T) {
	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()

	roles := []model.Role{
		{
			Id:          adminRoleId,
			DisplayName: RoleAdmin,
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			DisplayName: RoleViewer,
			Permissions: []string{PermissionsReadAll},
		},
	}

	// Test finding existing role
	adminRole := getRoleByDisplayName(roles, RoleAdmin)
	require.NotNil(t, adminRole)
	require.Equal(t, adminRoleId, adminRole.Id)
	require.Equal(t, RoleAdmin, adminRole.DisplayName)

	viewerRole := getRoleByDisplayName(roles, RoleViewer)
	require.NotNil(t, viewerRole)
	require.Equal(t, viewerRoleId, viewerRole.Id)
	require.Equal(t, RoleViewer, viewerRole.DisplayName)

	// Test role not found
	nonExistentRole := getRoleByDisplayName(roles, "NonExistent")
	require.Nil(t, nonExistentRole)
}

func TestListMembers_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	requesterId := userid.NewHumanUserId()
	user1Id := uuid.New()
	user2Id := uuid.New()

	member1 := model.MembershipWithIdentityProvider{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      user1Id,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserIdentities: map[model.UserIdentityProvider]string{
			model.UserIdentityProviderGoogle: "google-id-1",
		},
	}
	member2 := model.MembershipWithIdentityProvider{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      user2Id,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserIdentities: map[model.UserIdentityProvider]string{
			model.UserIdentityProviderMicrosoft: "ms-id-2",
			model.UserIdentityProviderGoogle:    "google-id-2",
		},
	}

	MockAuthorizationSuccess(s, requesterId, orgId, "membership_read")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMembersWithIdentities(gomock.Any(), nil, model.ListMembershipsParams{OrgId: &orgId}).
		Return([]model.MembershipWithIdentityProvider{member1, member2}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, requesterId.String())
	response, err := s.ListMembers(ctx, ListMembersRequestObject{OrgId: orgId, Params: ListMembersParams{}})
	require.NoError(t, err)

	successResponse, ok := response.(ListMembers200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 2)

	require.Equal(t, member1.Id, successResponse.Items[0].Id)
	require.Equal(t, user1Id, successResponse.Items[0].UserId)
	require.Equal(t, []string{"google"}, successResponse.Items[0].IdentityProviders)

	require.Equal(t, member2.Id, successResponse.Items[1].Id)
	require.Equal(t, user2Id, successResponse.Items[1].UserId)
	require.ElementsMatch(t, []string{"microsoft", "google"}, successResponse.Items[1].IdentityProviders)
}

func TestListMembers_FilterByUserId(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	requesterId := userid.NewHumanUserId()
	targetUserId := uuid.New()

	member := model.MembershipWithIdentityProvider{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      targetUserId,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserIdentities: map[model.UserIdentityProvider]string{
			model.UserIdentityProviderGoogle: "google-id",
		},
	}

	MockAuthorizationSuccess(s, requesterId, orgId, "membership_read")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMembersWithIdentities(gomock.Any(), nil, model.ListMembershipsParams{OrgId: &orgId, UserId: &targetUserId}).
		Return([]model.MembershipWithIdentityProvider{member}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, requesterId.String())
	response, err := s.ListMembers(ctx, ListMembersRequestObject{OrgId: orgId, Params: ListMembersParams{UserId: &targetUserId}})
	require.NoError(t, err)

	successResponse, ok := response.(ListMembers200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 1)
	require.Equal(t, targetUserId, successResponse.Items[0].UserId)
}

func TestListMembers_NoIdentities(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	requesterId := userid.NewHumanUserId()

	member := model.MembershipWithIdentityProvider{
		Membership: model.Membership{
			Id:          uuid.New(),
			CreatedAt:   time.Now(),
			OrgId:       orgId,
			UserId:      uuid.New(),
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     uuid.New().String(),
		},
		UserIdentities: map[model.UserIdentityProvider]string{},
	}

	MockAuthorizationSuccess(s, requesterId, orgId, "membership_read")

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		ListMembersWithIdentities(gomock.Any(), nil, model.ListMembershipsParams{OrgId: &orgId}).
		Return([]model.MembershipWithIdentityProvider{member}, "", nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, requesterId.String())
	response, err := s.ListMembers(ctx, ListMembersRequestObject{OrgId: orgId, Params: ListMembersParams{}})
	require.NoError(t, err)

	successResponse, ok := response.(ListMembers200JSONResponse)
	require.True(t, ok)
	require.Len(t, successResponse.Items, 1)
	require.Empty(t, successResponse.Items[0].IdentityProviders)
}
