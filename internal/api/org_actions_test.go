package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"

	platformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Tests for InternalSyncOrgToSpiceDB

func TestInternalSyncOrgToSpiceDB_OrganizationNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
			Body:         []byte("not found"),
		}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgToSpiceDB404JSONResponse{}, resp)
}

func TestInternalSyncOrgToSpiceDB_ControlPlaneError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusInternalServerError},
			Body:         []byte("internal error"),
		}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "unexpected status code 500")
}

func TestInternalSyncOrgToSpiceDB_Success_EmptyOrg(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return([]model.Role{}, nil)

	db.EXPECT().SeedRoles(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, orgId string, roles []model.Role) error {
			require.Len(t, roles, 2)
			require.Equal(t, RoleAdmin, roles[0].DisplayName)
			require.Equal(t, RoleViewer, roles[1].DisplayName)
			return nil
		})

	db.EXPECT().ListScopedRoles(gomock.Any(), gomock.Any(), model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)

	db.EXPECT().ListServiceUserRoles(gomock.Any(), gomock.Any(), model.ListServiceUserRolesParams{OrgId: &orgId}).Return([]model.ServiceUserRole{}, nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 1 for org
			require.Empty(t, filters)

			// Expected relationships:
			require.Empty(t, relationships)
			return "", 0, 0, nil
		})

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgToSpiceDB200JSONResponse{}, resp)
	respTyped := resp.(InternalSyncOrgToSpiceDB200JSONResponse)
	require.NotNil(t, respTyped.Removed)
	require.Equal(t, 0, *respTyped.Removed)
	require.Equal(t, 0, respTyped.Added)
}

func TestInternalSyncOrgToSpiceDB_Success_WithRolesAndMemberships(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	userId1 := uuid.New()
	userId2 := uuid.New()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   userId1,
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       orgId,
			DisplayName: RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   userId1,
			Permissions: []string{PermissionsReadAll},
		},
	}
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(roles, nil)

	db.EXPECT().ListScopedRoles(gomock.Any(), gomock.Any(), model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)

	memberships := []model.MembershipWithUserMetadata{
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId1,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     adminRoleId.String(),
				Role:        opt.Of(adminRoleId),
			},
			UserDisplayName: "User 1",
		},
		{
			Membership: model.Membership{
				Id:          uuid.New(),
				CreatedAt:   time.Now(),
				UserId:      userId2,
				OrgId:       orgId,
				SubjectType: model.MembershipSubjectTypeRole,
				Subject:     viewerRoleId.String(),
				Role:        opt.Of(viewerRoleId),
			},
			UserDisplayName: "User 2",
		},
	}
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return(memberships, nil)

	db.EXPECT().ListServiceUserRoles(gomock.Any(), gomock.Any(), model.ListServiceUserRolesParams{OrgId: &orgId}).Return([]model.ServiceUserRole{}, nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 2 for roles
			require.Len(t, filters, 2)

			// Expected relationships:
			// 2 roles × 2 relationships each (scoped_role->org, org->role) = 4
			// 2 memberships × 1 relationship each (user->scoped_role) = 2
			// Total = 6
			require.Len(t, relationships, 6)

			// Verify scoped_role->org relationships
			var scopedRoleOrgRels []*v1.Relationship
			var orgRoleRels []*v1.Relationship
			var userMemberRels []*v1.Relationship

			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels = append(scopedRoleOrgRels, rel)
				}
				if rel.Resource.ObjectType == spicedb.ObjectTypeOrg.String() &&
					(rel.Relation == spicedb.RelationAllManager.String() || rel.Relation == spicedb.RelationAllReader.String()) {
					orgRoleRels = append(orgRoleRels, rel)
				}
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationMember.String() {
					userMemberRels = append(userMemberRels, rel)
				}
			}

			require.Len(t, scopedRoleOrgRels, 2)
			require.Len(t, orgRoleRels, 2)
			require.Len(t, userMemberRels, 2)

			return "test-zed-token-123", 0, 6, nil
		})

	db.EXPECT().UpsertOrgZedToken(gomock.Any(), gomock.Nil(), orgId, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, orgId string, token *model.OrgZedTokens) (*model.OrgZedTokens, error) {
			require.Equal(t, "test-zed-token-123", token.ZedToken)
			return token, nil
		})

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgToSpiceDB200JSONResponse{}, resp)
	respTyped := resp.(InternalSyncOrgToSpiceDB200JSONResponse)
	require.NotNil(t, respTyped.Removed)
	require.Equal(t, 0, *respTyped.Removed)
	require.Equal(t, 6, respTyped.Added)
}

func TestInternalSyncOrgToSpiceDB_Success_WithServiceUserRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	adminRoleId := uuid.New()
	serviceUserId := uuid.New()
	createdBy := uuid.New()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsManageAll},
		},
	}
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(roles, nil)

	db.EXPECT().ListScopedRoles(gomock.Any(), gomock.Any(), model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)

	serviceUserRoles := []model.ServiceUserRole{
		{
			ServiceUserId: serviceUserId,
			RoleId:        adminRoleId,
			OrgId:         orgId,
			CreatedAt:     time.Now(),
		},
	}
	db.EXPECT().ListServiceUserRoles(gomock.Any(), gomock.Any(), model.ListServiceUserRolesParams{OrgId: &orgId}).Return(serviceUserRoles, nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected filters: 1 for the only role
			require.Len(t, filters, 1)

			// Expected relationships:
			// 1 role × 2 relationships each (scoped_role->org, org->role) = 2
			// 1 service user role × 1 relationship (user->scoped_role) = 1
			// Total = 3
			require.Len(t, relationships, 3)

			// Verify service user relationship exists
			var serviceUserRel *v1.Relationship
			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationMember.String() &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeUser.String() &&
					rel.Subject.Object.ObjectId == serviceUserId.String() {
					serviceUserRel = rel
					break
				}
			}
			require.NotNil(t, serviceUserRel)
			require.Equal(t, adminRoleId.String(), serviceUserRel.Resource.ObjectId)

			return "test-zed-token-456", 0, 3, nil
		})

	db.EXPECT().UpsertOrgZedToken(gomock.Any(), gomock.Nil(), orgId, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, orgId string, token *model.OrgZedTokens) (*model.OrgZedTokens, error) {
			require.Equal(t, "test-zed-token-456", token.ZedToken)
			return token, nil
		})

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgToSpiceDB200JSONResponse{}, resp)
	respTyped := resp.(InternalSyncOrgToSpiceDB200JSONResponse)
	require.NotNil(t, respTyped.Removed)
	require.Equal(t, 0, *respTyped.Removed)
	require.Equal(t, 3, respTyped.Added)
}

func TestInternalSyncOrgToSpiceDB_SpiceDBError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return([]model.Role{}, nil)

	db.EXPECT().SeedRoles(gomock.Any(), gomock.Any(), orgId, gomock.Any()).Return(nil)

	db.EXPECT().ListScopedRoles(gomock.Any(), gomock.Any(), model.ScopedRoleListParams{
		OrgId: orgId,
	}).Return([]model.ScopedRole{}, nil)

	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &orgId,
	}).Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().ListServiceUserRoles(gomock.Any(), gomock.Any(), model.ListServiceUserRolesParams{OrgId: &orgId}).Return([]model.ServiceUserRole{}, nil)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, (*uuid.UUID)(nil), gomock.Any(), gomock.Any()).
		Return("", 0, 0, errors.New("SpiceDB sync failed"))

	ctx := context.Background()
	resp, err := s.InternalSyncOrgToSpiceDB(ctx, InternalSyncOrgToSpiceDBRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "failed to sync organization relationships to SpiceDB")
}

// Tests for InternalSyncOrgScopes

func TestInternalSyncOrgScopes_OrganizationNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
			Body:         []byte("not found"),
		}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgScopes404JSONResponse{}, resp)
}

func TestInternalSyncOrgScopes_ControlPlaneError_GetOrg(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusInternalServerError},
			Body:         []byte("internal error"),
		}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "unexpected status code 500")
}

func TestInternalSyncOrgScopes_ControlPlaneError_ListProjects(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, gomock.Any()).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusInternalServerError},
			Body:         []byte("internal error"),
		}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "unexpected status code 500")
}

func TestInternalSyncOrgScopes_Success_NoProjects(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, gomock.Any()).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items:         []platformorchestratorcp.Project{},
				NextPageToken: nil,
			},
		}, nil)

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	createdBy := uuid.New()

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       orgId,
			DisplayName: RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsReadAll},
		},
		{
			Id:          deployerRoleId,
			OrgId:       orgId,
			DisplayName: RoleDeployer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsWriteAll},
		},
	}
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(roles, nil)

	// Mock BatchUpsertScopedRoles to return empty since no projects
	db.EXPECT().BatchUpsertScopedRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, requests []model.ScopedRole) ([]model.ScopedRole, error) {
			require.Empty(t, requests)
			return []model.ScopedRole{}, nil
		}).MaxTimes(1)

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			require.Empty(t, relationships)
			return "", 0, 0, nil
		})

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgScopes200JSONResponse{}, resp)
	respTyped := resp.(InternalSyncOrgScopes200JSONResponse)
	require.Equal(t, 0, respTyped.ProjectsSynced)
	require.Equal(t, 0, respTyped.EnvironmentsSynced)
	require.Equal(t, 0, respTyped.ScopedRolesCreated)
	require.Equal(t, 0, respTyped.RelationshipsAdded)
}

func TestInternalSyncOrgScopes_Success_WithProjectsAndEnvironments(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	project1Uuid := uuid.New()
	project2Uuid := uuid.New()
	env1Uuid := uuid.New()
	env2Uuid := uuid.New()
	env3Uuid := uuid.New()

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	// List projects - first page with project1
	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, &platformorchestratorcp.ListProjectsParams{Page: nil}).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items: []platformorchestratorcp.Project{
					{Uuid: project1Uuid},
				},
				NextPageToken: stringPtr("page2"),
			},
		}, nil)

	// List projects - second page with project2
	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, &platformorchestratorcp.ListProjectsParams{Page: stringPtr("page2")}).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items: []platformorchestratorcp.Project{
					{Uuid: project2Uuid},
				},
				NextPageToken: nil,
			},
		}, nil)

	// List environments for project1 - 2 environments
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, project1Uuid, gomock.Any()).Return(
		&platformorchestratorcp.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.EnvironmentPage{
				Items: []platformorchestratorcp.Environment{
					{Uuid: env1Uuid},
					{Uuid: env2Uuid},
				},
				NextPageToken: nil,
			},
		}, nil)

	// List environments for project2 - 1 environment
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, project2Uuid, gomock.Any()).Return(
		&platformorchestratorcp.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.EnvironmentPage{
				Items: []platformorchestratorcp.Environment{
					{Uuid: env3Uuid},
				},
				NextPageToken: nil,
			},
		}, nil)

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	createdBy := uuid.New()

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       orgId,
			DisplayName: RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsReadAll},
		},
		{
			Id:          deployerRoleId,
			OrgId:       orgId,
			DisplayName: RoleDeployer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsWriteAll},
		},
	}
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(roles, nil)

	// Mock BatchUpsertScopedRoles to return the same roles (simulating successful insert)
	db.EXPECT().BatchUpsertScopedRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, requests []model.ScopedRole) ([]model.ScopedRole, error) {
			// 2 projects + 3 environments = 5 scopes × 3 roles = 15 scoped roles
			require.Len(t, requests, 15)
			// Return the same roles (IDs unchanged since they're new)
			return requests, nil
		})

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, orgId string, userId *uuid.UUID, filters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
			// Expected relationships:
			// - 2 projects: 2 × (1 project->org + 3 roles × 2 relationships) = 2 × 7 = 14
			// - 3 environments: 3 × (1 env->project + 3 roles × 2 relationships) = 3 × 7 = 21
			// Total = 35 relationships
			require.Len(t, relationships, 35)

			// Count relationship types
			var projectOrgRels int
			var envProjectRels int
			var scopedRoleOrgRels int
			var scopeRoleRels int

			for _, rel := range relationships {
				if rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					projectOrgRels++
				} else if rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String() &&
					rel.Relation == spicedb.RelationProject.String() {
					envProjectRels++
				} else if rel.Resource.ObjectType == spicedb.ObjectTypeScopedRole.String() &&
					rel.Relation == spicedb.RelationOrg.String() {
					scopedRoleOrgRels++
				} else if (rel.Resource.ObjectType == spicedb.ObjectTypeProject.String() ||
					rel.Resource.ObjectType == spicedb.ObjectTypeEnv.String()) &&
					rel.Subject.Object.ObjectType == spicedb.ObjectTypeScopedRole.String() {
					scopeRoleRels++
				}
			}

			require.Equal(t, 2, projectOrgRels, "Expected 2 project->org relationships")
			require.Equal(t, 3, envProjectRels, "Expected 3 env->project relationships")
			require.Equal(t, 15, scopedRoleOrgRels, "Expected 15 scoped_role->org relationships")
			require.Equal(t, 15, scopeRoleRels, "Expected 15 scope->scoped_role relationships")

			return zedToken, 0, 35, nil
		})

	db.EXPECT().UpsertOrgZedToken(gomock.Any(), gomock.Nil(), orgId, gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, orgId string, token *model.OrgZedTokens) (*model.OrgZedTokens, error) {
			require.Equal(t, zedToken, token.ZedToken)
			return token, nil
		})

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.NoError(t, err)
	require.IsType(t, InternalSyncOrgScopes200JSONResponse{}, resp)
	respTyped := resp.(InternalSyncOrgScopes200JSONResponse)
	require.Equal(t, 2, respTyped.ProjectsSynced)
	require.Equal(t, 3, respTyped.EnvironmentsSynced)
	require.Equal(t, 15, respTyped.ScopedRolesCreated)
	require.Equal(t, 35, respTyped.RelationshipsAdded)
}

func TestInternalSyncOrgScopes_DatabaseError_ListRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	projectUuid := uuid.New()
	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, gomock.Any()).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items:         []platformorchestratorcp.Project{{Uuid: projectUuid}},
				NextPageToken: nil,
			},
		}, nil)

	// Mock listing environments (needed before database operations in refactored code)
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, projectUuid, gomock.Any()).Return(
		&platformorchestratorcp.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.EnvironmentPage{
				Items:         []platformorchestratorcp.Environment{},
				NextPageToken: nil,
			},
		}, nil)

	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(nil, errors.New("database error"))

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "failed to list organization roles")
}

func TestInternalSyncOrgScopes_DatabaseError_InsufficientRoles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	projectUuid := uuid.New()
	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, gomock.Any()).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items:         []platformorchestratorcp.Project{{Uuid: projectUuid}},
				NextPageToken: nil,
			},
		}, nil)

	// Mock listing environments (needed before database operations in refactored code)
	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, projectUuid, gomock.Any()).Return(
		&platformorchestratorcp.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.EnvironmentPage{
				Items:         []platformorchestratorcp.Environment{},
				NextPageToken: nil,
			},
		}, nil)

	// Return only 1 role, but we need at least 3 (BuiltinRolesNumber)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return([]model.Role{{Id: uuid.New()}}, nil)

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "organization roles not seeded yet")
}

func TestInternalSyncOrgScopes_SpiceDBError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	cpClient := s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface)
	db := s.Database.(*mockmodel.MockDatabaser)
	spiceDB := s.SpiceDB.(*mockspicedb.MockSpiceDB)

	project1Uuid := uuid.New()

	cpClient.EXPECT().GetInternalOrganizationWithResponse(gomock.Any(), orgId).Return(
		&platformorchestratorcp.GetInternalOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			Body:         []byte("{}"),
		}, nil)

	cpClient.EXPECT().ListProjectsWithResponse(gomock.Any(), orgId, gomock.Any()).Return(
		&platformorchestratorcp.ListProjectsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.ProjectPage{
				Items:         []platformorchestratorcp.Project{{Uuid: project1Uuid}},
				NextPageToken: nil,
			},
		}, nil)

	cpClient.EXPECT().ListInternalEnvironmentsByProjectUuidWithResponse(gomock.Any(), orgId, project1Uuid, gomock.Any()).Return(
		&platformorchestratorcp.ListInternalEnvironmentsByProjectUuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &platformorchestratorcp.EnvironmentPage{
				Items:         []platformorchestratorcp.Environment{},
				NextPageToken: nil,
			},
		}, nil)

	adminRoleId := uuid.New()
	viewerRoleId := uuid.New()
	deployerRoleId := uuid.New()
	createdBy := uuid.New()

	roles := []model.Role{
		{
			Id:          adminRoleId,
			OrgId:       orgId,
			DisplayName: RoleAdmin,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsManageAll},
		},
		{
			Id:          viewerRoleId,
			OrgId:       orgId,
			DisplayName: RoleViewer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsReadAll},
		},
		{
			Id:          deployerRoleId,
			OrgId:       orgId,
			DisplayName: RoleDeployer,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
			Permissions: []string{PermissionsWriteAll},
		},
	}
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).Return(roles, nil)

	// Mock BatchUpsertScopedRoles to return the roles
	db.EXPECT().BatchUpsertScopedRoles(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx model.Tx, requests []model.ScopedRole) ([]model.ScopedRole, error) {
			return requests, nil
		})

	spiceDB.EXPECT().SyncOrgRelationships(gomock.Any(), orgId, gomock.Nil(), gomock.Nil(), gomock.Any()).
		Return("", 0, 0, errors.New("SpiceDB sync failed"))

	ctx := context.Background()
	resp, err := s.InternalSyncOrgScopes(ctx, InternalSyncOrgScopesRequestObject{
		OrgId: orgId,
	})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "failed to sync organization relationships to SpiceDB")
}

func stringPtr(s string) *string {
	return &s
}
