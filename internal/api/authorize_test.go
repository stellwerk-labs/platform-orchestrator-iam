package api

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"
)

const zedToken = "test-zed-token"

func TestInternalAuthorize_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: zedToken}, nil)

	// Mock SpiceDB permission check
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			zedToken,
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_MemberPermissionNormalizedToRead(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock SpiceDB permission check - expect "read" even though "member" was requested
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read", // normalized from "member"
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "member"}, // request with "member"
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_OrganizationNormalizedToOrg(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock SpiceDB permission check
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg, // normalized from "organization"
			orgId,
			"",
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"}, // use "organization"
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_MultipleChecksAllPass(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken for first org
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), "org-1").
		Return(&model.OrgZedTokens{OrgId: "org-1", ZedToken: "token-1"}, nil)

	// Mock GetOrgZedToken for second org
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), "org-2").
		Return(&model.OrgZedTokens{OrgId: "org-2", ZedToken: "token-2"}, nil)

	// Mock SpiceDB permission checks
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			"org-1",
			"token-1",
		).
		Return(true, nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"write",
			spicedb.ObjectTypeOrg,
			"org-2",
			"token-2",
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:org-1", Permission: "read"},
				{Resource: "organization:org-2", Permission: "write"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_Failed(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock SpiceDB permission check - return false (not allowed)
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(false, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize403JSONResponse{
		N403ForbiddenJSONResponse: N403ForbiddenJSONResponse{
			Error:   "HTTP-403",
			Message: "one or more authorization checks failed",
			Details: &map[string]interface{}{
				"failed_checks": []ResourcePermissionCheck{
					{
						Resource:   "organization:test-org",
						Permission: "read",
					},
				},
			},
		},
	}, r)
}

func TestInternalAuthorize_PartialFailure(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken for first org
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), "org-allowed").
		Return(&model.OrgZedTokens{OrgId: "org-allowed", ZedToken: ""}, nil)

	// Mock GetOrgZedToken for second org
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), "org-denied").
		Return(&model.OrgZedTokens{OrgId: "org-denied", ZedToken: ""}, nil)

	// First check passes
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			"org-allowed",
			"",
		).
		Return(true, nil)

	// Second check fails
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			"org-denied",
			"",
		).
		Return(false, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:org-allowed", Permission: "read"},
				{Resource: "organization:org-denied", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize403JSONResponse{
		N403ForbiddenJSONResponse: N403ForbiddenJSONResponse{
			Error:   "HTTP-403",
			Message: "one or more authorization checks failed",
			Details: &map[string]interface{}{
				"failed_checks": []ResourcePermissionCheck{
					{
						Resource:   "organization:org-denied",
						Permission: "read",
					},
				},
			},
		},
	}, r)
}

func TestInternalAuthorize_InvalidResourceFormat(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "invalid-resource-format", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize403JSONResponse{
		N403ForbiddenJSONResponse: N403ForbiddenJSONResponse{
			Error:   "HTTP-403",
			Message: "one or more authorization checks failed",
			Details: &map[string]interface{}{
				"failed_checks": []ResourcePermissionCheck{
					{
						Resource:   "invalid-resource-format",
						Permission: "read",
					},
				},
			},
		},
	}, r)
}

func TestInternalAuthorize_SpiceDBInvalidArgument(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock SpiceDB permission check - return InvalidArgument error
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(false, status.Error(codes.InvalidArgument, "invalid argument"))

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize403JSONResponse{
		N403ForbiddenJSONResponse: N403ForbiddenJSONResponse{
			Error:   "HTTP-403",
			Message: "one or more authorization checks failed",
			Details: &map[string]interface{}{
				"failed_checks": []ResourcePermissionCheck{
					{
						Resource:   "organization:test-org",
						Permission: "read",
					},
				},
			},
		},
	}, r)
}

func TestInternalAuthorize_SpiceDBError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	// Mock SpiceDB permission check - return generic error
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(false, errors.New("spicedb error"))

	_, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "spicedb error")
}

func TestInternalAuthorize_OrgZedTokenNotFound(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken - return not found error
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(nil, model.NewErrNotFound("org zed token not found"))

	// Mock SpiceDB permission check with empty zedToken
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"", // empty zedToken when not found
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_OrgZedTokenDatabaseError(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// Mock GetOrgZedToken - return database error
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(nil, errors.New("database error"))

	_, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
}

func TestInternalAuthorize_NonOrgResourceSkipsZedToken(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// No GetOrgZedToken call expected for non-org resources

	// Mock SpiceDB permission check
	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeUser,
			"user-123",
			"", // empty zedToken for non-org resources
		).
		Return(true, nil)

	r, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "user:user-123", Permission: "read"},
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r)
}

func TestInternalAuthorize_CacheHit(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	// First call - should hit database and SpiceDB
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil).
		Times(1) // Only once

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(true, nil).
		Times(1) // Only once

	// First request
	r1, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r1)

	// Second request - should use cache, no new mock expectations
	r2, err := s.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{
		Body: &InternalAuthorizeBody{
			UserId: userId,
			Checks: []ResourcePermissionCheck{
				{Resource: "organization:test-org", Permission: "read"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, r2)
}

func TestCheckOrgMemberAuthorization_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(true, nil)

	err := s.checkOrgMemberAuthorization(t.Context(), userId, orgId)
	require.NoError(t, err)
}

func TestCheckOrgMemberAuthorization_SystemUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	// System user should skip authorization checks
	err := s.checkOrgMemberAuthorization(t.Context(), userid.InternalSystemUuid, "test-org")
	require.NoError(t, err)
}

func TestCheckOrgMemberAuthorization_Failed(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			"read",
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(false, nil)

	err := s.checkOrgMemberAuthorization(t.Context(), userId, orgId)
	require.Error(t, err)
}

func TestCheckUserIdSelfAuthorization_Success(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()

	err := s.checkUserIdSelfAuthorization(t.Context(), userId, userId)
	require.NoError(t, err)
}

func TestCheckUserIdSelfAuthorization_SystemUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	requestUserId := userid.NewHumanUserId()

	// System user should skip authorization checks
	err := s.checkUserIdSelfAuthorization(t.Context(), userid.InternalSystemUuid, requestUserId)
	require.NoError(t, err)
}

func TestCheckUserIdSelfAuthorization_ServiceUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	serviceUserId := userid.NewServiceUserTokenId()
	requestUserId := userid.NewHumanUserId()

	err := s.checkUserIdSelfAuthorization(t.Context(), serviceUserId, requestUserId)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service user token cannot access this endpoint")
}

func TestCheckUserIdSelfAuthorization_DifferentUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	userId := userid.NewHumanUserId()
	requestUserId := uuid.New()

	err := s.checkUserIdSelfAuthorization(t.Context(), userId, requestUserId)
	require.Error(t, err)
}
