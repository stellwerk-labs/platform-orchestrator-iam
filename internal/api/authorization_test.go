package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	mockauthorization "github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization/mocks"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestInternalAuthorizeUsesEmbeddedAuthorizer(t *testing.T) {
	_, server, finish := MockServer(t)
	defer finish()
	userId := userid.NewHumanUserId()
	server.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().Authorize(gomock.Any(), userId, []authorization.Check{
		{Resource: "project:test", Permission: "write"},
	}).Return([]authorization.Result{{Check: authorization.Check{Resource: "project:test", Permission: "write"}, Allowed: true}}, nil)

	response, err := server.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{Body: &InternalAuthorizeBody{
		UserId: userId, Checks: []ResourcePermissionCheck{{Resource: "project:test", Permission: "write"}},
	}})
	require.NoError(t, err)
	assert.Equal(t, InternalAuthorize204Response{}, response)
}

func TestInternalAuthorizeReportsDeniedChecks(t *testing.T) {
	_, server, finish := MockServer(t)
	defer finish()
	userId := userid.NewHumanUserId()
	server.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().Authorize(gomock.Any(), userId, gomock.Any()).Return(
		[]authorization.Result{{Check: authorization.Check{Resource: "env:test", Permission: "read"}, Allowed: false}}, nil,
	)

	response, err := server.InternalAuthorize(t.Context(), InternalAuthorizeRequestObject{Body: &InternalAuthorizeBody{
		UserId: userId, Checks: []ResourcePermissionCheck{{Resource: "env:test", Permission: "read"}},
	}})
	require.NoError(t, err)
	_, denied := response.(InternalAuthorize403JSONResponse)
	assert.True(t, denied)
}

func TestInternalAuthorizeRejectsInactiveSubjectBeforeCachedPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	database := mockmodel.NewMockDatabaser(ctrl)
	authorizer := mockauthorization.NewMockAuthorizer(ctrl)
	userID := userid.NewServiceUserTokenId()
	database.EXPECT().IsAuthorizationSubjectActive(gomock.Any(), nil, userID).Return(false, nil)
	server := &Server{Database: database, Authorizer: authorizer}
	check := ResourcePermissionCheck{Resource: "organization:acme", Permission: "read"}

	ok, failed, err := server.InternalAuthorizeInner(t.Context(), InternalAuthorizeBody{UserId: userID, Checks: []ResourcePermissionCheck{check}})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, []ResourcePermissionCheck{check}, failed)
}

func TestInternalAuthorizeFailsClosedWhenSubjectLivenessIsUnavailable(t *testing.T) {
	ctrl := gomock.NewController(t)
	database := mockmodel.NewMockDatabaser(ctrl)
	authorizer := mockauthorization.NewMockAuthorizer(ctrl)
	userID := userid.NewHumanUserId()
	database.EXPECT().IsAuthorizationSubjectActive(gomock.Any(), nil, userID).Return(false, errors.New("database unavailable"))
	server := &Server{Database: database, Authorizer: authorizer}

	_, _, err := server.InternalAuthorizeInner(t.Context(), InternalAuthorizeBody{
		UserId: userID, Checks: []ResourcePermissionCheck{{Resource: "organization:acme", Permission: "read"}},
	})
	require.EqualError(t, err, "database unavailable")
}

func TestInternalAuthorizePreservesInternalSystemPolicySemantics(t *testing.T) {
	ctrl := gomock.NewController(t)
	database := mockmodel.NewMockDatabaser(ctrl)
	authorizer := mockauthorization.NewMockAuthorizer(ctrl)
	check := authorization.Check{Resource: "organization:acme", Permission: "read"}
	authorizer.EXPECT().Authorize(gomock.Any(), userid.InternalSystemUuid, []authorization.Check{check}).Return(
		[]authorization.Result{{Check: check, Allowed: true}}, nil,
	)
	server := &Server{Database: database, Authorizer: authorizer}

	ok, failed, err := server.InternalAuthorizeInner(t.Context(), InternalAuthorizeBody{
		UserId: userid.InternalSystemUuid,
		Checks: []ResourcePermissionCheck{{Resource: check.Resource, Permission: check.Permission}},
	})
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Empty(t, failed)
}
