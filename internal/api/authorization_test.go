package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	mockauthorization "github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization/mocks"
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
