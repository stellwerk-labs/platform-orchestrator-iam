package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hmessaging"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	mockauthorization "github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization/mocks"
	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	mocksso "github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider/mocks"
)

func MockServer(t *testing.T) (*echo.Echo, *Server, func()) {
	ctrl := gomock.NewController(t)
	e, _ := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{
		AppName:          "test",
		Logger:           zaptest.NewLogger(t),
		OpenAPIRawSchema: MustDecodeOpenApiSpec(),
		OpenAPISkipperFn: OpenApiValidatorSkipper,
	})
	db := mockmodel.NewMockDatabaser(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)
	db.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(tx, nil).AnyTimes()
	db.EXPECT().UpsertAuthorizationResource(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	// Row-locking and invitation cleanup are cross-cutting lifecycle plumbing.
	// Their behavior is covered against real Postgres in the SCIM concurrency
	// and deprovisioning integration tests; unrelated handler unit tests should
	// not each repeat the same transport-shaped expectations.
	db.EXPECT().LockScimUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	db.EXPECT().LockScimGroupsForUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	db.EXPECT().DeleteInvitationsForScimUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), nil).AnyTimes()
	tx.EXPECT().Rollback().Return(nil).AnyTimes()
	tx.EXPECT().Commit().Return(nil).AnyTimes()
	s := &Server{
		Logger:                   zaptest.NewLogger(t),
		Database:                 db,
		SessionTokenCookieDomain: "cookie.domain",
		CpClient:                 mockplatformorchestratorcp.NewMockClientWithResponsesInterface(ctrl),
		Authorizer:               mockauthorization.NewMockAuthorizer(ctrl),
		Publisher:                new(hmessaging.RecordingPublisher),
		SsoProvider:              mocksso.NewMockProvider(ctrl),
		SsoStateSecret:           "test-secret-key-for-hmac-signing",
	}
	s.MapRoutes(e)
	return e, s, func() {
		ctrl.Finish()
	}
}

// MockAuthorizationSuccess mocks a successful authorization check for a user in an org
// This is a helper function to simplify tests that don't focus on authorization
func MockAuthorizationSuccess(s *Server, userId uuid.UUID, orgId, permission string) {
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, []authorization.Check{{Resource: "organization:" + orgId, Permission: permission}}).
		Return([]authorization.Result{{Check: authorization.Check{Resource: "organization:" + orgId, Permission: permission}, Allowed: true}}, nil).
		Times(1)
}

// MockAuthorizationFailure mocks a failed authorization check for a user in an org
// This is a helper function to simplify tests that focus on authorization failures
func MockAuthorizationFailure(s *Server, userId uuid.UUID, orgId string) {
	s.Authorizer.(*mockauthorization.MockAuthorizer).EXPECT().
		Authorize(gomock.Any(), userId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ uuid.UUID, checks []authorization.Check) ([]authorization.Result, error) {
			return []authorization.Result{{Check: checks[0], Allowed: false}}, nil
		}).
		Times(1)
}
