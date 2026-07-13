package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hrabbitmq"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	mockspicedb "github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb/mocks"
	mocksso "github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider/mocks"
)

func MockServer(t *testing.T) (*echo.Echo, *Server, func()) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	e, _ := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{
		AppName:          "test",
		Logger:           zaptest.NewLogger(t),
		OpenAPIRawSchema: MustDecodeOpenApiSpec(),
		OpenAPISkipperFn: OpenApiValidatorSkipper,
	})
	db := mockmodel.NewMockDatabaser(ctrl)
	tx := mockmodel.NewMockTxWithCommit(ctrl)
	db.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(tx, nil).AnyTimes()
	tx.EXPECT().Rollback().Return(nil).AnyTimes()
	tx.EXPECT().Commit().Return(nil).AnyTimes()
	s := &Server{
		Logger:                   zaptest.NewLogger(t),
		Database:                 db,
		SessionTokenCookieDomain: "cookie.domain",
		CpClient:                 mockplatformorchestratorcp.NewMockClientWithResponsesInterface(ctrl),
		SpiceDB:                  mockspicedb.NewMockSpiceDB(ctrl),
		RabbitMqPublisher:        new(hrabbitmq.NoOpPublisher),
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
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil).
		Times(1)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			permission,
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(true, nil).
		Times(1)
}

// MockAuthorizationFailure mocks a failed authorization check for a user in an org
// This is a helper function to simplify tests that focus on authorization failures
func MockAuthorizationFailure(s *Server, userId uuid.UUID, orgId string) {
	s.Database.(*mockmodel.MockDatabaser).EXPECT().
		GetOrgZedToken(gomock.Any(), gomock.Nil(), orgId).
		Return(&model.OrgZedTokens{OrgId: orgId, ZedToken: ""}, nil).
		Times(1)

	s.SpiceDB.(*mockspicedb.MockSpiceDB).EXPECT().
		HasSubjectPermissionOnObj(
			gomock.Any(),
			spicedb.SubjectTypeUser,
			userId.String(),
			gomock.Any(), // any permission
			spicedb.ObjectTypeOrg,
			orgId,
			"",
		).
		Return(false, nil).
		Times(1)
}
