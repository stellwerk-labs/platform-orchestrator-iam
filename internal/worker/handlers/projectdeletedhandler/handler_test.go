package projectdeletedhandler

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

func TestRemoveProjectAccess(t *testing.T) {
	controller := gomock.NewController(t)
	database := mockmodel.NewMockDatabaser(controller)
	scope := "project:project-id"

	database.EXPECT().BulkDeleteMemberships(gomock.Any(), nil, model.BulkDeleteMembershipsParams{Scope: opt.Of(scope)}).Return(int64(2), nil)
	database.EXPECT().BulkDeleteServiceUserRoles(gomock.Any(), nil, model.BulkDeleteServiceUserRolesParams{Scope: opt.Of(scope)}).Return(int64(1), nil)
	database.EXPECT().DeleteAuthorizationResource(gomock.Any(), nil, scope).Return(nil)

	require.NoError(t, New(database).removeProjectAccess(t.Context(), zap.NewNop(), "project-id"))
}
