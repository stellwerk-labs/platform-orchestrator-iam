package api

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
)

func TestSyncAuthorizationResourcesPersistsHierarchy(t *testing.T) {
	controller := gomock.NewController(t)
	database := mockmodel.NewMockDatabaser(controller)
	tx := mockmodel.NewMockTxWithCommit(controller)
	projectId := uuid.New()
	environmentId := uuid.New()

	database.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(tx, nil)
	tx.EXPECT().Rollback().Return(sql.ErrTxDone)
	database.EXPECT().UpsertAuthorizationResource(gomock.Any(), tx, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ model.Tx, resource *model.AuthorizationResource) error {
			assert.Equal(t, "organization:acme", resource.Resource)
			assert.Nil(t, resource.ParentResource)
			return nil
		},
	)
	database.EXPECT().UpsertAuthorizationResource(gomock.Any(), tx, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ model.Tx, resource *model.AuthorizationResource) error {
			assert.Equal(t, "project:"+projectId.String(), resource.Resource)
			require.NotNil(t, resource.ParentResource)
			assert.Equal(t, "organization:acme", *resource.ParentResource)
			return nil
		},
	)
	database.EXPECT().UpsertAuthorizationResource(gomock.Any(), tx, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ model.Tx, resource *model.AuthorizationResource) error {
			assert.Equal(t, "env:"+environmentId.String(), resource.Resource)
			require.NotNil(t, resource.ParentResource)
			assert.Equal(t, "project:"+projectId.String(), *resource.ParentResource)
			return nil
		},
	)
	tx.EXPECT().Commit().Return(nil)

	result, err := SyncAuthorizationResources(
		t.Context(), zap.NewNop(), database, "acme", map[uuid.UUID][]uuid.UUID{projectId: {environmentId}},
	)
	require.NoError(t, err)
	assert.Equal(t, 3, result.ResourcesUpserted)
}
