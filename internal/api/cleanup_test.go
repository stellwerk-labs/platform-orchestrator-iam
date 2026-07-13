package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
)

func Test_cleanupExpiredData_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	logger := zaptest.NewLogger(t)
	ctx := context.Background()

	db.EXPECT().DeleteExpiredSessionTokens(gomock.Any(), nil).Return(int64(5), nil)
	db.EXPECT().DeleteExpiredInvitations(gomock.Any(), nil).Return(int64(3), nil)

	cleanupExpiredData(ctx, logger, db)
}

func Test_cleanupExpiredData_NothingToDelete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	logger := zaptest.NewLogger(t)
	ctx := context.Background()

	db.EXPECT().DeleteExpiredSessionTokens(gomock.Any(), nil).Return(int64(0), nil)
	db.EXPECT().DeleteExpiredInvitations(gomock.Any(), nil).Return(int64(0), nil)

	cleanupExpiredData(ctx, logger, db)
}

func Test_cleanupExpiredData_BothErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	logger := zaptest.NewLogger(t)
	ctx := context.Background()

	expectedErr1 := errors.New("session token error")
	expectedErr2 := errors.New("invitation error")

	db.EXPECT().DeleteExpiredSessionTokens(gomock.Any(), nil).Return(int64(0), expectedErr1)
	db.EXPECT().DeleteExpiredInvitations(gomock.Any(), nil).Return(int64(0), expectedErr2)

	cleanupExpiredData(ctx, logger, db)
}

func TestScheduleExpiredDataCleanup_RunsMultipleTimes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mockmodel.NewMockDatabaser(ctrl)
	logger := zaptest.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interval := 50 * time.Millisecond

	callCount := 0
	db.EXPECT().DeleteExpiredSessionTokens(gomock.Any(), nil).DoAndReturn(func(context.Context, model.Tx) (int64, error) {
		callCount++
		return int64(1), nil
	}).MinTimes(2)

	db.EXPECT().DeleteExpiredInvitations(gomock.Any(), nil).Return(int64(0), nil).MinTimes(2)

	errChan := make(chan error, 1)
	go func() {
		errChan <- ScheduleExpiredDataCleanup(ctx, interval, logger, db)
	}()

	// Wait for at least 2 cycles plus some buffer
	time.Sleep(2*interval + 250*time.Millisecond)

	cancel()

	err := <-errChan
	require.NoError(t, err)

	require.GreaterOrEqual(t, callCount, 2, "cleanup should have run at least twice")
}
