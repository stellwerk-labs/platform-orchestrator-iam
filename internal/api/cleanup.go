package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/golib/htelemetry"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

// ScheduleExpiredDataCleanup periodically clean up expired records.
func ScheduleExpiredDataCleanup(ctx context.Context, interval time.Duration, logger *zap.Logger, db model.Databaser) error {
	logger.Info("Starting expired data cleanup task", zap.Duration("interval", interval))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanupExpiredData(ctx, logger, db)
		case <-ctx.Done():
			logger.Info("Expired data cleanup task stopped")
			return nil
		}
	}
}

func cleanupExpiredData(ctx context.Context, logger *zap.Logger, db model.Databaser) {
	performCleanupWithSpan(ctx, logger, "background:cleanup-expired-session-tokens", "expired session tokens", db.DeleteExpiredSessionTokens)
	performCleanupWithSpan(ctx, logger, "background:cleanup-expired-invitations", "expired invitations", db.DeleteExpiredInvitations)
}

func performCleanupWithSpan(ctx context.Context, logger *zap.Logger, spanName, entityName string, deleteFunc func(context.Context, model.Tx) (int64, error)) {
	span := htelemetry.StartSpan(spanName)
	subCtx := htelemetry.ContextWithSpan(ctx, span)
	subLogger := hlogger.TraceScopedLoggerFromCtx(logger, subCtx)

	deletedCount, err := deleteFunc(subCtx, nil)
	if err != nil {
		subLogger.Error("failed to delete "+entityName, zap.Error(err))
		span.Finish(htelemetry.WithError(err))
		return
	}

	if deletedCount > 0 {
		subLogger.Info("deleted "+entityName, zap.Int64("count", deletedCount))
	} else {
		subLogger.Debug("no " + entityName + " to delete")
	}

	span.Finish()
}

func (s *Server) InternalRemoveAccessFromOrg(ctx context.Context, request InternalRemoveAccessFromOrgRequestObject) (InternalRemoveAccessFromOrgResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	i, err := s.Database.BulkDeleteMemberships(ctx, tx, model.BulkDeleteMembershipsParams{OrgId: opt.Of(request.OrgId)})
	if err != nil {
		return nil, fmt.Errorf("failed to bulk delete org memberships: %w", err)
	}
	logger.Info("bulk deleted org memberships", zap.Int64("deleted_count", i))

	i, err = s.Database.BulkExpireAllServiceUserTokens(ctx, tx, request.OrgId)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk expire all service user tokens: %w", err)
	}
	logger.Info("bulk expired org service user tokens", zap.Int64("expired_count", i))

	messages, err := insertSpiceDBSyncEventMessages(ctx, request.OrgId, nil, s.Database, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to insert spice db event messages: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	reliableoutbox.OptimisticPublish(ctx, logger, s.Database.AsReliableOutboxStore(), s.Publisher, messages)
	return InternalRemoveAccessFromOrg204Response{}, nil
}
