package spicedbsynchandler

import (
	"context"
	"encoding/json"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/logging"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"go.uber.org/zap"
)

type SyncSpiceDBHandler struct {
	spiceDB   spicedb.SpiceDB
	db        model.Databaser
	publisher hmessaging.Publisher
}

// New is the constructor so that we don't miss new arguments.
func New(spiceDB spicedb.SpiceDB, db model.Databaser, publisher hmessaging.Publisher) *SyncSpiceDBHandler {
	return &SyncSpiceDBHandler{
		spiceDB:   spiceDB,
		db:        db,
		publisher: publisher,
	}
}

func (h *SyncSpiceDBHandler) Handle(ctx context.Context, logger *zap.Logger, d *hmessaging.Delivery) error {
	// Parse event and sync SpiceDB
	var body events.CloudEvent[genevents.SpiceDBSyncData]
	if err := json.Unmarshal(d.Data, &body); err != nil {
		return errors.Wrap(err, "failed to unmarshal runner status check event")
	}
	orgId := body.Data.OrgId
	if orgId == "" {
		return errors.New("missing org_id in event data")
	}

	logger = logger.With(logging.ZapOrgId(orgId))

	var userId *uuid.UUID
	userIdVal := ref.DerefOr(body.Data.UserId, genevents.UserId{})
	if u, err := uuid.FromBytes(userIdVal[:]); err == nil && u != uuid.Nil {
		logger = logger.With(zap.Stringer(hlogger.POUserId, u))
		userId = &u
	}

	if zedToken, removed, added, pendingMessages, err := api.SyncSpiceDBWithDB(ctx, logger, api.SyncSpiceDBParams{OrgId: orgId, UserId: opt.OfRef(userId)}, h.db, h.spiceDB); err != nil {
		var gracefulErr hmessaging.RetryError
		if errors.As(err, &gracefulErr) {
			// Publish the specific scope.sync messages that were created immediately so they can be processed before the retry
			if h.publisher != nil && len(pendingMessages) > 0 {
				logger.Sugar().Infow("publishing pending scope sync messages before retry", "count", len(pendingMessages))
				reliableoutbox.OptimisticPublish(ctx, logger, h.db.AsReliableOutboxStore(), h.publisher, pendingMessages)
			}
			logger.Sugar().Infow("graceful retry syncing organization to SpiceDB", "error", gracefulErr.Error())
			return gracefulErr
		}
		return errors.Wrap(err, "failed to sync organization to SpiceDB")
	} else {
		if zedToken != "" {
			// Store the zed token for this org
			if _, err := h.db.UpsertOrgZedToken(ctx, nil, orgId, &model.OrgZedTokens{ZedToken: zedToken}); err != nil {
				return errors.Wrap(err, "failed to upsert organization zed token")
			}
		}
		logger.Info("successfully synced organization to SpiceDB", zap.Int("removed", removed), zap.Int("added", added))
		return nil
	}
}
