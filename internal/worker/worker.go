package worker

import (
	"context"
	"regexp"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stellwerk-labs/golib/hmessaging"
	"github.com/stellwerk-labs/golib/hnats"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers/branchhandler"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers/envdeletedhandler"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers/projectdeletedhandler"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers/projectenvrelationshipinserter"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/handlers/spicedbsynchandler"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker/middleware"
)

const mainConsumerDurable = "platform-orchestrator-iam-main"

var retryBackOff = []time.Duration{
	2 * time.Second,
	10 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
	30 * time.Minute,
	1 * time.Hour,
}

type Worker struct {
	JetStream           jetstream.JetStream
	Publisher           hmessaging.Publisher
	DeadLetterPublisher hmessaging.Publisher
	RetryTimeout        time.Duration
	Logger              *zap.Logger
	DB                  model.Databaser
	SpiceDB             spicedb.SpiceDB
	CpClient            cpclient.ClientWithResponsesInterface
}

func (w *Worker) BuildMainConsumer(ctx context.Context) (*hnats.Consumer, error) {
	syncSpiceDBHandler := spicedbsynchandler.New(w.SpiceDB, w.DB, w.Publisher)
	projectEnvRelationshipInserter := projectenvrelationshipinserter.New(w.SpiceDB, w.DB, w.CpClient)
	projectDeletedHandler := projectdeletedhandler.New(w.DB, w.SpiceDB)
	envDeletedHandler := envdeletedhandler.New(w.DB, w.SpiceDB)

	// The first matching branch handles the event. The final branch protects
	// against a future filter/handler mismatch by acknowledging unknown input.
	var inner handlers.Handler = &branchhandler.Handler{
		{PrefixPattern: regexp.MustCompile(string(genevents.IoPlatformOrchestratorSpicedbSync)), Handler: syncSpiceDBHandler},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorProjectCreated)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorProjectDeleted)), Handler: projectDeletedHandler},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorEnvironmentCreated)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorEnvironmentDeleted)), Handler: envDeletedHandler},
		{PrefixPattern: regexp.MustCompile(string(genevents.IoPlatformOrchestratorScopeSync)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(""), Handler: handlers.HandlerFunc(func(_ context.Context, logger *zap.Logger, _ *hmessaging.Delivery) error {
			logger.Info("dropping unsupported message")
			return nil
		})},
	}
	inner = middleware.WrapWithObserver(inner, MainConsumerName, w.RetryTimeout)

	filters := []string{
		string(genevents.IoPlatformOrchestratorSpicedbSync),
		string(cpevents.IoPlatformOrchestratorProjectCreated),
		string(cpevents.IoPlatformOrchestratorProjectDeleted),
		string(cpevents.IoPlatformOrchestratorEnvironmentCreated),
		string(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		string(genevents.IoPlatformOrchestratorScopeSync),
	}
	consumer, err := hnats.EnsureDurableConsumer(ctx, w.JetStream, hnats.DurableConsumerConfig{
		Stream:         hmessaging.EventsStreamName,
		Durable:        mainConsumerDurable,
		FilterSubjects: filters,
		MaxDeliver:     10,
		AckWait:        w.RetryTimeout,
		MaxAckPending:  MainConsumerConcurrency,
		TimeoutBackOff: retryBackOff,
	})
	if err != nil {
		return nil, err
	}
	return hnats.NewConsumer(
		consumer,
		func(ctx context.Context, delivery hmessaging.Delivery) error {
			return inner.Handle(ctx, w.Logger, &delivery)
		},
		hnats.ProcessingConfig{
			MaxDeliveries: 10,
			RetryBackOff:  retryBackOff,
			DLQPublisher:  w.DeadLetterPublisher,
			Logger:        w.Logger,
		},
	)
}
