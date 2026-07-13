package worker

import (
	"context"
	"regexp"
	"time"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stellwerk-labs/golib/hrabbitmq"
	delayqueues "github.com/stellwerk-labs/golib/hrabbitmq/delayqueues/v2"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/wagslane/go-rabbitmq"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
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

type Worker struct {
	RabbitConn      *rabbitmq.Conn
	RabbitPublisher hrabbitmq.Publisher
	RetryTimeout    time.Duration
	Cache           *expirable.LRU[string, int32]
	Logger          *zap.Logger
	DB              model.Databaser
	SpiceDB         spicedb.SpiceDB
	CpClient        cpclient.ClientWithResponsesInterface
}

func (w *Worker) BuildMainConsumer() (*hrabbitmq.ConsumerWithHandlerWaiter, error) {
	syncSpiceDBHandler := spicedbsynchandler.New(
		w.SpiceDB,
		w.DB,
		w.RabbitPublisher,
	)

	projectEnvRelationshipInserter := projectenvrelationshipinserter.New(
		w.SpiceDB,
		w.DB,
		w.CpClient,
	)

	projectDeletedHandler := projectdeletedhandler.New(
		w.DB,
		w.SpiceDB,
	)

	envDeletedHandler := envdeletedhandler.New(
		w.DB,
		w.SpiceDB,
	)

	// Branch handler will send the message through _every_ handler that matches the regex.
	var inner handlers.Handler = &branchhandler.Handler{
		{PrefixPattern: regexp.MustCompile(string(genevents.IoPlatformOrchestratorSpicedbSync)), Handler: syncSpiceDBHandler},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorProjectCreated)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorProjectDeleted)), Handler: projectDeletedHandler},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorEnvironmentCreated)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(string(cpevents.IoPlatformOrchestratorEnvironmentDeleted)), Handler: envDeletedHandler},
		{PrefixPattern: regexp.MustCompile(string(genevents.IoPlatformOrchestratorScopeSync)), Handler: projectEnvRelationshipInserter},
		{PrefixPattern: regexp.MustCompile(""), Handler: handlers.HandlerFunc(func(ctx context.Context, logger *zap.Logger, d *rabbitmq.Delivery) error {
			logger.Info("dropping unsupported message")
			return nil
		})},
	}

	// This middleware handles timeouts, panic recovery, graceful retries, and logging
	inner = middleware.WrapWithObserver(inner, MainConsumerName, w.RabbitPublisher, w.Cache, w.RetryTimeout)

	return hrabbitmq.NewConsumerWithHandlerWaiter(
		w.RabbitConn,
		func(d rabbitmq.Delivery) (action rabbitmq.Action) {
			if err := inner.Handle(context.TODO(), w.Logger, &d); err != nil {
				return rabbitmq.NackDiscard
			}
			return rabbitmq.Ack
		},
		"platform-orchestrator-iam-main",
		rabbitmq.WithConsumerOptionsLogger(hrabbitmq.NewLogger(w.Logger)),
		rabbitmq.WithConsumerOptionsConsumerAutoAck(false),
		rabbitmq.WithConsumerOptionsConcurrency(MainConsumerConcurrency),
		rabbitmq.WithConsumerOptionsQueueDurable,
		rabbitmq.WithConsumerOptionsQueueArgs(rabbitmq.Table{
			"x-queue-type":              "quorum",
			"x-message-ttl":             MainConsumerMessageTtl.Milliseconds(),
			"x-dead-letter-exchange":    delayqueues.DefaultExchange,
			"x-dead-letter-routing-key": delayqueues.DeadLetterRoutingKey,
			// ensure we dead letter things correctly
			"x-dead-letter-strategy": "at-least-once",
			// ensure we reject publish if queue is full
			"x-overflow": "reject-publish",
		}),
		rabbitmq.WithConsumerOptionsExchangeName(events.DefaultExchange),
		rabbitmq.WithConsumerOptionsRoutingKey(string(genevents.IoPlatformOrchestratorSpicedbSync)),
		rabbitmq.WithConsumerOptionsRoutingKey(string(cpevents.IoPlatformOrchestratorProjectCreated)),
		rabbitmq.WithConsumerOptionsRoutingKey(string(cpevents.IoPlatformOrchestratorProjectDeleted)),
		rabbitmq.WithConsumerOptionsRoutingKey(string(cpevents.IoPlatformOrchestratorEnvironmentCreated)),
		rabbitmq.WithConsumerOptionsRoutingKey(string(cpevents.IoPlatformOrchestratorEnvironmentDeleted)),
		rabbitmq.WithConsumerOptionsRoutingKey(string(genevents.IoPlatformOrchestratorScopeSync)),
	)
}
