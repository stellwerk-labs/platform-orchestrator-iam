package integrationtests

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
)

// MustPublishProjectDeletedEvent publishes a ProjectDeleted event to RabbitMQ
func MustPublishProjectDeletedEvent(t *testing.T, orgId, projectId string, projectUuid uuid.UUID) {
	t.Helper()

	// Create the CloudEvent
	event := events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
		},
	}

	// Publish to RabbitMQ
	publishToRabbitMQ(t, string(cpevents.IoPlatformOrchestratorProjectDeleted), event)
}

// MustPublishEnvironmentDeletedEvent publishes an EnvironmentDeleted event to RabbitMQ
func MustPublishEnvironmentDeletedEvent(t *testing.T, orgId, projectId, envId string, projectUuid, envUuid uuid.UUID) {
	t.Helper()

	// Create the CloudEvent
	event := events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgId,
			ProjectId:   projectId,
			ProjectUuid: projectUuid,
			EnvId:       envId,
			EnvUuid:     envUuid,
		},
	}

	// Publish to RabbitMQ
	publishToRabbitMQ(t, string(cpevents.IoPlatformOrchestratorEnvironmentDeleted), event)
}

// publishToRabbitMQ is a helper that connects to RabbitMQ and publishes an event
func publishToRabbitMQ(t *testing.T, routingKey string, event interface{}) {
	t.Helper()

	// Get RabbitMQ connection details
	// In the integration test environment, RabbitMQ runs in Docker
	// and we need to use the internal Docker network hostname
	rabbitMQURL := os.Getenv("RABBITMQ_URL")
	if rabbitMQURL == "" {
		// The RabbitMQ service name from score-compose varies, but typically accessible via the internal network
		// For integration tests, we need to resolve this from the score-compose setup
		// Since we can't easily get the dynamic hostname, skip this test or use the worker's connection
		t.Skip("RABBITMQ_URL environment variable not set - cannot publish events for integration testing")
		return
	}

	// Connect to RabbitMQ
	conn, err := amqp.Dial(rabbitMQURL)
	require.NoError(t, err, "Failed to connect to RabbitMQ")
	defer func() { require.NoError(t, conn.Close()) }()

	// Create a channel
	ch, err := conn.Channel()
	require.NoError(t, err, "Failed to open channel")
	defer func() { require.NoError(t, ch.Close()) }()

	// Declare the exchange (using the same exchange as the worker)
	exchangeName := events.DefaultExchange
	err = ch.ExchangeDeclare(
		exchangeName, // name
		"topic",      // type
		true,         // durable
		false,        // auto-deleted
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	require.NoError(t, err, "Failed to declare exchange")

	// Marshal the event to JSON
	body, err := json.Marshal(event)
	require.NoError(t, err, "Failed to marshal event")

	// Publish the message
	err = ch.PublishWithContext(
		context.Background(),
		exchangeName, // exchange
		routingKey,   // routing key
		false,        // mandatory
		false,        // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
	require.NoError(t, err, "Failed to publish %s event", routingKey)

	t.Logf("Published event %s to RabbitMQ exchange %s", routingKey, exchangeName)
}
