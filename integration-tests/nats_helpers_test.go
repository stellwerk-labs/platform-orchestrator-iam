package integrationtests

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/golib/hmessaging"
	"github.com/stellwerk-labs/golib/hnats"
	cpevents "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
)

func MustPublishProjectDeletedEvent(t *testing.T, orgID, projectID string, projectUUID uuid.UUID) {
	t.Helper()
	publishToNATS(t, string(cpevents.IoPlatformOrchestratorProjectDeleted), events.CloudEvent[cpevents.ProjectChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorProjectDeleted),
		Time: time.Now().UTC(),
		Data: cpevents.ProjectChangedData{
			OrgId:       orgID,
			ProjectId:   projectID,
			ProjectUuid: projectUUID,
		},
	})
}

func MustPublishEnvironmentDeletedEvent(t *testing.T, orgID, projectID, envID string, projectUUID, envUUID uuid.UUID) {
	t.Helper()
	publishToNATS(t, string(cpevents.IoPlatformOrchestratorEnvironmentDeleted), events.CloudEvent[cpevents.EnvChangedData]{
		Type: genevents.EventType(cpevents.IoPlatformOrchestratorEnvironmentDeleted),
		Time: time.Now().UTC(),
		Data: cpevents.EnvChangedData{
			OrgId:       orgID,
			ProjectId:   projectID,
			ProjectUuid: projectUUID,
			EnvId:       envID,
			EnvUuid:     envUUID,
		},
	})
}

func publishToNATS(t *testing.T, subject string, event any) {
	t.Helper()
	url := os.Getenv("NATS_URL")
	if url == "" {
		t.Skip("NATS_URL is not set")
	}

	connection, err := nats.Connect(url, nats.Name("platform-orchestrator-iam-integration-tests"))
	require.NoError(t, err)
	t.Cleanup(connection.Close)
	js, err := hnats.NewJetStream(connection)
	require.NoError(t, err)
	body, err := json.Marshal(event)
	require.NoError(t, err)

	publisher := hnats.NewPublisher(js, hmessaging.EventsStreamName, nil)
	err = publisher.Publish(context.Background(), hmessaging.Message{
		ID:        uuid.NewString(),
		Subject:   subject,
		Data:      body,
		CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	t.Logf("published event %s to JetStream", subject)
}
