package events

import (
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
)

// Source is the CloudEvents source URI-reference identifying this service as
// the producer of an event (CloudEvents 1.0 §3, REQUIRED attribute).
const Source = "/platform-orchestrator/iam"

// CloudEvent is the CloudEvents 1.0 JSON envelope. This repo both produces it
// (SCIM lifecycle events via the outbox) and decodes it (worker handlers for
// the control plane's project/environment events and scope.sync). Id and
// Source are plain strings so a foreign producer that omits them still
// decodes; New fills them for everything produced here.
type CloudEvent[e any] struct {
	SpecVersion CloudEventSpecVersion1 `json:"specversion"`
	Id          string                 `json:"id"`
	Source      string                 `json:"source"`
	Type        genevents.EventType    `json:"type"`
	Time        time.Time              `json:"time"`
	Data        e                      `json:"data"`
}

// New builds an envelope with the CloudEvents 1.0 REQUIRED attributes set:
// a fresh UUID id (unique per event, so consumers can deduplicate redeliveries)
// and this service's source.
func New[e any](eventType genevents.EventType, data e) CloudEvent[e] {
	return CloudEvent[e]{
		Id:     uuid.NewString(),
		Source: Source,
		Type:   eventType,
		Time:   time.Now().UTC(),
		Data:   data,
	}
}

type CloudEventSpecVersion1 struct{}

func (c CloudEventSpecVersion1) MarshalJSON() ([]byte, error) {
	return []byte(`"1.0"`), nil
}

func (c CloudEventSpecVersion1) UnmarshalJSON(data []byte) error {
	return nil
}
