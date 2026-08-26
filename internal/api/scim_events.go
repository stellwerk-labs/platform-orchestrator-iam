package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hstandardoutbox"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
)

// SCIM provisioning lifecycle events, published through the transactional
// outbox so an operator can audit what an IDP did. The insert MUST run inside
// the transaction that performs the state change: the outbox row commits or
// rolls back together with it, so an event can never escape for a change that
// never happened.
//
// Semantics: "provisioned" fires when the user gains access (created active,
// or reactivated). A user staged with active=false emits nothing until
// activation — the payload carries no active flag, so a provisioned event for
// an access-less user would lie to whoever reads the audit trail.
// "deprovisioned" fires when access is removed, with a reason distinguishing
// active=false (deactivated) from a DELETE (deleted).

// insertScimUserProvisionedEvent writes a scim.user.provisioned event into the
// outbox within the caller's transaction.
func (s *Server) insertScimUserProvisionedEvent(ctx context.Context, tx model.Tx, scimUser model.ScimUser) error {
	return insertScimEventMessage(ctx, s.Database, tx, genevents.IoPlatformOrchestratorScimUserProvisioned, genevents.ScimUserProvisionedData{
		OrgId:      scimUser.OrgId,
		ScimUserId: scimUser.Id,
		UserId:     scimUser.UserId,
		UserName:   scimUser.UserName,
		ExternalId: scimUser.ExternalId.Ref(),
	})
}

// insertScimUserDeprovisionedEvent writes a scim.user.deprovisioned event into
// the outbox within the caller's transaction.
func (s *Server) insertScimUserDeprovisionedEvent(ctx context.Context, tx model.Tx, scimUser model.ScimUser, reason genevents.ScimDeprovisionReason) error {
	return insertScimEventMessage(ctx, s.Database, tx, genevents.IoPlatformOrchestratorScimUserDeprovisioned, genevents.ScimUserDeprovisionedData{
		OrgId:      scimUser.OrgId,
		ScimUserId: scimUser.Id,
		UserId:     scimUser.UserId,
		UserName:   scimUser.UserName,
		ExternalId: scimUser.ExternalId.Ref(),
		Reason:     reason,
	})
}

// insertScimEventMessage wraps the payload in a CloudEvent envelope and hands
// it to the outbox. A plain function because methods cannot have type params.
func insertScimEventMessage[T any](ctx context.Context, db model.Databaser, tx model.Tx, eventType genevents.EventType, data T) error {
	payload, err := json.Marshal(events.CloudEvent[T]{
		Type: eventType,
		Time: time.Now().UTC(),
		Data: data,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to marshal %s event", eventType)
	}
	if _, err := db.InsertPendingEventMessages(ctx, tx, []*hstandardoutbox.PendingEventMessage{{
		Subject: string(eventType),
		Payload: payload,
	}}); err != nil {
		return errors.Wrapf(err, "failed to insert %s event into outbox", eventType)
	}
	return nil
}
