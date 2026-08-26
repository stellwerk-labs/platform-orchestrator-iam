package integrationtests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
)

// scimUserEventEnvelope decodes both provisioned and deprovisioned CloudEvents:
// ScimUserDeprovisionedData is a strict superset of ScimUserProvisionedData
// (it adds Reason), so a provisioned payload unmarshals into it with an empty
// Reason.
type scimUserEventEnvelope struct {
	SpecVersion string                              `json:"specversion"`
	Id          string                              `json:"id"`
	Source      string                              `json:"source"`
	Type        string                              `json:"type"`
	Time        time.Time                           `json:"time"`
	Data        genevents.ScimUserDeprovisionedData `json:"data"`
}

// TestScimProvisioningEventsReachNats proves the second half of the SCIM audit
// trail. The unit tests in internal/api/scim_events_test.go pin the outbox
// INSERT; this test pins that the outbox flusher actually publishes the event
// and that a consumer on the events stream receives a well-formed CloudEvent.
//
// The flusher runs on a 60-90s schedule (reliableoutbox
// DefaultScheduledFlushPeriodFunc), so the final wait here is long by design.
func TestScimProvisioningEventsReachNats(t *testing.T) {
	t.Parallel()

	snapshot := startNatsEventCollector(t,
		string(genevents.IoPlatformOrchestratorScimUserProvisioned),
		string(genevents.IoPlatformOrchestratorScimUserDeprovisioned),
	)

	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	provision := func(t *testing.T, userName string) uuid.UUID {
		t.Helper()
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userName,
			Active:   true,
			Emails:   []testScimEmail{{Value: userName, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision %s: %s", userName, string(body))
		return uuid.MustParse(mustDecodeScimUser(t, body).Id)
	}

	deactivatedName := "scim-evt-deact-" + uuid.New().String()[:8] + "@test.example"
	deletedName := "scim-evt-del-" + uuid.New().String()[:8] + "@test.example"
	deactivatedScimId := provision(t, deactivatedName)
	deletedScimId := provision(t, deletedName)

	// Resolve the global user ids so the event payloads can be checked in full.
	deactivatedRow, err := db.GetScimUser(t.Context(), nil, orgId, deactivatedScimId)
	require.NoError(t, err)
	deletedRow, err := db.GetScimUser(t.Context(), nil, orgId, deletedScimId)
	require.NoError(t, err)

	// Deactivate the first user (reason: deactivated) ...
	status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", baseURL, deactivatedScimId), &caller, testScimPatch{
		Schemas: []string{testScimPatchSchema},
		Operations: []testScimPatchOp{
			{Op: "replace", Path: "active", Value: false},
		},
	})
	require.Equal(t, http.StatusOK, status, "deactivate: %s", string(body))

	// ... and delete the second (reason: deleted).
	status, body = scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", baseURL, deletedScimId), &caller, nil)
	require.Equal(t, http.StatusNoContent, status, "delete: %s", string(body))

	type wanted struct {
		subject  string
		scimId   uuid.UUID
		userId   uuid.UUID
		userName string
		reason   genevents.ScimDeprovisionReason
	}
	wants := []wanted{
		{string(genevents.IoPlatformOrchestratorScimUserProvisioned), deactivatedScimId, deactivatedRow.UserId, deactivatedName, ""},
		{string(genevents.IoPlatformOrchestratorScimUserProvisioned), deletedScimId, deletedRow.UserId, deletedName, ""},
		{string(genevents.IoPlatformOrchestratorScimUserDeprovisioned), deactivatedScimId, deactivatedRow.UserId, deactivatedName, genevents.Deactivated},
		{string(genevents.IoPlatformOrchestratorScimUserDeprovisioned), deletedScimId, deletedRow.UserId, deletedName, genevents.Deleted},
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		// Decode everything seen so far and keep only this org's events.
		type key struct {
			subject string
			scimId  uuid.UUID
			reason  genevents.ScimDeprovisionReason
		}
		got := make(map[key][]scimUserEventEnvelope)
		for _, raw := range snapshot() {
			var envelope scimUserEventEnvelope
			if !assert.NoError(c, json.Unmarshal(raw.Data, &envelope), "decode CloudEvent from: %s", string(raw.Data)) {
				continue
			}
			if envelope.Data.OrgId != orgId {
				continue
			}
			k := key{subject: raw.Subject, scimId: envelope.Data.ScimUserId, reason: envelope.Data.Reason}
			got[k] = append(got[k], envelope)
		}

		for _, w := range wants {
			matches := got[key{subject: w.subject, scimId: w.scimId, reason: w.reason}]
			if !assert.Len(c, matches, 1, "want exactly one %s event for scim user %s (reason %q)", w.subject, w.scimId, w.reason) {
				continue
			}
			e := matches[0]
			assert.Equal(c, "1.0", e.SpecVersion)
			// CloudEvents 1.0 REQUIRED attributes must survive the outbox round trip.
			_, idErr := uuid.Parse(e.Id)
			assert.NoError(c, idErr, "event id must be a uuid, got %q", e.Id)
			assert.Equal(c, "/platform-orchestrator/iam", e.Source)
			assert.Equal(c, w.subject, e.Type, "CloudEvent type must match the NATS subject")
			assert.False(c, e.Time.IsZero(), "event time must be set")
			assert.Equal(c, w.userId, e.Data.UserId)
			assert.Equal(c, w.userName, e.Data.UserName)
		}
	}, 4*time.Minute, 2*time.Second, "SCIM lifecycle events did not arrive on the events stream")
}
