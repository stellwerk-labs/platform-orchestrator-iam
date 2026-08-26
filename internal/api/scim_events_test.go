package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// expectScimUserEvent registers an expectation for EXACTLY one outbox insert
// carrying one CloudEvent of the given type, and returns a pointer that holds
// the decoded event once the insert happened. The strict mock controller
// enforces both directions: an unexpected insert and a missing insert each
// fail the test.
func expectScimUserEvent[T any](t *testing.T, db *mockmodel.MockDatabaser, eventType genevents.EventType) *events.CloudEvent[T] {
	t.Helper()
	captured := new(events.CloudEvent[T])
	db.EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, messages []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
			require.Len(t, messages, 1, "exactly one event per operation")
			assert.Equal(t, string(eventType), messages[0].Subject)
			require.NoError(t, json.Unmarshal(messages[0].Payload, captured))
			assert.Equal(t, eventType, captured.Type)
			assert.False(t, captured.Time.IsZero(), "event time must be set")
			return messages, nil
		}).Times(1)
	return captured
}

func testActiveScimUser() model.ScimUser {
	now := time.Now().UTC()
	return model.ScimUser{
		Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(),
		UserName: "events@example.com", ExternalId: opt.Of("ext-evt"),
		Active: true, CreatedAt: now, UpdatedAt: now,
	}
}

// ------------------------------------------------------------------ provision

func TestScimUserEvents_ProvisionEmitsProvisioned(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)
	globalUserId := userid.NewHumanUserId()

	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-evt").
		Return(&globalUserId, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Any(), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Eve N. T."}, nil)
	var storedScimUserId uuid.UUID
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u model.ScimUser) error {
			storedScimUserId = u.Id
			return nil
		})
	// User already holds a manual membership, so no Viewer fallback noise.
	mockReconcileNoMappings(db, globalUserId, []model.MembershipWithUserMetadata{{Membership: model.Membership{Id: uuid.New()}}})
	captured := expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)

	_, err := s.scimProvisionUser(t.Context(), zaptest.NewLogger(t), scimProvisionUserInput{
		OrgId: orgId, UserName: "events@example.com", ExternalId: "ext-evt", Active: true,
	})
	require.NoError(t, err)
	assert.Equal(t, orgId, captured.Data.OrgId)
	assert.Equal(t, storedScimUserId, captured.Data.ScimUserId)
	assert.Equal(t, globalUserId, captured.Data.UserId)
	assert.Equal(t, "events@example.com", captured.Data.UserName)
	require.NotNil(t, captured.Data.ExternalId)
	assert.Equal(t, "ext-evt", *captured.Data.ExternalId)
}

// A user staged with active=false has no access yet, so no provisioned event
// may escape; it fires at activation instead. The strict mock fails the test
// on any InsertPendingEventMessages call.
func TestScimUserEvents_StagedInactiveProvisionEmitsNothing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)
	globalUserId := userid.NewHumanUserId()

	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-evt").
		Return(&globalUserId, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Any(), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Staged"}, nil)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	_, err := s.scimProvisionUser(t.Context(), zaptest.NewLogger(t), scimProvisionUserInput{
		OrgId: orgId, UserName: "events@example.com", ExternalId: "ext-evt", Active: false,
	})
	require.NoError(t, err)
}

// A failed provisioning must not leak an event. The failure happens before the
// outbox insert in the same transaction, and the strict mock proves no insert
// was attempted.
func TestScimUserEvents_ProvisionFailureEmitsNothing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)
	globalUserId := userid.NewHumanUserId()

	db.EXPECT().GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderScim, orgId+":ext-evt").
		Return(&globalUserId, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Any(), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Doomed"}, nil)
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(model.NewErrConflict("scim user name already exists in org"))

	_, err := s.scimProvisionUser(t.Context(), zaptest.NewLogger(t), scimProvisionUserInput{
		OrgId: orgId, UserName: "events@example.com", ExternalId: "ext-evt", Active: true,
	})
	require.Error(t, err)
}

// ------------------------------------------------------------------ deactivate / reactivate

func TestScimUserEvents_DeactivationEmitsDeprovisionedDeactivated(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	existing := testActiveScimUser()
	updated := existing
	updated.Active = false

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId: opt.Of(orgId), UserId: opt.Of(existing.UserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &existing.UserId}).
		Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), existing.UserId).Return(int64(1), nil)
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	captured := expectScimUserEvent[genevents.ScimUserDeprovisionedData](t, db, genevents.IoPlatformOrchestratorScimUserDeprovisioned)

	_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
	require.NoError(t, err)
	assert.Equal(t, genevents.Deactivated, captured.Data.Reason)
	assert.Equal(t, orgId, captured.Data.OrgId)
	assert.Equal(t, existing.Id, captured.Data.ScimUserId)
	assert.Equal(t, existing.UserId, captured.Data.UserId)
	assert.Equal(t, existing.UserName, captured.Data.UserName)
	require.NotNil(t, captured.Data.ExternalId)
	assert.Equal(t, "ext-evt", *captured.Data.ExternalId)
}

func TestScimUserEvents_ReactivationEmitsProvisioned(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	existing := testActiveScimUser()
	existing.Active = false
	updated := existing
	updated.Active = true

	mockReconcileNoMappings(db, existing.UserId, []model.MembershipWithUserMetadata{{Membership: model.Membership{Id: uuid.New()}}})
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	captured := expectScimUserEvent[genevents.ScimUserProvisionedData](t, db, genevents.IoPlatformOrchestratorScimUserProvisioned)

	_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
	require.NoError(t, err)
	assert.Equal(t, existing.Id, captured.Data.ScimUserId)
	assert.Equal(t, existing.UserName, captured.Data.UserName)
}

// A deactivation whose membership removal fails must not leak the event.
func TestScimUserEvents_DeactivationFailureEmitsNothing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	existing := testActiveScimUser()
	updated := existing
	updated.Active = false

	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(int64(0), assert.AnError)

	_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
	require.Error(t, err)
}

// An update that does not cross the active boundary is not a provisioning
// lifecycle change and must stay silent.
func TestScimUserEvents_PlainUpdateEmitsNothing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	existing := testActiveScimUser()
	updated := existing
	updated.UserName = "renamed@example.com"

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
	require.NoError(t, err)
}

// ------------------------------------------------------------------ delete

func TestScimUserEvents_DeleteEmitsDeprovisionedDeleted(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	scimUser := testActiveScimUser()
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), model.BulkDeleteMembershipsParams{
		OrgId: opt.Of(orgId), UserId: opt.Of(scimUser.UserId),
	}).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{UserId: &scimUser.UserId}).
		Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), scimUser.UserId).Return(int64(0), nil)
	db.EXPECT().DeleteScimUser(gomock.Any(), gomock.Any(), orgId, scimUser.Id).Return(nil)
	captured := expectScimUserEvent[genevents.ScimUserDeprovisionedData](t, db, genevents.IoPlatformOrchestratorScimUserDeprovisioned)

	require.NoError(t, s.scimDeleteUser(t.Context(), zaptest.NewLogger(t), &scimUser))
	assert.Equal(t, genevents.Deleted, captured.Data.Reason)
	assert.Equal(t, orgId, captured.Data.OrgId)
	assert.Equal(t, scimUser.Id, captured.Data.ScimUserId)
	assert.Equal(t, scimUser.UserId, captured.Data.UserId)
	assert.Equal(t, scimUser.UserName, captured.Data.UserName)
}

// A failed delete must not leak the event.
func TestScimUserEvents_DeleteFailureEmitsNothing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	scimUser := testActiveScimUser()
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(1), nil)
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]model.MembershipWithUserMetadata{}, nil)
	db.EXPECT().DeleteSessionTokensByUserId(gomock.Any(), gomock.Any(), scimUser.UserId).Return(int64(0), nil)
	db.EXPECT().DeleteScimUser(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return(assert.AnError)

	require.Error(t, s.scimDeleteUser(t.Context(), zaptest.NewLogger(t), &scimUser))
}
