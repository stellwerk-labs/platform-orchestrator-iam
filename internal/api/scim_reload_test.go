package api

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// countingReloadAuthorizer records how mutations ask for policy reloads:
// synchronously (ReloadPolicy — the revocation path) or coalesced
// (ScheduleReloadPolicy — the grant path). The coalescing itself is proven in
// internal/authorization; this stub proves each SCIM mutation picks the right
// side of the asymmetry.
type countingReloadAuthorizer struct {
	syncReloads      atomic.Int64
	scheduledReloads atomic.Int64
}

func (c *countingReloadAuthorizer) Authorize(context.Context, uuid.UUID, []authorization.Check) ([]authorization.Result, error) {
	return []authorization.Result{}, nil
}

func (c *countingReloadAuthorizer) ReloadPolicy() error {
	c.syncReloads.Add(1)
	return nil
}

func (c *countingReloadAuthorizer) ScheduleReloadPolicy() {
	c.scheduledReloads.Add(1)
}

// Provisioning N users must not trigger N synchronous policy reloads — grants
// go through the coalescing scheduler. A deactivation (revocation) must reload
// synchronously so the stripped access stops working before the response.
func TestScimReloads_ProvisioningCoalescesDeactivationIsSynchronous(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	reloads := &countingReloadAuthorizer{}
	s.Authorizer = reloads
	db := s.Database.(*mockmodel.MockDatabaser)
	logger := zaptest.NewLogger(t)

	// Loose expectations: this test is about reload behavior, not query shape.
	db.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, u *model.User) (*model.User, error) { return u, nil }).AnyTimes()
	db.EXPECT().CreateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, gomock.Any()).
		Return([]uuid.UUID{}, nil).AnyTimes()
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]uuid.UUID{}, nil).AnyTimes()
	// A manual membership exists → no Viewer fallback noise, and the
	// deactivation path keeps the sessions (other access remains).
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{Id: uuid.New(), OrgId: "other-org"}}}, nil).AnyTimes()
	db.EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
			return m, nil
		}).AnyTimes()
	db.EXPECT().BulkDeleteMemberships(gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(1), nil).AnyTimes()
	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	const provisioned = 10
	for i := 0; i < provisioned; i++ {
		_, err := s.scimProvisionUser(t.Context(), logger, scimProvisionUserInput{
			OrgId:    orgId,
			UserName: fmt.Sprintf("burst-user-%d", i),
			Active:   true,
		})
		require.NoError(t, err)
	}
	assert.Equal(t, int64(provisioned), reloads.scheduledReloads.Load(), "every grant must request a (coalescable) reload — coalescing means fewer reloads, not lost ones")
	assert.Equal(t, int64(0), reloads.syncReloads.Load(), "provisioning must not reload synchronously per user")

	// Deactivation revokes access → synchronous reload, no coalescing.
	now := time.Now().UTC()
	existing := model.ScimUser{
		Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(),
		UserName: "burst-user-0", Active: true, CreatedAt: now, UpdatedAt: now,
	}
	updated := existing
	updated.Active = false
	_, err := s.scimUpdateUser(t.Context(), logger, &existing, updated, scimGlobalUserFields{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), reloads.syncReloads.Load(), "a deactivation must reload the policy synchronously")
	assert.Equal(t, int64(provisioned), reloads.scheduledReloads.Load(), "a revocation must not be downgraded to a coalesced reload")
}

// Reactivation is nominally a grant, but its reconcile CAN delete a stale
// managed membership. The reload classification must follow what actually
// happened: any deletion is a revocation → synchronous reload.
func TestScimReloads_ReactivationFollowsWhatTheReconcileDid(t *testing.T) {
	t.Run("reconcile deleted a membership: synchronous", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()
		reloads := &countingReloadAuthorizer{}
		s.Authorizer = reloads
		db := s.Database.(*mockmodel.MockDatabaser)

		now := time.Now().UTC()
		existing := model.ScimUser{
			Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(),
			UserName: "react@example.com", Active: false, CreatedAt: now, UpdatedAt: now,
		}
		updated := existing
		updated.Active = true

		// An inactive user should hold no managed memberships, but that is an
		// invariant of the current deactivation code, not a law of nature. If a
		// stale one exists, reconcile deletes it — and the reload must be sync.
		staleMembershipId := uuid.New()
		staleRoleId := uuid.New()
		mappedRoleId := uuid.New()
		db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, existing.Id).
			Return([]uuid.UUID{mappedRoleId}, nil)
		db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), existing.Id).
			Return([]uuid.UUID{staleMembershipId}, nil)
		db.EXPECT().GetMembership(gomock.Any(), gomock.Any(), staleMembershipId).
			Return(&model.Membership{Id: staleMembershipId, OrgId: orgId, UserId: existing.UserId,
				SubjectType: model.MembershipSubjectTypeRole, Subject: staleRoleId.String(), Role: opt.Of(staleRoleId)}, nil)
		db.EXPECT().DeleteMembership(gomock.Any(), gomock.Any(), staleMembershipId).Return(nil)
		db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ model.Tx, m *model.Membership) (*model.Membership, error) { return m, nil })
		db.EXPECT().CreateScimManagedMembership(gomock.Any(), gomock.Any(), gomock.Any(), existing.Id).Return(nil)
		db.EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
				return m, nil
			})
		db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), reloads.syncReloads.Load(), "a reconcile that deleted a membership revoked access and must reload synchronously")
		assert.Equal(t, int64(0), reloads.scheduledReloads.Load())
	})

	t.Run("pure grant: coalesced", func(t *testing.T) {
		_, s, fin := MockServer(t)
		defer fin()
		reloads := &countingReloadAuthorizer{}
		s.Authorizer = reloads
		db := s.Database.(*mockmodel.MockDatabaser)

		now := time.Now().UTC()
		existing := model.ScimUser{
			Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(),
			UserName: "react2@example.com", Active: false, CreatedAt: now, UpdatedAt: now,
		}
		updated := existing
		updated.Active = true

		mappedRoleId := uuid.New()
		db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, existing.Id).
			Return([]uuid.UUID{mappedRoleId}, nil)
		db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), existing.Id).
			Return([]uuid.UUID{}, nil)
		db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ model.Tx, m *model.Membership) (*model.Membership, error) { return m, nil })
		db.EXPECT().CreateScimManagedMembership(gomock.Any(), gomock.Any(), gomock.Any(), existing.Id).Return(nil)
		db.EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
				return m, nil
			})
		db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		_, err := s.scimUpdateUser(t.Context(), zaptest.NewLogger(t), &existing, updated, scimGlobalUserFields{})
		require.NoError(t, err)
		assert.Equal(t, int64(0), reloads.syncReloads.Load())
		assert.Equal(t, int64(1), reloads.scheduledReloads.Load(), "a reactivation that only granted may be coalesced")
	})
}
