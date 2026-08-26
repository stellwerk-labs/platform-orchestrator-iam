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
