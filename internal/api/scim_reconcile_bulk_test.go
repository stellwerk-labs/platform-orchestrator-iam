package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// The tests below drive reconcileScimUsersById, the bulk twin of
// reconcileScimUserRoles. The semantics under test are the same ones the
// per-user tests in scim_reconcile_test.go pin down; on top of that they pin
// the scalability contract: one batched call per lookup kind regardless of how
// many users are reconciled, and one batched call each for deletes and
// creates. The strict mock controller enforces the negative space — any
// DeleteMembershipsByIds or BulkCreateScimManagedMemberships call NOT expected
// here fails the test.

func testScimUsersForBulkReconcile(n int) []model.ScimUser {
	users := make([]model.ScimUser, 0, n)
	for i := 0; i < n; i++ {
		users = append(users, model.ScimUser{
			Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(), Active: true,
		})
	}
	return users
}

func scimIdsOf(users []model.ScimUser) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.Id)
	}
	return ids
}

// Many users, one reconciliation pass: exactly one lookup per kind and one
// batched delete + one batched create, with per-user semantics intact — user A
// gains its mapped role, user B loses its stale managed role and falls back to
// Viewer, user C's still-mapped managed role is left alone.
func TestBulkReconcile_BatchesLookupsAndWrites(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	users := testScimUsersForBulkReconcile(3)
	userA, userB, userC := users[0], users[1], users[2]
	roleA := uuid.New()
	roleC := uuid.New()
	staleRoleB := uuid.New()
	staleMembershipB := uuid.New()
	keptMembershipC := uuid.New()
	viewerRoleId := uuid.New()
	ids := scimIdsOf(users)

	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Any(), orgId, ids).Return(users, nil)
	db.EXPECT().ListRoleIdsForScimUsersGroups(gomock.Any(), gomock.Any(), orgId, ids).
		Return(map[uuid.UUID][]uuid.UUID{
			userA.Id: {roleA},
			userC.Id: {roleC},
		}, nil)
	db.EXPECT().ListScimManagedMembershipsForScimUsers(gomock.Any(), gomock.Any(), orgId, ids).
		Return([]model.ScimManagedMembership{
			{ScimUserId: userB.Id, MembershipId: staleMembershipB, RoleId: opt.Of(staleRoleB)},
			{ScimUserId: userC.Id, MembershipId: keptMembershipC, RoleId: opt.Of(roleC)},
		}, nil)
	// Only userB has no mapped roles → only its global user is checked for
	// manual grants. Its sole membership is the managed one → Viewer fallback.
	db.EXPECT().ListRoleMembershipIdsByUser(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{userB.UserId}).
		Return(map[uuid.UUID][]uuid.UUID{userB.UserId: {staleMembershipB}}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer, IsSystem: true}}, nil)

	db.EXPECT().DeleteMembershipsByIds(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{staleMembershipB}).Return(nil)
	db.EXPECT().BulkCreateScimManagedMemberships(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, items []model.NewScimManagedMembership) error {
			require.Len(t, items, 2)
			byScimUser := make(map[uuid.UUID]model.NewScimManagedMembership, len(items))
			for _, item := range items {
				byScimUser[item.ScimUserId] = item
			}
			require.Contains(t, byScimUser, userA.Id)
			assert.Equal(t, roleA, byScimUser[userA.Id].Membership.Role.Must(), "user A gains its freshly mapped role")
			assert.Equal(t, userA.UserId, byScimUser[userA.Id].Membership.UserId)
			require.Contains(t, byScimUser, userB.Id)
			assert.Equal(t, viewerRoleId, byScimUser[userB.Id].Membership.Role.Must(), "user B falls back to Viewer")
			require.NotContains(t, byScimUser, userC.Id, "user C's still-mapped managed role needs no create")
			return nil
		})

	require.NoError(t, s.reconcileScimUsersById(t.Context(), zaptest.NewLogger(t), nil, orgId, ids))
}

// Ids are deduplicated before the lookup, inactive users are skipped entirely,
// and ids the batched lookup does not return (deleted between the group read
// and this pass) are silently ignored — no error, no writes.
func TestBulkReconcile_DedupesSkipsInactiveAndMissing(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	inactive := model.ScimUser{Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(), Active: false}
	missingId := uuid.New()
	requested := []uuid.UUID{inactive.Id, inactive.Id, missingId}

	// The deduplicated id set goes into ONE lookup; the missing id is simply
	// absent from the result and the inactive user is dropped, so no further
	// queries and no writes happen (enforced by the strict mock).
	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{inactive.Id, missingId}).
		Return([]model.ScimUser{inactive}, nil)

	require.NoError(t, s.reconcileScimUsersById(t.Context(), zaptest.NewLogger(t), nil, orgId, requested))
}

// An empty id list must not touch the database at all.
func TestBulkReconcile_NoIdsNoQueries(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	require.NoError(t, s.reconcileScimUsersById(t.Context(), zaptest.NewLogger(t), nil, orgId, nil))
}

// A membership a human granted (present in the org's role memberships but not
// in scim_managed_memberships) is invisible to the delete pass and suppresses
// the Viewer fallback: nothing is deleted, nothing is created.
func TestBulkReconcile_LeavesManualMembershipAlone(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	db := s.Database.(*mockmodel.MockDatabaser)

	users := testScimUsersForBulkReconcile(1)
	user := users[0]
	manualMembershipId := uuid.New()

	db.EXPECT().GetScimUsersByIds(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{user.Id}).Return(users, nil)
	db.EXPECT().ListRoleIdsForScimUsersGroups(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{user.Id}).
		Return(map[uuid.UUID][]uuid.UUID{}, nil)
	db.EXPECT().ListScimManagedMembershipsForScimUsers(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{user.Id}).
		Return([]model.ScimManagedMembership{}, nil)
	db.EXPECT().ListRoleMembershipIdsByUser(gomock.Any(), gomock.Any(), orgId, []uuid.UUID{user.UserId}).
		Return(map[uuid.UUID][]uuid.UUID{user.UserId: {manualMembershipId}}, nil)
	// No ListRoles, no DeleteMembershipsByIds, no BulkCreateScimManagedMemberships:
	// the manual grant stands and no Viewer gets piled on top.

	require.NoError(t, s.reconcileScimUsersById(t.Context(), zaptest.NewLogger(t), nil, orgId, []uuid.UUID{user.Id}))
}
