package api

import (
	"context"
	"testing"
	"time"

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

// The tests below drive reconcileScimUserRoles directly. The strict mock
// controller enforces the negative space too: any DeleteMembership or
// CreateMembership call NOT expected here fails the test.

func testScimUserForReconcile() model.ScimUser {
	now := time.Now().UTC()
	return model.ScimUser{
		Id: uuid.New(), OrgId: orgId, UserId: userid.NewHumanUserId(),
		UserName: "recon@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
	}
}

func TestReconcile_AddsMappedRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	scimUser := testScimUserForReconcile()
	mappedRoleId := uuid.New()
	db := s.Database.(*mockmodel.MockDatabaser)

	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return([]uuid.UUID{mappedRoleId}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUser.Id).
		Return([]uuid.UUID{}, nil)
	var createdMembershipId uuid.UUID
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, m *model.Membership) (*model.Membership, error) {
			assert.Equal(t, orgId, m.OrgId)
			assert.Equal(t, scimUser.UserId, m.UserId)
			assert.Equal(t, mappedRoleId.String(), m.Subject)
			assert.Equal(t, mappedRoleId, m.Role.Must())
			createdMembershipId = m.Id
			return m, nil
		})
	db.EXPECT().CreateScimManagedMembership(gomock.Any(), gomock.Any(), gomock.Any(), scimUser.Id).
		DoAndReturn(func(_ context.Context, _ model.Tx, membershipId uuid.UUID, _ uuid.UUID) error {
			assert.Equal(t, createdMembershipId, membershipId)
			return nil
		})

	deleted, err := s.reconcileScimUserRoles(t.Context(), zaptest.NewLogger(t), nil, scimUser)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted, "a pure grant must not report deletions")
}

// A managed membership whose role is no longer mapped gets deleted, and with no
// mapping left and no manual grant the user falls back to a managed Viewer.
func TestReconcile_RemovesUnmappedManagedRoleAndFallsBackToViewer(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	scimUser := testScimUserForReconcile()
	staleMembershipId := uuid.New()
	staleRoleId := uuid.New()
	viewerRoleId := uuid.New()
	db := s.Database.(*mockmodel.MockDatabaser)

	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return([]uuid.UUID{}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUser.Id).
		Return([]uuid.UUID{staleMembershipId}, nil)
	// The only existing membership is the managed one → no manual grant → Viewer fallback.
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &scimUser.OrgId, UserId: &scimUser.UserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{
		{Membership: model.Membership{Id: staleMembershipId}},
	}, nil)
	db.EXPECT().ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer, IsSystem: true}}, nil)
	db.EXPECT().GetMembership(gomock.Any(), gomock.Any(), staleMembershipId).
		Return(&model.Membership{Id: staleMembershipId, OrgId: orgId, UserId: scimUser.UserId,
			SubjectType: model.MembershipSubjectTypeRole, Subject: staleRoleId.String(), Role: opt.Of(staleRoleId)}, nil)
	db.EXPECT().DeleteMembership(gomock.Any(), gomock.Any(), staleMembershipId).Return(nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, m *model.Membership) (*model.Membership, error) {
			assert.Equal(t, viewerRoleId.String(), m.Subject, "fallback must be the Viewer role")
			return m, nil
		})
	db.EXPECT().CreateScimManagedMembership(gomock.Any(), gomock.Any(), gomock.Any(), scimUser.Id).Return(nil)

	deleted, err := s.reconcileScimUserRoles(t.Context(), zaptest.NewLogger(t), nil, scimUser)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted, "the stale managed membership deletion must be reported so the caller reloads synchronously")
}

// A membership a human granted (not in scim_managed_memberships) is invisible
// to the reconciler's delete pass, and its presence suppresses the Viewer
// fallback: nothing is created, nothing is deleted.
func TestReconcile_LeavesManualMembershipAlone(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	scimUser := testScimUserForReconcile()
	manualRoleId := uuid.New()
	db := s.Database.(*mockmodel.MockDatabaser)

	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return([]uuid.UUID{}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUser.Id).
		Return([]uuid.UUID{}, nil)
	subjectTypeRole := model.MembershipSubjectTypeRole
	db.EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		OrgId: &scimUser.OrgId, UserId: &scimUser.UserId, SubjectType: &subjectTypeRole,
	}).Return([]model.MembershipWithUserMetadata{
		{Membership: model.Membership{Id: uuid.New(), Subject: manualRoleId.String(), Role: opt.Of(manualRoleId)}},
	}, nil)
	// No DeleteMembership, no CreateMembership, no ListRoles: the manual grant
	// stands and no Viewer gets piled on top. Enforced by the strict mock.

	deleted, err := s.reconcileScimUserRoles(t.Context(), zaptest.NewLogger(t), nil, scimUser)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
}

// A managed membership whose role is still mapped stays put: no delete, no
// duplicate create.
func TestReconcile_KeepsStillMappedManagedRole(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	scimUser := testScimUserForReconcile()
	mappedRoleId := uuid.New()
	managedMembershipId := uuid.New()
	db := s.Database.(*mockmodel.MockDatabaser)

	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return([]uuid.UUID{mappedRoleId}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUser.Id).
		Return([]uuid.UUID{managedMembershipId}, nil)
	db.EXPECT().GetMembership(gomock.Any(), gomock.Any(), managedMembershipId).
		Return(&model.Membership{Id: managedMembershipId, OrgId: orgId, UserId: scimUser.UserId,
			SubjectType: model.MembershipSubjectTypeRole, Subject: mappedRoleId.String(), Role: opt.Of(mappedRoleId)}, nil)

	deleted, err := s.reconcileScimUserRoles(t.Context(), zaptest.NewLogger(t), nil, scimUser)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
}

// When a human already granted the exact role a mapping targets, the conflict
// is swallowed and the grant is NOT adopted as SCIM-managed — a later group
// removal must not be able to revoke a human decision.
func TestReconcile_ManualGrantOfMappedRoleStaysManual(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	scimUser := testScimUserForReconcile()
	mappedRoleId := uuid.New()
	db := s.Database.(*mockmodel.MockDatabaser)

	db.EXPECT().ListRoleIdsForScimUserGroups(gomock.Any(), gomock.Any(), orgId, scimUser.Id).
		Return([]uuid.UUID{mappedRoleId}, nil)
	db.EXPECT().ListScimManagedMembershipIds(gomock.Any(), gomock.Any(), scimUser.Id).
		Return([]uuid.UUID{}, nil)
	db.EXPECT().CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, model.NewErrConflict("duplicate membership"))
	// No CreateScimManagedMembership: the strict mock fails the test if the
	// reconciler tries to claim the human's membership.

	deleted, err := s.reconcileScimUserRoles(t.Context(), zaptest.NewLogger(t), nil, scimUser)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
}
