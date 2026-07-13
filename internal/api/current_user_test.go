package api

import (
	"context"
	"testing"
	"time"

	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestCurrentUser(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	uid := userid.NewHumanUserId()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Any(), gomock.Eq(uid)).
		Return(&model.User{
			Id:             uid,
			CreatedAt:      time.Unix(1, 0),
			DisplayName:    "My User",
			LastLoggedInAt: &time.Time{},
			UserIdentities: map[model.UserIdentityProvider]string{
				model.UserIdentityProviderTestUser: "",
				model.UserIdentityProviderGoogle:   "",
			},
			PrimaryEmailAddress: opt.Of("user@example.com"),
		}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Any(), model.ListMembershipsParams{
		UserId: &uid,
	}).
		Return([]model.MembershipWithUserMetadata{
			{Membership: model.Membership{OrgId: "org-a"}},
			{Membership: model.Membership{OrgId: "org-b"}},
			{Membership: model.Membership{OrgId: "org-b"}},
			{Membership: model.Membership{OrgId: "org-a"}},
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())
	r, err := s.GetCurrentUser(ctx, GetCurrentUserRequestObject{})
	require.NoError(t, err)
	assert.Equal(t, GetCurrentUser200JSONResponse{
		CreatedAt:      time.Unix(1, 0),
		DisplayName:    "My User",
		Id:             uid,
		LastLoggedInAt: &time.Time{},
		LoginProviders: []string{"google", "testuser"},
		OrganizationMemberships: []CurrentUserOrgMembership{
			{Id: "org-a"},
			{Id: "org-b"},
		},
		PrimaryEmailAddress: opt.Of("user@example.com").Ref(),
	}, r)
}
