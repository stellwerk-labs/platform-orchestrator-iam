package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hrabbitmq/reliableoutbox"
	"github.com/stellwerk-labs/golib/hstandardreliableoutbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/emailprovider"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestListInvitations(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	sampleUuid := uuid.New()
	sampleUuid2 := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListInvitations(gomock.Any(), gomock.Nil(), orgId).
		Return([]model.Invitation{{
			CreatedAt:             time.Unix(1, 0),
			CreatedBy:             sampleUuid,
			EmailAddress:          "example@example.com",
			ExpiresAt:             time.Unix(2, 0),
			Id:                    sampleUuid2,
			MembershipSubject:     "virtual-group",
			MembershipSubjectType: "owners",
		}}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.ListInvitations(ctx, ListInvitationsRequestObject{OrgId: orgId})
	require.NoError(t, err)
	require.Equal(t, ListInvitations200JSONResponse{
		Items: []InvitationSummary{
			{
				CreatedAt:             time.Unix(1, 0),
				CreatedBy:             sampleUuid,
				EmailAddress:          "example@example.com",
				ExpiresAt:             time.Unix(2, 0),
				Id:                    sampleUuid2,
				MembershipSubject:     "virtual-group",
				MembershipSubjectType: "owners",
			},
		},
	}, r)
}

func TestCreateInvitation_cannot_be_service_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.EmailProvider = new(emailprovider.MockEmailProvider)

	serviceUserId := userid.NewServiceUserTokenId()

	MockAuthorizationSuccess(s, serviceUserId, orgId, "manage")

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, serviceUserId.String())
	r, err := s.CreateInvitation(ctx, CreateInvitationRequestObject{OrgId: orgId})
	require.NoError(t, err)
	require.Equal(t, CreateInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "service users may not create invitations"}}, r)
}

func TestCreateInvitation_invalid_email(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.EmailProvider = new(emailprovider.MockEmailProvider)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.CreateInvitation(ctx, CreateInvitationRequestObject{OrgId: orgId, Body: &CreateInvitationJSONRequestBody{EmailAddress: "not-an-email"}})
	require.NoError(t, err)
	require.Equal(t, CreateInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invalid email address"}}, r)
}

func TestCreateInvitation_not_supported(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	// EmailProvider is not set, so invitations are not supported
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.CreateInvitation(ctx, CreateInvitationRequestObject{OrgId: orgId, Body: &CreateInvitationJSONRequestBody{EmailAddress: "test@example.com"}})
	require.NoError(t, err)
	require.Equal(t, CreateInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invitations are not supported"}}, r)
}

func TestCreateInvitation_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	inviteUid := uuid.New()
	now := time.Now()
	adminRoleId := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Not(nil), orgId).
		Return([]model.Role{{
			Id:          adminRoleId,
			DisplayName: "Admin",
			Permissions: []string{PermissionsManageAll},
		}, {
			Id:          uuid.New(),
			DisplayName: "Viewer",
			Permissions: []string{PermissionsReadAll},
		}}, nil)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateInvitation(gomock.Any(), gomock.Not(nil), gomock.Any()).DoAndReturn(func(ctx context.Context, optionalTx model.Tx, invitation *model.Invitation) (*model.Invitation, error) {
		assert.Equal(t, orgId, invitation.OrgId)
		assert.Equal(t, "a@b", invitation.EmailAddress)
		assert.Equal(t, adminRoleId.String(), invitation.MembershipSubject)
		assert.Equal(t, model.MembershipSubjectTypeRole, invitation.MembershipSubjectType)
		assert.Greater(t, invitation.ExpiresAt.Unix(), invitation.CreatedAt.Unix())
		assert.NotEmpty(t, invitation.Id)
		assert.Equal(t, userid.InternalSystemUuid, invitation.CreatedBy)
		assert.NotEmpty(t, invitation.RedemptionTokenSha256Hash)
		return &model.Invitation{
			CreatedAt:                 now,
			CreatedBy:                 userid.InternalSystemUuid,
			EmailAddress:              "a@b",
			ExpiresAt:                 now.Add(time.Hour * 24 * 14),
			Id:                        inviteUid,
			MembershipSubject:         adminRoleId.String(),
			MembershipSubjectType:     model.MembershipSubjectTypeRole,
			RedemptionTokenSha256Hash: invitation.RedemptionTokenSha256Hash,
		}, nil
	})

	s.EmailProvider = new(emailprovider.MockEmailProvider)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	exp := 14
	r, err := s.CreateInvitation(ctx, CreateInvitationRequestObject{OrgId: orgId, Body: &CreateInvitationJSONRequestBody{
		EmailAddress: "a@b", MembershipSubjectType: SubjectTypeVirtualGroup, MembershipSubject: model.MembershipSubjectOrganizationOwners, ExpiryInDays: &exp,
	}})
	require.NoError(t, err)
	require.Equal(t, CreateInvitation201JSONResponse{
		CreatedAt:             now,
		CreatedBy:             userid.InternalSystemUuid,
		EmailAddress:          "a@b",
		ExpiresAt:             now.Add(time.Hour * 24 * 14),
		Id:                    inviteUid,
		MembershipSubject:     adminRoleId.String(),
		MembershipSubjectType: SubjectTypeRole,
	}, r)

	emails := s.EmailProvider.(*emailprovider.MockEmailProvider).SentEmails
	if assert.Len(t, emails, 1) {
		assert.Equal(t, "a@b", emails[0].Email)
		params := emails[0].Params.(emailprovider.InvitationEmailParams)
		assert.Equal(t, orgId, params.OrgId)
		assert.Equal(t, adminRoleId.String(), params.MembershipSubject)
		assert.Equal(t, string(model.MembershipSubjectTypeRole), params.MembershipSubjectType)
		assert.Equal(t, inviteUid, params.InvitationId)
		assert.NotEmpty(t, params.EncodedRedemptionToken)
	}
}

func TestCreateInvitation_nominal_no_roles(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	inviteUid := uuid.New()
	now := time.Now()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListRoles(gomock.Any(), gomock.Not(nil), orgId).Return([]model.Role{}, nil)
	var adminRole model.Role
	s.Database.(*mockmodel.MockDatabaser).EXPECT().SeedRoles(gomock.Any(), gomock.Not(nil), orgId, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, _ string, roles []model.Role) error {
			for _, role := range roles {
				if role.DisplayName == "Admin" {
					adminRole = role
				}
			}
			return nil
		})

	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateInvitation(gomock.Any(), gomock.Not(nil), gomock.Any()).DoAndReturn(func(ctx context.Context, optionalTx model.Tx, invitation *model.Invitation) (*model.Invitation, error) {
		assert.Equal(t, orgId, invitation.OrgId)
		assert.Equal(t, "a@b", invitation.EmailAddress)
		assert.Equal(t, adminRole.Id.String(), invitation.MembershipSubject)
		assert.Equal(t, model.MembershipSubjectTypeRole, invitation.MembershipSubjectType)
		assert.Greater(t, invitation.ExpiresAt.Unix(), invitation.CreatedAt.Unix())
		assert.NotEmpty(t, invitation.Id)
		assert.Equal(t, userid.InternalSystemUuid, invitation.CreatedBy)
		assert.NotEmpty(t, invitation.RedemptionTokenSha256Hash)
		return &model.Invitation{
			CreatedAt:                 now,
			CreatedBy:                 userid.InternalSystemUuid,
			EmailAddress:              "a@b",
			ExpiresAt:                 now.Add(time.Hour * 24 * 14),
			Id:                        inviteUid,
			MembershipSubject:         adminRole.Id.String(),
			MembershipSubjectType:     model.MembershipSubjectTypeRole,
			RedemptionTokenSha256Hash: invitation.RedemptionTokenSha256Hash,
		}, nil
	})

	s.EmailProvider = new(emailprovider.MockEmailProvider)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	exp := 14
	r, err := s.CreateInvitation(ctx, CreateInvitationRequestObject{OrgId: orgId, Body: &CreateInvitationJSONRequestBody{
		EmailAddress: "a@b", MembershipSubjectType: SubjectTypeVirtualGroup, MembershipSubject: model.MembershipSubjectOrganizationOwners, ExpiryInDays: &exp,
	}})
	require.NoError(t, err)
	require.Equal(t, CreateInvitation201JSONResponse{
		CreatedAt:             now,
		CreatedBy:             userid.InternalSystemUuid,
		EmailAddress:          "a@b",
		ExpiresAt:             now.Add(time.Hour * 24 * 14),
		Id:                    inviteUid,
		MembershipSubject:     adminRole.Id.String(),
		MembershipSubjectType: SubjectTypeRole,
	}, r)

	emails := s.EmailProvider.(*emailprovider.MockEmailProvider).SentEmails
	if assert.Len(t, emails, 1) {
		assert.Equal(t, "a@b", emails[0].Email)
		params := emails[0].Params.(emailprovider.InvitationEmailParams)
		assert.Equal(t, orgId, params.OrgId)
		assert.Equal(t, adminRole.Id.String(), params.MembershipSubject)
		assert.Equal(t, string(model.MembershipSubjectTypeRole), params.MembershipSubjectType)
		assert.Equal(t, inviteUid, params.InvitationId)
		assert.NotEmpty(t, params.EncodedRedemptionToken)
	}
}

func TestRevokeInvitation_not_found(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil, model.NewErrNotFound("invitation not found"))
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RevokeInvitation(ctx, RevokeInvitationRequestObject{OrgId: orgId, InvitationId: uuid.New()})
	require.NoError(t, err)
	require.Equal(t, RevokeInvitation404JSONResponse{N404NotFoundJSONResponse: N404NotFoundJSONResponse{Error: "HTTP-404", Message: "invitation not found"}}, r)
}

func TestRevokeInvitation_wrong_org(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(&model.Invitation{OrgId: "other-org"}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RevokeInvitation(ctx, RevokeInvitationRequestObject{OrgId: orgId, InvitationId: uuid.New()})
	require.NoError(t, err)
	require.Equal(t, RevokeInvitation404JSONResponse{N404NotFoundJSONResponse: N404NotFoundJSONResponse{Error: "HTTP-404", Message: "invitation not found"}}, r)
}

func TestRevokeInvitation_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	inviteUid := uuid.New()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteUid).Return(&model.Invitation{OrgId: orgId, Id: inviteUid}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteInvitation(gomock.Any(), gomock.Not(nil), inviteUid).Return(nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RevokeInvitation(ctx, RevokeInvitationRequestObject{OrgId: orgId, InvitationId: inviteUid})
	require.NoError(t, err)
	require.Equal(t, RevokeInvitation204Response{}, r)
}

func TestGetInvitation_as_user_wrong_org(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	inviteId := uuid.New()
	now := time.Now().UTC()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), nil, inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetInvitation(ctx, GetInvitationRequestObject{OrgId: "other-org", InvitationId: inviteId})
	require.NoError(t, err)
	require.Equal(t, GetInvitation404JSONResponse{N404NotFoundJSONResponse: N404NotFoundJSONResponse{Error: "HTTP-404", Message: "invitation not found"}}, r)
}

func TestGetInvitation_as_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	inviteId := uuid.New()
	now := time.Now().UTC()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), nil, inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetInvitation(ctx, GetInvitationRequestObject{OrgId: orgId, InvitationId: inviteId})
	require.NoError(t, err)
	require.Equal(t, GetInvitation200JSONResponse{
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Id:        inviteId,
	}, r)
}

func TestGetInvitation_with_bad_redemption_token(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()
	now := time.Now().UTC()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), nil, inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, CreatedAt: now, ExpiresAt: now.Add(time.Hour), RedemptionTokenSha256Hash: []byte("bad-hash"),
	}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	redemptionToken := base64.RawURLEncoding.EncodeToString([]byte("token"))
	r, err := s.GetInvitation(ctx, GetInvitationRequestObject{OrgId: orgId, InvitationId: inviteId, Params: GetInvitationParams{RedemptionToken: &redemptionToken}})
	require.NoError(t, err)
	require.Equal(t, GetInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invalid redemption token"}}, r)
}

func TestGetInvitation_with_redemption_token(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()
	now := time.Now().UTC()

	redemptionToken := base64.RawURLEncoding.EncodeToString([]byte("token"))
	redemptionTokenHash, _ := hashRedemptionToken(redemptionToken)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), nil, inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, CreatedAt: now, ExpiresAt: now.Add(time.Hour), RedemptionTokenSha256Hash: redemptionTokenHash,
	}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.GetInvitation(ctx, GetInvitationRequestObject{OrgId: orgId, InvitationId: inviteId, Params: GetInvitationParams{RedemptionToken: &redemptionToken}})
	require.NoError(t, err)
	require.Equal(t, GetInvitation200JSONResponse{
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Id:        inviteId,
	}, r)
}

func TestRedeemInvitation_cannot_be_system_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "only valid users can redeem invitations"}}, r)
}

func TestRedeemInvitation_cannot_be_service_user(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	serviceUser := userid.NewServiceUserTokenId()
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, serviceUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "only valid users can redeem invitations"}}, r)
}

func TestRedeemInvitation_invite_wrong_org(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(&model.Invitation{}, nil)
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{
		OrgId: orgId, InvitationId: inviteId, Params: RedeemInvitationParams{RedemptionToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation404JSONResponse{N404NotFoundJSONResponse: N404NotFoundJSONResponse{Error: "HTTP-404", Message: "invitation not found"}}, r)
}

func TestRedeemInvitation_invite_expired(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId,
	}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{
		OrgId: orgId, InvitationId: inviteId, Params: RedeemInvitationParams{RedemptionToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invitation has expired"}}, r)
}

func TestRedeemInvitation_invalid_token(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, ExpiresAt: time.Now().Add(time.Hour),
	}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{
		OrgId: orgId, InvitationId: inviteId, Params: RedeemInvitationParams{RedemptionToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: N400BadRequestJSONResponse{Error: "HTTP-400", Message: "invalid redemption token"}}, r)
}

func TestRedeemInvitation_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()
	membershipId := uuid.New()
	h := sha256.Sum256([]byte("token"))
	roleId := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, ExpiresAt: time.Now().Add(time.Hour), RedemptionTokenSha256Hash: h[:], MembershipSubjectType: model.MembershipSubjectTypeRole, MembershipSubject: roleId.String(),
	}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Not(nil), gomock.Any()).Return([]model.MembershipWithUserMetadata{}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().CreateMembership(gomock.Any(), gomock.Not(nil), gomock.Any()).DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.Membership) (*model.Membership, error) {
		assert.NotEmpty(t, in.CreatedAt)
		assert.Equal(t, humanUser, in.UserId)
		assert.Equal(t, orgId, in.OrgId)
		assert.Equal(t, model.MembershipSubjectTypeRole, in.SubjectType)
		assert.Equal(t, roleId.String(), in.Subject)
		assert.Equal(t, roleId, in.Role.Must())
		out := *in
		out.Id = membershipId
		out.CreatedAt = time.Unix(1, 0)
		return &out, nil
	})
	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(nil)
	store := new(reliableoutbox.InMemoryStorage[*hstandardreliableoutbox.PendingEventMessage])
	s.Database.(*mockmodel.MockDatabaser).EXPECT().InsertPendingEventMessages(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, m []*hstandardreliableoutbox.PendingEventMessage) ([]*hstandardreliableoutbox.PendingEventMessage, error) {
			store.Put(m)
			var msg events.CloudEvent[genevents.SpiceDBSyncData]
			require.NoError(t, json.Unmarshal(m[0].Payload, &msg))
			require.Equal(t, genevents.IoPlatformOrchestratorSpicedbSync, msg.Type)
			require.Equal(t, orgId, msg.Data.OrgId)
			require.Len(t, m, 1)
			return m, nil
		}).Times(1)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().AsReliableOutboxStore().Return(store).Times(1)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{
		OrgId: orgId, InvitationId: inviteId, Params: RedeemInvitationParams{RedemptionToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation200JSONResponse(UserMembership{
		CreatedAt:   time.Unix(1, 0),
		Id:          membershipId,
		OrgId:       orgId,
		Subject:     roleId.String(),
		SubjectType: SubjectTypeRole,
	}), r)
}

func TestRedeemInvitation_already_a_member(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	humanUser := userid.NewHumanUserId()
	inviteId := uuid.New()
	membershipId := uuid.New()
	h := sha256.Sum256([]byte("token"))
	roleId := uuid.New()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(&model.Invitation{
		Id: inviteId, OrgId: orgId, ExpiresAt: time.Now().Add(time.Hour), RedemptionTokenSha256Hash: h[:], MembershipSubjectType: model.MembershipSubjectTypeRole, MembershipSubject: roleId.String(),
	}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().ListMemberships(gomock.Any(), gomock.Not(nil), gomock.Any()).Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{
		Id: membershipId, UserId: humanUser, OrgId: orgId, SubjectType: model.MembershipSubjectTypeRole, Subject: roleId.String(), CreatedAt: time.Unix(1, 0),
	}}}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteInvitation(gomock.Any(), gomock.Not(nil), inviteId).Return(nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RedeemInvitation(ctx, RedeemInvitationRequestObject{
		OrgId: orgId, InvitationId: inviteId, Params: RedeemInvitationParams{RedemptionToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	require.Equal(t, RedeemInvitation200JSONResponse(UserMembership{
		CreatedAt:   time.Unix(1, 0),
		Id:          membershipId,
		OrgId:       orgId,
		Subject:     roleId.String(),
		SubjectType: SubjectTypeRole,
	}), r)
}
