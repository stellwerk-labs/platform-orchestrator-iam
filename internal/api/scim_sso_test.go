package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	mockplatformorchestratorcp "github.com/stellwerk-labs/platform-orchestrator-iam/internal/clients/platformorchestratorcp/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider"
	mocksso "github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// TestSsoCallback_ScimProvisionedUserLinked verifies that when a user was previously
// provisioned via SCIM (so they exist with a primary email address but no SSO identity),
// logging in via SSO does NOT create a duplicate global user — instead it attaches the
// SSO identity to the existing user and returns the same user id.
func TestSsoCallback_ScimProvisionedUserLinked(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	// Simulate a single-tenant SSO provider (no SSO config lookup).
	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()

	// Org exists.
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Organization{Id: orgId},
		}, nil)

	// SSO provider returns a valid profile.
	ssoProviderOrgId := "sso-provider-org"
	ssoProviderUserId := "sso-user-id-1"
	profile := &ssoprovider.UserProfile{
		Email:          "scim-user@example.com",
		DisplayName:    "SCIM User",
		ProviderOrgId:  ssoProviderOrgId,
		ProviderUserId: ssoProviderUserId,
	}
	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(profile, nil)

	identityId := ssoProviderOrgId + ":" + ssoProviderUserId
	db := s.Database.(*mockmodel.MockDatabaser)

	// No SSO identity exists yet → GetUserIdByIdentity returns not found.
	db.EXPECT().
		GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderSso, identityId).
		Return(nil, model.NewErrNotFound("not found"))

	// FindUserByPrimaryEmail finds the SCIM-provisioned user.
	scimProvisionedUserId := userid.NewHumanUserId()
	now := time.Now().UTC()
	existingUser := &model.User{
		Id:                  scimProvisionedUserId,
		DisplayName:         "SCIM User",
		PrimaryEmailAddress: opt.Of("scim-user@example.com"),
		CreatedAt:           now,
		UserIdentities:      map[model.UserIdentityProvider]string{model.UserIdentityProviderScim: orgId + ":ext-abc"},
	}
	db.EXPECT().
		FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "scim-user@example.com").
		Return(existingUser, nil)

	// The user was SCIM-provisioned (and is active) in this org, so linking is allowed.
	db.EXPECT().
		FindScimUserByUserId(gomock.Any(), gomock.Any(), orgId, scimProvisionedUserId).
		Return(&model.ScimUser{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: scimProvisionedUserId,
			Active: true,
		}, nil)

	// The SSO identity must be written to the identities table: UpdateUser
	// deliberately does not persist them, so without this the account would be
	// re-matched by email on every single login.
	db.EXPECT().
		AddUserIdentity(gomock.Any(), gomock.Any(), scimProvisionedUserId, model.UserIdentityProviderSso, identityId).
		Return(nil)

	// UpdateUser attaches the SSO identity to the existing user.
	db.EXPECT().
		UpdateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.TxWithCommit, u *model.User) (*model.User, error) {
			require.Equal(t, scimProvisionedUserId, u.Id, "must update the SCIM user, not create a new one")
			require.Equal(t, identityId, u.UserIdentities[model.UserIdentityProviderSso], "SSO identity must be attached")
			return u, nil
		})

	// Membership check / creation.
	db.EXPECT().
		ListMemberships(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]model.MembershipWithUserMetadata{{Membership: model.Membership{
			Id: uuid.New(), UserId: scimProvisionedUserId, OrgId: orgId,
		}}}, nil)

	// Session token creation.
	db.EXPECT().
		CreateSessionToken(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&model.SessionToken{UserId: scimProvisionedUserId, ExpiresAt: now.Add(24 * 3600e9)}, nil)

	state := testSsoState(t)
	authCode := TestSsoAuthCode
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	resp, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{
		Params: GetSsoCallbackParams{
			Code:  &authCode,
			State: &state,
		},
	})
	require.NoError(t, err)

	successResp, ok := resp.(GetSsoCallback200JSONResponse)
	require.True(t, ok, "expected 200, got %T", resp)
	require.Equal(t, scimProvisionedUserId, successResp.Body.Id,
		"SSO login should return the same user id as the SCIM-provisioned user")
}

// TestSsoCallback_ScimDeprovisionedUserRejected verifies that a user whose SCIM row
// in the org is inactive (the IDP decommissioned them) cannot resurrect access by
// logging in via SSO.
func TestSsoCallback_ScimDeprovisionedUserRejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Organization{Id: orgId},
		}, nil)

	profile := &ssoprovider.UserProfile{
		Email:          "deprovisioned@example.com",
		DisplayName:    "Gone User",
		ProviderOrgId:  "sso-provider-org",
		ProviderUserId: "sso-user-gone",
	}
	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(profile, nil)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().
		GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderSso, "sso-provider-org:sso-user-gone").
		Return(nil, model.NewErrNotFound("not found"))

	deprovisionedUserId := userid.NewHumanUserId()
	db.EXPECT().
		FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "deprovisioned@example.com").
		Return(&model.User{
			Id:                  deprovisionedUserId,
			DisplayName:         "Gone User",
			PrimaryEmailAddress: opt.Of("deprovisioned@example.com"),
			UserIdentities:      map[model.UserIdentityProvider]string{},
		}, nil)

	db.EXPECT().
		FindScimUserByUserId(gomock.Any(), gomock.Any(), orgId, deprovisionedUserId).
		Return(&model.ScimUser{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: deprovisionedUserId,
			Active: false,
		}, nil)

	state := testSsoState(t)
	authCode := TestSsoAuthCode
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	resp, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{
		Params: GetSsoCallbackParams{Code: &authCode, State: &state},
	})
	require.NoError(t, err)
	_, ok := resp.(GetSsoCallback401JSONResponse)
	require.True(t, ok, "deprovisioned SCIM user must get 401, got %T", resp)
}

// TestSsoCallback_ScimDeprovisionedUserWithLinkedSsoIdentityRejected covers the
// other half of the deprovisioning gate: the user already has an SSO identity
// linked (they logged in before), then the IDP deactivates them via SCIM. The
// next SSO login resolves the identity directly (no email matching) and must
// still be rejected — otherwise the membership integrity fallback would hand
// the deprovisioned user a fresh Viewer membership.
func TestSsoCallback_ScimDeprovisionedUserWithLinkedSsoIdentityRejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Organization{Id: orgId},
		}, nil)

	profile := &ssoprovider.UserProfile{
		Email:          "linked-gone@example.com",
		DisplayName:    "Linked Gone User",
		ProviderOrgId:  "sso-provider-org",
		ProviderUserId: "sso-user-linked-gone",
	}
	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(profile, nil)

	db := s.Database.(*mockmodel.MockDatabaser)

	// The SSO identity is already linked → resolves straight to the user id.
	linkedUserId := userid.NewHumanUserId()
	db.EXPECT().
		GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderSso, "sso-provider-org:sso-user-linked-gone").
		Return(&linkedUserId, nil)

	// The org's SCIM row says the IDP deactivated them.
	db.EXPECT().
		FindScimUserByUserId(gomock.Any(), gomock.Any(), orgId, linkedUserId).
		Return(&model.ScimUser{
			Id:     uuid.New(),
			OrgId:  orgId,
			UserId: linkedUserId,
			Active: false,
		}, nil)

	// No GetUser / UpdateUser / ListMemberships / CreateMembership /
	// CreateSessionToken expectations: any of those calls fails the test,
	// because a deprovisioned user must be stopped before touching them.

	state := testSsoState(t)
	authCode := TestSsoAuthCode
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	resp, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{
		Params: GetSsoCallbackParams{Code: &authCode, State: &state},
	})
	require.NoError(t, err)
	_, ok := resp.(GetSsoCallback401JSONResponse)
	require.True(t, ok, "deprovisioned SCIM user with a linked SSO identity must get 401, got %T", resp)
}

// TestSsoCallback_EmailCollisionWithoutScimIsNotLinked verifies that an SSO login
// whose email happens to match an existing account NOT provisioned by this org's
// IDP does not get linked to that account (cross-org account-takeover guard) —
// a fresh user is created instead, matching pre-SCIM behavior.
func TestSsoCallback_EmailCollisionWithoutScimIsNotLinked(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.SsoProvider.(*mocksso.MockProvider).EXPECT().IsMultitenant().Return(false).AnyTimes()
	s.CpClient.(*mockplatformorchestratorcp.MockClientWithResponsesInterface).EXPECT().
		GetOrganizationWithResponse(gomock.Any(), orgId).
		Return(&cpclient.GetOrganizationResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &cpclient.Organization{Id: orgId},
		}, nil)

	profile := &ssoprovider.UserProfile{
		Email:          "victim@example.com",
		DisplayName:    "Same Email",
		ProviderOrgId:  "sso-provider-org",
		ProviderUserId: "sso-user-2",
	}
	s.SsoProvider.(*mocksso.MockProvider).EXPECT().
		GetUserProfile(gomock.Any(), TestSsoAuthCode).
		Return(profile, nil)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().
		GetUserIdByIdentity(gomock.Any(), gomock.Any(), model.UserIdentityProviderSso, "sso-provider-org:sso-user-2").
		Return(nil, model.NewErrNotFound("not found"))

	victimUserId := userid.NewHumanUserId()
	db.EXPECT().
		FindUserByPrimaryEmail(gomock.Any(), gomock.Any(), "victim@example.com").
		Return(&model.User{
			Id:                  victimUserId,
			DisplayName:         "Victim",
			PrimaryEmailAddress: opt.Of("victim@example.com"),
			UserIdentities:      map[model.UserIdentityProvider]string{},
		}, nil)

	// Not SCIM-provisioned in this org: linking must NOT happen.
	db.EXPECT().
		FindScimUserByUserId(gomock.Any(), gomock.Any(), orgId, victimUserId).
		Return(nil, model.NewErrNotFound("scim user not found"))

	var newUserId uuid.UUID
	db.EXPECT().
		CreateUser(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, in *model.User) (*model.User, error) {
			require.NotEqual(t, victimUserId, in.Id, "must not reuse the victim's account")
			newUserId = in.Id
			return in, nil
		})

	viewerRoleId := uuid.New()
	db.EXPECT().
		ListRoles(gomock.Any(), gomock.Any(), orgId).
		Return([]model.Role{
			{Id: viewerRoleId, OrgId: orgId, DisplayName: RoleViewer},
			{Id: uuid.New(), OrgId: orgId, DisplayName: RoleAdmin},
		}, nil)
	db.EXPECT().
		HasMemberships(gomock.Any(), gomock.Any(), orgId).
		Return(true, nil)
	db.EXPECT().
		CreateMembership(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, in *model.Membership) (*model.Membership, error) {
			require.Equal(t, newUserId, in.UserId)
			return in, nil
		})

	now := time.Now().UTC()
	db.EXPECT().
		CreateSessionToken(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ model.Tx, in *model.SessionToken) (*model.SessionToken, error) {
			require.Equal(t, newUserId, in.UserId)
			return &model.SessionToken{Sha256Hash: in.Sha256Hash, UserId: newUserId, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
		})

	state := testSsoState(t)
	authCode := TestSsoAuthCode
	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	resp, err := s.GetSsoCallback(ctx, GetSsoCallbackRequestObject{
		Params: GetSsoCallbackParams{Code: &authCode, State: &state},
	})
	require.NoError(t, err)
	successResp, ok := resp.(GetSsoCallback200JSONResponse)
	require.True(t, ok, "expected 200, got %T", resp)
	require.Equal(t, newUserId, successResp.Body.Id)
	require.NotEqual(t, victimUserId, successResp.Body.Id)
}
