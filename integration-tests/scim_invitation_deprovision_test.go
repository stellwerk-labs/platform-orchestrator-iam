package integrationtests

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// TestScimDeprovisionRevokesInvitations proves that a bearer invitation cannot
// restore an organization membership after the IDP withdraws the user.
func TestScimDeprovisionRevokesInvitations(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := scimProxyBaseURL(t, orgId)

	victimEmail := fmt.Sprintf("invite-victim-%s@example.com", uuid.NewString())
	registered, err := client.RegisterUserWithResponse(t.Context(), &serverclient.RegisterUserParams{}, serverclient.RegisterUserBody{
		Provider: "testuser",
		ProviderToken: MustGenerateTestUserTokenWith(t, TestUser{
			ProviderId: rand.Text(), DisplayName: "Invite Victim", Email: victimEmail,
		}),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, registered.StatusCode(), "register victim: %s", string(registered.Body))
	victimId := registered.JSON202.Id

	status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
		Schemas: []string{testScimUserSchema}, UserName: victimEmail, Active: true,
		Emails: []testScimEmail{{Value: victimEmail, Primary: true, Type: "work"}},
	})
	require.Equal(t, http.StatusCreated, status, "provision victim: %s", string(body))
	scimUserId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

	viewerRoleId := MustObtainRoleIdByName(t, client, orgId, DefaultViewerRoleName)
	redemptionToken := []byte("scim-deprovision-invitation-" + uuid.NewString())
	redemptionHash := sha256.Sum256(redemptionToken)
	invitationId := uuid.New()
	db := MustDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.CreateInvitation(t.Context(), nil, &model.Invitation{
		Id: invitationId, OrgId: orgId, CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedBy: adminId,
		RedemptionTokenSha256Hash: redemptionHash[:], EmailAddress: victimEmail,
		MembershipSubjectType: model.MembershipSubjectTypeRole, MembershipSubject: viewerRoleId.String(),
	})
	require.NoError(t, err)

	status, body = scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", baseURL, scimUserId), &caller, testScimPatch{
		Schemas:    []string{testScimPatchSchema},
		Operations: []testScimPatchOp{{Op: "replace", Path: "active", Value: false}},
	})
	require.Equal(t, http.StatusOK, status, "deactivate victim: %s", string(body))

	invites, err := db.ListInvitations(t.Context(), nil, orgId)
	require.NoError(t, err)
	for _, invitation := range invites {
		require.NotEqual(t, invitationId, invitation.Id, "deprovisioning must delete the pending invitation")
	}

	redeem, err := client.RedeemInvitationWithResponse(t.Context(), orgId, invitationId, &serverclient.RedeemInvitationParams{
		RedemptionToken: base64.RawURLEncoding.EncodeToString(redemptionToken),
	}, WithAuthenticatedUserId(victimId))
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, redeem.StatusCode(), "the revoked invitation must not restore access: %s", string(redeem.Body))
	require.Equal(t, 0, countMembershipsByEmail(t, client, orgId, adminId, victimEmail), "deprovisioned user must still have no membership")
}
