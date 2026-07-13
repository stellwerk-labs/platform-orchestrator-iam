package emailprovider

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSendGrid(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	inviteId := uuid.New()
	rt := NewMockRoundTripper(ctrl)
	rt.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "https://api.sendgrid.com/v3/mail/send", req.URL.String())
		delete(req.Header, "User-Agent")
		assert.Equal(t, http.Header{
			"Accept":        []string{"application/json"},
			"Authorization": []string{"Bearer some-api-key"},
			"Content-Type":  []string{"application/json"},
		}, req.Header)
		raw, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{
	"personalizations":[{
		"to":[{"email":"my@email.com"}]
	}],
	"from":{"email":"product@po.com","name":"Platform Orchestrator"},
	"subject":"Your Platform Orchestrator user seat is ready to claim",
	"content":[{
		"type":"text/html",
		"value":"Hi,<br>\n<br>\nWelcome to Platform Orchestrator! You've been invited by Bob Smith to join the <b>my-org</b> organization on <a href=\"https://example.com\">Platform Orchestrator</a>.<br>\n`+
			`<br>\n`+
			`Click the link below <b>before 1970-01-01 00AM</b> to complete your registration and to get started. If you weren't expecting this invitation, please ignore this email.<br>\n`+
			`<br>\n`+
			`<a href=\"https://example.com/accept-invite?orgId=my-org&inviteId=`+inviteId.String()+`&redemptionToken=some-token\">Claim membership now</a><br>\n`+
			`<br>\n`+
			`Or copy and paste this link into your browser: <span style=\"user-select: all\">https://example.com/accept-invite?orgId=my-org&inviteId=`+inviteId.String()+`&redemptionToken=some-token</span><br>\n`+
			`<br>\n`+
			`Let us know if you have any questions. You can just respond to this email.<br>\n<br>\nHappy deploying,<br>\n<br>\nPlatform Orchestrator"
	}],
	"tracking_settings": {
      "click_tracking": { "enable": false, "enable_text": false },
      "open_tracking": { "enable": false }
    }
}`, string(raw))
		return &http.Response{StatusCode: 200}, nil
	})

	sp := NewSendGrid(&http.Client{Transport: rt}, "some-api-key", "Platform Orchestrator", "product@po.com", "Platform Orchestrator")

	require.NoError(t, sp.SendInvitationEmail(t.Context(), "my@email.com", InvitationEmailParams{
		UiHostUrl:               "https://example.com",
		OrgId:                   "my-org",
		InvitingUserDisplayName: "Bob Smith",
		InvitationId:            inviteId,
		InvitationExpiresAt:     time.Unix(1, 0).UTC(),
		EncodedRedemptionToken:  "some-token",
	}))
}

func TestSendGrid_CustomConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	inviteId := uuid.New()
	rt := NewMockRoundTripper(ctrl)
	rt.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{
	"personalizations":[{
		"to":[{"email":"my@email.com"}]
	}],
	"from":{"email":"noreply@platformorchestrator.io","name":"Platform Orchestrator Team"},
	"subject":"Your Platform Orchestrator user seat is ready to claim",
	"content":[{
		"type":"text/html",
		"value":"Hi,<br>\n<br>\nWelcome to Platform Orchestrator! You've been invited by Bob Smith to join the <b>my-org</b> organization on <a href=\"https://example.com\">Platform Orchestrator</a>.<br>\n`+
			`<br>\n`+
			`Click the link below <b>before 1970-01-01 00AM</b> to complete your registration and to get started. If you weren't expecting this invitation, please ignore this email.<br>\n`+
			`<br>\n`+
			`<a href=\"https://example.com/accept-invite?orgId=my-org&inviteId=`+inviteId.String()+`&redemptionToken=some-token\">Claim membership now</a><br>\n`+
			`<br>\n`+
			`Or copy and paste this link into your browser: <span style=\"user-select: all\">https://example.com/accept-invite?orgId=my-org&inviteId=`+inviteId.String()+`&redemptionToken=some-token</span><br>\n`+
			`<br>\n`+
			`Let us know if you have any questions. You can just respond to this email.<br>\n<br>\nHappy deploying,<br>\n<br>\nPlatform Orchestrator"
	}],
	"tracking_settings": {
      "click_tracking": { "enable": false, "enable_text": false },
      "open_tracking": { "enable": false }
    }
}`, string(raw))
		return &http.Response{StatusCode: 200}, nil
	})

	sp := NewSendGrid(&http.Client{Transport: rt}, "some-api-key", "Platform Orchestrator Team", "noreply@platformorchestrator.io", "Platform Orchestrator")

	require.NoError(t, sp.SendInvitationEmail(t.Context(), "my@email.com", InvitationEmailParams{
		UiHostUrl:               "https://example.com",
		OrgId:                   "my-org",
		InvitingUserDisplayName: "Bob Smith",
		InvitationId:            inviteId,
		InvitationExpiresAt:     time.Unix(1, 0).UTC(),
		EncodedRedemptionToken:  "some-token",
	}))
}
