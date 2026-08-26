package emailprovider

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
)

//go:generate go tool mockgen -destination round_trip_mock.go -package emailprovider net/http RoundTripper

const (
	htmlContentTemplate = `Hi,<br>
<br>
Welcome to {{ .ProductName }}! You've been invited by {{ .InvitingUserDisplayName }} to join the <b>{{ .OrgId }}</b> organization on <a href="{{ .UiHostUrl }}">{{ .ProductName }}</a>.<br>
<br>
Click the link below <b>before {{ .InvitationExpiresAt.Format "2006-01-02 15PM" }}</b> to complete your registration and to get started. If you weren't expecting this invitation, please ignore this email.<br>
<br>
<a href="{{ .UiHostUrl }}/accept-invite?orgId={{ .OrgId }}&inviteId={{ .InvitationId }}&redemptionToken={{ .EncodedRedemptionToken }}">Claim membership now</a><br>
<br>
Or copy and paste this link into your browser: <span style="user-select: all">{{ .UiHostUrl }}/accept-invite?orgId={{ .OrgId }}&inviteId={{ .InvitationId }}&redemptionToken={{ .EncodedRedemptionToken }}</span><br>
<br>
Let us know if you have any questions. You can just respond to this email.<br>
<br>
Happy deploying,<br>
<br>
{{ .ProductName }}`
)

type SendGrid struct {
	client        *sendgrid.Client
	htmlTemplate  *template.Template
	senderName    string
	senderAddress string
	productName   string
}

func NewSendGrid(client *http.Client, apiKey, senderName, senderAddress, productName string) *SendGrid {
	sendgrid.DefaultClient.HTTPClient = client
	sendClient := sendgrid.NewSendClient(apiKey)
	t, err := template.New("").Parse(htmlContentTemplate)
	if err != nil {
		panic(err)
	}
	return &SendGrid{client: sendClient, htmlTemplate: t, senderName: senderName, senderAddress: senderAddress, productName: productName}
}

var _ Provider = (*SendGrid)(nil)

func (s *SendGrid) SendInvitationEmail(ctx context.Context, email string, params InvitationEmailParams) error {
	var buff bytes.Buffer
	templateData := struct {
		InvitationEmailParams
		ProductName string
	}{params, s.productName}
	if err := s.htmlTemplate.ExecuteTemplate(&buff, "", templateData); err != nil {
		return errors.Wrap(err, "failed to execute template")
	}

	// build and email and personalize it
	newMail := mail.NewV3MailInit(
		mail.NewEmail(s.senderName, s.senderAddress),
		fmt.Sprintf("Your %s user seat is ready to claim", s.productName),
		mail.NewEmail("", email),
		mail.NewContent("text/html", buff.String()),
	)

	falseValue := false
	newMail.TrackingSettings = &mail.TrackingSettings{
		ClickTracking: &mail.ClickTrackingSetting{Enable: &falseValue, EnableText: &falseValue},
		OpenTracking:  &mail.OpenTrackingSetting{Enable: &falseValue},
	}

	// send the mail! under the hood the sendgrid client does some retries and rate limiting
	if r, err := s.client.SendWithContext(ctx, newMail); err != nil {
		return errors.Wrap(err, "failed to send email")
	} else if r.StatusCode >= 300 {
		return errors.Errorf("failed to send email: %d: %s", r.StatusCode, r.Body)
	} else {
		hlogger.TraceScopedLoggerFromCtx(zap.L(), ctx).Info("sent invitation email", zap.Int("status_code", r.StatusCode))
		return nil
	}
}
