package emailprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Provider interface {
	SendInvitationEmail(ctx context.Context, email string, params InvitationEmailParams) error
}

type InvitationEmailParams struct {
	UiHostUrl               string
	OrgId                   string
	InvitingUserDisplayName string
	MembershipSubjectType   string
	MembershipSubject       string
	InvitationId            uuid.UUID
	InvitationExpiresAt     time.Time
	EncodedRedemptionToken  string
}

type MockSentEmail struct {
	Email  string
	Params interface{}
}

type MockEmailProvider struct {
	mx             sync.Mutex
	SentEmails     []MockSentEmail
	WriteDirectory string
}

func (m *MockEmailProvider) SendInvitationEmail(ctx context.Context, email string, params InvitationEmailParams) error {
	m.mx.Lock()
	defer m.mx.Unlock()
	m.SentEmails = append(m.SentEmails, MockSentEmail{Email: email, Params: params})
	if m.WriteDirectory != "" {
		data, _ := json.Marshal(map[string]interface{}{
			"email":  email,
			"params": params,
		})
		fileName := fmt.Sprintf("%s-%s.json", uuid.Must(uuid.NewV7()), base64.RawURLEncoding.EncodeToString([]byte(email)))
		if err := os.MkdirAll(m.WriteDirectory, 0700); err != nil {
			return errors.Wrap(err, "failed to create mock email provider directory")
		} else if err := os.WriteFile(filepath.Join(m.WriteDirectory, fileName), data, 0655); err != nil { //nolint
			return errors.Wrap(err, "failed to write to mock email provider directory")
		}
	}
	return nil
}
