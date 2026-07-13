package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// TestUserProvider is an undocumented provider which allows test users to be registered by things like QA, etc.
// This uses the https://github.com/FiloSottile/age encryption standard and just requires the caller to know a
// secret recipient keys. The encrypted payload should just look like {"ProviderId":"","DisplayName":""}.
type TestUserProvider struct {
	identity age.Identity
}

func NewTestUserProvider(identity string) (*TestUserProvider, error) {
	r, err := age.ParseX25519Identity(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age identity '%s': %w", identity, err)
	}
	return &TestUserProvider{identity: r}, nil
}

func (t *TestUserProvider) IdentifyUser(ctx context.Context, logger *zap.Logger, token string) (IdentifiedUser, bool, error) {
	r, err := age.Decrypt(base64.NewDecoder(base64.StdEncoding, strings.NewReader(token)), t.identity)
	if err != nil {
		return IdentifiedUser{}, false, errors.Wrap(err, "failed to decrypt token")
	}
	var iu IdentifiedUser
	if err := json.NewDecoder(r).Decode(&iu); err != nil {
		return IdentifiedUser{}, false, errors.Wrap(err, "failed to decode decrypted token")
	}
	return iu, true, nil
}

// EncryptForTestUserProvider is a helper function to do the reverse of TestUserProvider.IdentifyUser
func EncryptForTestUserProvider(user IdentifiedUser, k *age.X25519Identity) string {
	buff := new(bytes.Buffer)
	bw := base64.NewEncoder(base64.StdEncoding, buff)
	aw, _ := age.Encrypt(bw, k.Recipient())
	_ = json.NewEncoder(aw).Encode(user)
	_ = aw.Close()
	_ = bw.Close()
	return buff.String()
}

var _ Provider = (*TestUserProvider)(nil)
