package api

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

func TestNewSessionToken(t *testing.T) {
	uid := uuid.New()
	raw, st := NewSessionToken(uid, model.UserIdentityProviderTestUser)
	assert.Equal(t, uid, st.UserId)
	assert.NotEmpty(t, st.CreatedAt)
	assert.Greater(t, st.ExpiresAt, st.CreatedAt)
	assert.Equal(t, model.UserIdentityProviderTestUser, st.Provider)

	dt, err := DecodeSessionToken(raw)
	if assert.NoError(t, err) {
		h := sha256.Sum256(dt)
		assert.Equal(t, h[:], st.Sha256Hash)
	}
}

func Test_generateSetCookieForToken(t *testing.T) {
	raw, st := NewSessionToken(uuid.New(), "")
	assert.Equal(t, fmt.Sprintf(
		"session-token=%s; Path=/; Domain=test.com; Expires=%s; HttpOnly; Secure; SameSite=None",
		raw, strings.Replace(st.ExpiresAt.Format(time.RFC1123), "UTC", "GMT", 1),
	), (&Server{SessionTokenCookieDomain: "test.com"}).generateSetCookieForToken(raw, st))
}

func Test_generateSetCookieForLogout(t *testing.T) {
	assert.Equal(t, "session-token=; Path=/; Domain=test.com; Max-Age=0; HttpOnly; Secure; SameSite=None", (&Server{SessionTokenCookieDomain: "test.com"}).generateSetCookieForLogout())
}
