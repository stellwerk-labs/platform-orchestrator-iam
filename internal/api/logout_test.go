package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
)

func TestLogout_with_session_invalidation(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteSessionTokenByHash(gomock.Any(), gomock.Any(), gomock.Eq([]byte("token-hash"))).
		Return(nil)

	tokenHash := EncodeSessionToken([]byte("token-hash"))
	r, err := s.LogoutSession(t.Context(), LogoutSessionRequestObject{Params: LogoutSessionParams{XTokenHash: &tokenHash}})
	require.NoError(t, err)
	assert.Equal(t, LogoutSession204Response{
		Headers: LogoutSession204ResponseHeaders{
			SetCookie: "session-token=; Path=/; Domain=cookie.domain; Max-Age=0; HttpOnly; Secure; SameSite=None",
		},
	}, r)
}

func TestLogout_with_expired_session(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	s.Database.(*mockmodel.MockDatabaser).EXPECT().DeleteSessionTokenByHash(gomock.Any(), gomock.Any(), gomock.Eq([]byte("token-hash"))).
		Return(model.NewErrNotFound("not found"))

	tokenHash := EncodeSessionToken([]byte("token-hash"))
	r, err := s.LogoutSession(t.Context(), LogoutSessionRequestObject{Params: LogoutSessionParams{XTokenHash: &tokenHash}})
	require.NoError(t, err)
	assert.Equal(t, LogoutSession204Response{
		Headers: LogoutSession204ResponseHeaders{
			SetCookie: "session-token=; Path=/; Domain=cookie.domain; Max-Age=0; HttpOnly; Secure; SameSite=None",
		},
	}, r)
}

func TestLogout_with_no_session(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	r, err := s.LogoutSession(t.Context(), LogoutSessionRequestObject{Params: LogoutSessionParams{}})
	require.NoError(t, err)
	assert.Equal(t, LogoutSession204Response{
		Headers: LogoutSession204ResponseHeaders{
			SetCookie: "session-token=; Path=/; Domain=cookie.domain; Max-Age=0; HttpOnly; Secure; SameSite=None",
		},
	}, r)
}
