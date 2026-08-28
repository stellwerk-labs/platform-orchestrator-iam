package api

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

var egSessionToken string
var egServiceUserToken string
var egTokenHash []byte

func init() {
	x, st := NewSessionToken(uuid.New(), model.UserIdentityProviderTestUser)
	egTokenHash = st.Sha256Hash
	egSessionToken = x
	egServiceUserToken = ServiceUserTokenPrefix + x
}

func TestInternalAuth_no_token(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, "Cookie, Bearer", resp.Header().Get("WWW-Authenticate"))
}

func TestSkipAuthenticationRegexDoesNotIncludeRetiredRunnerPolling(t *testing.T) {
	assert.False(t, skipAuthenticationRegex.MatchString(
		"/orgs/test-org/remote-runners/test-runner/actions/poll-requests",
	))
}

func TestInternalAuth_session_token_no_match(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(nil, model.NewErrNotFound("not found")).
		Times(1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egSessionToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, "Cookie, Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestInternalAuth_expired_session_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.SessionToken{ExpiresAt: time.Now().Add(-time.Minute)}, nil).
		Times(1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egSessionToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, "Cookie, Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestInternalAuth_valid_session_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	userId := userid.NewHumanUserId()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.SessionToken{Sha256Hash: egTokenHash, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), UserId: userId}, nil).
		Times(2)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egSessionToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, userId.String(), resp.Header().Get(authenticatedUserIdHeader))
		assert.Equal(t, base64.URLEncoding.EncodeToString(egTokenHash), resp.Header().Get(authenticatedUserIdTokenHashHeader))
	}
}

func TestInternalAuth_valid_session_token_cookie(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	userId := userid.NewHumanUserId()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.SessionToken{Sha256Hash: egTokenHash, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), UserId: userId}, nil).
		Times(2)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Cookie", SessionTokenCookieName+"="+egSessionToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, userId.String(), resp.Header().Get(authenticatedUserIdHeader))
		assert.Equal(t, base64.URLEncoding.EncodeToString(egTokenHash), resp.Header().Get(authenticatedUserIdTokenHashHeader))
	}
}

func TestInternalAuth_service_user_token_no_match(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(nil, model.NewErrNotFound("not found")).
		Times(1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egServiceUserToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, "Cookie, Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestInternalAuth_expired_service_user_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.ServiceUserToken{CurrentTokenExpiresAt: time.Now().Add(-time.Minute)}, nil).
		Times(1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egServiceUserToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, "Cookie, Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestInternalAuth_valid_service_user_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	userId := userid.NewHumanUserId()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.ServiceUserToken{CurrentTokenExpiresAt: time.Now().Add(time.Hour), Id: userId}, nil).
		Times(1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egServiceUserToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, userId.String(), resp.Header().Get(authenticatedUserIdHeader))
		assert.Equal(t, base64.URLEncoding.EncodeToString(egTokenHash), resp.Header().Get(authenticatedUserIdTokenHashHeader))
	}
}

func TestInternalAuth_session_revocation_is_not_hidden_by_cache(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	userId := userid.NewHumanUserId()
	gomock.InOrder(
		s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
			Return(&model.SessionToken{Sha256Hash: egTokenHash, ExpiresAt: time.Now().Add(time.Hour), UserId: userId}, nil),
		s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
			Return(nil, model.NewErrNotFound("revoked")),
	)

	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
		req.Header.Set("Authorization", "Bearer "+egSessionToken)
		resp := httptest.NewRecorder()
		e.ServeHTTP(resp, req)
		assert.Equal(t, want, resp.Code, "request %d", i+1)
	}
}

func TestInternalAuth_service_user_cache_does_not_accept_prefixless_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	serviceUserId := userid.NewServiceUserTokenId()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetServiceUserTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(&model.ServiceUserToken{CurrentTokenExpiresAt: time.Now().Add(time.Hour), Id: serviceUserId}, nil)
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), egTokenHash).
		Return(nil, model.NewErrNotFound("not a session token"))

	serviceReq := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
	serviceReq.Header.Set("Authorization", "Bearer "+egServiceUserToken)
	serviceResp := httptest.NewRecorder()
	e.ServeHTTP(serviceResp, serviceReq)
	assert.Equal(t, http.StatusOK, serviceResp.Code)

	prefixlessReq := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
	prefixlessReq.Header.Set("Authorization", "Bearer "+egSessionToken)
	prefixlessResp := httptest.NewRecorder()
	e.ServeHTTP(prefixlessResp, prefixlessReq)
	assert.Equal(t, http.StatusUnauthorized, prefixlessResp.Code)
}

const TestSuperUserToken = "test-super-user-secret"

func TestInternalAdminAuth_valid_super_user_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	h := sha256.Sum256([]byte(TestSuperUserToken))
	s.SuperUserTokenHash = h[:]

	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/admin/some/route", nil)
	req.Header.Set("Authorization", "Bearer "+TestSuperUserToken)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, userid.InternalSystemUuid.String(), resp.Header().Get(authenticatedUserIdHeader))
}

func TestInternalAdminAuth_invalid_super_user_token(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	h := sha256.Sum256([]byte(TestSuperUserToken))
	s.SuperUserTokenHash = h[:]

	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/admin/some/route", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, "Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
}

func TestInternalAdminAuth_super_user_token_disabled(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	// SuperUserTokenHash is nil (not configured)
	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/admin/some/route", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, "Bearer error=\"invalid_token\"", resp.Header().Get("WWW-Authenticate"))
}

func TestInternalAdminAuth_super_user_no_bearer(t *testing.T) {
	e, _, fin := MockServer(t)
	defer fin()

	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/admin/some/route", nil)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, "Bearer", resp.Header().Get("WWW-Authenticate"))
}

func TestInternalAdminAuth_super_user_non_admin_route(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()
	s.TokenByHashCache = NewGetTokenByHashCache(s.Database)

	h := sha256.Sum256([]byte(TestSuperUserToken))
	s.SuperUserTokenHash = h[:]

	// Super user token on a non-admin route goes through normal auth flow and won't match any DB token.
	s.Database.(*mockmodel.MockDatabaser).EXPECT().GetSessionTokenByHash(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, model.NewErrNotFound("not found")).
		Times(1)

	req := httptest.NewRequest(http.MethodPost, "/internal/authenticate/some/route", nil)
	req.Header.Set("Authorization", "Bearer "+TestSuperUserToken)
	resp := httptest.NewRecorder()
	e.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}
