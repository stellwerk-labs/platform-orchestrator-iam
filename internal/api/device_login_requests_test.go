package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mock_model "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func TestRequestDeviceLogin(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	s.UiHostUrl = "http://localhost:8080"

	s.Database.(*mock_model.MockDatabaser).EXPECT().CreateDeviceLoginRequest(gomock.Any(), nil, gomock.Not(nil)).
		DoAndReturn(func(ctx context.Context, tx model.Tx, req *model.DeviceLoginRequest) (*model.DeviceLoginRequest, error) {
			return req, nil
		})

	r, err := s.RequestDeviceLogin(t.Context(), RequestDeviceLoginRequestObject{})
	require.NoError(t, err)
	require.IsType(t, RequestDeviceLogin201JSONResponse{}, r)
	r201 := r.(RequestDeviceLogin201JSONResponse)
	assert.NotEmpty(t, r201.Id)
	assert.Len(t, r201.Code, 7)
	assert.NotEmpty(t, r201.CreatedAt)
	assert.Greater(t, r201.ExpiresAt, r201.CreatedAt)
	assert.Len(t, r201.PollingToken, 44)
	assert.Equal(t, fmt.Sprintf("http://localhost:8080/devicelogins/%s", r201.Code), r201.ApprovalUrl)
}

func TestPollDeviceLoginRequest_not_found(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(nil, model.NewErrNotFound("not found"))
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	assert.Equal(t, PollDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("not found")}, r)
}

func TestPollDeviceLoginRequest_invalid_polling_token(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(&model.DeviceLoginRequest{}, nil)
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	assert.Equal(t, PollDeviceLoginRequest400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid polling token")}, r)
}

func TestPollDeviceLoginRequest_expired(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	h := sha256.Sum256([]byte("token"))
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(&model.DeviceLoginRequest{PollingTokenSha256Hash: h[:], ExpiresAt: time.Now().Add(-time.Minute)}, nil)
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	assert.Equal(t, PollDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("device login request has expired")}, r)
}

func TestPollDeviceLoginRequest_undecided(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	h := sha256.Sum256([]byte("token"))
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(&model.DeviceLoginRequest{PollingTokenSha256Hash: h[:], ExpiresAt: time.Now().Add(time.Minute)}, nil)
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	assert.Equal(t, PollDeviceLoginRequest202Response{}, r)
}

func TestPollDeviceLoginRequest_rejected(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	h := sha256.Sum256([]byte("token"))
	decision := string(model.DeviceLoginRejected)
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(&model.DeviceLoginRequest{Id: reqId, PollingTokenSha256Hash: h[:], ExpiresAt: time.Now().Add(time.Minute), Decision: &decision}, nil)
	s.Database.(*mock_model.MockDatabaser).EXPECT().DeleteDeviceLoginRequest(gomock.Any(), gomock.Not(nil), reqId).Return(nil)
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	assert.Equal(t, PollDeviceLoginRequest400JSONResponse{N400BadRequestJSONResponse: Generate400Response("device login request was rejected")}, r)
}

func TestPollDeviceLoginRequest_accepted(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	now := time.Now().UTC()
	nowPlus1s := now.Add(time.Second)
	pollHash := sha256.Sum256([]byte("token"))
	decision := model.DeviceLoginAccepted
	userId := uuid.New()
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), nil, reqId).
		Return(&model.DeviceLoginRequest{
			Id:                     reqId,
			PollingTokenSha256Hash: pollHash[:],
			CreatedAt:              now,
			ExpiresAt:              now.Add(time.Minute),
			Decision:               &decision,
			DecidedBy:              &userId,
		}, nil)

	s.Database.(*mock_model.MockDatabaser).EXPECT().GetUser(gomock.Any(), gomock.Not(nil), userId).
		Return(&model.User{Id: userId}, nil)
	s.Database.(*mock_model.MockDatabaser).EXPECT().CreateSessionToken(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ context.Context, optionalTx model.Tx, in *model.SessionToken) (*model.SessionToken, error) {
			assert.Equal(t, userId, in.UserId)
			return &model.SessionToken{
				Sha256Hash: in.Sha256Hash,
				CreatedAt:  nowPlus1s,
				ExpiresAt:  now.Add(time.Hour),
				UserId:     userId,
			}, nil
		})
	s.Database.(*mock_model.MockDatabaser).EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), &model.User{Id: userId, LastLoggedInAt: &nowPlus1s}).
		Return(&model.User{Id: userId, LastLoggedInAt: &nowPlus1s}, nil)

	s.Database.(*mock_model.MockDatabaser).EXPECT().DeleteDeviceLoginRequest(gomock.Any(), gomock.Not(nil), reqId).Return(nil)
	r, err := s.PollDeviceLoginRequest(t.Context(), PollDeviceLoginRequestRequestObject{
		RequestId: reqId, Params: PollDeviceLoginRequestParams{PollingToken: base64.RawURLEncoding.EncodeToString([]byte("token"))},
	})
	require.NoError(t, err)
	r200 := r.(PollDeviceLoginRequest200JSONResponse)
	assert.NotEmpty(t, r200.Token)
	r200.Token = ""
	assert.Equal(t, PollDeviceLoginRequest200JSONResponse{
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Minute),
		Id:             reqId,
		TokenExpiresAt: now.Add(time.Hour),
	}, r200)
}

func TestGetDeviceLoginRequest_not_exists(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	h := sha256.Sum256([]byte("CODE"))
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequestByCodeHash(gomock.Any(), nil, h[:]).
		Return(nil, model.NewErrNotFound("device login request not found"))

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetDeviceLoginRequest(ctx, GetDeviceLoginRequestRequestObject{Code: "code"})
	require.NoError(t, err)
	assert.Equal(t, GetDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("device login request not found")}, r)
}

func TestGetDeviceLoginRequest_expires(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	h := sha256.Sum256([]byte("CODE"))
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequestByCodeHash(gomock.Any(), nil, h[:]).
		Return(&model.DeviceLoginRequest{ExpiresAt: time.Now().Add(-time.Minute)}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetDeviceLoginRequest(ctx, GetDeviceLoginRequestRequestObject{Code: "code"})
	require.NoError(t, err)
	assert.Equal(t, GetDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("device login request has expired")}, r)
}

func TestGetDeviceLoginRequest_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()
	now := time.Now()
	h := sha256.Sum256([]byte("CODE"))
	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequestByCodeHash(gomock.Any(), nil, h[:]).
		Return(&model.DeviceLoginRequest{
			CreatedAt: now,
			ExpiresAt: now.Add(time.Minute),
			Id:        reqId,
			UserAgent: "fizz buzz",
		}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, userid.InternalSystemUuid.String())
	r, err := s.GetDeviceLoginRequest(ctx, GetDeviceLoginRequestRequestObject{Code: "code"})
	require.NoError(t, err)
	assert.Equal(t, GetDeviceLoginRequest200JSONResponse{
		CreatedAt: now,
		ExpiresAt: now.Add(time.Minute),
		Id:        reqId,
		UserAgent: "fizz buzz",
	}, r)
}

func TestAcceptDeviceLoginRequest_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	humanUser := userid.NewHumanUserId()

	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), gomock.Not(nil), reqId).
		Return(&model.DeviceLoginRequest{}, nil)
	decision := model.DeviceLoginAccepted
	s.Database.(*mock_model.MockDatabaser).EXPECT().UpdateDeviceLoginRequest(gomock.Any(), gomock.Not(nil), &model.DeviceLoginRequest{DecidedBy: &humanUser, Decision: &decision}).
		Return(&model.DeviceLoginRequest{}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.AcceptDeviceLoginRequest(ctx, AcceptDeviceLoginRequestRequestObject{RequestId: reqId})
	require.NoError(t, err)
	assert.Equal(t, AcceptDeviceLoginRequest204Response{}, r)
}

func TestRejectDeviceLoginRequest_nominal(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()
	reqId := uuid.New()

	humanUser := userid.NewHumanUserId()

	s.Database.(*mock_model.MockDatabaser).EXPECT().GetDeviceLoginRequest(gomock.Any(), gomock.Not(nil), reqId).
		Return(&model.DeviceLoginRequest{}, nil)
	decision := model.DeviceLoginRejected
	s.Database.(*mock_model.MockDatabaser).EXPECT().UpdateDeviceLoginRequest(gomock.Any(), gomock.Not(nil), &model.DeviceLoginRequest{DecidedBy: &humanUser, Decision: &decision}).
		Return(&model.DeviceLoginRequest{}, nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, humanUser.String())
	r, err := s.RejectDeviceLoginRequest(ctx, RejectDeviceLoginRequestRequestObject{RequestId: reqId})
	require.NoError(t, err)
	assert.Equal(t, RejectDeviceLoginRequest204Response{}, r)
}
