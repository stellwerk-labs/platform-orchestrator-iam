package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	deviceLoginRequestExpiry = time.Minute * 10
	// deviceLoginShortCodeCharacters is a subset of the alphabet with I and O and L removed
	// since those are easily confused characters.
	deviceLoginShortCodeCharacters = "ABCDEFGHJKMNPQRSTUVWXYZ"
)

func randomDeviceLoginCodeChar() byte {
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(deviceLoginShortCodeCharacters))))
	return deviceLoginShortCodeCharacters[i.Int64()]
}

func (s *Server) RequestDeviceLogin(ctx context.Context, request RequestDeviceLoginRequestObject) (RequestDeviceLoginResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)

	reqId := uuid.Must(uuid.NewV7())
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zapDeviceLoginRequest(reqId)).WithLazy(ids.AsLogField())

	now := time.Now()
	userAgent := ""
	if request.Params.UserAgent != nil {
		userAgent = *request.Params.UserAgent
	}

	rawPollingToken := make([]byte, 33)
	if _, err := rand.Read(rawPollingToken); err != nil {
		panic(err)
	}
	encodedPollingToken := base64.RawURLEncoding.EncodeToString(rawPollingToken)
	pollingTokenHash := sha256.Sum256(rawPollingToken)

	verificationCode := string([]byte{
		randomDeviceLoginCodeChar(),
		randomDeviceLoginCodeChar(),
		randomDeviceLoginCodeChar(),
		'-',
		randomDeviceLoginCodeChar(),
		randomDeviceLoginCodeChar(),
		randomDeviceLoginCodeChar(),
	})
	verificationCodeHash := sha256.Sum256([]byte(verificationCode))

	req, err := s.Database.CreateDeviceLoginRequest(ctx, nil, &model.DeviceLoginRequest{
		Id:                         reqId,
		VerificationCodeSha256Hash: verificationCodeHash[:],
		CreatedAt:                  now,
		ExpiresAt:                  now.Add(deviceLoginRequestExpiry),
		UserAgent:                  userAgent,
		PollingTokenSha256Hash:     pollingTokenHash[:],
		ClientIp:                   opt.OfRef(request.Params.XClientIP),
		ClientCity:                 opt.OfRef(request.Params.XClientCity),
		ClientRegion:               opt.OfRef(request.Params.XClientRegion),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create device login request")
	}

	logger.Info("created device login request")
	return RequestDeviceLogin201JSONResponse{
		ApprovalUrl:  fmt.Sprintf("%s/devicelogins/%s", s.UiHostUrl, verificationCode),
		Code:         verificationCode,
		CreatedAt:    req.CreatedAt,
		ExpiresAt:    req.ExpiresAt,
		Id:           req.Id,
		PollingToken: encodedPollingToken,
	}, nil
}

func (s *Server) PollDeviceLoginRequest(ctx context.Context, request PollDeviceLoginRequestRequestObject) (PollDeviceLoginRequestResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zapDeviceLoginRequest(request.RequestId)).WithLazy(ids.AsLogField())

	req, err := s.Database.GetDeviceLoginRequest(ctx, nil, request.RequestId)
	if err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return PollDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, errors.Wrap(err, "failed to get device login request")
	}

	decodedPollingToken, _ := base64.RawURLEncoding.DecodeString(request.Params.PollingToken)
	pollingTokenHash := sha256.Sum256(decodedPollingToken)
	if !bytes.Equal(pollingTokenHash[:], req.PollingTokenSha256Hash) {
		return PollDeviceLoginRequest400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid polling token")}, nil
	}

	if req.ExpiresAt.Before(time.Now()) {
		return PollDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("device login request has expired")}, nil
	}

	if req.Decision == nil {
		return PollDeviceLoginRequest202Response{}, nil
	}

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	var encodedSessionToken string
	var session *model.SessionToken
	if *req.Decision == model.DeviceLoginAccepted {
		user, err := s.Database.GetUser(ctx, tx, *req.DecidedBy)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user who accepted device login request")
		}

		encodedSessionToken, session = NewSessionToken(user.Id, model.UserIdentityProviderDevice)
		session.ClientIp = req.ClientIp
		session.ClientRegion = req.ClientRegion
		session.ClientCity = req.ClientCity
		if session, err = s.Database.CreateSessionToken(ctx, tx, session); err != nil {
			return nil, errors.Wrap(err, "failed to create session token")
		}

		user.LastLoggedInAt = &session.CreatedAt
		if _, err := s.Database.UpdateUser(ctx, tx, user); err != nil {
			return nil, errors.Wrap(err, "failed to update user last logged in at")
		}
	}

	if err := s.Database.DeleteDeviceLoginRequest(ctx, tx, req.Id); err != nil {
		return nil, errors.Wrap(err, "failed to delete device login request")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	if session != nil {
		logger.Info("persisted new session token for accepted device login request")
		return PollDeviceLoginRequest200JSONResponse{
			CreatedAt:      req.CreatedAt,
			ExpiresAt:      req.ExpiresAt,
			Id:             req.Id,
			Token:          encodedSessionToken,
			TokenExpiresAt: session.ExpiresAt,
		}, nil
	}
	logger.Info("notifying device of rejected device login request")
	return PollDeviceLoginRequest400JSONResponse{N400BadRequestJSONResponse: Generate400Response("device login request was rejected")}, nil
}

// getByDeviceLoginCodeRateLimit mitigates brute force attacks against the 6 letter device login code.
var getByDeviceLoginCodeRateLimit = rate.NewLimiter(rate.Every(time.Second), 10)

func (s *Server) GetDeviceLoginRequest(ctx context.Context, request GetDeviceLoginRequestRequestObject) (GetDeviceLoginRequestResponseObject, error) {
	if _, herr := GetAuthenticatedUserIdOr401(ctx); herr != nil {
		return nil, herr
	}
	middleware.SetAuthAsserterChecked(ctx)

	request.Code = strings.ToUpper(request.Code)
	codeHash := sha256.Sum256([]byte(request.Code))

	// To prevent brute force attempts on the login code, apply a rate limiter
	if err := getByDeviceLoginCodeRateLimit.Wait(ctx); err != nil {
		return nil, err
	}

	req, err := s.Database.GetDeviceLoginRequestByCodeHash(ctx, nil, codeHash[:])
	if err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return GetDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, errors.Wrap(err, "failed to get device login request")
	} else if req.ExpiresAt.Before(time.Now()) {
		return GetDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404Response("device login request has expired")}, nil
	}

	return GetDeviceLoginRequest200JSONResponse(DeviceLoginRequest{
		CreatedAt:    req.CreatedAt,
		ExpiresAt:    req.ExpiresAt,
		Id:           req.Id,
		UserAgent:    req.UserAgent,
		ClientIp:     req.ClientIp.Ref(),
		ClientCity:   req.ClientCity.Ref(),
		ClientRegion: req.ClientRegion.Ref(),
	}), nil
}

func (s *Server) decideDeviceLoginRequest(ctx context.Context, requestId uuid.UUID, decision string) (*model.DeviceLoginRequest, error) {
	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if !userid.IsHumanUser(uid) {
		return nil, herrors.NewWithStatus(http.StatusBadRequest, "only normal users can accept or reject device login requests", nil)
	}
	middleware.SetAuthAsserterChecked(ctx)
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	ids.UserId = uid.String()
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zapDeviceLoginRequest(requestId)).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	req, err := s.Database.GetDeviceLoginRequest(ctx, tx, requestId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get device login request")
	}

	if req.Decision != nil {
		return nil, herrors.NewWithStatus(http.StatusBadRequest, "device login request is already decided", nil)
	}

	req.DecidedBy = &uid
	req.Decision = &decision

	req, err = s.Database.UpdateDeviceLoginRequest(ctx, tx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update device login request")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	logger.Info("decided device login request", zap.String("decision", decision))
	return req, nil
}

func (s *Server) RejectDeviceLoginRequest(ctx context.Context, request RejectDeviceLoginRequestRequestObject) (RejectDeviceLoginRequestResponseObject, error) {
	if _, err := s.decideDeviceLoginRequest(ctx, request.RequestId, model.DeviceLoginRejected); err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return RejectDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, err
	}
	return RejectDeviceLoginRequest204Response{}, nil
}

func (s *Server) AcceptDeviceLoginRequest(ctx context.Context, request AcceptDeviceLoginRequestRequestObject) (AcceptDeviceLoginRequestResponseObject, error) {
	if _, err := s.decideDeviceLoginRequest(ctx, request.RequestId, model.DeviceLoginAccepted); err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return AcceptDeviceLoginRequest404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, err
	}
	return AcceptDeviceLoginRequest204Response{}, nil
}
