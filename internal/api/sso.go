package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider"
)

const (
	SsoStateOrgIdParamName = "platform_orchestrator_org_id"
	ssoStateSignatureName  = "sig"
)

func computeHMAC(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func encodeState(stateData map[string]string, secret string) (string, error) {
	// Create payload without signature
	payloadJSON, err := json.Marshal(stateData)
	if err != nil {
		return "", err
	}

	// Sign the payload
	signature := computeHMAC(payloadJSON, secret)
	stateData[ssoStateSignatureName] = signature

	// Encode the full state with signature
	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(stateJSON), nil
}

func parseState(state string, secret string) (map[string]string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, errors.Wrap(err, "invalid state, must be base64 encoded JSON")
	}
	var stateData map[string]string
	if err := json.Unmarshal(decoded, &stateData); err != nil {
		return nil, errors.Wrap(err, "invalid state, must be base64 encoded JSON")
	}

	// Extract and verify signature
	signature, ok := stateData[ssoStateSignatureName]
	if !ok {
		return nil, errors.New("invalid state: missing signature")
	}
	delete(stateData, ssoStateSignatureName)

	// Recreate payload for verification (without signature)
	payloadJSON, err := json.Marshal(stateData)
	if err != nil {
		return nil, errors.Wrap(err, "invalid state: failed to verify")
	}

	expectedSignature := computeHMAC(payloadJSON, secret)
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return nil, errors.New("invalid state: signature verification failed")
	}

	return stateData, nil
}

// RequestSsoLogin Begin SSO login flow
// (POST /auth/sso/login)
func (s *Server) RequestSsoLogin(ctx context.Context, request RequestSsoLoginRequestObject) (RequestSsoLoginResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)
	if s.SsoProvider == nil {
		return nil, errors.New("sso provider is not configured")
	}

	state, err := encodeState(map[string]string{SsoStateOrgIdParamName: request.Body.OrgId}, s.SsoStateSecret)
	if err != nil {
		return nil, err
	}

	// For the self-hosted version Keycloak IdP is a single source of truth, so we don't use SSO configuration.
	// In the future we can reconsider this approach, e.g. for using different realms per organization.
	var providerOrgId string
	if s.SsoProvider.IsMultitenant() {
		ssoConfig, err := s.Database.GetSsoConfiguration(ctx, nil, request.Body.OrgId)
		if err != nil {
			var errNotFound model.ErrNotFound
			if errors.As(err, &errNotFound) {
				return RequestSsoLogin404JSONResponse{
					N404NotFoundJSONResponse{Error: notFoundErrorCode, Message: "SSO is not configured or organization doesn't exist"},
				}, nil
			}
			return nil, err
		}
		providerOrgId = ssoConfig.ProviderOrgId
	} else {
		// Since we don't look up the org's SSO configuration, we need to validate that the org exists
		if resp, err := s.CpClient.GetOrganizationWithResponse(ctx, request.Body.OrgId); err != nil {
			return nil, err
		} else if resp.StatusCode() == http.StatusNotFound {
			return RequestSsoLogin404JSONResponse{
				N404NotFoundJSONResponse{Error: notFoundErrorCode, Message: fmt.Sprintf("organization doesn't exist: %s", request.Body.OrgId)},
			}, nil
		} else if resp.StatusCode() != http.StatusOK {
			return nil, errors.Errorf("unexpected status code from control plane: %d", resp.StatusCode())
		}
	}

	authUrl, err := s.SsoProvider.GetAuthorizationURL(providerOrgId, state)
	if err != nil {
		return nil, err
	}
	return RequestSsoLogin200JSONResponse{
		RedirectUrl: authUrl,
	}, nil
}

// GetSsoCallback Callback SSO login flow
// (GET /auth/sso/callback)
func (s *Server) GetSsoCallback(ctx context.Context, request GetSsoCallbackRequestObject) (GetSsoCallbackResponseObject, error) {
	middleware.SetAuthAsserterChecked(ctx)
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	if request.Params.ErrorDescription != nil {
		return GetSsoCallback401JSONResponse{N401UnauthorizedJSONResponse{Body: Error{Error: unauthorizedErrorCode, Message: *request.Params.ErrorDescription}}}, nil
	} else if request.Params.Code == nil {
		return nil, errors.New("missing required parameters from SSO parameters")
	}

	// Get Platform Orchestrator organization from the SSO flow state
	var orgId string
	if request.Params.State == nil {
		return GetSsoCallback400JSONResponse{
			N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: "Missing required state query parameter"},
		}, nil
	} else if stateData, err := parseState(*request.Params.State, s.SsoStateSecret); err != nil {
		return GetSsoCallback400JSONResponse{
			N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: err.Error()},
		}, nil
	} else if orgId = stateData[SsoStateOrgIdParamName]; orgId == "" {
		return GetSsoCallback400JSONResponse{
			N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: fmt.Sprintf("Invalid state, must contain non-empty %s field", SsoStateOrgIdParamName)},
		}, nil
	}

	isMultitenant := s.SsoProvider.IsMultitenant()
	if !isMultitenant {
		// Since we don't look up the org's SSO configuration in this case, we need to validate that the org exists
		if resp, err := s.CpClient.GetOrganizationWithResponse(ctx, orgId); err != nil {
			return nil, err
		} else if resp.StatusCode() == http.StatusNotFound {
			return GetSsoCallback400JSONResponse{
				N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: fmt.Sprintf("Invalid state, no such organization: %s", orgId)},
			}, nil
		} else if resp.StatusCode() != http.StatusOK {
			return nil, errors.Errorf("unexpected status code from control plane: %d", resp.StatusCode())
		}
	}

	profile, err := s.SsoProvider.GetUserProfile(ctx, *request.Params.Code)
	if err != nil {
		var errBadRequest ssoprovider.ErrBadRequest
		if errors.As(err, &errBadRequest) {
			return GetSsoCallback400JSONResponse{
				N400BadRequestJSONResponse{Error: badRequestErrorCode, Message: errBadRequest.Message},
			}, nil
		}
		return GetSsoCallback401JSONResponse{N401UnauthorizedJSONResponse{Body: Error{Error: unauthorizedErrorCode, Message: err.Error()}}}, nil
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

	// For the self-hosted version Keycloak IdP is a single source of truth, so we don't use SSO configuration.
	// In the future we can reconsider this approach, e.g. for using different realms per organization.
	if isMultitenant {
		// Check that SSO is configured for the organization
		config, err := s.Database.GetSsoConfiguration(ctx, tx, orgId)
		if err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				msg := fmt.Sprintf("No SSO configuration found for organization %s", orgId)
				return GetSsoCallback401JSONResponse{N401UnauthorizedJSONResponse{Body: Error{Error: unauthorizedErrorCode, Message: msg}}}, nil
			}
			return nil, err
		}
		// Sanity check: SSO provider organization ID must match the configured one
		if config.ProviderOrgId != profile.ProviderOrgId {
			msg := fmt.Sprintf("SSO configuration for organization %s doesn't match provider's configuration", orgId)
			return GetSsoCallback401JSONResponse{N401UnauthorizedJSONResponse{Body: Error{Error: unauthorizedErrorCode, Message: msg}}}, nil
		}
	}

	identityId := fmt.Sprintf("%s:%s", profile.ProviderOrgId, profile.ProviderUserId)
	userId, err := s.Database.GetUserIdByIdentity(ctx, tx, model.UserIdentityProviderSso, identityId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); !ok {
			return nil, errors.Wrap(err, "failed to get user id by identity")
		}
	}

	now := time.Now().UTC()
	var user *model.User
	if userId == nil {
		newUser := model.User{
			Id:                  userid.NewHumanUserId(),
			DisplayName:         profile.DisplayName,
			PrimaryEmailAddress: opt.Of(profile.Email),
			CreatedAt:           now,
			LastLoggedInAt:      &now,
			UserIdentities: map[model.UserIdentityProvider]string{
				model.UserIdentityProviderSso: identityId,
			},
		}
		if user, err = s.Database.CreateUser(ctx, tx, &newUser); err != nil {
			return nil, errors.Wrap(err, "failed to create user")
		}
	} else {
		if user, err = s.Database.GetUser(ctx, tx, *userId); err != nil {
			return nil, errors.Wrap(err, "failed to get user")
		}
		user.LastLoggedInAt = &now
		user.PrimaryEmailAddress = opt.Of(profile.Email)
		user.DisplayName = profile.DisplayName
		if user, err = s.Database.UpdateUser(ctx, tx, user); err != nil {
			return nil, errors.Wrap(err, "failed to update user")
		}
	}

	createMembership := userId == nil
	if !createMembership {
		// Membership should be already created, but check for integrity
		if memberships, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{
			OrgId:       &orgId,
			UserId:      &user.Id,
			SubjectType: ref.Ref(model.MembershipSubjectTypeRole),
		}); err != nil {
			return nil, err
		} else if len(memberships) == 0 {
			createMembership = true
		}
	}

	var membership *model.Membership
	var messages []*hstandardoutbox.PendingEventMessage
	if createMembership {
		roles, err := s.listOrSeedRoles(ctx, logger, tx, orgId)
		if err != nil {
			return nil, err
		}

		// If this is the first user in the organization, assign Admin role; otherwise assign Viewer
		targetRole := RoleViewer
		hasMemberships, err := s.Database.HasMemberships(ctx, tx, orgId)
		if err != nil {
			return nil, errors.Wrap(err, "failed to check existing memberships")
		}
		if !hasMemberships {
			targetRole = RoleAdmin
		}

		var roleId opt.Opt[uuid.UUID]
		for _, role := range roles {
			if role.DisplayName == targetRole {
				roleId = opt.Of(role.Id)
				break
			}
		}
		if !roleId.IsSet() {
			return nil, fmt.Errorf("org %s doesn't have role %s", orgId, targetRole)
		}

		if membership, err = s.Database.CreateMembership(ctx, tx, &model.Membership{
			Id:          uuid.Must(uuid.NewV7()),
			CreatedAt:   now,
			OrgId:       orgId,
			UserId:      user.Id,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     roleId.Ref().String(),
			Role:        roleId,
		}); err != nil {
			return nil, errors.Wrap(err, "failed to create membership")
		}
		if messages, err = insertSpiceDBSyncEventMessages(ctx, orgId, ref.Ref(user.Id), s.Database, tx); err != nil {
			return nil, errors.Wrap(err, "failed to insert spiceDB sync event messages")
		}
	}

	logger.Info("creating session token", zap.String("user_id", user.Id.String()))
	rawToken, st := NewSessionToken(user.Id, model.UserIdentityProviderSso)
	st.ClientIp = opt.OfRef(request.Params.XClientIP)
	st.ClientRegion = opt.OfRef(request.Params.XClientRegion)
	st.ClientCity = opt.OfRef(request.Params.XClientCity)
	if st, err = s.Database.CreateSessionToken(ctx, tx, st); err != nil {
		return nil, errors.Wrap(err, "failed to create session token")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	if membership != nil && len(messages) > 0 {
		reliableoutbox.OptimisticPublish(ctx, logger, s.Database.AsReliableOutboxStore(), s.Publisher, messages)
		logger.Info("created membership", zap.String(hlogger.POUserId, membership.UserId.String()),
			zap.String("po-membership-id", membership.Id.String()), zap.String("po-subject-type", string(membership.SubjectType)),
			zap.String("po-subject", membership.Subject), zap.String("po-scope", membership.Scope))
	}

	return GetSsoCallback200JSONResponse{
		Body: User{
			CreatedAt:      user.CreatedAt,
			DisplayName:    user.DisplayName,
			Id:             user.Id,
			LastLoggedInAt: user.LastLoggedInAt,
			LoginProviders: slices.Sorted(func(yield func(string) bool) {
				for p := range user.UserIdentities {
					yield(string(p))
				}
			}),
			PrimaryEmailAddress: user.PrimaryEmailAddress.Ref(),
		},
		Headers: GetSsoCallback200ResponseHeaders{
			SetCookie: s.generateSetCookieForToken(rawToken, st),
		},
	}, nil
}

// InternalUpdateSsoConfiguration Update SSO configuration for the organization
// (PUT /internal/orgs/{orgId}/sso-configuration)
func (s *Server) InternalUpdateSsoConfiguration(ctx context.Context, request InternalUpdateSsoConfigurationRequestObject) (InternalUpdateSsoConfigurationResponseObject, error) {
	ssoConfig := &model.SsoConfiguration{ProviderOrgId: request.Body.ProviderOrgId}
	if _, err := s.Database.UpsertSsoConfiguration(ctx, nil, request.OrgId, ssoConfig); err != nil {
		if errConflict, ok := model.IsErrConflict(err); ok {
			return InternalUpdateSsoConfiguration409JSONResponse{N409ConflictJSONResponse{Error: "HTTP-409", Message: errConflict.Message}}, nil
		}
		return nil, err
	}
	return InternalUpdateSsoConfiguration200JSONResponse{ProviderOrgId: request.Body.ProviderOrgId}, nil
}

// InternalGetSsoConfiguration Get SSO configuration for the organization
// (GET /internal/orgs/{orgId}/sso-configuration)
func (s *Server) InternalGetSsoConfiguration(ctx context.Context, request InternalGetSsoConfigurationRequestObject) (InternalGetSsoConfigurationResponseObject, error) {
	ssoConfig, err := s.Database.GetSsoConfiguration(ctx, nil, request.OrgId)
	if err != nil {
		var errNotFound model.ErrNotFound
		if errors.As(err, &errNotFound) {
			return InternalGetSsoConfiguration404JSONResponse{
				N404NotFoundJSONResponse{Error: notFoundErrorCode, Message: "SSO is not configured or organization doesn't exist"},
			}, nil
		}
		return nil, err
	}
	return InternalGetSsoConfiguration200JSONResponse{ProviderOrgId: ssoConfig.ProviderOrgId}, nil
}
