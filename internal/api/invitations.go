package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/middleware"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/emailprovider"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

const (
	inviteRedemptionTokenEntropyBytes = 33
	inviteDayMultiplier               = time.Hour * 24
	inviteDefaultExpiry               = inviteDayMultiplier * 7
)

func inviteModelToSummary(item *model.Invitation) InvitationSummary {
	return InvitationSummary{
		Id:                           item.Id,
		CreatedAt:                    item.CreatedAt,
		ExpiresAt:                    item.ExpiresAt,
		CreatedBy:                    item.CreatedBy,
		CreatedByDisplayName:         item.CreatedByDisplayName,
		CreatedByPrimaryEmailAddress: item.CreatedByPrimaryEmailAddress.Ref(),
		EmailAddress:                 item.EmailAddress,
		MembershipSubjectType:        SubjectType(item.MembershipSubjectType),
		MembershipSubject:            item.MembershipSubject,
	}
}

func zapInvitationId(id uuid.UUID) zap.Field {
	return zap.Stringer("invitation_id", id)
}

func (s *Server) ListInvitations(ctx context.Context, request ListInvitationsRequestObject) (ListInvitationsResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	page, err := s.Database.ListInvitations(ctx, nil, request.OrgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list invitations")
	}

	out := make([]InvitationSummary, len(page))
	for i, item := range page {
		out[i] = inviteModelToSummary(&item)
	}

	return ListInvitations200JSONResponse{Items: out}, nil
}

func (s *Server) CreateInvitation(ctx context.Context, request CreateInvitationRequestObject) (CreateInvitationResponseObject, error) {
	if s.EmailProvider == nil {
		return CreateInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invitations are not supported")}, nil
	}

	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	} else if userid.IsServiceUser(uid) {
		return CreateInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("service users may not create invitations")}, nil
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	// This is really the only validation we should attempt to do on email addresses ourselves. Everything else is up to send grid.
	if ci := strings.LastIndex(request.Body.EmailAddress, "@"); ci == -1 || ci == 0 || ci == len(request.Body.EmailAddress)-1 {
		return CreateInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid email address")}, nil
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

	subjectType := request.Body.MembershipSubjectType
	subject := request.Body.MembershipSubject

	// Handle virtual group conversion to role
	if subjectType, subject, err = s.resolveVirtualGroupToRole(ctx, logger, tx, request.OrgId, subjectType, subject); err != nil {
		return nil, err
	}

	redemptionToken := make([]byte, inviteRedemptionTokenEntropyBytes)
	if _, err := rand.Read(redemptionToken); err != nil {
		return nil, errors.Wrap(err, "failed to generate redemption token")
	}
	rawRedemptionTokenHash := sha256.Sum256(redemptionToken)
	encodedRedemptionToken := base64.RawURLEncoding.EncodeToString(redemptionToken)

	var invitingUserDisplayName string
	var invitingUserEmail opt.Opt[string]
	if uid == userid.InternalSystemUuid {
		invitingUserDisplayName = "system"
	} else if invitingUser, err := s.Database.GetUser(ctx, tx, uid); err != nil {
		return nil, errors.Wrap(err, "failed to get inviting user")
	} else {
		invitingUserDisplayName = invitingUser.DisplayName
		invitingUserEmail = invitingUser.PrimaryEmailAddress
	}

	now := time.Now()
	expiry := inviteDefaultExpiry
	if request.Body.ExpiryInDays != nil {
		expiry = inviteDayMultiplier * time.Duration(*request.Body.ExpiryInDays)
	}
	invite, err := s.Database.CreateInvitation(ctx, tx, &model.Invitation{
		OrgId:                        request.OrgId,
		Id:                           uuid.Must(uuid.NewV7()),
		CreatedAt:                    now,
		ExpiresAt:                    now.Add(expiry),
		CreatedBy:                    uid,
		CreatedByDisplayName:         invitingUserDisplayName,
		CreatedByPrimaryEmailAddress: invitingUserEmail,
		RedemptionTokenSha256Hash:    rawRedemptionTokenHash[:],
		EmailAddress:                 request.Body.EmailAddress,
		MembershipSubjectType:        model.MembershipSubjectType(subjectType),
		MembershipSubject:            subject,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create invitation")
	}
	logger = logger.With(zapInvitationId(invite.Id))

	if err := s.EmailProvider.SendInvitationEmail(
		ctx,
		request.Body.EmailAddress,
		emailprovider.InvitationEmailParams{
			UiHostUrl:               s.UiHostUrl,
			OrgId:                   request.OrgId,
			InvitingUserDisplayName: invitingUserDisplayName,
			MembershipSubjectType:   string(subjectType),
			MembershipSubject:       subject,
			InvitationId:            invite.Id,
			InvitationExpiresAt:     invite.ExpiresAt,
			EncodedRedemptionToken:  encodedRedemptionToken,
		},
	); err != nil {
		return nil, errors.Wrap(err, "failed to send invitation email")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	logger.Info("created and sent org membership invitation")
	return CreateInvitation201JSONResponse(inviteModelToSummary(invite)), nil
}

func (s *Server) RevokeInvitation(ctx context.Context, request RevokeInvitationRequestObject) (RevokeInvitationResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zapInvitationId(request.InvitationId)).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	invite, err := s.Database.GetInvitation(ctx, tx, request.InvitationId)
	if err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return RevokeInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, errors.Wrap(err, "failed to get invitation")
	} else if invite.OrgId != request.OrgId {
		return RevokeInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404Response("invitation not found")}, nil
	}

	if err := s.Database.DeleteInvitation(ctx, tx, invite.Id); err != nil {
		return nil, errors.Wrap(err, "failed to delete invitation")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	logger.Info("revoked org membership invitation")
	return RevokeInvitation204Response{}, nil
}

func hashRedemptionToken(encodedToken string) ([]byte, error) {
	if v, err := base64.RawURLEncoding.DecodeString(encodedToken); err != nil || len(v) == 0 {
		return nil, errors.Wrap(err, "invalid redemption token")
	} else {
		h := sha256.Sum256(v)
		return h[:], nil
	}
}

func (s *Server) GetInvitation(ctx context.Context, request GetInvitationRequestObject) (GetInvitationResponseObject, error) {
	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	}

	// The get method has special authorization and only needs to check authz if the token is not provided. The token
	// bit will be checked later.
	if request.Params.RedemptionToken == nil {
		if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
			return nil, err
		}
	} else {
		// we're checking this further down
		middleware.SetAuthAsserterChecked(ctx)
	}

	invite, err := s.Database.GetInvitation(ctx, nil, request.InvitationId)
	if err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return GetInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, errors.Wrap(err, "failed to get invitation")
	} else if invite.OrgId != request.OrgId {
		return GetInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404Response("invitation not found")}, nil
	} else if invite.ExpiresAt.Before(time.Now()) {
		return GetInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invitation has expired")}, nil
	} else if request.Params.RedemptionToken != nil {
		redemptionTokenHash, err := hashRedemptionToken(*request.Params.RedemptionToken)
		if err != nil {
			return GetInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response(err.Error())}, nil
		} else if !bytes.Equal(redemptionTokenHash, invite.RedemptionTokenSha256Hash) {
			return GetInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid redemption token")}, nil
		}
	}

	return GetInvitation200JSONResponse(inviteModelToSummary(invite)), nil
}

func (s *Server) RedeemInvitation(ctx context.Context, request RedeemInvitationRequestObject) (RedeemInvitationResponseObject, error) {
	uid, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if !userid.IsHumanUser(uid) {
		return RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("only valid users can redeem invitations")}, nil
	}
	// manually set this since we're not using one of the helper functions
	middleware.SetAuthAsserterChecked(ctx)

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).With(zapInvitationId(request.InvitationId)).WithLazy(ids.AsLogField())

	// pull the redemption token from the query param and hash it
	redemptionTokenHash, err := hashRedemptionToken(request.Params.RedemptionToken)
	if err != nil {
		return RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response(err.Error())}, nil
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

	invite, err := s.Database.GetInvitation(ctx, tx, request.InvitationId)
	if err != nil {
		if me, ok := model.IsErrNotFound(err); ok {
			return RedeemInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404FromModelErr(me)}, nil
		}
		return nil, errors.Wrap(err, "failed to get invitation")
	} else if invite.OrgId != request.OrgId {
		return RedeemInvitation404JSONResponse{N404NotFoundJSONResponse: Generate404Response("invitation not found")}, nil
	} else if invite.ExpiresAt.Before(time.Now()) {
		return RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invitation has expired")}, nil
	} else if !bytes.Equal(redemptionTokenHash, invite.RedemptionTokenSha256Hash) {
		return RedeemInvitation400JSONResponse{N400BadRequestJSONResponse: Generate400Response("invalid redemption token")}, nil
	}

	var membership *model.Membership
	if p, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{
		OrgId:       &invite.OrgId,
		UserId:      &uid,
		SubjectType: &invite.MembershipSubjectType,
		Subject:     &invite.MembershipSubject,
	}); err != nil {
		return nil, errors.Wrap(err, "failed to list memberships")
	} else if len(p) > 0 {
		membership = &p[0].Membership
		logger.Info("redeemed org membership invitation, but user already has this membership")
	} else {
		var membershipRole opt.Opt[uuid.UUID]
		if invite.MembershipSubjectType == model.MembershipSubjectTypeRole {
			membershipRole = opt.Of(uuid.MustParse(invite.MembershipSubject))
		} else {
			membershipRole = opt.Empty[uuid.UUID]()
		}
		membership, err = s.Database.CreateMembership(ctx, tx, &model.Membership{
			Id:          uuid.Must(uuid.NewV7()),
			CreatedAt:   time.Now().UTC(),
			OrgId:       invite.OrgId,
			UserId:      uid,
			SubjectType: invite.MembershipSubjectType,
			Subject:     invite.MembershipSubject,
			Role:        membershipRole,
		})
		if err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				return RedeemInvitation409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, nil
			}
			return nil, errors.Wrap(err, "failed to create membership")
		}
	}

	if err := s.Database.DeleteInvitation(ctx, tx, invite.Id); err != nil {
		return nil, errors.Wrap(err, "failed to delete invitation")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return nil, err
	}

	logger.Info("redeemed org membership invitation")
	return RedeemInvitation200JSONResponse(UserMembership{
		CreatedAt:   membership.CreatedAt,
		Id:          membership.Id,
		OrgId:       membership.OrgId,
		Subject:     membership.Subject,
		SubjectType: SubjectType(membership.SubjectType),
	}), nil
}
