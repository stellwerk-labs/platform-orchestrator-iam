package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/herrors"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"go.uber.org/zap"

	usererrors "github.com/stellwerk-labs/platform-orchestrator-iam/internal/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
)

func (s *Server) InternalCreateOrgMembership(ctx context.Context, request InternalCreateOrgMembershipRequestObject) (InternalCreateOrgMembershipResponseObject, error) {
	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()
	resp, err := s.CpClient.GetInternalOrganizationWithResponse(ctx, request.OrgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get organization from control plane")
	}

	if resp.StatusCode() == http.StatusNotFound {
		return InternalCreateOrgMembership404JSONResponse{N404NotFoundJSONResponse: Generate404Response("organization not found")}, nil
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when getting organization from control plane: %s", resp.StatusCode(), string(resp.Body))
	}

	user, err := s.Database.GetUser(ctx, tx, request.Body.UserId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return InternalCreateOrgMembership409JSONResponse{N409ConflictJSONResponse: Generate409Response("user not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get user")
	}

	subjectType := request.Body.SubjectType
	subject := request.Body.Subject

	// Handle virtual group conversion to role
	if subjectType, subject, err = s.resolveVirtualGroupToRole(ctx, logger, tx, request.OrgId, subjectType, subject); err != nil {
		return nil, err
	}

	var membershipRole opt.Opt[uuid.UUID]
	if subjectType == SubjectTypeRole {
		membershipRole = opt.Of(uuid.MustParse(subject))
	} else {
		membershipRole = opt.Empty[uuid.UUID]()
	}

	if isValid, err := isScopeValidForRole(ctx, request.Body.Scope, request.OrgId, s.CpClient); !isValid {
		var userErr *usererrors.UserError
		if errors.As(err, &userErr) {
			return InternalCreateOrgMembership400JSONResponse{N400BadRequestJSONResponse: Generate400Response(userErr.Error())}, nil
		} else if err != nil {
			return nil, errors.Wrap(err, "failed to validate scope for role membership")
		} else {
			scopeValue := ""
			if request.Body.Scope != nil {
				scopeValue = *request.Body.Scope
			}
			return InternalCreateOrgMembership400JSONResponse{N400BadRequestJSONResponse: Generate400Response(fmt.Sprintf("invalid scope for role membership: %s", scopeValue))}, nil
		}
	}

	membership, err := s.Database.CreateMembership(ctx, tx, &model.Membership{
		Id:          uuid.Must(uuid.NewV7()),
		CreatedAt:   time.Now().UTC(),
		OrgId:       request.OrgId,
		UserId:      user.Id,
		SubjectType: model.MembershipSubjectType(subjectType),
		Subject:     subject,
		Role:        membershipRole,
		Scope:       ref.DerefOr(request.Body.Scope, ""),
	})
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return InternalCreateOrgMembership409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, nil
		} else if _, ok := model.IsErrConflict(err); ok {
			return InternalCreateOrgMembership409JSONResponse{N409ConflictJSONResponse: Generate409Response("membership conflict")}, nil
		}
		return nil, errors.Wrap(err, "failed to create membership")
	}

	messages, err := insertSpiceDBSyncEventMessages(ctx, request.OrgId, ref.Ref(user.Id), s.Database, tx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to insert spiceDB sync event messages")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	reliableoutbox.OptimisticPublish(ctx, logger, s.Database.AsReliableOutboxStore(), s.Publisher, messages)

	logger.Info("created membership", zap.String(hlogger.POUserId, membership.UserId.String()),
		zap.String("po-membership-id", membership.Id.String()), zap.String("po-subject-type", string(membership.SubjectType)),
		zap.String("po-subject", membership.Subject), zap.String("po-scope", membership.Scope))
	return InternalCreateOrgMembership201JSONResponse{
		CreatedAt:               membership.CreatedAt,
		Id:                      membership.Id,
		Subject:                 membership.Subject,
		SubjectType:             SubjectType(membership.SubjectType),
		UserId:                  membership.UserId,
		UserDisplayName:         user.DisplayName,
		UserPrimaryEmailAddress: user.PrimaryEmailAddress.Ref(),
		Scope:                   ref.Ref(membership.Scope),
	}, nil
}

func (s *Server) ListOrgMemberships(ctx context.Context, request ListOrgMembershipsRequestObject) (ListOrgMembershipsResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	page, err := s.Database.ListMemberships(ctx, nil, model.ListMembershipsParams{
		OrgId:  &request.OrgId,
		UserId: request.Params.UserId,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list memberships")
	}

	out := make([]OrgMembership, 0, len(page))
	for _, i := range page {
		out = append(out, OrgMembership{
			Id:                      i.Id,
			CreatedAt:               i.CreatedAt,
			UserId:                  i.UserId,
			UserDisplayName:         i.UserDisplayName,
			UserPrimaryEmailAddress: i.UserPrimaryEmailAddress.Ref(),
			SubjectType:             SubjectType(i.SubjectType),
			Subject:                 i.Subject,
			Scope:                   ref.Ref(i.Scope),
		})
	}

	return ListOrgMemberships200JSONResponse{Items: out}, nil
}

func (s *Server) ListUserMemberships(ctx context.Context, request ListUserMembershipsRequestObject) (ListUserMembershipsResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkUserIdSelfAuthorization(ctx, uid, request.UserId); err != nil {
		return nil, err
	}

	page, err := s.Database.ListMemberships(ctx, nil, model.ListMembershipsParams{
		UserId: &request.UserId,
		OrgId:  request.Params.OrgId,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list memberships")
	}

	out := make([]UserMembership, 0, len(page))
	for _, i := range page {
		out = append(out, UserMembership{
			Id:          i.Id,
			CreatedAt:   i.CreatedAt,
			OrgId:       i.OrgId,
			SubjectType: SubjectType(i.SubjectType),
			Subject:     i.Subject,
			Scope:       ref.Ref(i.Scope),
		})
	}

	return ListUserMemberships200JSONResponse{Items: out}, nil
}

func (s *Server) DeleteOrgMembership(ctx context.Context, request DeleteOrgMembershipRequestObject) (DeleteOrgMembershipResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAdminAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	membership, err := s.Database.GetMembership(ctx, tx, request.MembershipId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return DeleteOrgMembership404JSONResponse{N404NotFoundJSONResponse: Generate404Response("membership not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get membership")
	} else if membership.OrgId != request.OrgId {
		// edge case that's good to catch
		return DeleteOrgMembership404JSONResponse{N404NotFoundJSONResponse: Generate404Response("membership not found")}, nil
	}

	if membership.SubjectType == model.MembershipSubjectTypeRole {
		if role, err := s.Database.GetRole(ctx, tx, request.OrgId, uuid.MustParse(membership.Subject)); err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				return DeleteOrgMembership409JSONResponse{N409ConflictJSONResponse: Generate409Response("cannot delete membership: role not found")}, nil
			}
			return nil, errors.Wrap(err, "failed to get role")
		} else if role.DisplayName == RoleAdmin {
			if page, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{OrgId: &request.OrgId, SubjectType: &membership.SubjectType, Subject: &membership.Subject}); err != nil {
				return nil, errors.Wrap(err, "failed to list memberships")
			} else if len(page) == 1 && page[0].Id == membership.Id {
				return DeleteOrgMembership409JSONResponse{N409ConflictJSONResponse: Generate409Response("cannot delete the only remaining admin membership")}, nil
			}
		}
	}

	if err := s.Database.DeleteMembership(ctx, tx, request.MembershipId); err != nil {
		if _, ok := model.IsErrNotFound(err); !ok {
			return DeleteOrgMembership404JSONResponse{N404NotFoundJSONResponse: Generate404Response("membership not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to delete membership")
	}

	messages, err := insertSpiceDBSyncEventMessages(ctx, request.OrgId, ref.Ref(membership.UserId), s.Database, tx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to insert spiceDB sync event messages")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	reliableoutbox.OptimisticPublish(ctx, logger, s.Database.AsReliableOutboxStore(), s.Publisher, messages)

	logger.Info("deleted membership", zap.String("user_id", membership.UserId.String()), zap.String("membership_id", request.MembershipId.String()), zap.String("subject_type", string(membership.SubjectType)), zap.String("subject", membership.Subject))
	return DeleteOrgMembership204Response{}, nil
}

func getRoleByDisplayName(roles []model.Role, displayName string) *model.Role {
	for _, r := range roles {
		if r.DisplayName == displayName {
			return &r
		}
	}
	return nil
}

func (s *Server) resolveVirtualGroupToRole(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, orgId string, subjectType SubjectType, subject string) (SubjectType, string, error) {
	if subjectType != SubjectTypeVirtualGroup || subject != model.MembershipSubjectOrganizationOwners {
		return subjectType, subject, nil
	}

	// TODO: open this up to other kinds of invitations in the future
	var roles []model.Role
	var err error

	// Try to get roles in the organization, if there are none, seed admin and viewer roles
	if roles, err = s.listOrSeedRoles(ctx, logger, tx, orgId); err != nil {
		return "", "", err
	}

	// Find admin role
	adminRole := getRoleByDisplayName(roles, RoleAdmin)
	if adminRole == nil {
		// we should never end up here
		return "", "", errors.New("failed to find admin role")
	}

	return SubjectTypeRole, adminRole.Id.String(), nil
}

func (s *Server) ReplaceOrgUserMemberships(ctx context.Context, request ReplaceOrgUserMembershipsRequestObject) (ReplaceOrgUserMembershipsResponseObject, error) {
	// Authentication and authorization
	currentUserId, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if err := s.checkOrgAdminAuthorization(ctx, currentUserId, request.OrgId); err != nil {
		return nil, err
	}

	// Prevent users from modifying their own permissions to avoid accidental lockout
	if currentUserId == request.UserId {
		return ReplaceOrgUserMemberships409JSONResponse{N409ConflictJSONResponse: Generate409Response("cannot modify your own memberships")}, nil
	}

	ids, ctx := hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	ids.UserId = request.UserId.String()
	logger := hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx).WithLazy(ids.AsLogField())

	// Begin transaction
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	// Check if the target user exists and is a member of the organization
	currentMemberships, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{
		UserId: &request.UserId,
		OrgId:  &request.OrgId,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to check existing memberships")
	}
	if len(currentMemberships) == 0 {
		return ReplaceOrgUserMemberships404JSONResponse{N404NotFoundJSONResponse: Generate404Response("user not found")}, nil
	}

	// Get user metadata from membership
	userName := currentMemberships[0].UserDisplayName
	userEmail := currentMemberships[0].UserPrimaryEmailAddress

	// Delete all existing memberships for this user in this organization
	deletedCount, err := s.Database.BulkDeleteMemberships(ctx, tx, model.BulkDeleteMembershipsParams{UserId: opt.Of(request.UserId), OrgId: opt.Of(request.OrgId)})
	if err != nil {
		return nil, errors.Wrap(err, "failed to delete existing memberships")
	}

	// Create new memberships from request
	// TODO: if we start using this endpoint with multiple
	// roles, we should do this with one query
	var createdMemberships []model.MembershipWithUserMetadata
	for _, membershipRequest := range request.Body.Memberships {
		subjectType := membershipRequest.SubjectType
		subject := membershipRequest.Subject

		// Handle virtual group conversion to role
		if subjectType, subject, err = s.resolveVirtualGroupToRole(ctx, logger, tx, request.OrgId, subjectType, subject); err != nil {
			return nil, err
		}

		var membershipRole opt.Opt[uuid.UUID]
		if subjectType == SubjectTypeRole {
			membershipRole = opt.Of(uuid.MustParse(subject))
		} else {
			membershipRole = opt.Empty[uuid.UUID]()
		}

		if isValid, err := isScopeValidForRole(ctx, membershipRequest.Scope, request.OrgId, s.CpClient); !isValid {
			var userErr *usererrors.UserError
			if errors.As(err, &userErr) {
				return ReplaceOrgUserMemberships400JSONResponse{N400BadRequestJSONResponse: Generate400Response(userErr.Error())}, nil
			} else if err != nil {
				return nil, errors.Wrap(err, "failed to validate scope for role membership")
			} else {
				scopeValue := ""
				if membershipRequest.Scope != nil {
					scopeValue = *membershipRequest.Scope
				}
				return ReplaceOrgUserMemberships400JSONResponse{N400BadRequestJSONResponse: Generate400Response(fmt.Sprintf("invalid scope for role membership: %s", scopeValue))}, nil
			}
		}

		membership, err := s.Database.CreateMembership(ctx, tx, &model.Membership{
			Id:          uuid.Must(uuid.NewV7()),
			CreatedAt:   time.Now().UTC(),
			OrgId:       request.OrgId,
			UserId:      request.UserId,
			SubjectType: model.MembershipSubjectType(subjectType),
			Subject:     subject,
			Role:        membershipRole,
			Scope:       ref.DerefOr(membershipRequest.Scope, ""),
		})
		if err != nil {
			if _, ok := model.IsErrNotFound(err); ok {
				return ReplaceOrgUserMemberships409JSONResponse{N409ConflictJSONResponse: Generate409Response("role not found in the organization")}, nil
			} else if _, ok := model.IsErrConflict(err); ok {
				return ReplaceOrgUserMemberships409JSONResponse{N409ConflictJSONResponse: Generate409Response("membership conflict")}, nil
			}

			return nil, errors.Wrap(err, "failed to create membership")
		}

		// Add to created memberships list with user metadata
		createdMemberships = append(createdMemberships, model.MembershipWithUserMetadata{
			Membership:              *membership,
			UserDisplayName:         userName,
			UserPrimaryEmailAddress: userEmail,
		})
	}

	// Insert SpiceDB sync event messages
	messages, err := insertSpiceDBSyncEventMessages(ctx, request.OrgId, ref.Ref(uuid.MustParse(request.UserId.String())), s.Database, tx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to insert spiceDB sync event messages")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit transaction")
	}

	// Publish messages for SpiceDB sync
	reliableoutbox.OptimisticPublish(ctx, logger, s.Database.AsReliableOutboxStore(), s.Publisher, messages)

	// Convert to response format
	userMemberships := make([]UserMembership, 0, len(createdMemberships))
	for _, membership := range createdMemberships {
		userMemberships = append(userMemberships, UserMembership{
			Id:          membership.Id,
			CreatedAt:   membership.CreatedAt,
			OrgId:       membership.OrgId,
			SubjectType: SubjectType(membership.SubjectType),
			Subject:     membership.Subject,
			Scope:       ref.Ref(membership.Scope),
		})
	}

	logger.Info("replaced user memberships",
		zap.Int64("deleted_count", deletedCount),
		zap.Int("created_count", len(createdMemberships)))

	return ReplaceOrgUserMemberships200JSONResponse{
		Items: userMemberships,
	}, nil
}

func (s *Server) ListMembers(ctx context.Context, request ListMembersRequestObject) (ListMembersResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgMemberAuthorization(ctx, uid, request.OrgId); err != nil {
		return nil, err
	}

	var pageToken string
	if request.Params.Page != nil {
		pageToken = *request.Params.Page
	}
	var perPage int
	if request.Params.PerPage != nil {
		perPage = *request.Params.PerPage
	}

	members, nextPageToken, err := s.Database.ListMembersWithIdentities(ctx, nil, model.ListMembershipsParams{
		OrgId:     &request.OrgId,
		UserId:    request.Params.UserId,
		PageToken: pageToken,
		PerPage:   perPage,
	})
	if err != nil {
		if e, ok := model.IsErrBadRequest(err); ok {
			return nil, herrors.NewWithStatus(http.StatusBadRequest, e.Message, nil)
		}
		return nil, errors.Wrap(err, "failed to list members")
	}

	out := make([]Member, 0, len(members))
	for _, m := range members {
		providers := make([]string, 0, len(m.UserIdentities))
		for provider := range m.UserIdentities {
			providers = append(providers, string(provider))
		}
		member := Member{
			Id:                m.Id,
			CreatedAt:         m.CreatedAt,
			UserId:            m.UserId,
			UserDisplayName:   m.UserDisplayName,
			SubjectType:       SubjectType(m.SubjectType),
			Subject:           m.Subject,
			IdentityProviders: providers,
		}
		member.UserPrimaryEmailAddress = m.UserPrimaryEmailAddress.Ref()
		out = append(out, member)
	}

	response := ListMembers200JSONResponse{Items: out}
	if nextPageToken != "" {
		response.NextPageToken = ref.Ref(nextPageToken)
	}
	return response, nil
}
