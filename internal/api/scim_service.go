package api

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// scimProvisionUserInput holds everything needed to provision or update a SCIM user.
type scimProvisionUserInput struct {
	OrgId       string
	UserName    string
	DisplayName string // from displayName or name.formatted; fallback to userName
	ExternalId  string // empty if absent
	Active      bool
	Email       string // primary email; may be empty
}

// scimProvisionUser resolves or creates the global user record, ensures org membership,
// and inserts the scim_users row — all in one transaction.
//
// Returns the created ScimUser on success.
func (s *Server) scimProvisionUser(ctx context.Context, logger *zap.Logger, input scimProvisionUserInput) (*model.ScimUser, error) {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback scim provision transaction", zap.Error(err))
		}
	}()

	now := time.Now().UTC()

	user, err := s.resolveOrCreateGlobalUser(ctx, logger, tx, now, input)
	if err != nil {
		return nil, err
	}

	// Entra can stage users with active=false; they get their membership at
	// activation time, not before.
	if input.Active {
		if err := s.ensureOrgMembership(ctx, logger, tx, now, input.OrgId, user.Id); err != nil {
			return nil, err
		}
	}

	externalIdOpt := opt.Empty[string]()
	if input.ExternalId != "" {
		externalIdOpt = opt.Of(input.ExternalId)
	}

	scimUser := model.ScimUser{
		Id:         uuid.Must(uuid.NewV7()),
		OrgId:      input.OrgId,
		UserId:     user.Id,
		UserName:   input.UserName,
		ExternalId: externalIdOpt,
		Active:     input.Active,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.Database.CreateScimUser(ctx, tx, scimUser); err != nil {
		return nil, errors.Wrap(err, "failed to create scim user")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit scim provision transaction")
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return nil, err
	}
	return &scimUser, nil
}

// resolveOrCreateGlobalUser implements the three-way lookup described in the spec:
// (a) by SCIM identity (orgId:externalId), (b) by primary email, (c) create new.
func (s *Server) resolveOrCreateGlobalUser(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, now time.Time, input scimProvisionUserInput) (*model.User, error) {
	identityKey := fmt.Sprintf("%s:%s", input.OrgId, input.ExternalId)

	// (a) Look up by SCIM identity when externalId is present.
	if input.ExternalId != "" {
		userId, err := s.Database.GetUserIdByIdentity(ctx, tx, model.UserIdentityProviderScim, identityKey)
		if err != nil {
			if _, ok := model.IsErrNotFound(err); !ok {
				return nil, errors.Wrap(err, "failed to look up scim identity")
			}
		} else if userId != nil {
			user, err := s.Database.GetUser(ctx, tx, *userId)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get user by scim identity")
			}
			return user, nil
		}
	}

	// (b) Look up by primary email (fall back to userName if it contains @).
	emailToSearch := input.Email
	if emailToSearch == "" && strings.Contains(input.UserName, "@") {
		emailToSearch = input.UserName
	}
	if emailToSearch != "" {
		user, err := s.Database.FindUserByPrimaryEmail(ctx, tx, emailToSearch)
		if err != nil {
			if _, ok := model.IsErrNotFound(err); !ok {
				return nil, errors.Wrap(err, "failed to look up user by email")
			}
		} else if user != nil {
			// Attach the SCIM identity to this existing user if externalId is present.
			if input.ExternalId != "" {
				if err := s.Database.AddUserIdentity(ctx, tx, user.Id, model.UserIdentityProviderScim, identityKey); err != nil {
					return nil, errors.Wrap(err, "failed to attach scim identity to existing user")
				}
			}
			return user, nil
		}
	}

	// (c) Create a new global user.
	displayName := input.DisplayName
	if displayName == "" {
		displayName = input.UserName
	}
	emailOpt := opt.Empty[string]()
	if input.Email != "" {
		emailOpt = opt.Of(input.Email)
	} else if strings.Contains(input.UserName, "@") {
		emailOpt = opt.Of(input.UserName)
	}

	identities := map[model.UserIdentityProvider]string{}
	if input.ExternalId != "" {
		identities[model.UserIdentityProviderScim] = identityKey
	}

	newUser := model.User{
		Id:                  userid.NewHumanUserId(),
		DisplayName:         displayName,
		PrimaryEmailAddress: emailOpt,
		CreatedAt:           now,
		UserIdentities:      identities,
	}
	user, err := s.Database.CreateUser(ctx, tx, &newUser)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create global user for scim provisioning")
	}
	logger.Info("created new global user via scim provisioning", zap.String("user_id", user.Id.String()))
	return user, nil
}

// ensureOrgMembership adds a Viewer role membership for the user in the org if one
// doesn't already exist. Mirrors the SSO JIT path in sso.go.
func (s *Server) ensureOrgMembership(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, now time.Time, orgId string, userId uuid.UUID) error {
	subjectType := model.MembershipSubjectTypeRole
	existing, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{
		OrgId:       &orgId,
		UserId:      &userId,
		SubjectType: ref.Ref(subjectType),
	})
	if err != nil {
		return errors.Wrap(err, "failed to check existing memberships")
	}
	if len(existing) > 0 {
		return nil // already a member
	}

	roles, err := s.listOrSeedRoles(ctx, logger, tx, orgId)
	if err != nil {
		return err
	}

	viewerRole := getRoleByDisplayName(roles, RoleViewer)
	if viewerRole == nil {
		return fmt.Errorf("org %s is missing the Viewer system role", orgId)
	}

	_, err = s.Database.CreateMembership(ctx, tx, &model.Membership{
		Id:          uuid.Must(uuid.NewV7()),
		CreatedAt:   now,
		OrgId:       orgId,
		UserId:      userId,
		SubjectType: model.MembershipSubjectTypeRole,
		Subject:     viewerRole.Id.String(),
		Role:        opt.Of(viewerRole.Id),
	})
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return nil // race — already created
		}
		return errors.Wrap(err, "failed to create membership for scim-provisioned user")
	}
	return nil
}

// scimDeleteUser removes all org memberships and the scim_users row entirely.
// Session tokens are revoked if the user has no remaining memberships anywhere.
func (s *Server) scimDeleteUser(ctx context.Context, logger *zap.Logger, scimUser *model.ScimUser) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed to begin delete transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback delete transaction", zap.Error(err))
		}
	}()

	if err := s.removeOrgMembershipsAndMaybeSessions(ctx, tx, scimUser.OrgId, scimUser.UserId); err != nil {
		return err
	}

	if err := s.Database.DeleteScimUser(ctx, tx, scimUser.OrgId, scimUser.Id); err != nil {
		return errors.Wrap(err, "failed to delete scim user row")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "failed to commit delete transaction")
	}
	return s.reloadAuthorizationPolicy()
}

// removeOrgMembershipsAndMaybeSessions bulk-deletes all memberships for the user in
// the given org, then checks whether the user still has memberships in any org.
// If not, all session tokens are revoked.
func (s *Server) removeOrgMembershipsAndMaybeSessions(ctx context.Context, tx model.TxWithCommit, orgId string, userId uuid.UUID) error {
	if _, err := s.Database.BulkDeleteMemberships(ctx, tx, model.BulkDeleteMembershipsParams{
		OrgId:  opt.Of(orgId),
		UserId: opt.Of(userId),
	}); err != nil {
		return errors.Wrap(err, "failed to remove org memberships")
	}

	remaining, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{UserId: &userId})
	if err != nil {
		return errors.Wrap(err, "failed to check remaining memberships")
	}
	if len(remaining) == 0 {
		if _, err := s.Database.DeleteSessionTokensByUserId(ctx, tx, userId); err != nil {
			return errors.Wrap(err, "failed to revoke session tokens")
		}
	}
	return nil
}

// findScimUserForOrg returns the org's SCIM row for the user, or nil if the
// user was not SCIM-provisioned in that org.
func (s *Server) findScimUserForOrg(ctx context.Context, tx model.TxWithCommit, orgId string, userId uuid.UUID) (*model.ScimUser, error) {
	scimUser, err := s.Database.FindScimUserByUserId(ctx, tx, orgId, userId)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to look up scim user")
	}
	return scimUser, nil
}

// scimGlobalUserFields carries the parts of a SCIM payload that live on the
// global user record rather than the org-scoped SCIM row. A nil field means the
// IDP did not send it, so leave it alone; for anything it does send the IDP is
// authoritative, because it owns the lifecycle of provisioned users.
type scimGlobalUserFields struct {
	DisplayName *string
	Email       *string
}

// scimUpdateUser applies a SCIM user update. Membership side effects, the SCIM
// row, and the global user record all move in ONE transaction: a PATCH that
// both deactivates a user and renames them must not be able to strip
// memberships and then fail, leaving active=true with no access.
func (s *Server) scimUpdateUser(ctx context.Context, logger *zap.Logger, existing *model.ScimUser, updated model.ScimUser, global scimGlobalUserFields) (*model.ScimUser, error) {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin scim update transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback scim update transaction", zap.Error(err))
		}
	}()

	now := time.Now().UTC()
	switch {
	case existing.Active && !updated.Active:
		if err := s.removeOrgMembershipsAndMaybeSessions(ctx, tx, existing.OrgId, existing.UserId); err != nil {
			return nil, err
		}
	case !existing.Active && updated.Active:
		if err := s.ensureOrgMembership(ctx, logger, tx, now, existing.OrgId, existing.UserId); err != nil {
			return nil, err
		}
	}

	updated.UpdatedAt = now
	if err := s.Database.UpdateScimUser(ctx, tx, updated); err != nil {
		return nil, errors.Wrap(err, "failed to update scim user")
	}

	if err := s.applyGlobalUserFields(ctx, tx, updated.UserId, global); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit scim update transaction")
	}
	return &updated, s.reloadAuthorizationPolicy()
}

// applyGlobalUserFields writes IDP-supplied display name and email onto the
// global user record, so a rename in the IDP does not leave the orchestrator
// showing a stale name or address forever.
func (s *Server) applyGlobalUserFields(ctx context.Context, tx model.TxWithCommit, userId uuid.UUID, global scimGlobalUserFields) error {
	if global.DisplayName == nil && global.Email == nil {
		return nil
	}
	user, err := s.Database.GetUser(ctx, tx, userId)
	if err != nil {
		return errors.Wrap(err, "failed to get global user for scim field update")
	}
	changed := false
	if global.DisplayName != nil && *global.DisplayName != "" && user.DisplayName != *global.DisplayName {
		user.DisplayName = *global.DisplayName
		changed = true
	}
	if global.Email != nil && *global.Email != "" {
		current := ""
		if user.PrimaryEmailAddress.IsSet() {
			current = *user.PrimaryEmailAddress.Ref()
		}
		if current != *global.Email {
			user.PrimaryEmailAddress = opt.Of(*global.Email)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if _, err := s.Database.UpdateUser(ctx, tx, user); err != nil {
		return errors.Wrap(err, "failed to update global user from scim")
	}
	return nil
}

func scimLogger(s *Server, ctx context.Context) *zap.Logger {
	_, ctx = hlogger.EnsurePlatformOrchestratorIdsOnCtx(ctx)
	return hlogger.TraceScopedLoggerFromCtx(s.Logger, ctx)
}
