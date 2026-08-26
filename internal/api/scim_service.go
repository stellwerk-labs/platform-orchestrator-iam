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
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"
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

	// Entra can stage users with active=false; they get their membership at
	// activation time, not before. The scim_users row must exist first: the
	// reconciler joins group memberships and records managed memberships
	// against it. The provisioned audit event follows the same rule: a staged
	// user emits it at activation (scimUpdateUser), not here.
	if input.Active {
		if err := s.reconcileScimUserRoles(ctx, logger, tx, scimUser); err != nil {
			return nil, err
		}
		if err := s.insertScimUserProvisionedEvent(ctx, tx, scimUser); err != nil {
			return nil, err
		}
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

// reconcileScimUserRoles brings the SCIM-managed memberships of one user in
// line with the roles mapped to their SCIM groups. It must run inside the
// caller's transaction; the caller reloads the authorization policy after
// commit.
//
// Semantics:
//   - Target role set = the roles mapped (scim_group_role_mappings) to the
//     groups the user is in. If no mapping applies AND the user would otherwise
//     have no role membership in the org, the target is the Viewer system role
//     (preserves the pre-mapping behaviour: a provisioned user is never left
//     with no access).
//   - Only memberships recorded in scim_managed_memberships are ever deleted.
//     A role a human granted through the memberships API survives untouched.
//   - If a human already granted a role that is also in the target set, the
//     CreateMembership conflict is swallowed and the grant stays human-owned,
//     so a later group removal cannot revoke it.
func (s *Server) reconcileScimUserRoles(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, scimUser model.ScimUser) error {
	mappedRoleIds, err := s.Database.ListRoleIdsForScimUserGroups(ctx, tx, scimUser.OrgId, scimUser.Id)
	if err != nil {
		return errors.Wrap(err, "failed to list mapped roles for scim user")
	}

	managedIds, err := s.Database.ListScimManagedMembershipIds(ctx, tx, scimUser.Id)
	if err != nil {
		return errors.Wrap(err, "failed to list scim managed memberships")
	}
	managedIdSet := make(map[uuid.UUID]struct{}, len(managedIds))
	for _, id := range managedIds {
		managedIdSet[id] = struct{}{}
	}

	targetRoleIds := mappedRoleIds
	if len(targetRoleIds) == 0 {
		// No mapping applies. Fall back to Viewer, but only when the user has
		// no human-made role membership in the org — the fallback's only job
		// is to guarantee access, not to pile Viewer on top of a manual grant.
		subjectType := model.MembershipSubjectTypeRole
		existing, err := s.Database.ListMemberships(ctx, tx, model.ListMembershipsParams{
			OrgId:       &scimUser.OrgId,
			UserId:      &scimUser.UserId,
			SubjectType: ref.Ref(subjectType),
		})
		if err != nil {
			return errors.Wrap(err, "failed to check existing memberships")
		}
		manualExists := false
		for _, m := range existing {
			if _, managed := managedIdSet[m.Id]; !managed {
				manualExists = true
				break
			}
		}
		if !manualExists {
			roles, err := s.listOrSeedRoles(ctx, logger, tx, scimUser.OrgId)
			if err != nil {
				return err
			}
			viewerRole := getRoleByDisplayName(roles, RoleViewer)
			if viewerRole == nil {
				return fmt.Errorf("org %s is missing the Viewer system role", scimUser.OrgId)
			}
			targetRoleIds = []uuid.UUID{viewerRole.Id}
		}
	}
	targetSet := make(map[uuid.UUID]struct{}, len(targetRoleIds))
	for _, id := range targetRoleIds {
		targetSet[id] = struct{}{}
	}

	// Drop managed memberships whose role fell out of the target set; keep the
	// rest and note which target roles they already cover.
	covered := make(map[uuid.UUID]struct{}, len(targetRoleIds))
	for _, membershipId := range managedIds {
		membership, err := s.Database.GetMembership(ctx, tx, membershipId)
		if err != nil {
			return errors.Wrap(err, "failed to get scim managed membership")
		}
		if membership.Role.IsSet() {
			roleId := membership.Role.Must()
			if _, wanted := targetSet[roleId]; wanted {
				covered[roleId] = struct{}{}
				continue
			}
		}
		// The scim_managed_memberships row cascades away with the membership.
		if err := s.Database.DeleteMembership(ctx, tx, membershipId); err != nil {
			return errors.Wrap(err, "failed to delete stale scim managed membership")
		}
	}

	// Create what is missing, recording each new membership as SCIM-managed.
	for _, roleId := range targetRoleIds {
		if _, done := covered[roleId]; done {
			continue
		}
		membership, err := s.Database.CreateMembership(ctx, tx, &model.Membership{
			Id:          uuid.Must(uuid.NewV7()),
			CreatedAt:   time.Now().UTC(),
			OrgId:       scimUser.OrgId,
			UserId:      scimUser.UserId,
			SubjectType: model.MembershipSubjectTypeRole,
			Subject:     roleId.String(),
			Role:        opt.Of(roleId),
		})
		if err != nil {
			if _, ok := model.IsErrConflict(err); ok {
				// A human already granted this exact role. Leave it theirs:
				// adopting it as managed would let a group removal revoke it.
				continue
			}
			return errors.Wrap(err, "failed to create scim managed membership")
		}
		if err := s.Database.CreateScimManagedMembership(ctx, tx, membership.Id, scimUser.Id); err != nil {
			return err
		}
	}

	logger.Debug("reconciled scim user roles",
		zap.String("scim_user_id", scimUser.Id.String()),
		zap.Int("target_roles", len(targetRoleIds)))
	return nil
}

// reconcileScimUsersById reconciles the given SCIM users (deduplicated) after
// a group membership change. Inactive users are skipped: they hold no
// memberships until activation.
func (s *Server) reconcileScimUsersById(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, orgId string, scimUserIds []uuid.UUID) error {
	seen := make(map[uuid.UUID]struct{}, len(scimUserIds))
	for _, id := range scimUserIds {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		scimUser, err := s.Database.GetScimUser(ctx, tx, orgId, id)
		if err != nil {
			// A member deleted between the group read and this pass has no
			// memberships left to reconcile; don't fail the whole request.
			if _, ok := model.IsErrNotFound(err); ok {
				continue
			}
			return errors.Wrap(err, "failed to get scim user for reconciliation")
		}
		if !scimUser.Active {
			continue
		}
		if err := s.reconcileScimUserRoles(ctx, logger, tx, *scimUser); err != nil {
			return err
		}
	}
	return nil
}

// scimDeleteUser removes all org memberships and tombstones the scim_users row
// (deleted_at set, active=false, group membership rows removed). The row must
// survive: it is the only record that this org's IDP governs the user, and the
// SSO gate needs it to refuse a deleted user who tries to log back in. Session
// tokens are revoked if the user has no remaining memberships anywhere.
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

	if err := s.Database.TombstoneScimUser(ctx, tx, scimUser.OrgId, scimUser.Id); err != nil {
		return errors.Wrap(err, "failed to tombstone scim user row")
	}

	if err := s.insertScimUserDeprovisionedEvent(ctx, tx, *scimUser, genevents.Deleted); err != nil {
		return err
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

// findScimUserForOrg returns the org's SCIM governance record for the user:
// the live row if one exists, otherwise the most recent tombstone (DeletedAt
// set), otherwise nil — the org's SCIM never provisioned this user. Callers
// gate on Deprovisioned(), which covers both deactivated and deleted.
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
// IDP did not send it, so leave it alone. A non-nil blank DisplayName means the
// IDP cleared it (PUT omitted it, PATCH removed it), which resets it to the
// provisioning default. Whether any of it lands on the shared record is
// decided by the multi-org ownership rule in applyGlobalUserFields.
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
		// Audited with the updated row: a PATCH that renames and deactivates in
		// one go must report the name the user ends up with.
		if err := s.insertScimUserDeprovisionedEvent(ctx, tx, updated, genevents.Deactivated); err != nil {
			return nil, err
		}
	case !existing.Active && updated.Active:
		// Reactivation restores the roles the user's current groups map to
		// (or the Viewer fallback when nothing is mapped).
		if err := s.reconcileScimUserRoles(ctx, logger, tx, *existing); err != nil {
			return nil, err
		}
		if err := s.insertScimUserProvisionedEvent(ctx, tx, updated); err != nil {
			return nil, err
		}
	}

	updated.UpdatedAt = now
	if err := s.Database.UpdateScimUser(ctx, tx, updated); err != nil {
		return nil, errors.Wrap(err, "failed to update scim user")
	}

	// A changed externalId means the IDP now addresses this person by a new
	// key; bind it so resolveOrCreateGlobalUser's identity lookup keeps
	// working. The old binding is deliberately left in place: it still maps
	// the retired key to the same person (harmless, and historically
	// accurate), while deleting it would break a concurrent request that
	// resolved the old key moments ago. AddUserIdentity is idempotent.
	if updated.ExternalId.IsSet() && updated.ExternalId != existing.ExternalId {
		identityKey := fmt.Sprintf("%s:%s", updated.OrgId, updated.ExternalId.Must())
		if err := s.Database.AddUserIdentity(ctx, tx, updated.UserId, model.UserIdentityProviderScim, identityKey); err != nil {
			return nil, errors.Wrap(err, "failed to bind changed scim external id")
		}
	}

	if err := s.applyGlobalUserFields(ctx, logger, tx, updated, global); err != nil {
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
//
// Multi-organization ownership rule: the write only happens while the calling
// organization holds the SOLE live (non-tombstoned) SCIM record for this user.
// The global user is shared across organizations, so if two of them provision
// the same person, letting either IDP write here degrades to silent
// last-writer-wins renames that ripple into every other organization. No
// organization's IDP gets to rename a person for everybody else; with more
// than one live SCIM record the shared profile stays untouched and we log why.
func (s *Server) applyGlobalUserFields(ctx context.Context, logger *zap.Logger, tx model.TxWithCommit, scimUser model.ScimUser, global scimGlobalUserFields) error {
	if global.DisplayName == nil && global.Email == nil {
		return nil
	}
	governingOrgs, err := s.Database.CountLiveScimUsersForUser(ctx, tx, scimUser.UserId)
	if err != nil {
		return errors.Wrap(err, "failed to count live scim records for user")
	}
	if governingOrgs > 1 {
		logger.Info("skipping scim update of the shared global user profile: the user is scim-provisioned in multiple organizations, so no single organization's IDP owns the profile",
			zap.String("org_id", scimUser.OrgId),
			zap.String("user_id", scimUser.UserId.String()),
			zap.Int("governing_orgs", governingOrgs))
		return nil
	}
	user, err := s.Database.GetUser(ctx, tx, scimUser.UserId)
	if err != nil {
		return errors.Wrap(err, "failed to get global user for scim field update")
	}
	changed := false
	if global.DisplayName != nil {
		// A cleared display name (PUT omitted it, PATCH removed it) resets to
		// the same default used at provisioning time: the userName.
		target := *global.DisplayName
		if strings.TrimSpace(target) == "" {
			target = scimUser.UserName
		}
		if user.DisplayName != target {
			user.DisplayName = target
			changed = true
		}
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
