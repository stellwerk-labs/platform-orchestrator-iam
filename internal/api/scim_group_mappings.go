package api

import (
	"context"
	"strings"

	"github.com/pkg/errors"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
)

// SCIM group→role mappings decide which role a synced IDP group grants. They
// are guarded by membership_read/membership_write — NOT the provisioning
// permissions — on purpose: the provisioning permissions belong to the SCIM
// client (the IDP's service user), and if that client could redefine what a
// group grants, an IDP-side actor could self-escalate by mapping a group it
// controls to Admin. Mapping a populated group to a role assigns that role to
// its members, so it is membership administration and takes the same
// permission as granting memberships directly. role_write (managing role
// definitions) is deliberately NOT enough: being allowed to shape what a role
// can do does not mean being allowed to hand it to people.

func (s *Server) ListScimGroupMappings(ctx context.Context, request ListScimGroupMappingsRequestObject) (ListScimGroupMappingsResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAuthorization(ctx, uid, request.OrgId, sharedauthz.PermissionMembershipRead); err != nil {
		return nil, err
	}

	mappings, err := s.Database.ListScimGroupRoleMappings(ctx, nil, request.OrgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list scim group role mappings")
	}

	items := make([]ScimGroupMapping, 0, len(mappings))
	for _, m := range mappings {
		items = append(items, ScimGroupMapping{
			GroupDisplayName: m.GroupDisplayName,
			RoleId:           m.RoleId,
			CreatedAt:        m.CreatedAt,
		})
	}
	return ListScimGroupMappings200JSONResponse{Items: items}, nil
}

func (s *Server) UpsertScimGroupMapping(ctx context.Context, request UpsertScimGroupMappingRequestObject) (UpsertScimGroupMappingResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAuthorization(ctx, uid, request.OrgId, sharedauthz.PermissionMembershipWrite); err != nil {
		return nil, err
	}

	groupDisplayName := strings.TrimSpace(request.GroupDisplayName)
	if groupDisplayName == "" {
		return UpsertScimGroupMapping400JSONResponse{N400BadRequestJSONResponse: Generate400Response("group display name must not be blank")}, nil
	}

	// The role must live in THIS org. GetRole is org-scoped, so a role id from
	// another org comes back not-found; the composite foreign key on the
	// mapping table backstops the race where the role is deleted right after.
	if _, err := s.Database.GetRole(ctx, nil, request.OrgId, request.Body.RoleId); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return UpsertScimGroupMapping404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to get role for scim group mapping")
	}

	// One transaction: the mapping change and the role reconciliation of the
	// group's current members land together. Without the reconciliation the
	// mapping would only take effect at the next SCIM event, which makes the
	// feature look broken to the operator who just configured it.
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin scim group mapping transaction")
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.Database.UpsertScimGroupRoleMapping(ctx, tx, request.OrgId, groupDisplayName, request.Body.RoleId); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return UpsertScimGroupMapping404JSONResponse{N404NotFoundJSONResponse: Generate404Response("role not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to upsert scim group role mapping")
	}

	if err := s.reconcileScimGroupMembersByDisplayName(ctx, tx, request.OrgId, groupDisplayName); err != nil {
		return nil, err
	}

	// Read the row back for its authoritative created_at (an upsert onto an
	// existing mapping keeps the original creation time).
	mappings, err := s.Database.ListScimGroupRoleMappings(ctx, tx, request.OrgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read back scim group role mapping")
	}
	for _, m := range mappings {
		if strings.EqualFold(m.GroupDisplayName, groupDisplayName) {
			if err := tx.Commit(); err != nil {
				return nil, errors.Wrap(err, "failed to commit scim group mapping transaction")
			}
			if err := s.reloadAuthorizationPolicy(); err != nil {
				return nil, err
			}
			return UpsertScimGroupMapping200JSONResponse{
				GroupDisplayName: m.GroupDisplayName,
				RoleId:           m.RoleId,
				CreatedAt:        m.CreatedAt,
			}, nil
		}
	}
	return nil, errors.New("scim group role mapping vanished after upsert")
}

func (s *Server) DeleteScimGroupMapping(ctx context.Context, request DeleteScimGroupMappingRequestObject) (DeleteScimGroupMappingResponseObject, error) {
	if uid, err := GetAuthenticatedUserIdOr401(ctx); err != nil {
		return nil, err
	} else if err := s.checkOrgAuthorization(ctx, uid, request.OrgId, sharedauthz.PermissionMembershipWrite); err != nil {
		return nil, err
	}

	// Same transaction rule as the upsert: deleting a mapping must strip the
	// mapped role from the group's current members right away (falling back to
	// Viewer where nothing else applies), not at the next SCIM event.
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin scim group mapping transaction")
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.Database.DeleteScimGroupRoleMapping(ctx, tx, request.OrgId, request.GroupDisplayName); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return DeleteScimGroupMapping404JSONResponse{N404NotFoundJSONResponse: Generate404Response("scim group mapping not found")}, nil
		}
		return nil, errors.Wrap(err, "failed to delete scim group role mapping")
	}

	if err := s.reconcileScimGroupMembersByDisplayName(ctx, tx, request.OrgId, request.GroupDisplayName); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "failed to commit scim group mapping transaction")
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return nil, err
	}
	return DeleteScimGroupMapping204Response{}, nil
}

// reconcileScimGroupMembersByDisplayName reconciles the SCIM-managed roles of
// every user currently in the group the (case-insensitive) display name
// matches. Runs inside the caller's transaction; the caller reloads the
// authorization policy after commit.
func (s *Server) reconcileScimGroupMembersByDisplayName(ctx context.Context, tx model.TxWithCommit, orgId string, groupDisplayName string) error {
	memberIds, err := s.Database.ListScimUserIdsInGroupByDisplayName(ctx, tx, orgId, groupDisplayName)
	if err != nil {
		return errors.Wrap(err, "failed to list scim users in mapped group")
	}
	return s.reconcileScimUsersById(ctx, scimLogger(s, ctx), tx, orgId, memberIds)
}
