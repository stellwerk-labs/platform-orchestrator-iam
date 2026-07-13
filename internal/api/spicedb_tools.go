package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"

	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/genevents"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/events"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb"

	"github.com/pkg/errors"
	v2 "github.com/stellwerk-labs/golib/hrabbitmq/delayqueues/v2"
	"github.com/stellwerk-labs/golib/hstandardreliableoutbox"
	"go.uber.org/zap"
)

type SyncSpiceDBParams struct {
	OrgId  string
	UserId opt.Opt[uuid.UUID]
}

func insertSpiceDBSyncEventMessages(ctx context.Context, orgId string, userId *uuid.UUID, db model.Databaser, tx model.TxWithCommit) ([]*hstandardreliableoutbox.PendingEventMessage, error) {
	payload, _ := json.Marshal(events.CloudEvent[genevents.SpiceDBSyncData]{
		Type: genevents.IoPlatformOrchestratorSpicedbSync,
		Time: time.Now().UTC(),
		Data: genevents.SpiceDBSyncData{
			OrgId:  orgId,
			UserId: userId,
		},
	})

	msg := &hstandardreliableoutbox.PendingEventMessage{
		Exchange:   events.DefaultExchange,
		RoutingKey: string(genevents.IoPlatformOrchestratorSpicedbSync),
		Payload:    payload,
	}

	if messages, err := db.InsertPendingEventMessages(ctx, tx, []*hstandardreliableoutbox.PendingEventMessage{msg}); err != nil {
		return nil, err
	} else {
		return messages, nil
	}
}

// SyncSpiceDBWithDB syncs the SpiceDB relationships for a given organization or for a given user / service user based on the current state in the database.
// If only the orgId is provided, it syncs all relationships for the organization, i.e. it will add/remove all relationships for that org.
// If both orgId and userId are provided, it syncs only the relationships related to that specific user within the organization, i.e. it will only add/remove relationships for that user.
// Returns: zedToken, removed count, added count, pending event messages to publish, error
func SyncSpiceDBWithDB(ctx context.Context, logger *zap.Logger, syncParams SyncSpiceDBParams, db model.Databaser, spiceDB spicedb.SpiceDB) (string, int, int, []*hstandardreliableoutbox.PendingEventMessage, error) {
	// Start a database transaction
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", 0, 0, nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			logger.Error("failed to rollback transaction", zap.Error(err))
		}
	}()

	orgId := syncParams.OrgId

	var relationshipToRemoveFilters []*v1.RelationshipFilter
	var relationships []*v1.Relationship

	orgWideRoleRelationsById, err := mapOrgRelationByRoleId(ctx, db, tx, orgId)
	if err != nil {
		return "", 0, 0, nil, err
	}

	scopedRolesByOrgRoleAndScope, err := mapScopedRolesByOrgIdAndScope(ctx, db, tx, orgId)
	if err != nil {
		return "", 0, 0, nil, err
	}

	var memberships []model.MembershipWithUserMetadata
	var serviceUserRoles []model.ServiceUserRole

	// Fetch memberships for this org, optionally filtered by userId if provided (if userId is a service user, the memberships will be empty)
	if memberships, err = db.ListMemberships(ctx, tx, model.ListMembershipsParams{OrgId: &orgId, UserId: syncParams.UserId.Ref()}); err != nil {
		return "", 0, 0, nil, errors.Wrap(err, "failed to list memberships for organization")
	}

	// Fetch service user roles for this org, optionally filtered by userId if provided (if userId is a human user, the service user roles will be empty)
	if serviceUserRoles, err = db.ListServiceUserRoles(ctx, tx, model.ListServiceUserRolesParams{OrgId: &orgId, ServiceUserId: syncParams.UserId.Ref()}); err != nil {
		return "", 0, 0, nil, errors.Wrap(err, "failed to list service user roles for organization")
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return "", 0, 0, nil, errors.Wrap(err, "failed to commit transaction")
	}

	// Clear out relationships to remove based on org-wide roles and scoped roles
	for orgWideRoleId := range orgWideRoleRelationsById {
		relationshipToRemoveFilters = append(relationshipToRemoveFilters, &v1.RelationshipFilter{
			ResourceType:          spicedb.ObjectTypeScopedRole.String(),
			OptionalResourceId:    orgWideRoleId.String(),
			OptionalSubjectFilter: getSubjectFilterForUserId(syncParams.UserId.Ref()),
		})

		relationships = append(relationships,
			&v1.Relationship{
				// Relationship: scoped_role -> org via org relation in scoped_role definition
				Resource: &v1.ObjectReference{
					ObjectType: spicedb.ObjectTypeScopedRole.String(),
					ObjectId:   orgWideRoleId.String(),
				},
				Relation: spicedb.RelationOrg.String(),
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: spicedb.ObjectTypeOrg.String(),
						ObjectId:   orgId,
					},
				},
			},
			&v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: spicedb.ObjectTypeOrg.String(),
					ObjectId:   orgId,
				},
				Relation: orgWideRoleRelationsById[orgWideRoleId].String(),
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: spicedb.ObjectTypeScopedRole.String(),
						ObjectId:   orgWideRoleId.String(),
					},
				},
			})
	}

	for _, scopedRole := range scopedRolesByOrgRoleAndScope {
		relationshipToRemoveFilters = append(relationshipToRemoveFilters, &v1.RelationshipFilter{
			ResourceType:          spicedb.ObjectTypeScopedRole.String(),
			OptionalResourceId:    scopedRole.Id.String(),
			OptionalSubjectFilter: getSubjectFilterForUserId(syncParams.UserId.Ref()),
		})
	}

	// Populate relationships to add based on memberships
	for _, m := range memberships {
		if m.SubjectType == model.MembershipSubjectTypeRole && m.Role.IsSet() {
			if roleId, found := getRoleIdByOrgIdAndScope(m.Scope, m.Role.Must(), scopedRolesByOrgRoleAndScope); !found {
				if messages, err := createScopeSyncEventMessages(ctx, orgId, m.Scope, db); err != nil {
					return "", 0, 0, nil, errors.Wrap(err, "failed to insert scope sync event message")
				} else {
					return "", 0, 0, messages, v2.NewGracefulRetryError(errors.Errorf("scoped role not found for org role id %s and scope %s", m.Role.Must().String(), m.Scope))
				}
			} else {
				relationships = append(relationships, &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedb.ObjectTypeScopedRole.String(),
						ObjectId:   roleId.String(),
					},
					Relation: spicedb.RelationMember.String(),
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedb.ObjectTypeUser.String(),
							ObjectId:   m.UserId.String(),
						},
					},
				})
			}
		}
	}

	// Fetch service user roles for this org
	for _, sur := range serviceUserRoles {
		if roleId, found := getRoleIdByOrgIdAndScope(sur.Scope, sur.RoleId, scopedRolesByOrgRoleAndScope); !found {
			if messages, err := createScopeSyncEventMessages(ctx, orgId, sur.Scope, db); err != nil {
				return "", 0, 0, nil, errors.Wrap(err, "failed to insert scope sync event message")
			} else {
				return "", 0, 0, messages, v2.NewGracefulRetryError(errors.Errorf("scoped role not found for org role id %s and scope %s", sur.RoleId.String(), sur.Scope))
			}
		} else {
			relationships = append(relationships, &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: spicedb.ObjectTypeScopedRole.String(),
					ObjectId:   roleId.String(),
				},
				Relation: spicedb.RelationMember.String(),
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: spicedb.ObjectTypeUser.String(),
						ObjectId:   sur.ServiceUserId.String(),
					},
				},
			})
		}
	}

	if zedToken, removed, added, err := spiceDB.SyncOrgRelationships(ctx, orgId, syncParams.UserId.Ref(), relationshipToRemoveFilters, relationships); err != nil {
		return "", 0, 0, nil, errors.Wrap(err, "failed to sync organization relationships to SpiceDB")
	} else {
		return zedToken, removed, added, nil, nil
	}
}

// GetRelationByRoleDisplayName maps role display names to SpiceDB org relations
// Based on the schema: org has relations all_manager and all_reader
func GetRelationByRoleDisplayName(roleName string) spicedb.Relation {
	switch roleName {
	case RoleAdmin:
		return spicedb.RelationAllManager
	case RoleViewer:
		return spicedb.RelationAllReader
	case RoleDeployer:
		return spicedb.RelationAllWriter
	default:
		return spicedb.RelationAllReader
	}
}

// mapOrgRelationByRoleId returns a map of role IDs to their corresponding SpiceDB relation according to their display names.
func mapOrgRelationByRoleId(ctx context.Context, db model.Databaser, optionalTx model.Tx, orgId string) (map[uuid.UUID]spicedb.Relation, error) {
	if roles, err := db.ListRoles(ctx, optionalTx, orgId); err != nil {
		return nil, errors.Wrap(err, "failed to list roles")
	} else {
		var rolesToOrgRelation = make(map[uuid.UUID]spicedb.Relation)
		for _, role := range roles {
			rolesToOrgRelation[role.Id] = GetRelationByRoleDisplayName(role.DisplayName)
		}
		return rolesToOrgRelation, nil
	}
}

// mapScopedRolesByOrgIdAndScope returns a map where the key is a combination of orgRoleId and scope, and the value is the corresponding ScopedRole.
func mapScopedRolesByOrgIdAndScope(ctx context.Context, db model.Databaser, optionalTx model.Tx, orgId string) (map[string]model.ScopedRole, error) {
	if scopedRoles, err := db.ListScopedRoles(ctx, optionalTx, model.ScopedRoleListParams{
		OrgId: orgId,
	}); err != nil {
		return nil, errors.Wrap(err, "failed to list scoped roles")
	} else {
		scopedRolesMap := make(map[string]model.ScopedRole)
		for _, sr := range scopedRoles {
			scopedRolesMap[sr.OrgRoleId.String()+"@"+sr.Scope] = sr
		}
		return scopedRolesMap, nil
	}
}

// getRoleIdByOrgIdAndScope returns the appropriate role ID based on whether a scope is provided.
func getRoleIdByOrgIdAndScope(scope string, orgRoleId uuid.UUID, scopedRolesByOrgRoleAndScope map[string]model.ScopedRole) (uuid.UUID, bool) {
	if scope == "" {
		return orgRoleId, true
	}
	if scopedRole, ok := scopedRolesByOrgRoleAndScope[fmt.Sprintf("%s@%s", orgRoleId.String(), scope)]; !ok {
		return uuid.Nil, false
	} else {
		return scopedRole.Id, true
	}
}

func getSubjectFilterForUserId(userId *uuid.UUID) *v1.SubjectFilter {
	if userId == nil {
		return nil
	}
	return &v1.SubjectFilter{
		SubjectType:       spicedb.ObjectTypeUser.String(),
		OptionalSubjectId: userId.String(),
	}
}

func createScopeSyncEventMessages(ctx context.Context, orgId, scope string, db model.Databaser) ([]*hstandardreliableoutbox.PendingEventMessage, error) {
	payload, _ := json.Marshal(events.CloudEvent[genevents.ScopeSyncData]{
		Type: genevents.IoPlatformOrchestratorScopeSync,
		Time: time.Now().UTC(),
		Data: genevents.ScopeSyncData{
			OrgId: orgId,
			Scope: scope,
		},
	})

	msg := &hstandardreliableoutbox.PendingEventMessage{
		Exchange:   events.DefaultExchange,
		RoutingKey: string(genevents.IoPlatformOrchestratorScopeSync),
		Payload:    payload,
	}

	if messages, err := db.InsertPendingEventMessages(ctx, nil, []*hstandardreliableoutbox.PendingEventMessage{msg}); err != nil {
		return nil, err
	} else {
		return messages, nil
	}
}
