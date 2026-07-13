package spicedb

import (
	"context"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	PermissionRead   = "read"
	PermissionWrite  = "write"
	PermissionManage = "manage"
)

// SpiceDB Object Types
// These correspond to the definitions in schema.zed

type ObjectType string

func (o ObjectType) String() string {
	return string(o)
}

const (
	ObjectTypeUser       ObjectType = "user"
	ObjectTypeScopedRole ObjectType = "scoped_role"
	ObjectTypeOrg        ObjectType = "org"
	ObjectTypeProject    ObjectType = "project"
	ObjectTypeEnv        ObjectType = "env"
)

// SpiceDB Relations
// These correspond to the relations defined in schema.zed
type Relation string

func (r Relation) String() string {
	return string(r)
}

const (
	RelationMember     Relation = "member"
	RelationOrg        Relation = "org"
	RelationProject    Relation = "project"
	RelationAllReader  Relation = "all_reader"
	RelationAllManager Relation = "all_manager"
	RelationAllWriter  Relation = "all_writer"
)

// BulkDeleteScopedRolesParams specifies which scoped roles to delete from SpiceDB.
type BulkDeleteScopedRolesParams struct {
	ResourceType ObjectType
	ResourceId   string
}

// SpicedDB Subject Types
// These correspond to the definitions in schema.zed
type SubjectType string

func (s SubjectType) String() string {
	return string(s)
}

const (
	SubjectTypeUser SubjectType = "user"
)

type spicedb struct {
	client *authzed.Client
	logger *zap.Logger
}

//go:generate go tool mockgen  -destination mocks/spicedb.go github.com/stellwerk-labs/platform-orchestrator-iam/internal/spicedb SpiceDB

type SpiceDB interface {
	WriteSchema(ctx context.Context) error
	// SyncOrgRelationships performs a snapshot sync of an organization's relationships to SpiceDB.
	// It deletes all existing relationships for the org and bulk inserts the provided ones.
	// It returns the number of relationships added and removed and a zedToken for consistency.
	SyncOrgRelationships(ctx context.Context, orgId string, userId *uuid.UUID, relationshipFilters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error)

	// HasSubjectPermissionOnObj checks if a subject (user or service user) has a specific permission on an object (org or scoped role).
	// It returns true if the subject has the permission, false otherwise.
	// If zedToken is provided, it is used for consistency.
	HasSubjectPermissionOnObj(ctx context.Context, subjType SubjectType, subjId string, permission string, objType ObjectType, objId string, zedToken string) (bool, error)

	// CheckBulkPermissions performs a bulk permission check for multiple subject-object-permission tuples.
	CheckBulkPermissions(ctx context.Context, checks []*v1.CheckBulkPermissionsRequestItem) ([]*v1.CheckBulkPermissionsPair, error)

	// LookupSubjects returns all subjects (users) that have a specific permission on a resource.
	// It supports cursor-based pagination using the cursor parameter.
	// If zedToken is provided, it is used for consistency.
	// Returns the subjects, the next cursor (empty if no more results), and an error if any.
	LookupSubjects(ctx context.Context, resource ObjectType, resourceId string, permission string, cursor string, zedToken string) ([]*v1.ResolvedSubject, string, error)

	// BulkDeleteScopedRoles deletes all scoped roles associated with the specified resource.
	BulkDeleteScopedRoles(ctx context.Context, params BulkDeleteScopedRolesParams) error
}
