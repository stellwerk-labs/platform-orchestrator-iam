package spicedb

import (
	"context"
	"io"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// findScopedRoleIds finds all scoped_role IDs linked to a specific resource
// via all_manager, all_reader, or all_writer relations.
func (s *spicedb) findScopedRoleIds(ctx context.Context, resourceType ObjectType, resourceId string) (map[string]struct{}, error) {
	scopedRoleIds := make(map[string]struct{})
	relations := []Relation{RelationAllManager, RelationAllReader, RelationAllWriter}

	for _, rel := range relations {
		stream, err := s.client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
			RelationshipFilter: &v1.RelationshipFilter{
				ResourceType:       resourceType.String(),
				OptionalResourceId: resourceId,
				OptionalRelation:   rel.String(),
				OptionalSubjectFilter: &v1.SubjectFilter{
					SubjectType: ObjectTypeScopedRole.String(),
				},
			},
		})
		if err != nil {
			return nil, err
		}

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if resp.Relationship.Subject.Object.ObjectType == ObjectTypeScopedRole.String() {
				scopedRoleIds[resp.Relationship.Subject.Object.ObjectId] = struct{}{}
			}
		}
	}

	return scopedRoleIds, nil
}

// deleteScopedRoleRelationships deletes all relationships for the given scoped role IDs.
// This includes:
//   - Relationships where scoped_role is the resource (scoped_role#org, scoped_role#member)
//   - Relationships where scoped_role is the subject (org/project/env#all_*@scoped_role)
func (s *spicedb) deleteScopedRoleRelationships(ctx context.Context, logger *zap.Logger, scopedRoleIds map[string]struct{}) error {
	for roleId := range scopedRoleIds {
		// Delete relationships where scoped_role is the resource
		_, err := s.client.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
			RelationshipFilter: &v1.RelationshipFilter{
				ResourceType:       ObjectTypeScopedRole.String(),
				OptionalResourceId: roleId,
			},
		})
		if err != nil {
			logger.Error("failed to delete relationships where scoped_role is resource",
				zap.String("role_id", roleId), zap.Error(err))
			return err
		}

		// Delete relationships where scoped_role is the subject
		resourceTypes := []ObjectType{ObjectTypeOrg, ObjectTypeProject, ObjectTypeEnv}
		for _, rt := range resourceTypes {
			_, err := s.client.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
				RelationshipFilter: &v1.RelationshipFilter{
					ResourceType: rt.String(),
					OptionalSubjectFilter: &v1.SubjectFilter{
						SubjectType:       ObjectTypeScopedRole.String(),
						OptionalSubjectId: roleId,
					},
				},
			})
			if err != nil {
				logger.Error("failed to delete relationships where scoped_role is subject",
					zap.String("role_id", roleId),
					zap.String("resource_type", rt.String()),
					zap.Error(err))
				return err
			}
		}
	}
	return nil
}

// BulkDeleteScopedRoles deletes all scoped roles associated with the specified resource.
func (s *spicedb) BulkDeleteScopedRoles(ctx context.Context, params BulkDeleteScopedRolesParams) error {
	logger := s.logger.With(
		zap.String("resource_type", params.ResourceType.String()),
		zap.String("resource_id", params.ResourceId),
	)

	// Find all scoped role IDs
	scopedRoleIds, err := s.findScopedRoleIds(ctx, params.ResourceType, params.ResourceId)
	if err != nil {
		return errors.Wrap(err, "failed to find scoped role IDs")
	}

	if len(scopedRoleIds) == 0 {
		logger.Debug("no scope roles found for resource")
		return nil
	}

	logger.Info("deleting scope roles from SpiceDB", zap.Int("count", len(scopedRoleIds)))

	// Delete all relationships for these scoped roles
	if err := s.deleteScopedRoleRelationships(ctx, logger, scopedRoleIds); err != nil {
		return err
	}

	logger.Info("successfully deleted scope roles")
	return nil
}
