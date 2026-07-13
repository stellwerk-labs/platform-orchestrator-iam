package spicedb

import (
	"context"
	"io"
	"slices"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
)

func (s *spicedb) SyncOrgRelationships(ctx context.Context, orgId string, userId *uuid.UUID, relationshipFilters []*v1.RelationshipFilter, relationships []*v1.Relationship) (string, int, int, error) {
	logger := hlogger.TraceScopedLoggerFromCtx(s.logger, ctx).With(zap.String(hlogger.POOrgId, orgId), zap.Any(hlogger.POUserId, ref.DerefOr(userId, uuid.Nil).String()))
	// Read all existing relationships matching the provided filters
	var existingRelationships []*v1.Relationship
	for _, filter := range relationshipFilters {
		if rels, err := s.readRelationshipsByFilter(ctx, filter, ""); err != nil {
			return "", 0, 0, errors.Wrap(err, "failed to read existing relationships")
		} else {
			existingRelationships = append(existingRelationships, rels...)
		}
	}

	relationshipsToDelete := make([]*v1.Relationship, 0)
	// Remove any relationships that are already present in the new set from the delete list as a relationship can only be specified in an update once per overall WriteRelationships request
	for _, rel := range existingRelationships {
		if idx := slices.IndexFunc(relationships, func(r *v1.Relationship) bool { return r.String() == rel.String() }); idx != -1 {
			relationships = slices.Delete(relationships, idx, idx+1)
		} else {
			relationshipsToDelete = append(relationshipsToDelete, rel)
		}
	}

	var toRemove = len(relationshipsToDelete)
	var toAdd = len(relationships)

	// Build atomic updates: deletes for existing + touches for new
	updates := make([]*v1.RelationshipUpdate, 0, len(existingRelationships)+len(relationships))

	// Add delete operations for all existing relationships
	for _, rel := range relationshipsToDelete {
		updates = append(updates, &v1.RelationshipUpdate{
			Operation:    v1.RelationshipUpdate_OPERATION_DELETE,
			Relationship: rel,
		})
	}

	// Add touch operations for new relationships
	for _, rel := range relationships {
		updates = append(updates, &v1.RelationshipUpdate{
			Operation:    v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: rel,
		})
	}

	var zedToken string
	// Execute all operations atomically in a single write
	if len(updates) > 0 {
		if resp, err := s.client.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
			Updates: updates,
		}); err != nil {
			return "", 0, 0, errors.Wrap(err, "failed to atomically sync relationships to SpiceDB")
		} else {
			zedToken = resp.WrittenAt.Token
			logger.Info("successfully synced org relationships to SpiceDB", zap.Int("deleted", len(relationshipsToDelete)), zap.Int("created", len(relationships)))
		}

	} else {
		logger.Info("no relationships to sync for org")
	}

	return zedToken, toRemove, toAdd, nil
}

// readRelationshipsByFilter reads all relationships matching a given filter
func (s *spicedb) readRelationshipsByFilter(ctx context.Context, filter *v1.RelationshipFilter, zedToken string) ([]*v1.Relationship, error) {
	var allRelationships []*v1.Relationship

	resp, err := s.client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: filter,
		Consistency:        calculateConsistency(zedToken),
	})
	if err != nil {
		if err := convertContextCancelledErr(hlogger.TraceScopedLoggerFromCtx(s.logger, ctx), err); err != nil {
			return nil, err
		}
		return nil, errors.Wrap(err, "failed to read relationships in SpiceDB")
	}

	for {
		msg, err := resp.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		allRelationships = append(allRelationships, msg.Relationship)
	}

	return allRelationships, nil
}
