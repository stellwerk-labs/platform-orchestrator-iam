package spicedb

import (
	"context"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hlogger"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// convertContextCancelledErr attempts to convert a GRPC error into a real context.Canceled error.
// Normally our REST server converts client-cancelled errors into HTTP 499 codes and prevents them being alerted on.
// However, when using the spicedb GRPC connection, this root cause gets obscured and we need to convert it back
// into the native context canceled error.
func convertContextCancelledErr(logger *zap.Logger, err error) error {
	if st := status.Convert(err); st != nil && st.Code() == codes.Canceled {
		logger.Warn("request canceled - converting grpc cancelled into native context cancel", zap.Error(err))
		return context.Canceled
	}
	return nil
}

var ErrInvalidCursor = errors.New("invalid pagination cursor")

func isInvalidCursorErr(err error) bool {
	if st := status.Convert(err); st != nil && st.Code() == codes.InvalidArgument {
		return strings.Contains(st.Message(), "error decoding cursor")
	}

	return false
}

func (s *spicedb) HasSubjectPermissionOnObj(ctx context.Context, subjType SubjectType, subjId string, permission string, objType ObjectType, objId string, zedToken string) (bool, error) {
	if resp, err := s.client.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Resource: &v1.ObjectReference{
			ObjectType: objType.String(),
			ObjectId:   objId,
		},
		Permission: permission,
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: subjType.String(),
				ObjectId:   subjId,
			},
		},
		Consistency: calculateConsistency(zedToken),
	}); err != nil {
		if err := convertContextCancelledErr(hlogger.TraceScopedLoggerFromCtx(s.logger, ctx), err); err != nil {
			return false, err
		}
		return false, errors.Wrap(err, "failed to check permission in SpiceDB")
	} else {
		return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
	}
}

func (s *spicedb) CheckBulkPermissions(ctx context.Context, checks []*v1.CheckBulkPermissionsRequestItem) ([]*v1.CheckBulkPermissionsPair, error) {
	if resp, err := s.client.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{Items: checks}); err != nil {
		if err := convertContextCancelledErr(hlogger.TraceScopedLoggerFromCtx(s.logger, ctx), err); err != nil {
			return nil, err
		}
		return nil, errors.Wrap(err, "failed to check bulk permissions in SpiceDB")
	} else {
		return resp.Pairs, nil
	}
}

func (s *spicedb) LookupSubjects(ctx context.Context, resource ObjectType, resourceId string, permission string, cursor string, zedToken string) ([]*v1.ResolvedSubject, string, error) {
	req := &v1.LookupSubjectsRequest{
		Resource: &v1.ObjectReference{
			ObjectType: resource.String(),
			ObjectId:   resourceId,
		},
		Permission:        permission,
		SubjectObjectType: ObjectTypeUser.String(),
		Consistency:       calculateConsistency(zedToken),
	}
	if cursor != "" {
		req.OptionalCursor = &v1.Cursor{Token: cursor}
	}

	stream, err := s.client.LookupSubjects(ctx, req)
	if err != nil {
		if err := convertContextCancelledErr(hlogger.TraceScopedLoggerFromCtx(s.logger, ctx), err); err != nil {
			return nil, "", err
		}
		if isInvalidCursorErr(err) {
			return nil, "", ErrInvalidCursor
		}
		return nil, "", errors.Wrap(err, "failed to lookup subjects in SpiceDB")
	}

	var subjects []*v1.ResolvedSubject
	var nextCursor string

	for {
		resp, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			if err := convertContextCancelledErr(hlogger.TraceScopedLoggerFromCtx(s.logger, ctx), err); err != nil {
				return nil, "", err
			}
			if isInvalidCursorErr(err) {
				return nil, "", ErrInvalidCursor
			}
			return nil, "", errors.Wrap(err, "failed to receive subject from stream")
		}

		if resp.Subject != nil {
			subjects = append(subjects, resp.Subject)
		}

		if resp.AfterResultCursor != nil {
			nextCursor = resp.AfterResultCursor.Token
		}
	}

	return subjects, nextCursor, nil
}
