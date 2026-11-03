package api

import (
	"context"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/adminapi"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

func (s *Server) InternalIsOrganizationAdmin(ctx context.Context, request adminapi.InternalIsOrganizationAdminRequestObject) (adminapi.InternalIsOrganizationAdminResponseObject, error) {
	allowed, err := model.IsOrganizationAdmin(ctx, s.Database, request.OrgId, request.UserId)
	if err != nil {
		return nil, err
	}
	return adminapi.InternalIsOrganizationAdmin200JSONResponse{Allowed: allowed}, nil
}
