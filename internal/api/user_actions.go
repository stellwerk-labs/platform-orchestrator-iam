package api

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

func (s *Server) DismissPrompt(ctx context.Context, request DismissPromptRequestObject) (DismissPromptResponseObject, error) {
	userId, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if !userid.IsHumanUser(userId) {
		return nil, echo.NewHTTPError(http.StatusForbidden)
	} else if err := s.checkUserIdSelfAuthorization(ctx, userId, request.UserId); err != nil {
		return nil, err
	}

	if request.Params.Id == "" {
		return DismissPrompt400JSONResponse{
			N400BadRequestJSONResponse: N400BadRequestJSONResponse{
				Message: "Prompt ID is required",
			},
		}, nil
	}

	if err := s.Database.DismissUserPrompt(ctx, nil, request.UserId, request.Params.Id); err != nil {
		return nil, err
	}

	return DismissPrompt204Response{}, nil
}
