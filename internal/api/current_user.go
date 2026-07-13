package api

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

func (s *Server) GetCurrentUser(ctx context.Context, request GetCurrentUserRequestObject) (GetCurrentUserResponseObject, error) {
	userId, herr := GetAuthenticatedUserIdOr401(ctx)
	if herr != nil {
		return nil, herr
	} else if !userid.IsHumanUser(userId) {
		return nil, echo.NewHTTPError(http.StatusForbidden)
	} else if err := s.checkUserIdSelfAuthorization(ctx, userId, userId); err != nil {
		return nil, err
	}

	user, err := s.Database.GetUser(ctx, nil, userId)
	if err != nil {
		return nil, err
	}

	userMemberships, err := s.Database.ListMemberships(ctx, nil, model.ListMembershipsParams{
		UserId: &userId,
	})
	if err != nil {
		return nil, err
	}

	uniqueOrgs := maps.Collect(func(yield func(CurrentUserOrgMembership, bool) bool) {
		for _, membership := range userMemberships {
			yield(CurrentUserOrgMembership{Id: membership.OrgId}, true)
		}
	})
	orgs := append([]CurrentUserOrgMembership{}, slices.SortedFunc(maps.Keys(uniqueOrgs), func(membership CurrentUserOrgMembership, membership2 CurrentUserOrgMembership) int {
		return strings.Compare(membership.Id, membership2.Id)
	})...)

	loginProviders := append([]string{}, slices.Sorted(func(yield func(string) bool) {
		for p := range user.UserIdentities {
			yield(string(p))
		}
	})...)

	return GetCurrentUser200JSONResponse{
		CreatedAt:               user.CreatedAt,
		DisplayName:             user.DisplayName,
		Id:                      user.Id,
		LastLoggedInAt:          user.LastLoggedInAt,
		LoginProviders:          loginProviders,
		OrganizationMemberships: orgs,
		PrimaryEmailAddress:     user.PrimaryEmailAddress.Ref(),
		DismissedPrompts:        user.DismissedPrompts,
	}, nil
}
