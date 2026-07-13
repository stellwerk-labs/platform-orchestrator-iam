package ssoprovider

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/workos/workos-go/v6/pkg/sso"
	workoserrors "github.com/workos/workos-go/v6/pkg/workos_errors"
)

type WorkOs struct {
	callbackUrl string
}

func NewWorkOs(callbackUrl string) Provider {
	return &WorkOs{callbackUrl: callbackUrl}
}

func (w *WorkOs) GetAuthorizationURL(providerOrgId, state string) (string, error) {
	if rawAuthUrl, err := sso.GetAuthorizationURL(sso.GetAuthorizationURLOpts{
		Organization: providerOrgId,
		RedirectURI:  w.callbackUrl,
		State:        state,
	}); err != nil {
		return "", err
	} else {
		authUrl, err := url.QueryUnescape(rawAuthUrl.String())
		if err != nil {
			return "", err
		}
		return authUrl, nil
	}
}

func (w *WorkOs) GetUserProfile(ctx context.Context, authCode string) (*UserProfile, error) {
	profile, err := sso.GetProfileAndToken(ctx, sso.GetProfileAndTokenOpts{
		Code: authCode,
	})
	if err != nil {
		var wErr workoserrors.HTTPError
		if errors.As(err, &wErr) && wErr.Code == http.StatusBadRequest {
			return nil, ErrBadRequest{Message: wErr.Message}
		}
		return nil, err
	}
	// Custom org roles have a prefix in WorkOS
	// https://workos.com/docs/authkit/roles-and-permissions/organization-roles/creating-organization-roles
	role := strings.TrimPrefix(profile.Profile.Role.Slug, "org-")
	return &UserProfile{
		ProviderUserId: profile.Profile.ID,
		ProviderOrgId:  profile.Profile.OrganizationID,
		Email:          profile.Profile.Email,
		DisplayName:    profile.Profile.FirstName + " " + profile.Profile.LastName,
		Role:           role,
	}, nil
}

func (w *WorkOs) IsMultitenant() bool {
	return true
}
