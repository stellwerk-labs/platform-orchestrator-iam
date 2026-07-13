package identity

import (
	"context"

	"go.uber.org/zap"
)

type Provider interface {
	IdentifyUser(ctx context.Context, logger *zap.Logger, token string) (IdentifiedUser, bool, error)
}

type IdentifiedUser struct {
	// ProviderId is the identifier this identity provider uses to uniquely identify the user. This might be an
	// account name, email address, or user id.
	ProviderId string

	// DisplayName is an initial attribute for the display name of the user if the identity provider can provide one.
	DisplayName *string

	// PrimaryEmailAddress returns the primary email address if available for this user
	PrimaryEmailAddress *string
}
