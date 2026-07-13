//go:generate go tool mockgen  -destination mocks/ssoprovider_mock.go github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider Provider
package ssoprovider

import "context"

type Provider interface {
	GetAuthorizationURL(providerOrgId, state string) (string, error)
	GetUserProfile(ctx context.Context, authCode string) (*UserProfile, error)
	IsMultitenant() bool
}

type UserProfile struct {
	Email          string
	DisplayName    string
	ProviderOrgId  string
	ProviderUserId string
	Role           string
}
