package identity

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

type MicrosoftOauthProvider struct {
	client              *http.Client
	keyCache            map[string]*rsa.PublicKey
	allowedJwtAudiences []string
}

// MicrosoftOauthProvider uses Microsoft Entra ID OAuth to get the identity of the user using an ID token.
// See https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens. In this case, the frontend
// generally does most of the oauth dance until finally returning the ID token to our backend to setup the user.
// We verify the token using Microsoft's JWKS endpoint.
type microsoftIdTokenClaims struct {
	jwt.RegisteredClaims

	// unique identifier for user
	// https://docs.azure.cn/en-us/entra/identity-platform/id-token-claims-reference#use-claims-to-reliably-identify-a-user
	// oid: unique ID for a user in a given tenant and across applications
	// it is a bit unclear from docs, if it is unique across tenants or should be combined with tid to ensure identifier uniqueness (ids are not reused across different tenants for different users) so adding tenant id to be safe
	UserIdentifier string `json:"oid"`
	UserTenantId   string `json:"tid"`

	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"preferred_username"`
}

func (m *microsoftIdTokenClaims) Valid() error {
	return nil
}

func NewMicrosoftProvider(c *http.Client, allowedJwtAudiences []string) *MicrosoftOauthProvider {
	return &MicrosoftOauthProvider{
		client:              c,
		allowedJwtAudiences: allowedJwtAudiences,
	}
}

const (
	// Base URL for Microsoft authentication endpoints
	MicrosoftBaseURL = "https://login.microsoftonline.com"

	// OpenID configuration path for multi-tenant authentication
	MicrosoftOpenIDConfigPath = "common/v2.0/.well-known/openid-configuration"

	// JWKS discovery path (expected to be returned by OpenID config)
	MicrosoftJWKSPath = "common/discovery/v2.0/keys"
)

func ConfigURL() string {
	u, _ := url.JoinPath(MicrosoftBaseURL, MicrosoftOpenIDConfigPath)
	return u
}

func JWKsUrl() string {
	u, _ := url.JoinPath(MicrosoftBaseURL, MicrosoftJWKSPath)
	return u
}

func (m *MicrosoftOauthProvider) refillKeyCache(ctx context.Context) error {
	// Get the current JWKS endpoint URL from OpenID configuration
	u, err := getJwksUriFromOpenIdConfig(ctx, m.client, ConfigURL())
	if err != nil {
		return errors.Wrap(err, "failed to get jwks uri from openid config")
	}

	// Fetch the raw key data from Microsoft's JWKS endpoint
	keys, err := getRawJwksKeys(ctx, m.client, u)
	if err != nil {
		return errors.Wrap(err, "failed to get raw jwks keys")
	}

	// Initialize cache if needed and populate with RSA keys
	if m.keyCache == nil {
		m.keyCache = make(map[string]*rsa.PublicKey, len(keys))
	}

	// Extract and cache only valid RSA public keys
	for keyId, key := range keys {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			m.keyCache[keyId] = rsaKey
		}
	}

	return nil
}

func (m *MicrosoftOauthProvider) wrapKeyFunc(ctx context.Context, logger *zap.Logger) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyId := token.Header["kid"]
		if keyId == nil {
			return nil, errors.Errorf("jwt is missing a key id")
		}

		if _, ok := m.keyCache[keyId.(string)]; !ok {
			logger.Info("microsoft oauth key cache is missing public key - fetching", zap.String("key_id", keyId.(string)))
			if err := m.refillKeyCache(ctx); err != nil {
				return nil, err
			}
			logger.Info("microsoft oauth key cache refilled", zap.Int("num_keys", len(m.keyCache)))
		}

		key, ok := m.keyCache[keyId.(string)]
		if !ok {
			return nil, errors.Errorf("key not found in cache")
		}

		return key, nil
	}
}

func (m *MicrosoftOauthProvider) IdentifyUser(ctx context.Context, logger *zap.Logger, idToken string) (IdentifiedUser, bool, error) {
	var claims microsoftIdTokenClaims
	_, err := jwt.ParseWithClaims(idToken, &claims, m.wrapKeyFunc(ctx, logger))
	if err != nil {
		return IdentifiedUser{}, false, errors.Wrap(err, "failed to parse id token")
	}

	// Verify token claims
	// https://docs.azure.cn/en-us/entra/identity-platform/id-tokens#validate-tokens

	// Verify required timestamp claims are present (the library validates them if present)
	if claims.ExpiresAt == nil {
		return IdentifiedUser{}, false, errors.Errorf("token is missing expiration claim")
	}
	if claims.IssuedAt == nil {
		return IdentifiedUser{}, false, errors.Errorf("token is missing issued at claim")
	}
	if claims.NotBefore == nil {
		return IdentifiedUser{}, false, errors.Errorf("token is missing not before claim")
	}

	// Validate issued at time is not in the future
	if claims.IssuedAt.After(time.Now()) {
		return IdentifiedUser{}, false, errors.Errorf("token issued at time is in the future")
	}

	// Verify issuer
	if !strings.HasPrefix(claims.Issuer, "https://login.microsoftonline.com/") {
		return IdentifiedUser{}, false, errors.Errorf("token has an invalid issuer: %s", claims.Issuer)
	}
	if !strings.HasSuffix(claims.Issuer, "/v2.0") {
		return IdentifiedUser{}, false, errors.Errorf("token has an invalid issuer: %s", claims.Issuer)
	}

	// Verify audience (client ID)
	if len(claims.Audience) == 0 {
		return IdentifiedUser{}, false, errors.Errorf("token is missing audience claim")
	}
	hasValidAudience := slices.IndexFunc(claims.Audience, func(a string) bool {
		return a != "" && slices.Contains(m.allowedJwtAudiences, a)
	}) >= 0
	if !hasValidAudience {
		return IdentifiedUser{}, false, errors.Errorf("token is missing an allowed audience claim: %v", claims.Audience)
	}

	// Verify required user identifier (oid) is present
	if claims.UserIdentifier == "" {
		return IdentifiedUser{}, false, errors.Errorf("token is missing oid (user identifier) claim")
	}
	if claims.UserTenantId == "" {
		return IdentifiedUser{}, false, errors.Errorf("token is missing tid (user tenant id) claim")
	}

	iu := IdentifiedUser{
		// oid is unique and immutable for a user in a given tenant
		// sub is not the same across applications
		// https://docs.azure.cn/en-us/entra/identity-platform/id-token-claims-reference#use-claims-to-reliably-identify-a-user
		ProviderId: claims.UserIdentifier + ":" + claims.UserTenantId,

		// these are mutable and potentially missing
		DisplayName:         opt.OfNonZero(claims.Name).OrOpt(opt.OfNonZero(claims.Username)).Ref(),
		PrimaryEmailAddress: opt.OfNonZero(claims.Email).Ref(),
	}

	return iu, true, nil
}

var _ Provider = (*MicrosoftOauthProvider)(nil)
