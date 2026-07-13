package identity

import (
	"context"
	"crypto/rsa"
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
)

const googleIssuerHost = "accounts.google.com"

// GoogleOauthProvider uses Google Oauth to get the identity of the user using an ID token.
// See https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo. In this case, the frontend
// generally does most of the oauth dance until finally returning the ID token to our backend to setup the user.
// In V1 we used the Google identity debugging endpoint (token info) but in v2 we are doing this properly via jwks.
type GoogleOauthProvider struct {
	client              *http.Client
	keyCache            map[string]*rsa.PublicKey
	allowedJwtAudiences []string
}

func NewGoogleProvider(c *http.Client, allowedJwtAudiences []string) *GoogleOauthProvider {
	return &GoogleOauthProvider{client: c, allowedJwtAudiences: allowedJwtAudiences}
}

type googleIdTokenClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (g *googleIdTokenClaims) Valid() error {
	return nil
}

func (g *GoogleOauthProvider) refillKeyCache(ctx context.Context) error {
	const jwkUrl = "https://accounts.google.com/.well-known/openid-configuration"

	if u, err := getJwksUriFromOpenIdConfig(ctx, g.client, jwkUrl); err != nil {
		return errors.Wrap(err, "failed to get jwks uri from openid config")
	} else if keys, err := getRawJwksKeys(ctx, g.client, u); err != nil {
		return errors.Wrap(err, "failed to get raw jwks keys")
	} else {
		if g.keyCache == nil {
			g.keyCache = make(map[string]*rsa.PublicKey, len(keys))
		}
		for keyId, key := range keys {
			if rk, ok := key.(*rsa.PublicKey); ok {
				g.keyCache[keyId] = rk
			}
		}
		return nil
	}
}

func (g *GoogleOauthProvider) wrapKeyFunc(ctx context.Context, logger *zap.Logger) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		keyId := token.Header["kid"]
		if keyId == nil {
			return nil, errors.Errorf("jwt is missing a key id")
		}
		if _, ok := g.keyCache[keyId.(string)]; !ok {
			logger.Info("google oauth key cache is missing public key - fetching", zap.String("key_id", keyId.(string)))
			if err := g.refillKeyCache(ctx); err != nil {
				return nil, err
			}
			logger.Info("google oauth key cache refilled", zap.Int("num_keys", len(g.keyCache)))
		}
		key, ok := g.keyCache[keyId.(string)]
		if !ok {
			return nil, errors.Errorf("key not found in cache")
		}
		return key, nil
	}
}

func (g *GoogleOauthProvider) IdentifyUser(ctx context.Context, logger *zap.Logger, idToken string) (IdentifiedUser, bool, error) {
	var claims googleIdTokenClaims
	_, err := jwt.ParseWithClaims(idToken, &claims, g.wrapKeyFunc(ctx, logger))
	if err != nil {
		return IdentifiedUser{}, false, errors.Wrap(err, "failed to parse id token")
	}
	// as specified in https://developers.google.com/identity/gsi/web/guides/verify-google-id-token, it's important
	// to verify that these are valid to ensure we don't allow tokens from the wrong sources.

	if claims.ExpiresAt == nil {
		return IdentifiedUser{}, false, errors.Errorf("token is missing expiration claim")
	} else if claims.Issuer != googleIssuerHost && claims.Issuer != "https://"+googleIssuerHost {
		return IdentifiedUser{}, false, errors.Errorf("token has an invalid issuer: %s", claims.Issuer)
	} else if len(claims.Audience) == 0 {
		return IdentifiedUser{}, false, errors.Errorf("token is missing audience claim")
	} else if slices.IndexFunc(claims.Audience, func(a string) bool {
		return a != "" && slices.Contains(g.allowedJwtAudiences, a)
	}) < 0 {
		return IdentifiedUser{}, false, errors.Errorf("token is missing an allowed audience claim: %v", claims.Audience)
	}

	iu := IdentifiedUser{
		ProviderId:          claims.Subject,
		DisplayName:         opt.OfNonZero(claims.Name).Ref(),
		PrimaryEmailAddress: opt.OfNonZero(claims.Email).Ref(),
	}

	if iu.DisplayName == nil && iu.PrimaryEmailAddress != nil {
		iu.DisplayName = opt.Of(strings.Split(*iu.PrimaryEmailAddress, "@")[0]).Ref()
	}

	return iu, true, nil
}

var _ Provider = (*GoogleOauthProvider)(nil)
