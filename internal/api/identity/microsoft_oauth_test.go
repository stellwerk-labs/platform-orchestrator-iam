package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// Helper functions for test setup and JWT creation
func createTestJWT(t *testing.T, k *rsa.PrivateKey, claims microsoftIdTokenClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	signed, err := token.SignedString(k)
	require.NoError(t, err)
	return signed
}

func createClaims() microsoftIdTokenClaims {
	return microsoftIdTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "my-user-subject",
			Issuer:    "https://login.microsoftonline.com/common/v2.0",
			Audience:  []string{"aud-1"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		UserIdentifier: "00000000-0000-0000-66f3-3332eca7ea81",
		UserTenantId:   "12345678-1234-1234-1234-123456789012",
		Name:           "Bob Smith",
		Email:          "bob.smith@example.com",
	}
}

func TestMicrosoftOauth(t *testing.T) {
	// Generate a test RSA key for signing tokens
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Public key
	pk := k.Public().(*rsa.PublicKey)
	bigE := big.NewInt(int64(pk.E))

	// Provider with mocked JWKS
	prov := NewMicrosoftProvider(&http.Client{
		Transport: jsonMapTransport{
			"/" + MicrosoftOpenIDConfigPath: map[string]interface{}{
				"jwks_uri": JWKsUrl(),
			},
			"/" + MicrosoftJWKSPath: map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"e":   base64.RawURLEncoding.EncodeToString(bigE.Bytes()),
						"alg": "RS256",
						"use": "sig",
						"n":   base64.RawURLEncoding.EncodeToString(pk.N.Bytes()),
						"kty": "RSA",
						"kid": "1",
					},
				},
			},
		},
	}, []string{"aud-1"})

	t.Run("fallback to preferred_username when name is missing", func(t *testing.T) {
		claims := createClaims()
		claims.Name = ""
		claims.Username = "bobs"
		signed := createTestJWT(t, k, claims)

		iu, ok, err := prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		require.NoError(t, err)
		assert.True(t, ok)

		assert.Equal(t, "00000000-0000-0000-66f3-3332eca7ea81:12345678-1234-1234-1234-123456789012", iu.ProviderId)
		assert.Equal(t, "bobs", *iu.DisplayName)
		assert.Equal(t, "bob.smith@example.com", *iu.PrimaryEmailAddress)
	})

	t.Run("expired token", func(t *testing.T) {
		claims := createClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "failed to parse id token: token has invalid claims: token is expired")
	})

	t.Run("token not yet valid", func(t *testing.T) {
		claims := createClaims()
		claims.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "failed to parse id token: token has invalid claims: token is not valid yet")
	})

	t.Run("token issued in future", func(t *testing.T) {
		claims := createClaims()
		claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token issued at time is in the future")
	})

	t.Run("invalid issuer", func(t *testing.T) {
		claims := createClaims()
		claims.Issuer = "https://invalid.example.com"
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token has an invalid issuer: https://invalid.example.com")
	})

	t.Run("invalid audience", func(t *testing.T) {
		claims := createClaims()
		claims.Audience = []string{"unknown-audience"}
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token is missing an allowed audience claim: [unknown-audience]")
	})

	t.Run("missing tenant id", func(t *testing.T) {
		claims := createClaims()
		claims.UserTenantId = ""
		signed := createTestJWT(t, k, claims)

		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token is missing tid (user tenant id) claim")
	})

	t.Run("multi-tenant issuer validation", func(t *testing.T) {
		testCases := []struct {
			name       string
			issuer     string
			shouldPass bool
		}{
			{
				name:       "valid tenant specific issuer",
				issuer:     "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
				shouldPass: true,
			},
			{
				name:       "valid common tenant issuer",
				issuer:     "https://login.microsoftonline.com/common/v2.0",
				shouldPass: true,
			},
			{
				name:       "valid organizations issuer",
				issuer:     "https://login.microsoftonline.com/organizations/v2.0",
				shouldPass: true,
			},
			{
				name:       "invalid missing v2.0",
				issuer:     "https://login.microsoftonline.com/common",
				shouldPass: false,
			},
			{
				name:       "invalid wrong domain",
				issuer:     "https://login.example.com/common/v2.0",
				shouldPass: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				claims := createClaims()
				claims.Issuer = tc.issuer
				signed := createTestJWT(t, k, claims)

				_, ok, err := prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)

				if tc.shouldPass {
					require.NoError(t, err)
					assert.True(t, ok)
				} else {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "invalid issuer")
				}
			})
		}
	})
}
