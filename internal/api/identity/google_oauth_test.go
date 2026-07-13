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

func TestGoogleOauth(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pk := k.Public().(*rsa.PublicKey)
	bigE := big.NewInt(int64(pk.E))
	prov := NewGoogleProvider(&http.Client{
		Transport: jsonMapTransport{
			"/.well-known/openid-configuration": map[string]interface{}{
				"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
			},
			"/oauth2/v3/certs": map[string]interface{}{
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

	t.Run("valid token", func(t *testing.T) {
		unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, googleIdTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "my-user-id",
				Issuer:    "accounts.google.com",
				Audience:  []string{"aud-1"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Name:  "bob.smith",
			Email: "bob.smith@example.com",
		})
		unsigned.Header["kid"] = "1"
		signed, err := unsigned.SignedString(k)
		require.NoError(t, err)

		iu, ok, err := prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		require.NoError(t, err)
		assert.True(t, ok)

		assert.Equal(t, "my-user-id", iu.ProviderId)
		assert.Equal(t, "bob.smith", *iu.DisplayName)
		assert.Equal(t, "bob.smith@example.com", *iu.PrimaryEmailAddress)
	})

	t.Run("expired", func(t *testing.T) {
		unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, googleIdTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "my-user-id",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		})
		unsigned.Header["kid"] = "1"
		signed, err := unsigned.SignedString(k)
		require.NoError(t, err)
		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "failed to parse id token: token has invalid claims: token is expired")
	})

	t.Run("invalid issuer", func(t *testing.T) {
		unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, googleIdTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "my-user-id",
				Issuer:    "unknown",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		unsigned.Header["kid"] = "1"
		signed, err := unsigned.SignedString(k)
		require.NoError(t, err)
		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token has an invalid issuer: unknown")
	})

	t.Run("invalid audience", func(t *testing.T) {
		unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, googleIdTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "my-user-id",
				Issuer:    "accounts.google.com",
				Audience:  []string{"unknown"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		unsigned.Header["kid"] = "1"
		signed, err := unsigned.SignedString(k)
		require.NoError(t, err)
		_, _, err = prov.IdentifyUser(t.Context(), zaptest.NewLogger(t), signed)
		assert.EqualError(t, err, "token is missing an allowed audience claim: [unknown]")
	})
}
