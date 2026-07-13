package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"

	"github.com/pkg/errors"
)

const rsaKeyType = "RSA"

func getJwksUriFromOpenIdConfig(ctx context.Context, c *http.Client, url string) (string, error) {
	var openIdConfig struct {
		JwksUri string `json:"jwks_uri"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create openid config request")
	}
	r, err := c.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to get openid config")
	} else if r.StatusCode != http.StatusOK {
		return "", errors.Errorf("failed to get openid config: %d", r.StatusCode)
	}
	defer func() {
		_ = r.Body.Close()
	}()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read openid config")
	}
	if err := json.Unmarshal(raw, &openIdConfig); err != nil {
		return "", errors.Wrap(err, "failed to decode openid config "+string(raw))
	} else if openIdConfig.JwksUri == "" {
		return "", errors.New("failed to get jwks uri - empty")
	}
	return openIdConfig.JwksUri, nil
}

// oauthJwksKey represents a JSON Web Key (JWK) object
// as specified in the JWK standard (RFC 7517).
type oauthJwksKey struct {
	KeyId   string `json:"kid"` // Key ID is a unique identifier for the key.
	KeyType string `json:"kty"` // Key type (e.g., RSA, EC) defines the algorithm family used by the key.
	Alg     string `json:"alg"` // Algorithm specifies the cryptographic algorithm used with the key (e.g., RS256).
	Use     string `json:"use"` // Use indicates the intended use for the key (e.g., "sig" for signing, "enc" for encryption).
	N       string `json:"n"`   // Modulus is the base64url-encoded modulus value of the RSA public key.
	E       string `json:"e"`   // Exponent is the base64url-encoded public exponent of the RSA key.
}

func (k oauthJwksKey) ToPublicKey() (crypto.PublicKey, error) {
	if k.KeyType != rsaKeyType {
		return nil, errors.Errorf("unsupported key type: %s", k.KeyType)
	}
	var rsaKey rsa.PublicKey
	if raw, err := base64.RawURLEncoding.DecodeString(k.N); err != nil {
		return nil, errors.Wrap(err, "failed to decode modulus")
	} else {
		var bi big.Int
		bi.SetBytes(raw)
		rsaKey.N = &bi
	}
	if raw, err := base64.RawURLEncoding.DecodeString(k.E); err != nil {
		return nil, errors.Wrap(err, "failed to decode exponent")
	} else {
		var bi big.Int
		bi.SetBytes(raw)
		rsaKey.E = int(bi.Int64())
	}
	return &rsaKey, nil
}

func getRawJwksKeys(ctx context.Context, c *http.Client, url string) (map[string]crypto.PublicKey, error) {
	var resp struct {
		Keys []oauthJwksKey `json:"keys"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create openid config request")
	}
	r, err := c.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get jwks keys")
	} else if r.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to get jwks keys: %d", r.StatusCode)
	}

	defer func() {
		_ = r.Body.Close()
	}()

	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return nil, errors.Wrap(err, "failed to decode jwks keys")
	}
	out := make(map[string]crypto.PublicKey, len(resp.Keys))
	for _, key := range resp.Keys {
		if out[key.KeyId], err = key.ToPublicKey(); err != nil {
			return nil, errors.Wrapf(err, "failed to convert jwks key '%s' to public key", key.KeyId)
		}
	}
	return out, nil
}
