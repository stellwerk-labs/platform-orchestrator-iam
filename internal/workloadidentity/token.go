// Package workloadidentity implements the v1alpha plugin workload token
// exchange. A projected Kubernetes ServiceAccount token is verified against the
// configured cluster issuer and exchanged for a short-lived opaque IAM token
// that authenticates as the service user of the matching workload binding.
//
//	plugin Pod --projected SA JWT--> IAM exchange: issuer, JWKS, aud, exp, nbf, sub, binding
//	plugin Pod <--PWT- token------- IAM stores only its hash, expiry and binding
//	plugin Pod --Bearer PWT-...---> gateway ext-auth --> IAM authenticate --> From: service user
package workloadidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix marks issued plugin workload tokens on the wire.
	TokenPrefix = "PWT-"
	// MaxTokenLifetime bounds every issued plugin workload token.
	MaxTokenLifetime = 15 * time.Minute

	tokenEntropyBytes = 33
)

var (
	// ErrInvalidSubjectToken is returned for every subject token IAM refuses to exchange.
	ErrInvalidSubjectToken = errors.New("invalid subject token")
	// ErrKeysUnavailable is returned while no verification key of the issuer can be loaded.
	ErrKeysUnavailable = errors.New("workload token verification keys are unavailable")
)

// NewToken returns a fresh opaque token and its SHA-256 hash, the only form IAM stores.
func NewToken() (string, []byte) {
	raw := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	hash := sha256.Sum256(raw)
	return TokenPrefix + base64.URLEncoding.EncodeToString(raw), hash[:]
}

// HashToken returns the stored hash of a well-formed plugin workload token.
func HashToken(token string) ([]byte, bool) {
	encoded, found := strings.CutPrefix(token, TokenPrefix)
	if !found {
		return nil, false
	}
	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != tokenEntropyBytes {
		return nil, false
	}
	hash := sha256.Sum256(raw)
	return hash[:], true
}

// IssuedLifetime returns the whole-second lifetime of a token issued at now: the
// configured TTL, capped by MaxTokenLifetime and by the subject token's expiry,
// so an exchanged token never outlives the credential that justified it.
func IssuedLifetime(now time.Time, ttl time.Duration, subjectExpiry time.Time) (time.Duration, error) {
	lifetime := min(ttl, MaxTokenLifetime, subjectExpiry.Sub(now)).Truncate(time.Second)
	if lifetime < time.Second {
		return 0, fmt.Errorf("%w: subject token expires too soon", ErrInvalidSubjectToken)
	}
	return lifetime, nil
}
