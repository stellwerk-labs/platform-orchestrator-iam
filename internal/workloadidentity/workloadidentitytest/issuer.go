// Package workloadidentitytest runs a real in-process Kubernetes-style
// ServiceAccount token issuer for tests: generated keys, a JWKS served over
// HTTP and genuinely signed tokens. Nothing is stubbed.
package workloadidentitytest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// KeyType selects the signing algorithm family of a generated key.
type KeyType int

const (
	RSA KeyType = iota
	ECDSA
)

// DefaultKeyID names the RSA key every new issuer starts with.
const DefaultKeyID = "rsa-1"

// Issuer serves a JWKS and signs ServiceAccount tokens.
type Issuer struct {
	// URL is the issuer identifier and the base URL of the JWKS server.
	URL string
	// JWKSURL serves the published public keys.
	JWKSURL string

	server  *httptest.Server
	fetches atomic.Int64

	mu        sync.Mutex
	private   map[string]signingKey
	published []string
	status    int
}

type signingKey struct {
	algorithm jose.SignatureAlgorithm
	key       crypto.Signer
}

// Claims describe one token. Zero times are omitted from the token.
type Claims struct {
	Issuer         string
	Subject        string
	Audience       []string
	Expiry         time.Time
	NotBefore      time.Time
	IssuedAt       time.Time
	Namespace      string
	ServiceAccount string
	OmitKubernetes bool
}

func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	issuer := &Issuer{private: map[string]signingKey{}, status: http.StatusOK}
	issuer.server = httptest.NewServer(http.HandlerFunc(issuer.serveJWKS))
	t.Cleanup(issuer.server.Close)
	issuer.URL = issuer.server.URL
	issuer.JWKSURL = issuer.server.URL + "/openid/v1/jwks"
	issuer.AddKey(t, DefaultKeyID, RSA)
	return issuer
}

// AddKey generates and publishes a signing key.
func (i *Issuer) AddKey(t testing.TB, keyID string, keyType KeyType) {
	t.Helper()
	var key signingKey
	switch keyType {
	case RSA:
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key = signingKey{algorithm: jose.RS256, key: private}
	case ECDSA:
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = signingKey{algorithm: jose.ES256, key: private}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.private[keyID] = key
	i.published = append(i.published, keyID)
}

// Unpublish removes a key from the JWKS while it can still sign tokens.
func (i *Issuer) Unpublish(keyID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for index, published := range i.published {
		if published == keyID {
			i.published = append(i.published[:index], i.published[index+1:]...)
			return
		}
	}
}

// SetJWKSStatus makes the JWKS endpoint answer with status, for outage tests.
func (i *Issuer) SetJWKSStatus(status int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status = status
}

// Fetches counts JWKS requests.
func (i *Issuer) Fetches() int64 {
	return i.fetches.Load()
}

// JWKS returns the currently published key set.
func (i *Issuer) JWKS(t testing.TB) []byte {
	t.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	raw, err := i.jwksLocked()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ValidClaims returns the claims of a well-formed projected token valid for ten minutes from now.
func (i *Issuer) ValidClaims(now time.Time, namespace, serviceAccount, audience string) Claims {
	return Claims{
		Issuer:         i.URL,
		Subject:        fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount),
		Audience:       []string{audience},
		Expiry:         now.Add(10 * time.Minute),
		NotBefore:      now,
		IssuedAt:       now,
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
	}
}

// Sign signs claims with the key named keyID, published or not.
func (i *Issuer) Sign(t testing.TB, keyID string, claims Claims) string {
	t.Helper()
	i.mu.Lock()
	key, found := i.private[keyID]
	i.mu.Unlock()
	if !found {
		t.Fatalf("unknown signing key %q", keyID)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.algorithm, Key: jose.JSONWebKey{Key: key.key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	registered := jwt.Claims{Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience)}
	if !claims.Expiry.IsZero() {
		registered.Expiry = jwt.NewNumericDate(claims.Expiry)
	}
	if !claims.NotBefore.IsZero() {
		registered.NotBefore = jwt.NewNumericDate(claims.NotBefore)
	}
	if !claims.IssuedAt.IsZero() {
		registered.IssuedAt = jwt.NewNumericDate(claims.IssuedAt)
	}
	builder := jwt.Signed(signer).Claims(registered)
	if !claims.OmitKubernetes {
		builder = builder.Claims(map[string]any{"kubernetes.io": map[string]any{
			"namespace":      claims.Namespace,
			"serviceaccount": map[string]any{"name": claims.ServiceAccount, "uid": "00000000-0000-4000-8000-000000000001"},
			"pod":            map[string]any{"name": claims.ServiceAccount + "-0", "uid": "00000000-0000-4000-8000-000000000002"},
		}})
	}
	token, err := builder.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (i *Issuer) serveJWKS(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/openid/v1/jwks" {
		http.NotFound(response, request)
		return
	}
	i.fetches.Add(1)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.status != http.StatusOK {
		http.Error(response, http.StatusText(i.status), i.status)
		return
	}
	raw, err := i.jwksLocked()
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = response.Write(raw)
}

func (i *Issuer) jwksLocked() ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(i.published))}
	for _, keyID := range i.published {
		key := i.private[keyID]
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: key.key.Public(), KeyID: keyID, Algorithm: string(key.algorithm), Use: "sig"})
	}
	return json.Marshal(set)
}
