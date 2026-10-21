package workloadidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"
)

const (
	// keyRefreshInterval spaces reload attempts. The exchange endpoint is
	// unauthenticated, so arbitrary key IDs must not become API server traffic.
	keyRefreshInterval = 30 * time.Second
	// keyMaxAge bounds how long a key removed by the issuer stays trusted while
	// the issuer is reachable.
	keyMaxAge      = 10 * time.Minute
	keyLoadTimeout = 10 * time.Second
	maxJWKSBytes   = 1 << 20
)

var signingAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512}

// KeySource returns the raw JSON Web Key Set of the cluster issuer.
type KeySource func(ctx context.Context) ([]byte, error)

// KeySourceConfig selects where verification keys come from. A static File
// takes precedence over the URL.
type KeySourceConfig struct {
	File            string
	URL             string
	CAFile          string
	BearerTokenFile string
}

// NewKeySource returns the configured key source. The URL source trusts
// CAFile and authenticates with BearerTokenFile when they are set, which is
// how IAM reads the in-cluster JWKS with its own ServiceAccount.
func NewKeySource(config KeySourceConfig) (KeySource, error) {
	if config.File != "" {
		return FileKeySource(config.File), nil
	}
	if config.URL == "" {
		return nil, errors.New("a JWKS file or URL is required")
	}
	client, err := InClusterClient(config.CAFile, config.BearerTokenFile)
	if err != nil {
		return nil, err
	}
	return HTTPKeySource(config.URL, client), nil
}

// FileKeySource reads an operator-supplied JWKS file on every reload.
func FileKeySource(path string) KeySource {
	return func(context.Context) ([]byte, error) {
		file, err := os.Open(path) // #nosec G304 -- operator-configured JWKS path.
		if err != nil {
			return nil, fmt.Errorf("open JWKS file: %w", err)
		}
		defer func() { _ = file.Close() }()
		return readLimited(file)
	}
}

// HTTPKeySource fetches the JWKS from url.
func HTTPKeySource(url string, client *http.Client) KeySource {
	return func(ctx context.Context) ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create JWKS request: %w", err)
		}
		request.Header.Set("Accept", "application/jwk-set+json, application/json")
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch JWKS: unexpected status %s", response.Status)
		}
		return readLimited(response.Body)
	}
}

// InClusterClient trusts caFile when set and sends the current content of
// bearerTokenFile when set. The token file is re-read for every request
// because kubelet rotates projected ServiceAccount tokens.
func InClusterClient(caFile, bearerTokenFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		certificates, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured CA path.
		if err != nil {
			return nil, fmt.Errorf("read JWKS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certificates) {
			return nil, errors.New("JWKS CA file contains no PEM certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	var roundTripper http.RoundTripper = transport
	if bearerTokenFile != "" {
		roundTripper = bearerTokenTransport{tokenFile: bearerTokenFile, next: transport}
	}
	return &http.Client{Transport: roundTripper, Timeout: keyLoadTimeout}, nil
}

type bearerTokenTransport struct {
	tokenFile string
	next      http.RoundTripper
}

func (t bearerTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	token, err := os.ReadFile(t.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read JWKS bearer token file: %w", err)
	}
	authenticated := request.Clone(request.Context())
	authenticated.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return t.next.RoundTrip(authenticated)
}

func readLimited(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	if len(raw) > maxJWKSBytes {
		return nil, errors.New("JWKS exceeds 1 MiB")
	}
	return raw, nil
}

// KeySet caches the issuer's public signing keys and implements oidc.KeySet.
// A token with an unknown key ID or a cache older than keyMaxAge triggers a
// reload, at most once per keyRefreshInterval. A failed reload keeps the
// previous keys, so a briefly unreachable issuer does not stop the exchange.
type KeySet struct {
	source KeySource
	logger *zap.Logger
	now    func() time.Time

	mu          sync.Mutex
	keys        []jose.JSONWebKey
	loadedAt    time.Time
	attemptedAt time.Time
}

func NewKeySet(source KeySource, logger *zap.Logger, now func() time.Time) *KeySet {
	return &KeySet{source: source, logger: logger, now: now}
}

// VerifySignature verifies a compact JWS and returns its payload.
func (k *KeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	signed, err := jose.ParseSignedCompact(token, signingAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return nil, errors.New("token must carry exactly one signature")
	}
	keyID := signed.Signatures[0].Header.KeyID
	keys, err := k.keysFor(ctx, keyID)
	if err != nil {
		return nil, err
	}
	for index := range keys {
		if keyID != "" && keys[index].KeyID != keyID {
			continue
		}
		if payload, err := signed.Verify(&keys[index]); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no trusted key verifies the token signature")
}

// Ready loads the keys when needed and returns ErrKeysUnavailable while none can be loaded.
func (k *KeySet) Ready(ctx context.Context) error {
	_, err := k.keysFor(ctx, "")
	return err
}

func (k *KeySet) keysFor(ctx context.Context, keyID string) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	stale := k.loadedAt.IsZero() || now.Sub(k.loadedAt) >= keyMaxAge
	unknown := keyID != "" && !slices.ContainsFunc(k.keys, func(key jose.JSONWebKey) bool { return key.KeyID == keyID })
	mayReload := k.attemptedAt.IsZero() || now.Sub(k.attemptedAt) >= keyRefreshInterval
	if (stale || unknown) && mayReload {
		k.attemptedAt = now
		// A cancelled exchange request must not waste the reload slot.
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyLoadTimeout)
		keys, err := k.load(loadCtx)
		cancel()
		if err != nil {
			k.logger.Error("failed to load plugin workload token verification keys", zap.Error(err))
		} else {
			k.keys, k.loadedAt = keys, now
		}
	}
	if len(k.keys) == 0 {
		return nil, ErrKeysUnavailable
	}
	return k.keys, nil
}

func (k *KeySet) load(ctx context.Context) ([]jose.JSONWebKey, error) {
	raw, err := k.source(ctx)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make([]jose.JSONWebKey, 0, len(set.Keys))
	for _, key := range set.Keys {
		if key.IsPublic() && key.Valid() && (key.Use == "" || key.Use == "sig") {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no public signing key")
	}
	return keys, nil
}
