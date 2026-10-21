package workloadidentity

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity/workloadidentitytest"
)

func TestFileKeySourceReloadsTheStaticJWKSForAnUnknownKeyID(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, issuer.JWKS(t), 0o600))
	clock := newTestClock()
	source, err := NewKeySource(KeySourceConfig{File: path, URL: "https://ignored.example.test/jwks"})
	require.NoError(t, err)
	verifier := NewVerifier(issuer.URL, NewKeySet(source, zaptest.NewLogger(t), clock.Now), clock.Now)
	verify := func(keyID string) error {
		claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
		_, err := verifier.Verify(t.Context(), issuer.Sign(t, keyID, claims))
		return err
	}
	require.NoError(t, verify(workloadidentitytest.DefaultKeyID))

	issuer.AddKey(t, "ec-2", workloadidentitytest.ECDSA)
	require.NoError(t, os.WriteFile(path, issuer.JWKS(t), 0o600))
	require.ErrorIs(t, verify("ec-2"), ErrInvalidSubjectToken)
	clock.Advance(keyRefreshInterval)
	require.NoError(t, verify("ec-2"))
	require.Zero(t, issuer.Fetches(), "the static source never contacts the issuer")
}

func TestKeySetRejectsAJWKSWithoutPublicSigningKeys(t *testing.T) {
	for name, jwks := range map[string]string{
		"empty":      `{"keys":[]}`,
		"encryption": `{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
		"malformed":  `{"keys":`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "jwks.json")
			require.NoError(t, os.WriteFile(path, []byte(jwks), 0o600))
			keys := NewKeySet(FileKeySource(path), zaptest.NewLogger(t), newTestClock().Now)
			require.ErrorIs(t, keys.Ready(t.Context()), ErrKeysUnavailable)
		})
	}
}

func TestNewKeySourceRequiresAFileOrURL(t *testing.T) {
	_, err := NewKeySource(KeySourceConfig{})
	require.Error(t, err)
	_, err = NewKeySource(KeySourceConfig{URL: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: filepath.Join(t.TempDir(), "missing.crt")})
	require.Error(t, err)
}

func TestInClusterClientTrustsTheClusterCAAndSendsTheCurrentServiceAccountToken(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	var mu sync.Mutex
	var authorizations []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		mu.Unlock()
		response.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = response.Write(issuer.JWKS(t))
	}))
	t.Cleanup(server.Close)

	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	tokenFile := filepath.Join(directory, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("first-token\n"), 0o600))

	source, err := NewKeySource(KeySourceConfig{URL: server.URL + "/openid/v1/jwks", CAFile: caFile, BearerTokenFile: tokenFile})
	require.NoError(t, err)
	_, err = source(t.Context())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tokenFile, []byte("rotated-token"), 0o600))
	_, err = source(t.Context())
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, []string{"Bearer first-token", "Bearer rotated-token"}, authorizations)
	mu.Unlock()

	untrusted, err := NewKeySource(KeySourceConfig{URL: server.URL + "/openid/v1/jwks"})
	require.NoError(t, err)
	_, err = untrusted(t.Context())
	require.Error(t, err, "the system roots must not trust the cluster CA")

	require.NoError(t, os.Remove(tokenFile))
	_, err = source(t.Context())
	require.Error(t, err, "a missing ServiceAccount token must fail the fetch")
}

func TestHTTPKeySourceRejectsNonOKResponsesAndOversizedKeySets(t *testing.T) {
	oversized := make([]byte, maxJWKSBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/large" {
			_, _ = response.Write(oversized)
			return
		}
		http.Error(response, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	_, err := HTTPKeySource(server.URL+"/forbidden", http.DefaultClient)(t.Context())
	require.ErrorContains(t, err, "403")
	_, err = HTTPKeySource(server.URL+"/large", http.DefaultClient)(t.Context())
	require.ErrorContains(t, err, "1 MiB")
}
