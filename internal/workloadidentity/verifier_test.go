package workloadidentity

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/workloadidentity/workloadidentitytest"
)

const (
	testNamespace      = "plugins"
	testServiceAccount = "rollouts-runtime"
	testAudience       = "stellwerk-iam-plugin-workload"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Now().UTC().Truncate(time.Second)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func newTestVerifier(t *testing.T, issuer *workloadidentitytest.Issuer, clock *testClock) *Verifier {
	t.Helper()
	keys := NewKeySet(HTTPKeySource(issuer.JWKSURL, http.DefaultClient), zaptest.NewLogger(t), clock.Now)
	return NewVerifier(issuer.URL, keys, clock.Now)
}

func TestVerifierAcceptsProjectedServiceAccountTokens(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	issuer.AddKey(t, "ec-1", workloadidentitytest.ECDSA)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)

	for _, keyID := range []string{workloadidentitytest.DefaultKeyID, "ec-1"} {
		t.Run(keyID, func(t *testing.T) {
			claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
			verified, err := verifier.Verify(t.Context(), issuer.Sign(t, keyID, claims))
			require.NoError(t, err)
			require.Equal(t, Claims{
				Issuer:         issuer.URL,
				Namespace:      testNamespace,
				ServiceAccount: testServiceAccount,
				Audience:       []string{testAudience},
				Expiry:         claims.Expiry,
			}, normalizeExpiry(verified))
		})
	}
	require.Equal(t, int64(1), issuer.Fetches(), "both keys come from one cached JWKS")
}

func TestVerifierRejectsTokensItMustNotExchange(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	foreign := workloadidentitytest.NewIssuer(t)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	now := clock.Now()
	valid := func(mutate func(*workloadidentitytest.Claims)) workloadidentitytest.Claims {
		claims := issuer.ValidClaims(now, testNamespace, testServiceAccount, testAudience)
		mutate(&claims)
		return claims
	}
	tokens := map[string]string{
		"wrong issuer": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Issuer = "https://other-cluster.example.test"
		})),
		"expired": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Expiry = now.Add(-time.Second)
		})),
		"without expiry": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Expiry = time.Time{}
		})),
		"not yet valid beyond clock skew": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.NotBefore = now.Add(6 * time.Minute)
			c.Expiry = now.Add(16 * time.Minute)
		})),
		"node subject": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Subject = "system:node:worker-1"
		})),
		"plural serviceaccounts subject": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Subject = "system:serviceaccounts:" + testNamespace + ":" + testServiceAccount
		})),
		"subject with extra segment": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Subject += ":extra"
		})),
		"kubernetes namespace mismatch": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.Namespace = "other"
		})),
		"kubernetes serviceaccount mismatch": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.ServiceAccount = "other"
		})),
		"without kubernetes claims": issuer.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(c *workloadidentitytest.Claims) {
			c.OmitKubernetes = true
		})),
		"signed by a foreign key with a trusted key id": foreign.Sign(t, workloadidentitytest.DefaultKeyID, valid(func(*workloadidentitytest.Claims) {})),
		"unsigned":       unsignedToken(t, valid(func(*workloadidentitytest.Claims) {})),
		"hmac with jwks": hmacToken(t, issuer.JWKS(t), valid(func(*workloadidentitytest.Claims) {})),
		"garbage":        "not-a-jwt",
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			_, err := verifier.Verify(t.Context(), token)
			require.ErrorIs(t, err, ErrInvalidSubjectToken)
		})
	}
}

func TestVerifierAcceptsNotBeforeWithinClockSkew(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
	claims.NotBefore = clock.Now().Add(4 * time.Minute)

	_, err := verifier.Verify(t.Context(), issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims))
	require.NoError(t, err)
}

func TestVerifierRefreshesKeysForAnUnknownKeyIDAtMostOncePerInterval(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	verify := func(keyID string) error {
		claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
		_, err := verifier.Verify(t.Context(), issuer.Sign(t, keyID, claims))
		return err
	}
	require.NoError(t, verify(workloadidentitytest.DefaultKeyID))
	require.Equal(t, int64(1), issuer.Fetches())

	issuer.AddKey(t, "rsa-2", workloadidentitytest.RSA)
	for range 5 {
		require.ErrorIs(t, verify("rsa-2"), ErrInvalidSubjectToken)
	}
	require.Equal(t, int64(1), issuer.Fetches(), "unknown key IDs must not trigger a JWKS fetch per request")

	clock.Advance(keyRefreshInterval)
	require.NoError(t, verify("rsa-2"))
	require.Equal(t, int64(2), issuer.Fetches())
	require.NoError(t, verify(workloadidentitytest.DefaultKeyID))
	require.Equal(t, int64(2), issuer.Fetches(), "known key IDs use the cache")
}

func TestVerifierStopsTrustingKeysTheIssuerRemoved(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	issuer.AddKey(t, "rsa-2", workloadidentitytest.RSA)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	verify := func(keyID string) error {
		claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
		_, err := verifier.Verify(t.Context(), issuer.Sign(t, keyID, claims))
		return err
	}
	require.NoError(t, verify(workloadidentitytest.DefaultKeyID))

	issuer.Unpublish(workloadidentitytest.DefaultKeyID)
	clock.Advance(keyMaxAge)
	require.ErrorIs(t, verify(workloadidentitytest.DefaultKeyID), ErrInvalidSubjectToken)
	require.NoError(t, verify("rsa-2"))
}

func TestVerifierKeepsCachedKeysWhileTheIssuerIsUnreachable(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	verify := func() error {
		claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
		_, err := verifier.Verify(t.Context(), issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims))
		return err
	}
	require.NoError(t, verify())

	issuer.SetJWKSStatus(http.StatusServiceUnavailable)
	clock.Advance(keyMaxAge)
	require.NoError(t, verify())
	require.Equal(t, int64(2), issuer.Fetches())
}

func TestVerifierReportsUnavailableKeysWithoutRetryingEveryRequest(t *testing.T) {
	issuer := workloadidentitytest.NewIssuer(t)
	issuer.SetJWKSStatus(http.StatusServiceUnavailable)
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock)
	verify := func() error {
		claims := issuer.ValidClaims(clock.Now(), testNamespace, testServiceAccount, testAudience)
		_, err := verifier.Verify(t.Context(), issuer.Sign(t, workloadidentitytest.DefaultKeyID, claims))
		return err
	}

	require.ErrorIs(t, verify(), ErrKeysUnavailable)
	require.ErrorIs(t, verify(), ErrKeysUnavailable)
	require.Equal(t, int64(1), issuer.Fetches())

	issuer.SetJWKSStatus(http.StatusOK)
	clock.Advance(keyRefreshInterval)
	require.NoError(t, verify())
	require.Equal(t, int64(2), issuer.Fetches())
}

func normalizeExpiry(claims Claims) Claims {
	claims.Expiry = claims.Expiry.UTC()
	return claims
}

func unsignedToken(t *testing.T, claims workloadidentitytest.Claims) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"rsa-1"}`))
	payload, err := json.Marshal(map[string]any{
		"iss": claims.Issuer, "sub": claims.Subject, "aud": claims.Audience, "exp": claims.Expiry.Unix(),
		"kubernetes.io": map[string]any{"namespace": claims.Namespace, "serviceaccount": map[string]any{"name": claims.ServiceAccount}},
	})
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// hmacToken signs with HS256 using the public JWKS as secret, the classic
// algorithm-confusion attack against verifiers that trust the token's alg.
func hmacToken(t *testing.T, secret []byte, claims workloadidentitytest.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jose.JSONWebKey{Key: secret, KeyID: workloadidentitytest.DefaultKeyID}}, nil)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience), Expiry: jwt.NewNumericDate(claims.Expiry),
	}).Claims(map[string]any{"kubernetes.io": map[string]any{
		"namespace": claims.Namespace, "serviceaccount": map[string]any{"name": claims.ServiceAccount},
	}}).Serialize()
	require.NoError(t, err)
	require.Len(t, strings.Split(token, "."), 3)
	return token
}
