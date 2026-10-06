package workloadidentity

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewTokenRoundTripsThroughHashToken(t *testing.T) {
	token, hash := NewToken()
	require.True(t, strings.HasPrefix(token, TokenPrefix))
	require.Len(t, hash, sha256.Size)

	parsed, ok := HashToken(token)
	require.True(t, ok)
	require.Equal(t, hash, parsed)

	other, otherHash := NewToken()
	require.NotEqual(t, token, other)
	require.NotEqual(t, hash, otherHash)
}

func TestHashTokenRejectsMalformedTokens(t *testing.T) {
	for name, token := range map[string]string{
		"empty":                "",
		"service user prefix":  "SU-" + base64.URLEncoding.EncodeToString(make([]byte, tokenEntropyBytes)),
		"missing payload":      TokenPrefix,
		"invalid base64":       TokenPrefix + "!!!!",
		"short payload":        TokenPrefix + base64.URLEncoding.EncodeToString(make([]byte, tokenEntropyBytes-1)),
		"long payload":         TokenPrefix + base64.URLEncoding.EncodeToString(make([]byte, tokenEntropyBytes+3)),
		"lowercase prefix":     strings.ToLower(TokenPrefix) + base64.URLEncoding.EncodeToString(make([]byte, tokenEntropyBytes)),
		"whitespace in prefix": " " + TokenPrefix + base64.URLEncoding.EncodeToString(make([]byte, tokenEntropyBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := HashToken(token)
			require.False(t, ok)
		})
	}
}

func TestIssuedLifetimeIsBoundedByTTLMaximumAndSubjectExpiry(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for name, testCase := range map[string]struct {
		ttl           time.Duration
		subjectExpiry time.Time
		want          time.Duration
	}{
		"configured ttl":           {ttl: 5 * time.Minute, subjectExpiry: now.Add(10 * time.Minute), want: 5 * time.Minute},
		"subject expiry":           {ttl: 15 * time.Minute, subjectExpiry: now.Add(10 * time.Minute), want: 10 * time.Minute},
		"maximum lifetime":         {ttl: time.Hour, subjectExpiry: now.Add(2 * time.Hour), want: MaxTokenLifetime},
		"whole seconds":            {ttl: 15 * time.Minute, subjectExpiry: now.Add(90*time.Second + 900*time.Millisecond), want: 90 * time.Second},
		"one second left suffices": {ttl: 15 * time.Minute, subjectExpiry: now.Add(time.Second), want: time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			lifetime, err := IssuedLifetime(now, testCase.ttl, testCase.subjectExpiry)
			require.NoError(t, err)
			require.Equal(t, testCase.want, lifetime)
		})
	}
	for name, subjectExpiry := range map[string]time.Time{
		"sub-second remainder": now.Add(999 * time.Millisecond),
		"already expired":      now.Add(-time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := IssuedLifetime(now, 15*time.Minute, subjectExpiry)
			require.ErrorIs(t, err, ErrInvalidSubjectToken)
		})
	}
}
