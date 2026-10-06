package workloadidentity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseServiceAccountSubjectAcceptsKubernetesServiceAccounts(t *testing.T) {
	for subject, want := range map[string][2]string{
		"system:serviceaccount:plugins:rollouts-runtime":          {"plugins", "rollouts-runtime"},
		"system:serviceaccount:a:b":                               {"a", "b"},
		"system:serviceaccount:team-1:runtime.v1":                 {"team-1", "runtime.v1"},
		"system:serviceaccount:" + strings.Repeat("n", 63) + ":x": {strings.Repeat("n", 63), "x"},
	} {
		t.Run(subject, func(t *testing.T) {
			namespace, name, err := ParseServiceAccountSubject(subject)
			require.NoError(t, err)
			require.Equal(t, want, [2]string{namespace, name})
		})
	}
}

func TestParseServiceAccountSubjectRejectsOtherSubjects(t *testing.T) {
	for _, subject := range []string{
		"",
		"system:serviceaccount:plugins",
		"system:serviceaccount::runtime",
		"system:serviceaccount:plugins:",
		"system:serviceaccounts:plugins:runtime",
		"system:serviceaccount:plugins:runtime:extra",
		"system:serviceaccount:Plugins:runtime",
		"system:serviceaccount:plugins:Runtime",
		"system:serviceaccount:plugins:-runtime",
		"system:serviceaccount:plugins:runtime..v1",
		"system:serviceaccount:plu.gins:runtime",
		"system:node:worker-1",
		"system:serviceaccount:" + strings.Repeat("n", 64) + ":runtime",
		"system:serviceaccount:plugins:" + strings.Repeat("r", 254),
		" system:serviceaccount:plugins:runtime",
		"system:serviceaccount:plugins:runtime\n",
	} {
		t.Run(subject, func(t *testing.T) {
			_, _, err := ParseServiceAccountSubject(subject)
			require.ErrorIs(t, err, ErrInvalidSubjectToken)
		})
	}
}

func TestValidServiceAccountUsesTheSubjectRule(t *testing.T) {
	require.True(t, ValidServiceAccount("plugins", "rollouts-runtime"))
	require.False(t, ValidServiceAccount("plugins", "runtime:other"))
	require.False(t, ValidServiceAccount("plugins:x", "runtime"))
	require.False(t, ValidServiceAccount("", "runtime"))
}

func TestMatchAudienceRequiresExactlyTheExchangeAudience(t *testing.T) {
	const audience = "stellwerk-iam-plugin-workload"
	require.NoError(t, MatchAudience([]string{audience}, audience))
	for name, tokenAudience := range map[string][]string{
		"none":       nil,
		"different":  {"https://kubernetes.default.svc"},
		"additional": {audience, "https://kubernetes.default.svc"},
		"prefix":     {audience + "-other"},
		"substring":  {"stellwerk-iam"},
		"case":       {strings.ToUpper(audience)},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, MatchAudience(tokenAudience, audience), ErrInvalidSubjectToken)
		})
	}
}

func TestValidAudienceAcceptsPrintableASCIIWithoutSpaces(t *testing.T) {
	require.True(t, ValidAudience("stellwerk-iam-plugin-workload"))
	require.True(t, ValidAudience("https://iam.example.test/plugin-workload"))
	require.True(t, ValidAudience(strings.Repeat("a", 255)))
	for _, audience := range []string{"", " ", "with space", "tab\taudience", "line\n", "ümlaut", strings.Repeat("a", 256)} {
		require.False(t, ValidAudience(audience), audience)
	}
}
