package workloadidentity

import (
	"fmt"
	"regexp"
)

const (
	maxNamespaceLength          = 63
	maxServiceAccountNameLength = 253
	dnsLabel                    = `[a-z0-9](?:[-a-z0-9]*[a-z0-9])?`
)

var audiencePattern = regexp.MustCompile(`^[!-~]{1,255}$`)

var serviceAccountSubject = regexp.MustCompile(
	`^system:serviceaccount:(` + dnsLabel + `):(` + dnsLabel + `(?:\.` + dnsLabel + `)*)$`,
)

// ParseServiceAccountSubject splits a Kubernetes ServiceAccount token subject
// of the form system:serviceaccount:<namespace>:<name>.
func ParseServiceAccountSubject(subject string) (namespace, name string, err error) {
	match := serviceAccountSubject.FindStringSubmatch(subject)
	if match == nil || len(match[1]) > maxNamespaceLength || len(match[2]) > maxServiceAccountNameLength {
		return "", "", fmt.Errorf("%w: subject is not a Kubernetes ServiceAccount", ErrInvalidSubjectToken)
	}
	return match[1], match[2], nil
}

// ValidServiceAccount reports whether namespace and name form a valid
// ServiceAccount identity, using the same rule as token subjects.
func ValidServiceAccount(namespace, name string) bool {
	parsedNamespace, parsedName, err := ParseServiceAccountSubject("system:serviceaccount:" + namespace + ":" + name)
	return err == nil && parsedNamespace == namespace && parsedName == name
}

// ValidAudience reports whether audience is a usable exchange audience:
// 1 to 255 printable ASCII characters without spaces.
func ValidAudience(audience string) bool {
	return audiencePattern.MatchString(audience)
}

// MatchAudience requires the token to carry exactly the binding's exchange
// audience and nothing else, so a token minted for several audiences (for
// example also for the Kubernetes API server) cannot be exchanged.
func MatchAudience(tokenAudience []string, exchangeAudience string) error {
	if len(tokenAudience) != 1 || tokenAudience[0] != exchangeAudience {
		return fmt.Errorf("%w: audience is not the exchange audience", ErrInvalidSubjectToken)
	}
	return nil
}
