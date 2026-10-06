package workloadidentity

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims are the verified facts of a projected ServiceAccount token.
type Claims struct {
	Issuer         string
	Namespace      string
	ServiceAccount string
	Audience       []string
	Expiry         time.Time
}

// Verifier checks projected ServiceAccount tokens of one cluster issuer.
type Verifier struct {
	keys     *KeySet
	verifier *oidc.IDTokenVerifier
}

func NewVerifier(issuer string, keys *KeySet, now func() time.Time) *Verifier {
	algorithms := make([]string, len(signingAlgorithms))
	for index, algorithm := range signingAlgorithms {
		algorithms[index] = string(algorithm)
	}
	return &Verifier{keys: keys, verifier: oidc.NewVerifier(issuer, keys, &oidc.Config{
		// The exchange audience belongs to the binding; MatchAudience checks it exactly.
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: algorithms,
		Now:                  now,
	})}
}

// Verify checks signature, issuer, expiry and not-before (go-oidc tolerates
// five minutes of clock skew for nbf only), then requires a
// system:serviceaccount subject that agrees with the kubernetes.io claims.
// The audience is left to MatchAudience against the binding.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	if err := v.keys.Ready(ctx); err != nil {
		return Claims{}, err
	}
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidSubjectToken, err)
	}
	namespace, name, err := ParseServiceAccountSubject(token.Subject)
	if err != nil {
		return Claims{}, err
	}
	var private struct {
		Kubernetes struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := token.Claims(&private); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidSubjectToken, err)
	}
	if private.Kubernetes.Namespace != namespace || private.Kubernetes.ServiceAccount.Name != name {
		return Claims{}, fmt.Errorf("%w: kubernetes.io claims do not match the subject", ErrInvalidSubjectToken)
	}
	return Claims{
		Issuer:         token.Issuer,
		Namespace:      namespace,
		ServiceAccount: name,
		Audience:       token.Audience,
		Expiry:         token.Expiry,
	}, nil
}
