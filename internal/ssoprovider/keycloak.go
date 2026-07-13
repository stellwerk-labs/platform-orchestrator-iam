package ssoprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type Keycloak struct {
	realm        string
	httpClient   *http.Client
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// transportRewriter is a custom http.RoundTripper that rewrites the host of a request from a source URL to a target URL.
// This is used to make the OIDC client use an internal URL for Keycloak while still validating against the external issuer URL.
type transportRewriter struct {
	transport http.RoundTripper
	source    *url.URL
	target    *url.URL
}

func (t *transportRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do this only if the request host matches the source (external) URL
	if req.URL.Hostname() == t.source.Hostname() {
		req = req.Clone(req.Context())
		req.URL.Scheme = t.target.Scheme
		req.URL.Host = t.target.Host
		req.Host = t.target.Host
	}
	return t.transport.RoundTrip(req)
}

func NewKeycloak(ctx context.Context, httpClient *http.Client, publicBaseUrl, internalBaseUrl, realm, clientId, clientSecret, callbackUrl string) (Provider, error) {
	issuerURL := fmt.Sprintf("%s/realms/%s", strings.TrimRight(publicBaseUrl, "/"), realm)

	// If an internal URL is provided and is different from the issuer URL, set up custom transport to rewrite requests.
	if internalBaseUrl != "" && internalBaseUrl != publicBaseUrl {
		sourceURL, err := url.Parse(publicBaseUrl)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse Keycloak URL")
		}
		targetURL, err := url.Parse(internalBaseUrl)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse internal Keycloak URL")
		}

		// Copy HTTP client to avoid mutating the original
		c := *httpClient
		httpClient = &c
		if httpClient.Transport == nil {
			if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
				httpClient.Transport = defaultTransport.Clone()
			}
		}
		httpClient.Transport = &transportRewriter{transport: httpClient.Transport, source: sourceURL, target: targetURL}
	}

	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to discover Keycloak OIDC provider")
	}

	return &Keycloak{
		realm:      realm,
		httpClient: httpClient,
		oauth2Config: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  callbackUrl,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
	}, nil
}

func (k *Keycloak) GetAuthorizationURL(_, state string) (string, error) {
	return k.oauth2Config.AuthCodeURL(state), nil
}

func (k *Keycloak) GetUserProfile(ctx context.Context, authCode string) (*UserProfile, error) {
	ctx = oidc.ClientContext(ctx, k.httpClient)

	oauth2Token, err := k.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to exchange authorization code")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token in token response")
	}

	idToken, err := k.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify ID token")
	}

	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.Wrap(err, "failed to parse ID token claims")
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}

	return &UserProfile{
		ProviderUserId: idToken.Subject,
		// For potential future use - for multiple realms we may want to store it as a part of user identity
		ProviderOrgId: k.realm,
		Email:         claims.Email,
		DisplayName:   displayName,
	}, nil
}

func (k *Keycloak) IsMultitenant() bool {
	return false
}
