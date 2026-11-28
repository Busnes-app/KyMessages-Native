package sso

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// idpTimeout bounds each call to the IdP (discovery, keys, code exchange). Discovery runs
// under the flow's mutex, so an unbounded call to a hung IdP would queue every sign-in.
var idpTimeout = 10 * time.Second

// idpContext carries the bounded client unless the caller supplied one (oidc.ClientContext).
func idpContext(ctx context.Context) context.Context {
	if _, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return ctx
	}
	return oidc.ClientContext(ctx, &http.Client{Timeout: idpTimeout})
}

type oauthFlow struct {
	issuer       string
	clientID     string
	clientSecret string
	mu           sync.Mutex
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

func newOAuthFlow(issuer, clientID, clientSecret string) *oauthFlow {
	return &oauthFlow{issuer: strings.TrimRight(issuer, "/"), clientID: clientID, clientSecret: clientSecret}
}

func (f *oauthFlow) getProvider(ctx context.Context) (*oidc.Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.provider != nil {
		return f.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, idpTimeout)
	defer cancel()
	ctx = idpContext(ctx)
	provider, err := oidc.NewProvider(ctx, f.issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		Issuer                           string   `json:"issuer"`
		JWKSURI                          string   `json:"jwks_uri"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	algs, err := supportedSigningAlgs(metadata.IDTokenSigningAlgValuesSupported)
	if err != nil {
		return nil, err
	}
	client := http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = configured
	}
	jwksClient := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	jwksClient.Transport = strongJWKSTransport{base: transport}
	if jwksClient.Timeout == 0 {
		jwksClient.Timeout = idpTimeout
	}
	issuer := metadata.Issuer
	if issuer == "" {
		issuer = f.issuer
	}
	keySet := newRemoteJWKSKeySet(metadata.JWKSURI, &jwksClient, algs)
	f.verifier = oidc.NewVerifier(issuer, keySet, &oidc.Config{
		ClientID:             f.clientID,
		SupportedSigningAlgs: algs,
	})
	f.provider = provider
	return provider, nil
}

// allowedOIDCSigningAlgs mirrors coreos/go-oidc's asymmetric allowlist plus RFC 9964 ML-DSA-65.
var allowedOIDCSigningAlgs = map[string]bool{
	"ML-DSA-65": true,
	oidc.RS256:  true,
	oidc.RS384:  true,
	oidc.RS512:  true,
	oidc.ES256:  true,
	oidc.ES384:  true,
	oidc.ES512:  true,
	oidc.PS256:  true,
	oidc.PS384:  true,
	oidc.PS512:  true,
	oidc.EdDSA:  true,
}

func supportedSigningAlgs(advertised []string) ([]string, error) {
	if len(advertised) == 0 {
		return []string{oidc.RS256}, nil
	}
	seen := make(map[string]struct{}, len(advertised))
	out := make([]string, 0, len(advertised))
	for _, alg := range advertised {
		if !allowedOIDCSigningAlgs[alg] {
			continue
		}
		if _, dup := seen[alg]; dup {
			continue
		}
		seen[alg] = struct{}{}
		out = append(out, alg)
	}
	if len(out) == 0 {
		return nil, errors.New("OIDC provider advertises no supported asymmetric signing algorithms")
	}
	return out, nil
}

func (f *oauthFlow) config(ctx context.Context, redirectURI string) (*oauth2.Config, *oidc.Provider, error) {
	if f.issuer == "" || f.clientID == "" {
		return nil, nil, ErrProviderDisabled
	}
	provider, err := f.getProvider(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{ClientID: f.clientID, ClientSecret: f.clientSecret, Endpoint: provider.Endpoint(), RedirectURL: redirectURI, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, provider, nil
}

func (f *oauthFlow) authCodeURL(ctx context.Context, redirectURI, state, verifier, nonce string, options ...oauth2.AuthCodeOption) (string, error) {
	config, _, err := f.config(ctx, redirectURI)
	if err != nil {
		return "", err
	}
	options = append(options, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	return config.AuthCodeURL(state, options...), nil
}

func (f *oauthFlow) exchange(ctx context.Context, code, verifier, redirectURI, expectedNonce string) (*IdentityClaims, error) {
	idToken, err := f.exchangeIDToken(ctx, code, verifier, redirectURI, expectedNonce)
	if err != nil {
		return nil, err
	}
	return claimsFromIDToken(idToken)
}

func (f *oauthFlow) exchangeIDToken(ctx context.Context, code, verifier, redirectURI, expectedNonce string) (*oidc.IDToken, error) {
	ctx = idpContext(ctx)
	config, _, err := f.config(ctx, redirectURI)
	if err != nil {
		return nil, err
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("missing id_token in token response")
	}
	idToken, err := f.verifier.Verify(ctx, rawIDToken)
	if err != nil || expectedNonce == "" || idToken.Nonce != expectedNonce {
		return nil, ErrInvalidIDToken
	}
	return idToken, nil
}

func claimsFromIDToken(idToken *oidc.IDToken) (*IdentityClaims, error) {
	var raw struct {
		Sub               string `json:"sub"`
		SID               string `json:"sid"`
		OrgID             string `json:"org_id"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Role              string `json:"role"`
		AuthTime          int64  `json:"auth_time"`
		ExportOnly        bool   `json:"export_only"`
	}
	if err := idToken.Claims(&raw); err != nil || raw.Sub == "" || raw.SID == "" || len(raw.SID) > 256 || idToken.IssuedAt.IsZero() {
		return nil, ErrInvalidIDToken
	}
	username := raw.PreferredUsername
	if username == "" {
		username = raw.Email
	}
	if username == "" {
		username = raw.Sub
	}
	claims := &IdentityClaims{
		Issuer:            idToken.Issuer,
		SessionID:         raw.SID,
		IssuedAt:          idToken.IssuedAt.Unix(),
		Subject:           raw.Sub,
		OrgID:             strings.TrimSpace(raw.OrgID),
		Email:             raw.Email,
		Name:              raw.Name,
		PreferredUsername: username,
		Role:              raw.Role,
		ExportOnly:        raw.ExportOnly,
	}
	if raw.AuthTime > 0 && raw.AuthTime <= idToken.IssuedAt.Unix() && raw.AuthTime <= time.Now().Unix() {
		claims.AuthenticatedAt = time.Unix(raw.AuthTime, 0).UTC()
	}
	return claims, nil
}
