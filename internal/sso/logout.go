package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutClaims has passed the issuer's RS256 signature and the logout-only profile.
type LogoutClaims struct {
	Subject   string                     `json:"sub"`
	OrgID     string                     `json:"org_id"`
	SID       string                     `json:"sid"`
	JTI       string                     `json:"jti"`
	IssuedAt  int64                      `json:"iat"`
	ExpiresAt int64                      `json:"exp"`
	Events    map[string]json.RawMessage `json:"events"`
}

// DirectoryOrg narrows the signed top-level org_id before directory authority is used.
// Single-mode KyIdentity omits it; that mode retains its existing directory behavior.
func DirectoryOrg(body []byte, tenancy config.TenancyConfig) (string, error) {
	if !tenancy.IsMultiTenant() {
		return "", nil
	}
	var payload struct {
		OrgID string `json:"org_id"`
	}
	if json.Unmarshal(body, &payload) != nil || !config.IsCanonicalUUID(payload.OrgID) {
		return "", ErrSyncMalformed
	}
	return payload.OrgID, nil
}

func (k *KyIdentityClient) VerifyLogout(ctx context.Context, raw string) (*LogoutClaims, error) {
	flow, err := k.currentFlow(ctx)
	if err != nil {
		return nil, err
	}
	provider, err := flow.getProvider(ctx)
	if err != nil {
		return nil, err
	}
	token, err := provider.Verifier(&oidc.Config{ClientID: flow.clientID, SupportedSigningAlgs: []string{oidc.RS256}}).Verify(idpContext(ctx), raw)
	if err != nil {
		return nil, err
	}
	// coreos verifies the signature/issuer/audience/expiry; the security-event profile
	// additionally requires an explicit type, event, bounded iat/exp and no login claims.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidIDToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Type string `json:"typ"`
	}
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Type != "logout+jwt" {
		return nil, ErrInvalidIDToken
	}
	var fields map[string]json.RawMessage
	if err := token.Claims(&fields); err != nil {
		return nil, err
	}
	if _, present := fields["nonce"]; present {
		return nil, ErrInvalidIDToken
	}
	if _, present := fields["token_use"]; present {
		return nil, ErrInvalidIDToken
	}
	var claims LogoutClaims
	if err := token.Claims(&claims); err != nil {
		return nil, ErrInvalidIDToken
	}
	now := time.Now().Unix()
	if claims.Subject == "" || len(claims.Subject) > 256 || claims.JTI == "" || len(claims.JTI) > 256 || len(claims.SID) > 256 ||
		claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.IssuedAt < now-120 || claims.ExpiresAt <= now ||
		claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 120 {
		return nil, ErrInvalidIDToken
	}
	if sid, present := fields["sid"]; present && (string(sid) == "null" || claims.SID == "") {
		return nil, ErrInvalidIDToken
	}
	var event map[string]json.RawMessage
	if json.Unmarshal(claims.Events[logoutEvent], &event) != nil || event == nil {
		return nil, ErrInvalidIDToken
	}
	if k.tenancy.IsMultiTenant() && !config.IsCanonicalUUID(claims.OrgID) {
		return nil, ErrSyncMalformed
	}
	if !k.tenancy.IsMultiTenant() {
		if _, present := fields["org_id"]; present {
			return nil, errors.New("unexpected organization claim")
		}
	}
	return &claims, nil
}
