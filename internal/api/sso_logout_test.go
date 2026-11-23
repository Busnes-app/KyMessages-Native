package api_test

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
)

func (f *fakeIdP) logoutToken(t *testing.T, changes map[string]any, key *rsa.PrivateKey) string {
	t.Helper()
	claims := map[string]any{"iss": f.issuer, "aud": "client", "sub": "logout-sub", "sid": "sid-a", "org_id": testStaffOrg,
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(), "jti": crypto.RandomHex(16),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	maps.Copy(claims, changes)
	for k, v := range claims {
		if v == nil {
			delete(claims, k)
		}
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k","typ":"logout+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	if key == nil {
		key = f.key
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, stdcrypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIdP) logout(srv *api.Server, raw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/sso/kyidentity/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.httpClient != nil {
		r = r.WithContext(oidc.ClientContext(r.Context(), f.httpClient))
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func TestSSOLogoutContractAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	_, st, cfg := setupTestServer(t)
	cfg.SSO.Enabled = true
	cfg.Tenancy = config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}
	idp := makeFakeIdP(t, cfg, true)
	if _, err := st.Chat().EnsureTenant(ctx, testStaffOrg); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "logout-user", Username: "logout-user", SSOProvider: "kyidentity", SSOSubject: "logout-sub", OrgID: testStaffOrg, Status: "active", Role: "user"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// Separate connection pools, as two replicas on the same primary.
	other, err := store.Open(ctx, cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	first, second := api.NewServer(cfg, st), api.NewServer(cfg, other)
	defer first.CloseChat()
	defer second.CloseChat()
	sessions := map[string]*http.Cookie{}
	for _, sid := range []string{"sid-a", "sid-b"} {
		w := idp.signIn(first, map[string]any{"sub": u.SSOSubject, "sid": sid, "org_id": testStaffOrg})
		c := sessionCookie(w)
		if c == nil {
			t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
		}
		sessions[sid] = c
		saved, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(c.Value)))
		if err != nil || saved.SID != sid || saved.Issuer != idp.issuer {
			t.Fatalf("sid not retained: %+v %v", saved, err)
		}
	}
	// Devices inherit the exact IdP session, including through a second pairing.
	derived := sessions["sid-a"]
	for range 2 {
		w := adminDo(t, first, derived, "POST", "/api/devices/pair/init", nil)
		var pending struct {
			Secret string `json:"secret"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pending) != nil {
			t.Fatalf("pair init: %d %s", w.Code, w.Body.String())
		}
		r := httptest.NewRequest("POST", "/api/devices/pair/verify", strings.NewReader(`{"secret":"`+pending.Secret+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		first.ServeHTTP(w, r)
		derived = sessionCookie(w)
		if derived == nil {
			t.Fatalf("pair verify: %d %s", w.Code, w.Body.String())
		}
		saved, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(derived.Value)))
		if err != nil || saved.SID != "sid-a" || saved.Issuer != idp.issuer {
			t.Fatalf("pair lost binding: %+v %v", saved, err)
		}
	}
	live := func(sid string) bool {
		_, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(sessions[sid].Value)))
		return err == nil
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, changes := range map[string]map[string]any{
		"wrong org":      {"org_id": "00000000-0000-4000-8000-000000000002"},
		"wrong issuer":   {"iss": "https://other.example"},
		"wrong audience": {"aud": "other-client"},
		"expired":        {"iat": time.Now().Add(-3 * time.Minute).Unix(), "exp": time.Now().Add(-time.Minute).Unix()},
		"future iat":     {"iat": time.Now().Add(time.Minute).Unix()},
		"long lifetime":  {"exp": time.Now().Add(time.Hour).Unix()},
		"missing event":  {"events": map[string]any{}},
		"nonce":          {"nonce": "login"},
		"token use":      {"token_use": "id_token"},
		"missing org":    {"org_id": nil},
		"null org":       {"org_id": json.RawMessage("null")},
		"missing jti":    {"jti": nil},
		"missing exp":    {"exp": nil},
	} {
		t.Run(name, func(t *testing.T) {
			w := idp.logout(second, idp.logoutToken(t, changes, nil))
			if w.Code != 400 || !live("sid-a") || !live("sid-b") {
				t.Fatalf("refusal changed sessions: %d %s", w.Code, w.Body.String())
			}
		})
	}
	if w := idp.logout(second, idp.logoutToken(t, nil, wrongKey)); w.Code != 400 || !live("sid-a") || !live("sid-b") {
		t.Fatalf("signature: %d", w.Code)
	}
	unknown := idp.logoutToken(t, map[string]any{"sub": "unprovisioned-other"}, nil)
	if w := idp.logout(second, unknown); w.Code != 200 || !live("sid-a") || !live("sid-b") {
		t.Fatalf("unprovisioned subject affected existing sessions: %d", w.Code)
	}
	if w := idp.logout(first, unknown); w.Code != 400 || !live("sid-a") || !live("sid-b") {
		t.Fatalf("unprovisioned replay affected existing sessions: %d", w.Code)
	}
	// Refused org comparison must leave the jti available for a correctly bound event.
	jti := "org-comparison"
	if w := idp.logout(second, idp.logoutToken(t, map[string]any{"jti": jti, "org_id": "00000000-0000-4000-8000-000000000002"}, nil)); w.Code != 400 {
		t.Fatal(w.Code)
	}
	raw := idp.logoutToken(t, map[string]any{"jti": jti}, nil)
	if w := idp.logout(second, raw); w.Code != 200 || live("sid-a") || !live("sid-b") {
		t.Fatalf("sid logout: %d %s", w.Code, w.Body.String())
	}
	if _, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(derived.Value))); err == nil {
		t.Fatal("derived session survived sid logout")
	}
	if w := idp.signIn(first, map[string]any{"sub": u.SSOSubject, "sid": "sid-a", "org_id": testStaffOrg}); sessionCookie(w) != nil {
		t.Fatal("revoked sid signed in again")
	}
	if w := idp.logout(first, raw); w.Code != 400 || !live("sid-b") {
		t.Fatalf("replay: %d", w.Code)
	}
	if w := idp.logout(first, idp.logoutToken(t, map[string]any{"sid": nil}, nil)); w.Code != 200 || live("sid-b") {
		t.Fatalf("subject logout: %d %s", w.Code, w.Body.String())
	}
}

func TestSSOLogoutFencesInFlightCallback(t *testing.T) {
	for _, fixture := range []struct {
		name               string
		provisioned, multi bool
	}{{"existing", true, false}, {"first-login", false, false}, {"first-login-multi", false, true}} {
		for _, sid := range []string{"sid-a", ""} {
			t.Run(fixture.name+"/scope="+sid, func(t *testing.T) {
				_, st, cfg := setupTestServer(t)
				cfg.SSO.Enabled = true
				cfg.SSO.AutoProvision = true
				orgID := ""
				if fixture.multi {
					cfg.Tenancy = config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}
					orgID = testStaffOrg
				}
				idp := makeFakeIdP(t, cfg, true)
				if fixture.provisioned {
					u := &store.User{ID: "logout-user", Username: "logout-user", SSOProvider: "kyidentity", SSOSubject: "logout-sub", OrgID: orgID, Status: "active", Role: "user"}
					if err := st.Users().CreateUser(context.Background(), u); err != nil {
						t.Fatal(err)
					}
				}
				first, second := api.NewServer(cfg, st), api.NewServer(cfg, st)
				defer first.CloseChat()
				defer second.CloseChat()
				entered, release := make(chan struct{}), make(chan struct{})
				idp.mu.Lock()
				idp.onToken = func() { close(entered); <-release }
				idp.mu.Unlock()
				done := make(chan *httptest.ResponseRecorder, 1)
				claims := map[string]any{"sub": "logout-sub", "sid": "sid-a", "iat": time.Now().Unix() + 1}
				changes := map[string]any{"org_id": nil}
				if fixture.multi {
					claims["org_id"] = orgID
					changes["org_id"] = orgID
				}
				go func() { done <- idp.signIn(first, claims) }()
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("exchange did not start")
				}
				if sid == "" {
					changes["sid"] = nil
				}
				w := idp.logout(second, idp.logoutToken(t, changes, nil))
				close(release)
				if w.Code != 200 {
					t.Fatalf("logout: %d %s", w.Code, w.Body.String())
				}
				select {
				case w := <-done:
					if sessionCookie(w) != nil {
						t.Fatal("in-flight callback issued a session after logout")
					}
					if w.Code != 500 || !strings.Contains(w.Body.String(), "Session creation failed") {
						t.Fatalf("callback did not reach the issuance fence: %d %s", w.Code, w.Body.String())
					}
				case <-time.After(10 * time.Second):
					t.Fatal("callback did not finish")
				}
			})
		}
	}
}

func TestSSOSignInRequiresSessionBinding(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.SSO.Enabled = true
	idp := makeFakeIdP(t, cfg, true)
	srv := api.NewServer(cfg, st)
	defer srv.CloseChat()
	for _, sid := range []any{"", nil, 42} {
		w := idp.signIn(srv, map[string]any{"sub": "binding-required", "sid": sid})
		if w.Code != 401 || sessionCookie(w) != nil {
			t.Fatalf("unbound sign-in accepted: %d %s", w.Code, w.Body.String())
		}
	}
}
