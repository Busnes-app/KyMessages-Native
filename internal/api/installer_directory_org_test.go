package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/applysetup"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestInstallerDirectoryOrgBinding(t *testing.T) {
	ctx := context.Background()
	_, st, cfg := setupTestServer(t)
	cfg.Server.AppURL = "https://chat.example"
	secret := filepath.Join(t.TempDir(), "directory.secret")
	if err := os.WriteFile(secret, []byte(testMultiTenantHMAC), 0600); err != nil {
		t.Fatal(err)
	}
	bundle := applysetup.Common{Schema: applysetup.Schema, Service: "kymessage", SetupID: "12345678-1234-1234-1234-123456789abc",
		SSO:      &applysetup.SSO{IssuerURL: "https://identity.example", ClientID: "client", ClientSecretFile: secret, DirectorySecretFile: secret, RedirectURI: "https://chat.example/api/sso/kyidentity/callback"},
		Admins:   []applysetup.Identity{{Issuer: "https://identity.example", Subject: "owner", Username: "owner-admin"}},
		Everyday: []applysetup.Identity{{Issuer: "https://identity.example", Subject: "daily", Username: "daily"}}}
	if _, err := st.ApplyInstaller(ctx, bundle, false); err != nil {
		t.Fatal(err)
	}
	if err := config.ApplyInstallerConfiguration(cfg, bundle); err != nil {
		t.Fatal(err)
	}
	cfg.Tenancy = config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}
	if _, err := st.Chat().EnsureTenant(ctx, testStaffOrg); err != nil {
		t.Fatal(err)
	}
	u, err := st.Users().GetUserBySSO(ctx, "kyidentity", "daily")
	if err != nil {
		t.Fatal(err)
	}
	// Model an already-bound installer-owned account; org provisioning is a separate task.
	driver := cfg.Database.Driver
	if driver == "postgres" {
		driver = "pgx"
	}
	db, err := sql.Open(driver, cfg.Database.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "UPDATE users SET org_id = '"+testStaffOrg+"' WHERE id = '"+u.ID+"'"); err != nil {
		t.Fatal(err)
	}
	u, err = st.Users().GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "installer-org", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(cfg, st)
	defer srv.CloseChat()
	send := func(event string, org any) *httptest.ResponseRecorder {
		attrs := map[string]any{"id": "daily", "active": true, "org_id": org, "meta": map[string]any{"version": `W/"1"`}}
		if org == "omit" {
			delete(attrs, "org_id")
		}
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatal(err)
		}
		headers, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), event, "installer-org-event", raw)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/api/sso/kyidentity/sync", strings.NewReader(string(raw)))
		headers.Apply(r)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	for _, event := range []string{"user.updated", "user.mfa_reset", "user.deleted"} {
		for _, org := range []any{"00000000-0000-4000-8000-000000000002", "omit", "", nil, 42, strings.ToUpper("abcdef00-0000-4000-8000-000000000001")} {
			w := send(event, org)
			if w.Code < 400 {
				t.Fatalf("%s org %v accepted: %d", event, org, w.Code)
			}
			if _, err := st.Sessions().GetSession(ctx, "installer-org"); err != nil {
				t.Fatal("refused event changed session", err)
			}
			if current, err := st.Users().GetUserByID(ctx, u.ID); err != nil || current.Status != "active" || current.PasswordHash != u.PasswordHash {
				t.Fatal("refused event changed account", err)
			}
		}
	}
	if w := send("user.mfa_reset", testStaffOrg); w.Code != 204 {
		t.Fatalf("correct org: %d %s", w.Code, w.Body.String())
	}
	if _, err := st.Sessions().GetSession(ctx, "installer-org"); err == nil {
		t.Fatal("correct org reset retained session")
	}
}
