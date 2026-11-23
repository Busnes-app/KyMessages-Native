package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// While an org is deletion_scheduled KyIdentity issues export_only tokens. KyMessages has no
// export route, so multi mode refuses them exactly as it refuses a suspended org, and creates
// nothing. Single mode never acts on the claim.
func TestExportOnlyTokenIsRefusedInMultiMode(t *testing.T) {
	ctx := context.Background()
	_, st, cfg := setupTestServer(t)
	cfg.Tenancy = config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg}
	cfg.SSO.AutoProvision = true
	idp := newFakeIdP(t, cfg)
	srv := api.NewServer(cfg, st)
	const org = "00000000-0000-4000-8000-0000000000e1"

	w := idp.signIn(srv, map[string]any{"sub": "exp-1", "preferred_username": "leaving", "org_id": org, "export_only": true})
	if w.Code != http.StatusForbidden || sessionCookie(w) != nil {
		t.Fatalf("export_only sign-in = %d %s (session %v)", w.Code, w.Body.String(), sessionCookie(w))
	}
	// The same answer a suspended org gets.
	if _, err := st.Chat().EnsureTenant(ctx, "00000000-0000-4000-8000-0000000000e2"); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().SetTenantStatus(ctx, "00000000-0000-4000-8000-0000000000e2", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	suspended := idp.signIn(srv, map[string]any{"sub": "exp-2", "preferred_username": "paused", "org_id": "00000000-0000-4000-8000-0000000000e2"})
	if suspended.Code != w.Code || suspended.Body.String() != w.Body.String() {
		t.Fatalf("export_only answer %d %s differs from suspended %d %s", w.Code, w.Body.String(), suspended.Code, suspended.Body.String())
	}
	if _, err := st.Users().GetUserBySSO(ctx, "kyidentity", "exp-1"); err == nil {
		t.Fatal("an export_only sign-in provisioned an account")
	}
	recs, _, err := st.Audit().ListAuditRecords(ctx, 0, 10, "sso.export_only_refused")
	if err != nil || len(recs) != 1 || recs[0].Resource != "tenant:"+org || recs[0].UserID != "" || recs[0].Details != "" {
		t.Fatalf("audit: %v %+v", err, recs)
	}
	// export_only false signs in once the org is admitted by the directory.
	admitOrg(t, st, org)
	if w := idp.signIn(srv, map[string]any{"sub": "exp-3", "preferred_username": "staying", "org_id": org, "export_only": false}); sessionCookie(w) == nil {
		t.Fatalf("ordinary sign-in = %d %s", w.Code, w.Body.String())
	}
}

func TestExportOnlyClaimIsIgnoredInSingleMode(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.SSO.AutoProvision = true
	idp := newFakeIdP(t, cfg)
	srv := api.NewServer(cfg, st)
	if w := idp.signIn(srv, map[string]any{"sub": "single-1", "preferred_username": "solo", "export_only": true}); sessionCookie(w) == nil {
		t.Fatalf("single-mode sign-in = %d %s", w.Code, w.Body.String())
	}
}
