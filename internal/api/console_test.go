package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/health"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func staleAdmin(t *testing.T, st store.Store) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	createLocalUser(t, st, "usr_old", "old-admin", "admin", "OldAdminPass123!")
	user, err := st.Users().GetUserByID(ctx, "usr_old")
	if err != nil {
		t.Fatal(err)
	}
	raw := crypto.RandomHex(32)
	if err := st.Sessions().CreateSession(ctx, &store.Session{
		TokenHash: crypto.SHA256Hex([]byte(raw)), UserID: "usr_old",
		CreatedAt: time.Now().UTC().Add(-11 * time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, user.PasswordHash); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.SessionCookieName, Value: raw}
}

type componentsBody struct {
	Components []health.Component `json:"components"`
}

func TestHealthReportsNativeComponentsAndLiveKit(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")

	// Without LiveKit configured: kymessages + database.
	h := decode[componentsBody](t, adminDo(t, srv, admin, "GET", "/api/admin/health", nil))
	if len(h.Components) != 2 || h.Components[0].Name != "kymessages" || h.Components[1].Name != "database" ||
		h.Components[0].Status != "up" || h.Components[1].Status != "up" {
		t.Fatalf("health without LiveKit: %+v", h)
	}

	// With LiveKit configured and reachable.
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer lk.Close()
	cfg.RTC.LiveKitURL = lk.URL
	cfg.RTC.LiveKitAPIKey = "devkey"
	cfg.RTC.LiveKitAPISecret = "devsecret"

	h = decode[componentsBody](t, adminDo(t, srv, admin, "GET", "/api/admin/health", nil))
	if len(h.Components) != 3 {
		t.Fatalf("health with LiveKit: %+v", h)
	}
	by := map[string]health.Component{}
	for _, c := range h.Components {
		by[c.Name] = c
	}
	if c := by["livekit"]; c.Status != "up" || c.Error != "" {
		t.Errorf("livekit up: %+v", c)
	}

	// With LiveKit unreachable: status=down, error non-empty, secret never leaked.
	lk.Close()
	w := adminDo(t, srv, admin, "GET", "/api/admin/health", nil)
	if strings.Contains(w.Body.String(), "devsecret") {
		t.Fatal("health response leaked LiveKit secret")
	}
	h = decode[componentsBody](t, w)
	if len(h.Components) != 3 || h.Components[2].Name != "livekit" || h.Components[2].Status != "down" || h.Components[2].Error == "" {
		t.Fatalf("livekit down: %+v", h)
	}
}

func TestRetiredMatrixRoutesReturn404(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/admin/matrix/users"},
		{"GET", "/api/admin/matrix/rooms"},
		{"GET", "/api/admin/matrix/sync-status"},
		{"GET", "/api/admin/federation"},
		{"POST", "/api/rtc/sfu/get"},
	} {
		if w := adminDo(t, srv, admin, rt.method, rt.path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s %s: got %d, want 404", rt.method, rt.path, w.Code)
		}
	}
}

func TestAuditListsNewestFirstByKind(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin") // writes auth.login
	ctx := context.Background()
	for _, r := range []store.AuditRecord{
		{UserID: "usr_root", Action: "admin.backup_run", Resource: "cap-1", Details: `outcome="success" trigger="admin"`, IPAddress: "192.0.2.9"},
		{Action: "agent.expire", Resource: "agent-triage", Details: `outcome="expired" owner="alice"`},
		{UserID: "usr_gone", Action: "scim.user.create", Resource: "erin"},
	} {
		if err := st.Audit().LogAudit(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	type rec struct{ Action, Actor, Target, Outcome, Details, IP string }
	type page struct {
		Records []rec
		Total   int
	}
	get := func(q string) page { return decode[page](t, adminDo(t, srv, admin, "GET", "/api/admin/audit"+q, nil)) }
	all := get("")
	if len(all.Records) < 4 || all.Records[0].Action != "scim.user.create" || all.Records[1].Action != "agent.expire" || all.Records[2].Action != "admin.backup_run" {
		t.Fatalf("order: %+v", all.Records)
	}
	if r := all.Records[0]; r.Actor != "scim" || r.Target != "erin" || r.Outcome != "" {
		t.Errorf("scim row: %+v", r)
	}
	if r := all.Records[1]; r.Actor != "system" || r.Outcome != "expired" {
		t.Errorf("agent row: %+v", r)
	}
	if r := all.Records[2]; r.Actor != "root" || r.Outcome != "success" || r.Target != "cap-1" || r.IP != "192.0.2.9" || !strings.Contains(r.Details, `trigger="admin"`) {
		t.Errorf("backup row: %+v", r)
	}
	if b := get("?kind=backup"); b.Total != 1 || b.Records[0].Action != "admin.backup_run" {
		t.Errorf("backup kind: %+v", b)
	}
	if a := get("?kind=agents"); a.Total != 1 || a.Records[0].Action != "agent.expire" {
		t.Errorf("agents kind: %+v", a)
	}
	for _, r := range get("?kind=auth").Records {
		if !strings.HasPrefix(r.Action, "auth.") && !strings.HasPrefix(r.Action, "device.") {
			t.Errorf("auth kind returned %s", r.Action)
		}
	}
	if p := get("?limit=1&offset=1"); len(p.Records) != 1 || p.Records[0] != all.Records[1] || p.Total != all.Total {
		t.Errorf("page: %+v", p)
	}
	for _, bad := range []string{"?kind=", "?kind=matrix", "?kind=messaging", "?limit=500", "?offset=x"} {
		if w := adminDo(t, srv, admin, "GET", "/api/admin/audit"+bad, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
}

func TestAuditOutcomeIgnoresSpoofs(t *testing.T) {
	for details, want := range map[string]string{
		`trigger="admin" outcome="success"`:                 "success",
		`remote="boom outcome=ok" outcome="failed"`:         "failed",
		`remote="a \" outcome=ok"`:                          "",
		`subject="s" reason="r"`:                            "",
		`error=recovery pairing: HTTP 400: outcome=success`: "",
		`bad.outcome=delivered`:                             "",
		`outcome="error: abc`:                               "",
		`outcome="success" trailing outcome=failure`:        "",
		`outcome="success"  trigger="x"`:                    "",
	} {
		if got := api.DetailOutcomeForTest(details); got != want {
			t.Errorf("%q: got %q want %q", details, got, want)
		}
	}
}

func TestAuditClipsLongActorAndTarget(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	ctx := context.Background()
	long := strings.Repeat("\U0001F600", 100)
	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_long", Username: long, Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []store.AuditRecord{
		{UserID: "usr_long", Action: "auth.login", Resource: long},
		{UserID: "usr_long", Action: "scim.user.create", Resource: long},
	} {
		if err := st.Audit().LogAudit(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	type rec struct{ Action, Actor, Target string }
	recs := decode[struct{ Records []rec }](t, adminDo(t, srv, admin, "GET", "/api/admin/audit?limit=2", nil)).Records
	if len(recs) != 2 {
		t.Fatalf("records %+v", recs)
	}
	for _, r := range recs {
		if len(r.Target) > 200 || !utf8.ValidString(r.Target) || !strings.HasPrefix(long, r.Target) || r.Target == "" {
			t.Errorf("%s target %d bytes", r.Action, len(r.Target))
		}
	}
	if a := recs[0].Actor; recs[0].Action != "scim.user.create" || a != "scim" {
		t.Errorf("scim actor %q", a)
	}
	if a := recs[1].Actor; len(a) > 200 || !utf8.ValidString(a) || !strings.HasPrefix(long, a) || a == "" {
		t.Errorf("long actor %d bytes", len(a))
	}
}

func TestAuditClipsLongDetailsOutcomeAndIP(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	ip := strings.Repeat("\U0001F600", 64)
	outcome := strings.Repeat("\U0001F600", 1500)
	details := `outcome="` + outcome + `"`
	if err := st.Audit().LogAudit(context.Background(), &store.AuditRecord{Action: "agent.create", Details: details, IPAddress: ip}); err != nil {
		t.Fatal(err)
	}
	type rec struct{ Details, Outcome, IP string }
	recs := decode[struct{ Records []rec }](t, adminDo(t, srv, admin, "GET", "/api/admin/audit?limit=1", nil)).Records
	if len(recs) != 1 {
		t.Fatalf("records %+v", recs)
	}
	for _, f := range []struct {
		name, got, full string
		max             int
	}{{"details", recs[0].Details, details, 4096}, {"outcome", recs[0].Outcome, outcome, 1024}, {"ip", recs[0].IP, ip, 64}} {
		if len(f.got) > f.max || f.got == "" || !utf8.ValidString(f.got) || !strings.HasPrefix(f.full, f.got) {
			t.Errorf("%s %d bytes", f.name, len(f.got))
		}
	}
}
