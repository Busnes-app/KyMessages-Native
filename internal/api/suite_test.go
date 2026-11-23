package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"github.com/google/uuid"
)

const (
	suiteIssuer     = "https://id.example"
	suiteKyPostKey  = "kypost-pair-secret-0123456789abcdef"
	suiteKyCalKey   = "kycalendar-pair-secret-0123456789ab"
	suiteOrgA       = "00000000-0000-4000-8000-00000000000a"
	suiteOrgB       = "00000000-0000-4000-8000-00000000000b"
	suiteAppURL     = "https://chat.example.com"
	suiteUnknownSub = "sub-nobody"
)

// suiteEnv is one KyMessages server paired with KyPost and KyCalendar from the environment.
type suiteEnv struct {
	t   *testing.T
	srv *api.Server
	st  store.Store
	cfg *config.Config
}

func newSuiteEnv(t *testing.T, mode string) *suiteEnv {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{
		Server:     config.ServerConfig{AppName: "KyMessages", AppURL: suiteAppURL},
		Database:   config.DatabaseConfig{DataDir: t.TempDir()},
		Security:   config.SecurityConfig{SessionTTL: time.Hour},
		SSO:        config.SSOConfig{Enabled: true, KyIdentityIssuer: suiteIssuer, KyIdentityHMACSecret: testMultiTenantHMAC},
		RTC:        config.RTCConfig{MeetingSyncSecret: testMultiTenantHMAC},
		Tenancy:    config.TenancyConfig{Mode: mode},
		KyPost:     config.PairConfig{URL: "https://mail.example", Secret: []byte(suiteKyPostKey)},
		KyCalendar: config.PairConfig{URL: "https://cal.example", Secret: []byte(suiteKyCalKey)},
	}
	if mode == config.TenancyMulti {
		cfg.Tenancy.StaffOrgID = testStaffOrg
	}
	if err := api.EnsureTenancyMode(context.Background(), st, cfg.Tenancy); err != nil {
		t.Fatalf("EnsureTenancyMode: %v", err)
	}
	return &suiteEnv{t: t, srv: newSuiteServer(t, cfg, st), st: st, cfg: cfg}
}

func newSuiteServer(t *testing.T, cfg *config.Config, st store.Store) *api.Server {
	srv := api.NewServer(cfg, st)
	t.Cleanup(func() { srv.WaitDetached() })
	return srv
}

func (e *suiteEnv) user(id, role, orgID string) *store.User {
	e.t.Helper()
	if orgID != "" {
		admitOrg(e.t, e.st, orgID)
	}
	u := &store.User{ID: id, Username: id, Role: role, Status: "active", SSOProvider: "kyidentity", SSOSubject: "sub-" + id, OrgID: orgID}
	if err := e.st.Users().CreateUser(context.Background(), u); err != nil {
		e.t.Fatalf("CreateUser(%s): %v", id, err)
	}
	return u
}

// signed is one signed request; zero fields take the defaults in do.
type signed struct {
	method, path string
	event, id    string
	key          string
	at           time.Time
	raw          []byte
}

func (e *suiteEnv) do(srv *api.Server, s signed) *httptest.ResponseRecorder {
	e.t.Helper()
	if s.method == "" {
		s.method = http.MethodPost
	}
	if s.id == "" {
		s.id = "evt-" + uuid.NewString()
	}
	if s.key == "" {
		s.key = suiteKyPostKey
	}
	if s.at.IsZero() {
		s.at = time.Now()
	}
	h, err := syncauth.Sign([]byte(s.key), s.at, s.event, s.id, s.raw)
	if err != nil {
		e.t.Fatal(err)
	}
	req := httptest.NewRequest(s.method, s.path, bytes.NewReader(s.raw))
	req.Header.Set("Content-Type", "application/json")
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func (e *suiteEnv) chat(body string) *httptest.ResponseRecorder {
	return e.do(e.srv, signed{path: "/api/suite/chat", event: "kypost.chat.open", raw: []byte(body)})
}

func chatBody(sub, orgID, target string) string {
	m := map[string]any{"sub": sub, "issuer": suiteIssuer, "target_sub": target}
	if orgID != "" {
		m["org_id"] = orgID
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code, what string) {
	t.Helper()
	var got struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != status || got.Code != code {
		t.Fatalf("%s = %d %s, want %d %s", what, rec.Code, rec.Body.String(), status, code)
	}
}

func TestSuiteChatMultiTenant(t *testing.T) {
	e := newSuiteEnv(t, config.TenancyMulti)
	alice := e.user("alice", "user", suiteOrgA)
	bob := e.user("bob", "user", suiteOrgA)
	carol := e.user("carol", "user", suiteOrgB)
	staff := e.user("staff", "admin", testStaffOrg)

	rec := e.chat(chatBody(alice.SSOSubject, suiteOrgA, bob.SSOSubject))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("same-org chat = %d: %s", rec.Code, rec.Body.String())
	}
	var ok struct{ URL string }
	_ = json.Unmarshal(rec.Body.Bytes(), &ok)
	if ok.URL != suiteAppURL+"/#dm="+bob.ID {
		t.Fatalf("url = %q", ok.URL)
	}

	// #1 wrong org_id answers exactly like an unknown subject.
	unknown := e.chat(chatBody(suiteUnknownSub, suiteOrgA, bob.SSOSubject))
	wantCode(t, unknown, http.StatusNotFound, "no_user", "unknown caller")
	wrongOrg := e.chat(chatBody(alice.SSOSubject, suiteOrgB, carol.SSOSubject))
	wantCode(t, wrongOrg, http.StatusNotFound, "no_user", "wrong org_id")
	if wrongOrg.Body.String() != unknown.Body.String() {
		t.Fatalf("wrong org body %q differs from unknown body %q", wrongOrg.Body, unknown.Body)
	}

	// #2 missing or malformed org_id.
	for _, org := range []string{``, `,"org_id":""`, `,"org_id":null`, `,"org_id":42`, `,"org_id":"` + strings.ToUpper(suiteOrgA) + `"`, `,"org_id":"org-a"`} {
		body := `{"sub":"` + alice.SSOSubject + `","issuer":"` + suiteIssuer + `","target_sub":"` + bob.SSOSubject + `"` + org + `}`
		wantCode(t, e.chat(body), http.StatusBadRequest, "bad_body", "org_id "+org)
	}
	wantCode(t, e.chat(`{"sub":"`+alice.SSOSubject+`","issuer":"`+suiteIssuer+`","org_id":"`+suiteOrgA+`","target_sub":"`+bob.SSOSubject+`","extra":1}`), http.StatusBadRequest, "bad_body", "unknown field")

	// #4 a cross-org target answers exactly like an unknown person.
	unknownTarget := e.chat(chatBody(alice.SSOSubject, suiteOrgA, suiteUnknownSub))
	wantCode(t, unknownTarget, http.StatusNotFound, "no_target", "unknown target")
	cross := e.chat(chatBody(alice.SSOSubject, suiteOrgA, carol.SSOSubject))
	wantCode(t, cross, http.StatusNotFound, "no_target", "cross-org target")
	if cross.Body.String() != unknownTarget.Body.String() {
		t.Fatal("cross-org target body differs from unknown target body")
	}

	// #8 administrators, self and inactive orgs.
	wantCode(t, e.chat(chatBody(staff.SSOSubject, testStaffOrg, bob.SSOSubject)), http.StatusNotFound, "no_user", "admin caller")
	wantCode(t, e.chat(chatBody(alice.SSOSubject, suiteOrgA, staff.SSOSubject)), http.StatusNotFound, "no_target", "admin target")
	wantCode(t, e.chat(chatBody(alice.SSOSubject, suiteOrgA, alice.SSOSubject)), http.StatusNotFound, "no_target", "self target")
	if err := e.st.Chat().SetTenantStatus(context.Background(), suiteOrgA, store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.chat(chatBody(alice.SSOSubject, suiteOrgA, bob.SSOSubject)), http.StatusNotFound, "no_user", "suspended org caller")
}

func TestSuiteChatSingleTenantWire(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	alice := e.user("alice", "user", "")
	bob := e.user("bob", "user", "")

	// #7 byte-for-byte: no org_id in, none out.
	rec := e.chat(chatBody(alice.SSOSubject, "", bob.SSOSubject))
	if want := `{"url":"` + suiteAppURL + `/#dm=` + bob.ID + `"}` + "\n"; rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("single chat = %d %q, want %q", rec.Code, rec.Body.String(), want)
	}
	// #3 org_id is refused in single mode, even empty or null.
	for _, org := range []string{`"` + suiteOrgA + `"`, `""`, `null`} {
		body := `{"sub":"` + alice.SSOSubject + `","issuer":"` + suiteIssuer + `","org_id":` + org + `,"target_sub":"` + bob.SSOSubject + `"}`
		wantCode(t, e.chat(body), http.StatusBadRequest, "bad_body", "single org_id "+org)
	}
	wantCode(t, e.chat(`{"sub":"`+alice.SSOSubject+`","issuer":"https://other.example","target_sub":"`+bob.SSOSubject+`"}`), http.StatusNotFound, "no_user", "foreign issuer")
	// KyCalendar's event under KyCalendar's secret works too.
	if rec := e.do(e.srv, signed{path: "/api/suite/chat", event: "kycalendar.chat.open", key: suiteKyCalKey, raw: []byte(chatBody(alice.SSOSubject, "", bob.SSOSubject))}); rec.Code != http.StatusOK {
		t.Fatalf("kycalendar chat = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSuiteChatReplayAndSignatures(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	alice := e.user("alice", "user", "")
	bob := e.user("bob", "user", "")
	body := []byte(chatBody(alice.SSOSubject, "", bob.SSOSubject))
	chat := signed{path: "/api/suite/chat", event: "kypost.chat.open", raw: body}

	// #5 a replay is acknowledged without acting, on this server and on another replica.
	chat.id = "kypost-chat-replay"
	if rec := e.do(e.srv, chat); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("first = %d %s", rec.Code, rec.Body.String())
	}
	// An event ID longer than a VARCHAR(255) still records and replays (PostgreSQL included).
	long := chat
	long.id = "kypost-chat-" + strings.Repeat("x", 300)
	for i, want := range []string{`{"url":`, `{"outcome":"duplicate"}`} {
		if rec := e.do(e.srv, long); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), want) {
			t.Fatalf("long event ID #%d = %d %s", i, rec.Code, rec.Body.String())
		}
	}
	replica := newSuiteServer(t, e.cfg, e.st)
	for name, srv := range map[string]*api.Server{"same": e.srv, "replica": replica} {
		if rec := e.do(srv, chat); rec.Code != http.StatusOK || rec.Body.String() != `{"outcome":"duplicate"}`+"\n" {
			t.Fatalf("%s replay = %d %s", name, rec.Code, rec.Body.String())
		}
	}

	// #6 bad signatures and envelope abuse.
	cases := map[string]signed{
		"kycalendar secret on kypost event": {key: suiteKyCalKey},
		"wrong event type":                  {event: "kypost.presence.ooo"},
		"stale":                             {at: time.Now().Add(-6 * time.Minute)},
		"future":                            {at: time.Now().Add(6 * time.Minute)},
		"too large":                         {raw: append(append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), 64<<10)...), '"', '}')},
	}
	for name, c := range cases {
		c.path = "/api/suite/chat"
		if c.event == "" {
			c.event = "kypost.chat.open"
		}
		if c.raw == nil {
			c.raw = body
		}
		wantCode(t, e.do(e.srv, c), http.StatusUnauthorized, "bad_signature", name)
	}
	// A body changed after signing.
	h, _ := syncauth.Sign([]byte(suiteKyPostKey), time.Now(), "kypost.chat.open", "evt-tamper", body)
	req := httptest.NewRequest(http.MethodPost, "/api/suite/chat", bytes.NewReader(bytes.Replace(body, []byte("bob"), []byte("eve"), 1)))
	h.Apply(req)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	wantCode(t, rec, http.StatusUnauthorized, "bad_signature", "tampered body")
	// A refused signature never consumes the event ID.
	if fresh, err := e.st.SuiteReplay().Record(context.Background(), "evt-tamper", 0, time.Now().Add(time.Hour).Unix()); err != nil || !fresh {
		t.Fatalf("tampered event ID was retained: fresh=%v err=%v", fresh, err)
	}
}

func TestSuiteChatRateLimitReleasesEvent(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	alice := e.user("alice", "user", "")
	bob := e.user("bob", "user", "")
	chat := signed{path: "/api/suite/chat", event: "kypost.chat.open", raw: []byte(chatBody(alice.SSOSubject, "", bob.SSOSubject))}
	for i := range 60 {
		if rec := e.do(e.srv, chat); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	chat.id = "evt-limited"
	rec := e.do(e.srv, chat)
	wantCode(t, rec, http.StatusTooManyRequests, "rate_limited", "61st request")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	if fresh, err := e.st.SuiteReplay().Record(context.Background(), "evt-limited", 0, time.Now().Add(time.Hour).Unix()); err != nil || !fresh {
		t.Fatalf("rate-limited event ID was retained: fresh=%v err=%v", fresh, err)
	}
}

func TestSuiteChatUnpaired(t *testing.T) {
	e := newSuiteEnv(t, config.TenancySingle)
	cfg := *e.cfg
	cfg.KyPost, cfg.SSO = config.PairConfig{}, config.SSOConfig{}
	srv := newSuiteServer(t, &cfg, e.st)
	wantCode(t, e.do(srv, signed{path: "/api/suite/chat", event: "kypost.chat.open", raw: []byte(`{}`)}), http.StatusNotFound, "kypost_off", "unpaired kypost")
}

func TestMeetingSyncReplayAndOrgRules(t *testing.T) {
	meeting := func(org string) []byte {
		m := map[string]any{"title": "Standup", "organizer_sub": "sub-alice"}
		if org != "" {
			m["org_id"] = org
		}
		b, _ := json.Marshal(m)
		return b
	}
	put := func(raw []byte, id string) signed {
		return signed{method: http.MethodPut, path: "/api/meetings/ext-replay", event: "kycalendar.meeting.put", key: testMultiTenantHMAC, raw: raw, id: id}
	}

	single := newSuiteEnv(t, config.TenancySingle)
	single.user("alice", "user", "")
	// #3 single mode refuses org_id on meeting routes.
	for _, raw := range [][]byte{meeting(suiteOrgA), []byte(`{"org_id":null,"title":"x"}`)} {
		if rec := single.do(single.srv, put(raw, "")); rec.Code != http.StatusBadRequest {
			t.Fatalf("single PUT with org_id %s = %d", raw, rec.Code)
		}
	}
	if rec := single.do(single.srv, signed{method: http.MethodDelete, path: "/api/meetings/ext-replay", event: "kycalendar.meeting.close", key: testMultiTenantHMAC, raw: []byte(`{"org_id":""}`)}); rec.Code != http.StatusBadRequest {
		t.Fatalf("single DELETE with org_id = %d", rec.Code)
	}
	// #5 replay on the meeting routes.
	if rec := single.do(single.srv, put(meeting(""), "evt-meet-1")); rec.Code != http.StatusOK {
		t.Fatalf("single PUT = %d %s", rec.Code, rec.Body.String())
	}
	if rec := single.do(single.srv, put(meeting(""), "evt-meet-1")); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("replayed PUT = %d %s", rec.Code, rec.Body.String())
	}

	// #2 multi mode requires a canonical org_id.
	multi := newSuiteEnv(t, config.TenancyMulti)
	for _, org := range []string{strings.ToUpper(suiteOrgA), "org-a"} {
		if rec := multi.do(multi.srv, put(meeting(org), "")); rec.Code != http.StatusBadRequest {
			t.Fatalf("multi PUT org_id %q = %d", org, rec.Code)
		}
	}
}
