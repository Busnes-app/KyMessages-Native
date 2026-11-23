package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"github.com/google/uuid"
)

const (
	replicaOrgA = "00000000-0000-4000-8000-0000000000a1"
	replicaOrgB = "00000000-0000-4000-8000-0000000000b1"
)

// newReplicas starts two multi-mode servers on one database, as two replicas would run.
func newReplicas(t *testing.T, opts ...func(*config.Config)) (a, b *api.Server, st store.Store, cfg *config.Config) {
	t.Helper()
	db := testdb.Config(t)
	cfg = &config.Config{
		Server:   config.ServerConfig{AppName: "KyMessages", AppURL: "https://chat.example.com"},
		Database: config.DatabaseConfig{DataDir: t.TempDir()},
		Security: config.SecurityConfig{SessionTTL: time.Hour, SessionSecret: "replica-shared-session-secret-0123456789"},
		SSO:      config.SSOConfig{KyIdentityHMACSecret: testMultiTenantHMAC},
		RTC:      config.RTCConfig{MeetingSyncSecret: testMultiTenantHMAC},
		Tenancy:  config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: testStaffOrg},
	}
	for _, o := range opts {
		o(cfg)
	}
	open := func() (*api.Server, store.Store) {
		s, err := store.Open(context.Background(), db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := api.EnsureTenancyMode(context.Background(), s, cfg.Tenancy); err != nil {
			t.Fatal(err)
		}
		srv := api.NewServer(cfg, s)
		t.Cleanup(func() { srv.WaitDetached() })
		return srv, s
	}
	a, st = open()
	b, _ = open()
	return a, b, st, cfg
}

// One sign-in budget across replicas: failures on either count toward the same limit.
func TestReplicasShareTheSignInBudget(t *testing.T) {
	a, b, st, _ := newReplicas(t)
	createLocalUser(t, st, "usr_rep", "replica", "user", "ReplicaPass123!")
	wrong := map[string]string{"username": "replica", "password": "nope"}
	for i := range 10 {
		srv := a
		if i%2 == 1 {
			srv = b
		}
		if w := postJSON(t, srv, "/api/auth/login", "192.0.2.50:1", wrong); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i+1, w.Code)
		}
	}
	right := map[string]string{"username": "replica", "password": "ReplicaPass123!"}
	for name, srv := range map[string]*api.Server{"a": a, "b": b} {
		if w := postJSON(t, srv, "/api/auth/login", "192.0.2.50:1", right); w.Code != http.StatusTooManyRequests {
			t.Fatalf("replica %s after ten failures across both = %d, want 429", name, w.Code)
		}
	}
	// Another client keeps its own budget.
	if w := postJSON(t, b, "/api/auth/login", "192.0.2.51:1", right); w.Code != http.StatusOK {
		t.Fatalf("other client = %d, want 200", w.Code)
	}
}

func solvePoW(t *testing.T, secret string) string {
	t.Helper()
	ch, err := auth.GeneratePoWChallenge(50, secret)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= ch.MaxNumber; n++ {
		if crypto.SHA256Hex([]byte(ch.Salt+strconv.Itoa(n))) == ch.Challenge {
			sol, _ := json.Marshal(auth.PoWSolution{Algorithm: ch.Algorithm, Salt: ch.Salt, Challenge: ch.Challenge,
				Number: n, MaxNumber: ch.MaxNumber, ExpiresAt: ch.ExpiresAt, Signature: ch.Signature})
			return base64.StdEncoding.EncodeToString(sol)
		}
	}
	t.Fatal("no solution")
	return ""
}

// A solved challenge is spent everywhere: replaying it on the other replica fails.
func TestReplicasSpendProofOfWorkOnce(t *testing.T) {
	a, b, st, cfg := newReplicas(t)
	cfg.Captcha.Provider = "pow"
	createLocalUser(t, st, "usr_powrep", "powrep", "user", "PowRepPass123!")
	body := map[string]string{"username": "powrep", "password": "PowRepPass123!", "captcha_token": solvePoW(t, cfg.Security.SessionSecret)}
	if w := postJSON(t, a, "/api/auth/login", "192.0.2.60:1", body); w.Code != http.StatusOK {
		t.Fatalf("first use on a = %d: %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, b, "/api/auth/login", "192.0.2.60:1", body); w.Code != http.StatusForbidden {
		t.Fatalf("replay on b = %d, want 403", w.Code)
	}
	if w := postJSON(t, a, "/api/auth/login", "192.0.2.60:1", body); w.Code != http.StatusForbidden {
		t.Fatalf("replay on a = %d, want 403", w.Code)
	}
}

type replicaMeeting struct {
	roomID, token string
}

func putMeeting(t *testing.T, srv http.Handler, id, org, organizerSub string) replicaMeeting {
	t.Helper()
	now := time.Now().UTC()
	raw, _ := json.Marshal(map[string]any{"org_id": org, "title": "Shared " + org[len(org)-2:], "organizer_sub": organizerSub,
		"member_subs": []string{organizerSub}, "guests": []map[string]string{{"key": "client"}},
		"windows": []map[string]string{{"start": now.Add(-time.Minute).Format(time.RFC3339), "end": now.Add(time.Hour).Format(time.RFC3339)}}})
	req := httptest.NewRequest(http.MethodPut, "/api/meetings/"+id, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "meeting.sync", uuid.NewString(), raw)
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT meeting %s for %s = %d: %s", id, org, rec.Code, rec.Body.String())
	}
	var m struct {
		RoomID    string            `json:"room_id"`
		GuestURLs map[string]string `json:"guest_urls"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	_, tok, _ := strings.Cut(m.GuestURLs["client"], "/meet/")
	return replicaMeeting{roomID: m.RoomID, token: tok}
}

func guestKnock(t *testing.T, srv http.Handler, token string) (guestID, secret string) {
	t.Helper()
	rec := goldenWithCookie(srv, http.MethodPost, "/api/meet/"+token+"/knock", nil, `{"display_name":"Visitor"}`)
	var k struct {
		GuestID string `json:"guest_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &k)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "ky_guest_session" {
			secret = c.Value
		}
	}
	if rec.Code != http.StatusOK || k.GuestID == "" || secret == "" {
		t.Fatalf("knock = %d: %s", rec.Code, rec.Body.String())
	}
	return k.GuestID, secret
}

func guestMessages(srv http.Handler, token, secret string) int {
	return goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token+"/messages", &http.Cookie{Name: "ky_guest_session", Value: secret}, "").Code
}

// A guest knocks on one replica, is listed and admitted on the other, and is recognised on both.
func TestReplicasShareGuestSessions(t *testing.T) {
	a, b, st, _ := newReplicas(t)
	host, hostTok := createOrgUser(t, st, "usr_rep_host", "rephost", "user", replicaOrgA)
	m := putMeeting(t, a, "shared-1", replicaOrgA, host.SSOSubject)
	guestID, secret := guestKnock(t, a, m.token)

	if code := guestMessages(b, m.token, secret); code != http.StatusForbidden {
		t.Fatalf("waiting guest on b = %d, want 403 (known, not yet admitted)", code)
	}
	rec := doBearerJSON(t, b, http.MethodGet, "/api/v1/rooms/"+m.roomID+"/lobby", hostTok, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), guestID) {
		t.Fatalf("lobby on b = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doBearerJSON(t, b, http.MethodPost, "/api/v1/rooms/"+m.roomID+"/lobby/"+guestID+"/admit", hostTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admit on b = %d: %s", rec.Code, rec.Body.String())
	}
	for name, srv := range map[string]*api.Server{"a": a, "b": b} {
		if code := guestMessages(srv, m.token, secret); code != http.StatusOK {
			t.Fatalf("admitted guest on %s = %d, want 200", name, code)
		}
	}
	// A second knock with the same invite replaces the first session everywhere.
	_, secret2 := guestKnock(t, b, m.token)
	if code := guestMessages(a, m.token, secret); code != http.StatusUnauthorized {
		t.Fatalf("replaced session on a = %d, want 401", code)
	}
	if code := guestMessages(a, m.token, secret2); code != http.StatusForbidden {
		t.Fatalf("new session on a = %d, want 403", code)
	}
	// Closing the meeting on one replica ends the session on both.
	raw := []byte(`{"org_id":"` + replicaOrgA + `"}`)
	req := httptest.NewRequest(http.MethodDelete, "/api/meetings/shared-1", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h, _ := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "meeting.close", uuid.NewString(), raw)
	h.Apply(req)
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("close = %d: %s", rr.Code, rr.Body.String())
	}
	if code := guestMessages(b, m.token, secret2); code != http.StatusNotFound {
		t.Fatalf("guest after close on b = %d, want 404", code)
	}
}

// Two orgs hold the same meeting ID: each gets its own meeting, room and lobby, and nothing
// one org does reaches the other's guest.
func TestTwoOrgsShareAMeetingIDButNothingElse(t *testing.T) {
	a, b, st, _ := newReplicas(t)
	hostA, tokA := createOrgUser(t, st, "usr_rep_ha", "repha", "user", replicaOrgA)
	hostB, tokB := createOrgUser(t, st, "usr_rep_hb", "rephb", "user", replicaOrgB)
	ma := putMeeting(t, a, "same-id", replicaOrgA, hostA.SSOSubject)
	mb := putMeeting(t, b, "same-id", replicaOrgB, hostB.SSOSubject)
	if ma.roomID == mb.roomID || ma.token == mb.token {
		t.Fatal("two orgs' meetings with one ID share a room or a link")
	}
	// Updating one org's meeting leaves the other's untouched.
	_ = putMeeting(t, a, "same-id", replicaOrgA, hostA.SSOSubject)
	if code := goldenWithCookie(b, http.MethodGet, "/api/meet/"+mb.token, nil, "").Code; code != http.StatusOK {
		t.Fatalf("org B link after org A update = %d", code)
	}

	gA, sA := guestKnock(t, a, ma.token)
	gB, sB := guestKnock(t, b, mb.token)
	lobbyA := doBearerJSON(t, b, http.MethodGet, "/api/v1/rooms/"+ma.roomID+"/lobby", tokA, nil, nil).Body.String()
	if !strings.Contains(lobbyA, gA) || strings.Contains(lobbyA, gB) {
		t.Fatalf("org A lobby: %s", lobbyA)
	}
	// Org A's host cannot see or admit org B's guest.
	if rec := doBearerJSON(t, a, http.MethodGet, "/api/v1/rooms/"+mb.roomID+"/lobby", tokA, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("org A host on org B lobby = %d, want 404", rec.Code)
	}
	if rec := doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms/"+ma.roomID+"/lobby/"+gB+"/admit", tokA, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("org A host admitting org B guest = %d, want 404", rec.Code)
	}
	if rec := doBearerJSON(t, b, http.MethodPost, "/api/v1/rooms/"+ma.roomID+"/lobby/"+gA+"/admit", tokA, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admit org A guest = %d", rec.Code)
	}
	if code := guestMessages(a, ma.token, sA); code != http.StatusOK {
		t.Fatalf("org A guest after admit = %d", code)
	}
	if code := guestMessages(a, mb.token, sB); code != http.StatusForbidden {
		t.Fatalf("org B guest after org A admission = %d, want 403 (still waiting)", code)
	}
	// One org's session secret is no key to the other's link.
	if code := guestMessages(b, mb.token, sA); code != http.StatusUnauthorized {
		t.Fatalf("org A secret on org B link = %d, want 401", code)
	}
	_ = tokB
}
