package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/single-tenant-golden.txt")

const goldenPath = "testdata/single-tenant-golden.txt"

// goldenScrub replaces values that differ per run (IDs, times, tokens) with placeholders.
var goldenScrub = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`), "<time>"},
	{regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), "<uuid>"},
	{regexp.MustCompile(`\b(att|msg|room|rm|mtg|g|gst|call)_[A-Za-z0-9-]{6,}`), "${1}_<id>"},
	{regexp.MustCompile(`/meet/[A-Za-z0-9_-]{16,}`), "/meet/<token>"},
	{regexp.MustCompile(`"(\w*_at|expires|created|updated|ts|at)":\s*-?\d{9,}`), `"$1":<num>`},
	{regexp.MustCompile(`[A-Za-z0-9_-]{32,}`), "<token>"},
}

func scrubGolden(s string) string {
	for _, r := range goldenScrub {
		s = r.re.ReplaceAllString(s, r.rep)
	}
	return s
}

// goldenLog records each answer as status, chosen headers and a scrubbed body.
type goldenLog struct{ b strings.Builder }

func (g *goldenLog) add(step string, rec *httptest.ResponseRecorder) {
	fmt.Fprintf(&g.b, "== %s\nstatus %d\n", step, rec.Code)
	for _, h := range []string{"Content-Type", "Content-Range", "Content-Length", "Retry-After"} {
		if v := rec.Header().Get(h); v != "" {
			fmt.Fprintf(&g.b, "%s: %s\n", h, v)
		}
	}
	body := rec.Body.Bytes()
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		fmt.Fprintf(&g.b, "%s\n", scrubGolden(strings.TrimSpace(string(body))))
	} else if len(body) > 0 {
		sum := sha256.Sum256(body)
		fmt.Fprintf(&g.b, "sha256 %s\n", hex.EncodeToString(sum[:]))
	}
}

func goldenSigned(srv http.Handler, secret, method, path, event string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	h, _ := syncauth.Sign([]byte(secret), time.Now(), event, "evt-"+crypto.RandomHex(8), raw)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func goldenWithCookie(srv http.Handler, method, path string, c *http.Cookie, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestSingleTenantGolden replays a fixed single-tenant script over every path the tenancy build
// touches (sign-in limits, proof of work, attachments and their cap, meetings and guests, backup
// status) and compares the answers with the transcript recorded before that build began. Any
// change in a single-tenant answer fails here. Regenerate only for an intended single-mode change:
// go test ./internal/api -run TestSingleTenantGolden -update-golden
func TestSingleTenantGolden(t *testing.T) {
	var g goldenLog

	// Sign-in limits: one peer, one account, repeated wrong passwords.
	{
		srv, st, _ := setupTestServer(t)
		createLocalUser(t, st, "usr_gold", "gold", "admin", "GoldPass123!")
		for i := 1; i <= 12; i++ {
			g.add(fmt.Sprintf("login wrong %d", i), postJSON(t, srv, "/api/auth/login", "192.0.2.10:1", map[string]string{"username": "gold", "password": "nope"}))
		}
		g.add("login right after limit", postJSON(t, srv, "/api/auth/login", "192.0.2.10:1", map[string]string{"username": "gold", "password": "GoldPass123!"}))
		g.add("login right other peer", postJSON(t, srv, "/api/auth/login", "192.0.2.11:1", map[string]string{"username": "gold", "password": "GoldPass123!"}))
	}

	// Proof of work: a solution is single use.
	{
		srv, st, cfg := setupTestServer(t)
		cfg.Captcha.Provider = "pow"
		createLocalUser(t, st, "usr_pow", "powgold", "user", "PowGoldPass123!")
		ch, err := auth.GeneratePoWChallenge(50, cfg.Security.SessionSecret)
		if err != nil {
			t.Fatal(err)
		}
		var tok string
		for n := 1; n <= ch.MaxNumber; n++ {
			if crypto.SHA256Hex([]byte(ch.Salt+strconv.Itoa(n))) == ch.Challenge {
				sol, _ := json.Marshal(auth.PoWSolution{Algorithm: ch.Algorithm, Salt: ch.Salt, Challenge: ch.Challenge,
					Number: n, MaxNumber: ch.MaxNumber, ExpiresAt: ch.ExpiresAt, Signature: ch.Signature})
				tok = base64.StdEncoding.EncodeToString(sol)
			}
		}
		body := map[string]string{"username": "powgold", "password": "PowGoldPass123!", "captcha_token": tok}
		g.add("pow first use", postJSON(t, srv, "/api/auth/login", "192.0.2.20:1", body))
		g.add("pow replay", postJSON(t, srv, "/api/auth/login", "192.0.2.20:1", body))
		g.add("pow missing", postJSON(t, srv, "/api/auth/login", "192.0.2.20:1", map[string]string{"username": "powgold", "password": "PowGoldPass123!"}))
		req := httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		g.add("pow challenge", rec)
	}

	// Attachments: upload, list, post, download, range, delete, and the per-install cap.
	{
		_, st, cfg := setupTestServer(t)
		cfg.Attachments.MaxUploadBytes = 2048
		cfg.Attachments.MaxPendingUserBytes = 2500
		cfg.Attachments.MaxTotalBytes = 3500
		cfg.Attachments.PendingTTL = time.Hour
		srv := api.NewServer(cfg, st)
		startChatBus(t, srv)
		defer srv.CloseChat()
		_, aliceTok := createChatTestUser(t, st, "u_g_alice", "galice", "user")
		_, bobTok := createChatTestUser(t, st, "u_g_bob", "gbob", "user")
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "gold-room", "member_ids": []string{"u_g_bob"}}, nil)
		g.add("create room", rec)
		var room struct {
			Room store.Room `json:"room"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &room)
		up := "/api/v1/rooms/" + room.Room.ID + "/attachments"
		file := bytes.Repeat([]byte("golden text line\n"), 100) // 1700 bytes
		rec = doMultipartUpload(t, srv, up, aliceTok, "file", "a.txt", file)
		g.add("upload a", rec)
		var att struct {
			Attachment store.Attachment `json:"attachment"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &att)
		g.add("upload over user staging cap", doMultipartUpload(t, srv, up, aliceTok, "file", "b.txt", file))
		g.add("upload oversize", doMultipartUpload(t, srv, up, aliceTok, "file", "c.txt", bytes.Repeat([]byte("x"), 2049)))
		g.add("list staged", doBearerJSON(t, srv, http.MethodGet, up, aliceTok, nil, nil))
		g.add("post message", doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room.Room.ID+"/messages", aliceTok, sealed("file", map[string]any{"attachment_ids": []string{att.Attachment.ID}}), nil))
		rec = doMultipartUpload(t, srv, up, bobTok, "file", "d.txt", file)
		g.add("bob upload", rec)
		var bobAtt struct {
			Attachment store.Attachment `json:"attachment"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &bobAtt)
		g.add("bob upload over install cap", doMultipartUpload(t, srv, up, bobTok, "file", "e.txt", file))
		g.add("download", doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+att.Attachment.ID, bobTok, nil, nil))
		g.add("download range", doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+att.Attachment.ID, bobTok, nil, map[string]string{"Range": "bytes=10-19"}))
		g.add("download unknown", doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/att_00000000-0000-7000-8000-000000000000", bobTok, nil, nil))
		g.add("delete by non-owner", doBearerJSON(t, srv, http.MethodDelete, "/api/v1/attachments/"+att.Attachment.ID, bobTok, nil, nil))
		g.add("delete by owner", doBearerJSON(t, srv, http.MethodDelete, "/api/v1/attachments/"+att.Attachment.ID, aliceTok, nil, nil))
		g.add("delete staged by owner", doBearerJSON(t, srv, http.MethodDelete, "/api/v1/attachments/"+bobAtt.Attachment.ID, bobTok, nil, nil))
		g.add("download staged deleted", doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+bobAtt.Attachment.ID, bobTok, nil, nil))
		g.add("upload after delete", doMultipartUpload(t, srv, up, bobTok, "file", "f.txt", file))
		g.add("download posted", doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+att.Attachment.ID, bobTok, nil, nil))
	}

	// Meetings and guests: create, update, the guest lobby, and close.
	{
		srv, st, _ := setupTestServer(t, withKyCalendar)
		startChatBus(t, srv)
		defer srv.CloseChat()
		host, hostTok := createChatTestUser(t, st, "u_g_host", "ghost", "user")
		host.SSOProvider, host.SSOSubject = "kyidentity", "sub-g-host"
		if err := st.Users().UpdateUser(context.Background(), host); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		meeting := func(title string) map[string]any {
			return map[string]any{"sub": "sub-g-host", "title": title, "member_subs": []string{"sub-g-host"},
				"guests":  []map[string]string{{"key": "ext-gold"}},
				"windows": []map[string]string{{"start": now.Add(-5 * time.Minute).Format(time.RFC3339), "end": now.Add(45 * time.Minute).Format(time.RFC3339)}}}
		}
		rec := calSigned(srv, testMultiTenantHMAC, http.MethodPut, "/api/meetings/gold-1", meeting("Gold"))
		g.add("meeting create", rec)
		var m struct {
			RoomID    string            `json:"room_id"`
			GuestURLs map[string]string `json:"guest_urls"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		g.add("meeting update", calSigned(srv, testMultiTenantHMAC, http.MethodPut, "/api/meetings/gold-1", meeting("Gold 2")))
		g.add("meeting bad signature", calSigned(srv, "wrong-secret-wrong-secret-wrong-secret!!", http.MethodPut, "/api/meetings/gold-1", meeting("Bad")))
		g.add("meeting with org_id in single", calSigned(srv, testMultiTenantHMAC, http.MethodPut, "/api/meetings/gold-2", map[string]any{"org_id": "00000000-0000-4000-8000-00000000000a", "sub": "sub-g-host", "title": "x"}))
		gu := m.GuestURLs["ext-gold"]
		token := gu[strings.LastIndex(gu, "/meet/")+len("/meet/"):]
		g.add("guest info", goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token, nil, ""))
		g.add("guest info unknown", goldenWithCookie(srv, http.MethodGet, "/api/meet/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil, ""))
		knock := goldenWithCookie(srv, http.MethodPost, "/api/meet/"+token+"/knock", nil, `{"display_name":"Gold Guest"}`)
		g.add("guest knock", knock)
		var k struct {
			GuestID string `json:"guest_id"`
		}
		_ = json.Unmarshal(knock.Body.Bytes(), &k)
		var gc *http.Cookie
		for _, c := range knock.Result().Cookies() {
			if c.Name == "ky_guest_session" {
				gc = c
			}
		}
		g.add("guest messages before admit", goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token+"/messages", gc, ""))
		g.add("guest messages no cookie", goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token+"/messages", nil, ""))
		g.add("lobby list", doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+m.RoomID+"/lobby", hostTok, nil, nil))
		g.add("admit", doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+m.RoomID+"/lobby/"+k.GuestID+"/admit", hostTok, nil, nil))
		g.add("guest post", goldenWithCookie(srv, http.MethodPost, "/api/meet/"+token+"/messages", gc, `{"body":"hello"}`))
		g.add("guest messages", goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token+"/messages", gc, ""))
		g.add("meeting close", calSigned(srv, testMultiTenantHMAC, http.MethodDelete, "/api/meetings/gold-1", map[string]any{"sub": "sub-g-host"}))
		g.add("guest after close", goldenWithCookie(srv, http.MethodGet, "/api/meet/"+token+"/messages", gc, ""))
	}

	// Backup status: the capsule scheduler stays on in single mode.
	{
		srv, st, _ := setupTestServer(t)
		admin := loginAs(t, srv, st, "goldadmin", "admin")
		rec := do(t, srv, http.MethodGet, "/api/backup/status", admin)
		var status map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &status)
		_, schedErr := status["scheduler_error"]
		fmt.Fprintf(&g.b, "== backup status\nstatus %d\nscheduler_error present %v\n", rec.Code, schedErr)
	}

	// Startup: single mode loads without the shared secrets multi mode requires.
	{
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_TENANCY_MODE", "")
		_, err := config.LoadFromEnv()
		fmt.Fprintf(&g.b, "== single config without shared secrets\nerror %v\n", err != nil)
	}

	got := g.b.String()
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("single-tenant answers changed.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
