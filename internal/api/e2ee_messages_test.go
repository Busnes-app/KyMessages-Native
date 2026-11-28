package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

type sentMessage struct {
	Message store.Message `json:"message"`
}

// encryptedRoomFixture is a channel holding alice (a browser session) and a kybot_ bot.
func encryptedRoomFixture(t *testing.T) (srv *api.Server, alice *http.Cookie, botToken, roomPath string) {
	t.Helper()
	ctx := context.Background()
	srv, st, cfg := setupTestServer(t)
	cfg.Server.AppURL = "https://chat.example.com"
	admin := loginAs(t, srv, st, "root", "admin")
	alice = loginAs(t, srv, st, "alice", "user")
	aliceUser, err := st.Users().GetLocalUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	created := decode[agentTokenBody](t, adminDo(t, srv, admin, "POST", "/api/admin/agents", map[string]string{
		"name": "agent-relay", "owner": aliceUser.ID,
	}))
	rec := adminDo(t, srv, alice, "POST", "/api/v1/rooms", map[string]any{
		"kind": "channel", "name": "sealed", "member_ids": []string{created.Agent.UserID},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d %s", rec.Code, rec.Body.String())
	}
	var room struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &room)
	return srv, alice, created.Token, "/api/v1/rooms/" + room.Room.ID + "/messages"
}

func refusalCode(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Code
}

func TestMembersMustSendEncryptedMessages(t *testing.T) {
	srv, alice, _, msgs := encryptedRoomFixture(t)

	// plain_v1, named or by default, is refused to a member's session with a clear code.
	for _, body := range []map[string]any{
		{"body": "hello"},
		{"body": "hello", "encoding": "plain_v1"},
		{"body": "", "encoding": "plain_v1", "attachment_ids": []string{"att_x"}},
	} {
		rec := adminDo(t, srv, alice, "POST", msgs, body)
		if rec.Code != http.StatusBadRequest || refusalCode(t, rec.Body.Bytes()) != api.CodeE2EERequired {
			t.Fatalf("plain_v1 %v from a member = %d %s, want 400 %s", body, rec.Code, rec.Body.String(), api.CodeE2EERequired)
		}
	}

	// An envelope is stored and relayed exactly as sent; the server never opens it.
	env := testEnvelope("hello, sealed")
	rec := adminDo(t, srv, alice, "POST", msgs, map[string]any{"body": env, "encoding": "e2ee_room_v1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("envelope send = %d %s", rec.Code, rec.Body.String())
	}
	var sent sentMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &sent)
	if sent.Message.Body != env || sent.Message.Encoding != store.MessageEncodingE2EERoomV1 {
		t.Fatalf("stored message = %+v", sent.Message)
	}

	// Edits are encrypted too.
	edit := msgs + "/" + sent.Message.ID
	if rec := adminDo(t, srv, alice, "PATCH", edit, map[string]any{"body": "edited in the clear"}); rec.Code != http.StatusBadRequest || refusalCode(t, rec.Body.Bytes()) != api.CodeE2EERequired {
		t.Fatalf("plain edit = %d %s, want 400 %s", rec.Code, rec.Body.String(), api.CodeE2EERequired)
	}
	env2 := testEnvelope("edited, sealed")
	rec = adminDo(t, srv, alice, "PATCH", edit, map[string]any{"body": env2, "encoding": "e2ee_room_v1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("envelope edit = %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sent)
	if sent.Message.Body != env2 || sent.Message.Encoding != store.MessageEncodingE2EERoomV1 || sent.Message.EditedAt == nil {
		t.Fatalf("edited message = %+v", sent.Message)
	}
}

func TestEnvelopeShapeIsChecked(t *testing.T) {
	srv, alice, _, msgs := encryptedRoomFixture(t)
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	envelope := func(edit func(map[string]any)) string {
		m := map[string]any{"alg": "megolm.v1", "sender_key": key, "device_id": "DEVICE0001", "session_id": key, "ciphertext": "AwgA"}
		edit(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	for name, body := range map[string]string{
		"plaintext":        "hello",
		"wrong alg":        envelope(func(m map[string]any) { m["alg"] = "none" }),
		"short key":        envelope(func(m map[string]any) { m["sender_key"] = "AAAA" }),
		"bad device":       envelope(func(m map[string]any) { m["device_id"] = "x" }),
		"empty ciphertext": envelope(func(m map[string]any) { m["ciphertext"] = "" }),
		"padded base64":    envelope(func(m map[string]any) { m["ciphertext"] = "AwgA==" }),
		"extra field":      envelope(func(m map[string]any) { m["body"] = "hello" }),
		"trailing data":    envelope(func(map[string]any) {}) + `{}`,
		"oversized":        envelope(func(m map[string]any) { m["ciphertext"] = strings.Repeat("A", 48<<10) }),
	} {
		if rec := adminDo(t, srv, alice, "POST", msgs, map[string]any{"body": body, "encoding": "e2ee_room_v1"}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: envelope send = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if rec := adminDo(t, srv, alice, "POST", msgs, map[string]any{"body": envelope(func(map[string]any) {}), "encoding": "e2ee_room_v1"}); rec.Code != http.StatusCreated {
		t.Fatalf("valid envelope = %d %s", rec.Code, rec.Body.String())
	}
}

// E4 ends the plaintext transition: a bot token is refused plain_v1 like everyone (spec §10),
// and posts envelopes as a device.
func TestBotTokensAreRefusedPlaintextSinceE4(t *testing.T) {
	srv, _, botToken, msgs := encryptedRoomFixture(t)

	for name, body := range map[string]map[string]any{
		"omitted encoding": {"body": "build passed"},
		"plain_v1":         {"body": "build passed", "encoding": "plain_v1"},
	} {
		rec := botDo(t, srv, botToken, "POST", msgs, body)
		if rec.Code != http.StatusBadRequest || refusalCode(t, rec.Body.Bytes()) != api.CodeE2EERequired {
			t.Fatalf("%s: bot plain send = %d %s, want 400 e2ee_required", name, rec.Code, rec.Body.String())
		}
	}
	rec := botDo(t, srv, botToken, "POST", msgs, sealed("build passed", nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("bot envelope send = %d %s", rec.Code, rec.Body.String())
	}
	var sent sentMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &sent)
	if sent.Message.Encoding != store.MessageEncodingE2EERoomV1 {
		t.Fatalf("bot message = %+v", sent.Message)
	}
	if rec := botDo(t, srv, botToken, "PATCH", msgs+"/"+sent.Message.ID, map[string]any{"body": "build passed (2)", "encoding": "plain_v1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bot plain edit = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestCSPLetsTheBrowserCompileWebAssemblyOnly(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	rec := doBearerJSON(t, srv, http.MethodGet, "/", "", nil, nil)
	csp := rec.Header().Get("Content-Security-Policy")
	var scriptSrc string
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") {
			scriptSrc = d
		}
	}
	// 'wasm-unsafe-eval' allows WebAssembly.compile and nothing else: no eval, no inline script.
	if scriptSrc != "script-src 'self' 'wasm-unsafe-eval'" {
		t.Fatalf("script-src = %q in %q", scriptSrc, csp)
	}
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lost %q: %s", want, csp)
		}
	}
}
