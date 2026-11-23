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

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
)

func createChatTestUser(t *testing.T, st store.Store, id, username, role string) (*store.User, string) {
	t.Helper()
	hash, err := password.Hash("TestPass123!")
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		ID:           id,
		Username:     username,
		Email:        username + "@example.com",
		DisplayName:  strings.ToUpper(username[:1]) + username[1:],
		PasswordHash: hash,
		Role:         role,
		Status:       "active",
	}
	if err := st.Users().CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser(%s): %v", username, err)
	}
	rawToken := "tok_" + crypto.RandomHex(24)
	sess := &store.Session{
		TokenHash: crypto.SHA256Hex([]byte(rawToken)),
		UserID:    u.ID,
		IPAddress: "127.0.0.1",
		UserAgent: "test",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.Sessions().CreateSession(context.Background(), sess, u.PasswordHash); err != nil {
		t.Fatalf("CreateSession(%s): %v", username, err)
	}
	return u, rawToken
}

func doBearerJSON(t *testing.T, handler http.Handler, method, path, token string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func readWSEvent(t *testing.T, conn *websocket.Conn) chat.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws Read: %v", err)
	}
	var ev chat.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("unmarshal ws event: %v", err)
	}
	return ev
}

func startChatBus(t *testing.T, srv *api.Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.RunChatBus(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := srv.ChatHub().WaitReady(readyCtx); err != nil {
		t.Fatalf("wait for chat bus ready: %v", err)
	}
}

func TestChatEndToEndRESTAndWebSocket(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()

	ts := httptest.NewServer(srv)
	defer ts.Close()
	cfg.Server.AppURL = ts.URL

	alice, aliceTok := createChatTestUser(t, st, "usr_chat_alice", "alice_chat", "admin")
	bob, bobTok := createChatTestUser(t, st, "usr_chat_bob", "bob_chat", "user")
	_, eveTok := createChatTestUser(t, st, "usr_chat_eve", "eve_chat", "user")

	// 1. Bootstrap returns user + default tenant + empty rooms.
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/bootstrap", aliceTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap = %d (%s)", rec.Code, rec.Body.String())
	}
	var boot struct {
		Tenant store.Tenant        `json:"tenant"`
		Rooms  []store.RoomSummary `json:"rooms"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &boot); err != nil {
		t.Fatal(err)
	}
	if boot.Tenant.ID != store.DefaultTenantID || boot.Tenant.P2PPolicy != store.P2PPolicyHybrid {
		t.Fatalf("unexpected tenant in bootstrap: %+v", boot.Tenant)
	}

	// 2. Alice creates a private channel with Bob.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       "channel",
		"name":       "engineering",
		"topic":      "Native KyMessages",
		"is_private": true,
		"member_ids": []string{bob.ID},
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create room = %d (%s)", rec.Code, rec.Body.String())
	}
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	roomID := roomResp.Room.ID

	// 3. Connect Alice & Bob over /api/v1/ws with same-origin Origin.
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	dial := func(tok string) *websocket.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{
				"Authorization": []string{"Bearer " + tok},
				"Origin":        []string{ts.URL},
			},
		})
		if err != nil {
			t.Fatalf("ws dial: %v", err)
		}
		t.Cleanup(func() { _ = c.CloseNow() })
		if ev := readWSEvent(t, c); ev.Type != chat.EventHello {
			t.Fatalf("expected hello, got %+v", ev)
		}
		return c
	}
	aliceWS := dial(aliceTok)
	bobWS := dial(bobTok)

	// 4. Alice posts a message with Idempotency-Key; Bob receives real-time message.new.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", aliceTok,
		map[string]any{"body": "hello native world"},
		map[string]string{"Idempotency-Key": "idem-1"},
	)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send msg = %d (%s)", rec.Code, rec.Body.String())
	}
	var msgResp struct {
		Message store.Message `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &msgResp)
	msgID := msgResp.Message.ID
	if msgResp.Message.Seq != 1 {
		t.Fatalf("seq = %d, want 1", msgResp.Message.Seq)
	}

	if ev := readWSEvent(t, bobWS); ev.Type != chat.EventMessageNew || ev.Seq != 1 {
		t.Fatalf("bob ws event = %+v, want message.new seq 1", ev)
	}
	if ev := readWSEvent(t, aliceWS); ev.Type != chat.EventMessageNew || ev.Seq != 1 {
		t.Fatalf("alice ws event = %+v, want message.new seq 1", ev)
	}

	// Idempotent retry returns 200 and same message ID/seq.
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/messages", aliceTok,
		map[string]any{"body": "duplicate"},
		map[string]string{"Idempotency-Key": "idem-1"},
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent retry = %d, want 200", rec.Code)
	}

	// 5. Reaction & Edit & Read Cursor sync.
	rec = doBearerJSON(t, srv, http.MethodPut, "/api/v1/rooms/"+roomID+"/messages/"+msgID+"/reactions/🚀", bobTok, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("add reaction = %d (%s)", rec.Code, rec.Body.String())
	}
	if ev := readWSEvent(t, aliceWS); ev.Type != chat.EventReactionSet {
		t.Fatalf("alice reaction event = %+v", ev)
	}
	_ = readWSEvent(t, bobWS)

	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+roomID+"/read", bobTok, map[string]any{"seq": 1}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark read = %d", rec.Code)
	}
	if ev := readWSEvent(t, bobWS); ev.Type != chat.EventReadSync {
		t.Fatalf("bob read sync event = %+v", ev)
	}

	// 6. IDOR checks: non-member Eve gets 404 everywhere and zero search hits.
	for _, check := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/rooms/" + roomID, nil},
		{http.MethodGet, "/api/v1/rooms/" + roomID + "/messages", nil},
		{http.MethodPost, "/api/v1/rooms/" + roomID + "/messages", map[string]any{"body": "sneak"}},
		{http.MethodPost, "/api/v1/rooms/" + roomID + "/read", map[string]any{"seq": 1}},
	} {
		r := doBearerJSON(t, srv, check.method, check.path, eveTok, check.body, nil)
		if r.Code != http.StatusNotFound {
			t.Fatalf("IDOR %s %s as non-member = %d, want 404", check.method, check.path, r.Code)
		}
	}

	// 7. DM deduplication.
	dm1 := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind": "dm", "dm_user_id": bob.ID,
	}, nil)
	if dm1.Code != http.StatusCreated {
		t.Fatalf("dm1 = %d (%s)", dm1.Code, dm1.Body.String())
	}
	dm2 := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", bobTok, map[string]any{
		"kind": "dm", "dm_user_id": alice.ID,
	}, nil)
	if dm2.Code != http.StatusOK {
		t.Fatalf("dm2 dedup = %d, want 200", dm2.Code)
	}
}

func TestChatSecurityCSWSHGoneWebhooksAndInstantRevocation(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	startChatBus(t, srv)
	defer srv.CloseChat()

	ts := httptest.NewServer(srv)
	defer ts.Close()
	cfg.Server.AppURL = ts.URL

	alice, aliceTok := createChatTestUser(t, st, "usr_sec_alice", "sec_alice", "admin")
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

	// 1. CSWSH: cross-origin WebSocket upgrade MUST be rejected with 403.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + aliceTok},
			"Origin":        []string{"https://evil.attacker.example"},
		},
	})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin WS dial = (err=%v, resp=%+v), want 403 Forbidden", err, resp)
	}

	// Cookie-authenticated upgrade with missing Origin MUST also be rejected with 403.
	_, resp, err = websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Cookie": []string{"ky_session=" + aliceTok},
		},
	})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie WS without Origin = (err=%v, resp=%+v), want 403 Forbidden", err, resp)
	}

	// 2. Incoming webhooks are gone: every sender gets the same 410, whatever the ID or token.
	for _, path := range []string{"/api/v1/webhooks/in/whk_anything", "/api/v1/webhooks/in/unknown"} {
		rec := doBearerJSON(t, srv, http.MethodPost, path, "kywh_any", map[string]any{"text": "hi"}, nil)
		if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), `"code":"gone"`) {
			t.Fatalf("incoming webhook %s = %d %s, want 410 gone", path, rec.Code, rec.Body.String())
		}
	}

	// Connect Alice WS to observe real-time webhook message.
	aliceWS, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + aliceTok},
			"Origin":        []string{ts.URL},
		},
	})
	if err != nil {
		t.Fatalf("alice ws dial: %v", err)
	}
	defer func() { _ = aliceWS.CloseNow() }()
	_ = readWSEvent(t, aliceWS) // hello

	// 3. Instant logout disconnects Alice's live WebSocket immediately.
	logout := doBearerJSON(t, srv, http.MethodPost, "/api/auth/logout", aliceTok, nil, nil)
	if logout.Code != http.StatusOK {
		t.Fatalf("logout = %d", logout.Code)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	for {
		_, data, err := aliceWS.Read(readCtx)
		if err != nil {
			break // closed as expected
		}
		var frame chat.Event
		_ = json.Unmarshal(data, &frame)
		if frame.Type != chat.EventAuthRevoked {
			t.Fatalf("unexpected frame after logout: %+v", frame)
		}
	}

	// Verify Hub cleaned up the connection.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		clients, _, _ := srv.ChatHub().Stats()
		if clients == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if clients, _, _ := srv.ChatHub().Stats(); clients != 0 {
		t.Fatalf("expected 0 live clients after logout, got %d (user %s)", clients, alice.ID)
	}
	_ = api.NewServer // ensure api import stays used
}

func TestChatUsersDirectoryAndDMDisplayNames(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	defer srv.CloseChat()
	alice, aliceTok := createChatTestUser(t, st, "usr_dir_alice", "alice_dir", "user")
	bob, bobTok := createChatTestUser(t, st, "usr_dir_bob", "bob_dir", "user")

	// GET /api/v1/users exposes minimal active directory entries.
	dirRec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/users", aliceTok, nil, nil)
	if dirRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users = %d, body=%s", dirRec.Code, dirRec.Body.String())
	}
	var dirResp struct {
		Users []struct {
			ID          string `json:"id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
		} `json:"users"`
	}
	if err := json.Unmarshal(dirRec.Body.Bytes(), &dirResp); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	if len(dirResp.Users) < 2 {
		t.Fatalf("expected at least 2 active directory users, got %d", len(dirResp.Users))
	}

	// Create DM between Alice and Bob; Alice should see Bob's display name and Bob should see Alice's.
	dmRec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{
		"kind":       "dm",
		"dm_user_id": bob.ID,
	}, nil)
	if dmRec.Code != http.StatusCreated {
		t.Fatalf("create DM = %d, body=%s", dmRec.Code, dmRec.Body.String())
	}

	aliceRooms := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", aliceTok, nil, nil)
	var aResp struct {
		Rooms []store.RoomSummary `json:"rooms"`
	}
	_ = json.Unmarshal(aliceRooms.Body.Bytes(), &aResp)
	if len(aResp.Rooms) != 1 || aResp.Rooms[0].Name != bob.DisplayName {
		t.Fatalf("Alice DM name = %+v, want %q", aResp.Rooms, bob.DisplayName)
	}

	bobBoot := doBearerJSON(t, srv, http.MethodGet, "/api/v1/bootstrap", bobTok, nil, nil)
	var bResp struct {
		Rooms []store.RoomSummary `json:"rooms"`
	}
	_ = json.Unmarshal(bobBoot.Body.Bytes(), &bResp)
	if len(bResp.Rooms) != 1 || bResp.Rooms[0].Name != alice.DisplayName {
		t.Fatalf("Bob DM name = %+v, want %q", bResp.Rooms, alice.DisplayName)
	}
}
