package api_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
)

// agentPathID is a syntactically valid agent UUID used by authz_test.go.
const agentPathID = "00000000-0000-0000-0000-000000000001"

type agentOwnerBody struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

type agentRowBody struct {
	ID          string         `json:"id"`
	UserID      string         `json:"user_id"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	Owner       agentOwnerBody `json:"owner"`
	TokenState  string         `json:"token_state"`
	LastUsedAt  *time.Time     `json:"last_used_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

type agentListBody struct {
	Agents []agentRowBody   `json:"agents"`
	Owners []agentOwnerBody `json:"owners"`
}

type agentTokenBody struct {
	Agent   agentRowBody      `json:"agent"`
	Token   string            `json:"token"`
	Configs map[string]string `json:"configs"`
}

func botDo(t *testing.T, srv *api.Server, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestNativeAgentLifecycleAuthGuardrailsAndWS(t *testing.T) {
	ctx := context.Background()
	srv, st, cfg := setupTestServer(t)
	cfg.Server.AppURL = "https://chat.example.com"
	admin := loginAs(t, srv, st, "root", "admin")
	ownerCookie := loginAs(t, srv, st, "alice", "user")
	aliceUser, err := st.Users().GetLocalUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	// List returns owners including active users and excludes bots.
	list := decode[agentListBody](t, adminDo(t, srv, admin, "GET", "/api/admin/agents", nil))
	if len(list.Agents) != 0 {
		t.Fatalf("initial agents: %+v", list.Agents)
	}
	if len(list.Owners) < 2 {
		t.Fatalf("expected owners list, got %+v", list.Owners)
	}

	// Create agent requires fresh admin.
	stale := staleAdmin(t, st)
	if w := adminDo(t, srv, stale, "POST", "/api/admin/agents", map[string]string{
		"name": "agent-triage", "owner": aliceUser.ID,
	}); w.Code != http.StatusForbidden {
		t.Fatalf("stale admin create: %d %s", w.Code, w.Body.String())
	}

	// Validation: bad name, bad owner.
	for _, bad := range []map[string]string{
		{"name": "triage", "owner": aliceUser.ID},
		{"name": "agent-UPPER", "owner": aliceUser.ID},
		{"name": "agent-triage", "owner": "usr_missing"},
	} {
		if w := adminDo(t, srv, admin, "POST", "/api/admin/agents", bad); w.Code != http.StatusBadRequest {
			t.Errorf("bad create %v: got %d %s", bad, w.Code, w.Body.String())
		}
	}

	// Create native bot agent.
	w := adminDo(t, srv, admin, "POST", "/api/admin/agents", map[string]string{
		"name":         "agent-triage",
		"display_name": "Triage Bot",
		"owner":        aliceUser.ID,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("create agent: %d %s", w.Code, w.Body.String())
	}
	var created agentTokenBody
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, auth.AgentTokenPrefix) {
		t.Fatalf("token %q missing %q prefix", created.Token, auth.AgentTokenPrefix)
	}
	if created.Agent.Username != "agent-triage" || created.Agent.DisplayName != "Triage Bot" ||
		created.Agent.Owner.ID != aliceUser.ID || created.Agent.TokenState != store.AgentTokenActive ||
		!strings.HasPrefix(created.Agent.UserID, "bot_") {
		t.Fatalf("unexpected agent: %+v", created.Agent)
	}
	if !strings.Contains(created.Configs["openclaw"], created.Token) ||
		!strings.Contains(created.Configs["hermes"], "https://chat.example.com") {
		t.Fatalf("unexpected configs: %+v", created.Configs)
	}

	// Duplicate name returns 409.
	if dup := adminDo(t, srv, admin, "POST", "/api/admin/agents", map[string]string{
		"name": "agent-triage", "owner": aliceUser.ID,
	}); dup.Code != http.StatusConflict {
		t.Fatalf("duplicate name: got %d want 409 (%s)", dup.Code, dup.Body.String())
	}

	// GET /api/admin/agents never echoes the raw token or token_hash, and excludes bot from owners.
	listResp := adminDo(t, srv, admin, "GET", "/api/admin/agents", nil)
	if strings.Contains(listResp.Body.String(), created.Token) || strings.Contains(listResp.Body.String(), "token_hash") {
		t.Fatal("GET /api/admin/agents leaked secret")
	}
	list = decode[agentListBody](t, listResp)
	if len(list.Agents) != 1 || list.Agents[0].ID != created.Agent.ID {
		t.Fatalf("listed agents: %+v", list.Agents)
	}
	for _, o := range list.Owners {
		if o.ID == created.Agent.UserID {
			t.Fatal("bot user listed as an eligible owner")
		}
	}

	// Bot cannot authenticate via session cookie.
	cookieReq := httptest.NewRequest("GET", "/api/v1/rooms", nil)
	cookieReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: created.Token})
	cw := httptest.NewRecorder()
	srv.ServeHTTP(cw, cookieReq)
	if cw.Code != http.StatusUnauthorized {
		t.Fatalf("bot token via cookie: got %d want 401", cw.Code)
	}

	// Bot authenticates via Authorization: Bearer kybot_...
	me := decode[map[string]any](t, botDo(t, srv, created.Token, "GET", "/api/auth/me", nil))
	meUser, ok := me["user"].(map[string]any)
	if !ok || meUser["id"] != created.Agent.UserID || meUser["role"] != "bot" {
		t.Fatalf("bot /api/auth/me: %+v", me)
	}

	// Alice sees the bot with role="bot" in /api/v1/users, creates a room, and adds the bot.
	usersResp := decode[struct {
		Users []struct {
			ID, Username, Role string
		}
	}](t, adminDo(t, srv, ownerCookie, "GET", "/api/v1/users", nil))
	foundBot := false
	for _, u := range usersResp.Users {
		if u.ID == created.Agent.UserID && u.Role == "bot" {
			foundBot = true
		}
	}
	if !foundBot {
		t.Fatalf("bot missing or missing role=bot in /api/v1/users: %+v", usersResp.Users)
	}

	roomResp := adminDo(t, srv, ownerCookie, "POST", "/api/v1/rooms", map[string]any{
		"kind": "channel", "name": "triage", "member_ids": []string{created.Agent.UserID},
	})
	if roomResp.Code != http.StatusCreated {
		t.Fatalf("create room: %d %s", roomResp.Code, roomResp.Body.String())
	}
	var roomCreated struct {
		Room struct {
			ID string `json:"id"`
		} `json:"room"`
	}
	_ = json.Unmarshal(roomResp.Body.Bytes(), &roomCreated)
	roomID := roomCreated.Room.ID

	// Bot sends and reads a message in the invited room.
	sendResp := botDo(t, srv, created.Token, "POST", "/api/v1/rooms/"+roomID+"/messages", sealed("Hello from native Triage Bot!", nil))
	if sendResp.Code != http.StatusCreated {
		t.Fatalf("bot send message: %d %s", sendResp.Code, sendResp.Body.String())
	}
	msgs := decode[struct {
		Messages []struct {
			SenderID string `json:"sender_id"`
			Body     string `json:"body"`
		}
	}](t, botDo(t, srv, created.Token, "GET", "/api/v1/rooms/"+roomID+"/messages", nil))
	if len(msgs.Messages) != 1 || msgs.Messages[0].SenderID != created.Agent.UserID {
		t.Fatalf("bot list messages: %+v", msgs)
	}

	// Verify last_used_at was recorded.
	gotAgent, err := st.Agents().GetAgent(ctx, created.Agent.ID)
	if err != nil || gotAgent.LastUsedAt == nil {
		t.Fatalf("expected last_used_at to be set: agent=%+v err=%v", gotAgent, err)
	}

	// Guardrails: bot is forbidden from admin routes, creating rooms/meetings, joining calls, or pairing devices.
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/admin/agents", nil},
		{"POST", "/api/v1/rooms", map[string]any{"kind": "channel", "name": "nope"}},
		{"POST", "/api/v1/meetings", map[string]any{"title": "nope"}},
		{"POST", "/api/v1/rooms/" + roomID + "/calls/join", map[string]any{}},
		{"POST", "/api/v1/rooms/" + roomID + "/meeting/guest-link", map[string]any{}},
		{"POST", "/api/devices/pair/init", map[string]any{}},
	} {
		if rw := botDo(t, srv, created.Token, tc.method, tc.path, tc.body); rw.Code != http.StatusForbidden {
			t.Errorf("bot guardrail %s %s: got %d want 403 (%s)", tc.method, tc.path, rw.Code, rw.Body.String())
		}
	}

	// Bot connects via WebSocket with Bearer token and is disconnected immediately on rotate.
	ts := httptest.NewServer(srv)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	dialBotWS := func(tok string) (*websocket.Conn, error) {
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tok}},
		})
		return c, err
	}
	conn, err := dialBotWS(created.Token)
	if err != nil {
		t.Fatalf("bot ws dial: %v", err)
	}
	defer conn.CloseNow()

	// Rotate issues a new token, kills the old token and live WS immediately.
	rotated := decode[agentTokenBody](t, adminDo(t, srv, admin, "POST", "/api/admin/agents/"+created.Agent.ID+"/rotate", nil))
	if rotated.Token == created.Token || !strings.HasPrefix(rotated.Token, auth.AgentTokenPrefix) {
		t.Fatalf("rotate returned invalid token: %+v", rotated)
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		if _, _, err := conn.Read(readCtx); err != nil {
			break
		}
	}
	if w := botDo(t, srv, created.Token, "GET", "/api/v1/rooms", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotate: got %d want 401", w.Code)
	}
	if w := botDo(t, srv, rotated.Token, "GET", "/api/v1/rooms", nil); w.Code != http.StatusOK {
		t.Fatalf("new token after rotate: got %d want 200", w.Code)
	}

	// Revoke cuts access in one click (no fresh-admin step-up required) and disconnects WS.
	conn2, err := dialBotWS(rotated.Token)
	if err != nil {
		t.Fatalf("bot ws dial rotated: %v", err)
	}
	defer conn2.CloseNow()

	if rw := adminDo(t, srv, stale, "POST", "/api/admin/agents/"+created.Agent.ID+"/revoke", nil); rw.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rw.Code, rw.Body.String())
	}
	revAgent, err := st.Agents().GetAgent(ctx, created.Agent.ID)
	if err != nil || revAgent.TokenState != store.AgentTokenRevoked {
		t.Fatalf("after revoke: %+v err=%v", revAgent, err)
	}
	readCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	for {
		if _, _, err := conn2.Read(readCtx2); err != nil {
			break
		}
	}
	if w := botDo(t, srv, rotated.Token, "GET", "/api/v1/rooms", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token still accepted: %d", w.Code)
	}

	// Delete removes the agent row, marks bot user deleted, and preserves sent messages.
	if w := adminDo(t, srv, admin, "DELETE", "/api/admin/agents/"+created.Agent.ID, nil); w.Code != http.StatusOK {
		t.Fatalf("delete agent: %d %s", w.Code, w.Body.String())
	}
	botUser, err := st.Users().GetUserByID(ctx, created.Agent.UserID)
	if err != nil || botUser.Status != "deleted" {
		t.Fatalf("bot user after delete: %+v err=%v", botUser, err)
	}
	aliceMsgs := decode[struct {
		Messages []struct{ Body string }
	}](t, adminDo(t, srv, ownerCookie, "GET", "/api/v1/rooms/"+roomID+"/messages", nil))
	if len(aliceMsgs.Messages) != 1 || aliceMsgs.Messages[0].Body != testEnvelope("Hello from native Triage Bot!") {
		t.Fatalf("bot messages lost after delete: %+v", aliceMsgs)
	}
}

func TestNativeAgentOwnerOffboardingAndIdleExpiry(t *testing.T) {
	ctx := context.Background()
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	_ = loginAs(t, srv, st, "alice", "user")
	_ = loginAs(t, srv, st, "bob", "user")
	aliceUser, err := st.Users().GetLocalUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	bobUser, err := st.Users().GetLocalUserByUsername(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}

	mkAgent := func(name, ownerID string) agentTokenBody {
		w := adminDo(t, srv, admin, "POST", "/api/admin/agents", map[string]string{
			"name": name, "owner": ownerID,
		})
		if w.Code != http.StatusOK {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body.String())
		}
		var out agentTokenBody
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}

	idle := mkAgent("agent-idle", aliceUser.ID)
	active := mkAgent("agent-active", aliceUser.ID)
	ownedByBob := mkAgent("agent-bob", bobUser.ID)

	// Touch active recently; idle stays untouched and was created >90 days ago via ExpireIdleAgents clock.
	now := time.Now().UTC()
	if err := st.Agents().TouchAgentLastUsed(ctx, active.Agent.ID, now.Add(95*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Deactivate Bob: ownedByBob stops authenticating immediately even before maintenance sweep.
	bobUser.Status = "disabled"
	if err := st.Users().UpdateUser(ctx, bobUser); err != nil {
		t.Fatal(err)
	}
	if w := botDo(t, srv, ownedByBob.Token, "GET", "/api/v1/rooms", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("bot with disabled owner accepted: %d", w.Code)
	}

	// Maintenance sweep at now+96d expires idle (>90d), revokes ownedByBob (inactive owner), keeps active.
	srv.ExpireIdleAgents(ctx, now.Add(96*24*time.Hour))

	aIdle, _ := st.Agents().GetAgent(ctx, idle.Agent.ID)
	aActive, _ := st.Agents().GetAgent(ctx, active.Agent.ID)
	aBob, _ := st.Agents().GetAgent(ctx, ownedByBob.Agent.ID)
	if aIdle.TokenState != store.AgentTokenExpired || aIdle.TokenHash != "" {
		t.Errorf("idle agent not expired: %+v", aIdle)
	}
	if aActive.TokenState != store.AgentTokenActive {
		t.Errorf("active agent should remain active: %+v", aActive)
	}
	if aBob.TokenState != store.AgentTokenRevoked || aBob.TokenHash != "" {
		t.Errorf("disabled-owner agent not revoked: %+v", aBob)
	}
}

func TestAgentSkillZipDownload(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")

	w := adminDo(t, srv, admin, "GET", "/api/admin/agents/skill", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("skill.zip: got %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("invalid zip: %v", err)
	}
	foundSkill := false
	for _, f := range zr.File {
		if f.Name == "kymessages/SKILL.md" {
			foundSkill = true
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(rc)
			_ = rc.Close()
			if !strings.Contains(string(raw), "/api/v1/rooms") {
				t.Errorf("SKILL.md does not document native /api/v1/rooms API")
			}
		}
	}
	if !foundSkill {
		t.Fatal("kymessages/SKILL.md missing from skill.zip")
	}
}
