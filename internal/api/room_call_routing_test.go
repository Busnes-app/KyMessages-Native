package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/coder/websocket"
)

func TestRoomCallHTTPAndSocketChooseOneAuthorizedReplica(t *testing.T) {
	a, b, st, _ := newReplicas(t)
	alice, token := createOrgUser(t, st, "routed-api-alice", "routedapialice", "user", replicaOrgA)
	bob, bobToken := createOrgUser(t, st, "routed-api-bob", "routedapibob", "user", replicaOrgA)
	_, outsider := createOrgUser(t, st, "routed-api-outside", "routedoutside", "user", replicaOrgB)
	room := roomOf(t, doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": "channel", "name": "affine", "member_ids": []string{bob.ID}}, nil))
	path := "/api/v1/rooms/" + room + "/calls/"
	join := doBearerJSON(t, a, http.MethodPost, path+"join", token, map[string]bool{"audio": true}, nil)
	if join.Code != http.StatusOK {
		t.Fatalf("join:%d %s", join.Code, join.Body.String())
	}
	var first struct {
		CallID string `json:"call_id"`
		Socket string `json:"call_ws_path"`
		PeerID string `json:"peer_id"`
	}
	if err := json.Unmarshal(join.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Socket != path+"ws" {
		t.Fatalf("unroutable call socket:%q", first.Socket)
	}
	for _, operation := range []struct{ method, path string }{{http.MethodGet, "state"}, {http.MethodPost, "join"}, {http.MethodPost, "escalate"}, {http.MethodPost, "leave"}} {
		result := doBearerJSON(t, b, operation.method, path+operation.path, token, map[string]bool{"audio": true}, nil)
		if result.Code != http.StatusServiceUnavailable || result.Header().Get("Retry-After") == "" || !strings.Contains(result.Body.String(), "call_owner_unavailable") {
			t.Fatalf("wrong replica %s:%d %s", operation.path, result.Code, result.Body.String())
		}
	}
	other := doBearerJSON(t, b, http.MethodGet, path+"state", outsider, nil, nil)
	unknown := doBearerJSON(t, b, http.MethodGet, "/api/v1/rooms/not-a-room/calls/state", outsider, nil, nil)
	if other.Code != unknown.Code || other.Body.String() != unknown.Body.String() {
		t.Fatalf("wrong-org owner probe:%d %s / %d %s", other.Code, other.Body.String(), unknown.Code, unknown.Body.String())
	}
	server := httptest.NewServer(a)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func(userToken, socketPath string) *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+socketPath, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + userToken}}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.CloseNow() })
		if event := readWSEvent(t, conn); event.Type != chat.EventHello {
			t.Fatalf("hello:%+v", event)
		}
		return conn
	}
	aliceWS := dial(token, first.Socket)
	bobJoin := doBearerJSON(t, a, http.MethodPost, path+"join", bobToken, map[string]bool{"audio": true}, nil)
	if bobJoin.Code != http.StatusOK {
		t.Fatalf("second join:%d %s", bobJoin.Code, bobJoin.Body.String())
	}
	var second struct {
		PeerID string `json:"peer_id"`
	}
	if err := json.Unmarshal(bobJoin.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	bobWS := dial(bobToken, first.Socket)
	raw, _ := json.Marshal(map[string]any{"t": chat.ClientFrameCallSignal, "room": room, "call_id": first.CallID, "to_peer_id": second.PeerID, "kind": "offer", "data": map[string]string{"sdp": "opaque private signal"}})
	if err := aliceWS.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
	signal := readWSEvent(t, bobWS)
	if signal.Type != chat.EventCallSignal || signal.UserID != bob.ID || strings.Contains(string(signal.Data), alice.ID) {
		t.Fatalf("wrong signal:%+v", signal)
	}
}

func TestGuestRoomCallAliasRequiresExactMeetingAndAdmission(t *testing.T) {
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer lk.Close()
	a, b, st, _ := newReplicas(t, func(c *config.Config) {
		c.RTC.LiveKitURL = lk.URL
		c.RTC.LiveKitAPIKey = "test"
		c.RTC.LiveKitAPISecret = "test-secret"
	})
	user, token := createOrgUser(t, st, "routed-guest-host", "routedguesthost", "user", replicaOrgA)
	meeting := putMeeting(t, a, "routed-guest", replicaOrgA, user.SSOSubject)
	gid, secret := guestKnock(t, a, meeting.token)
	path := "/api/v1/rooms/" + meeting.roomID + "/calls/guest/" + meeting.token + "/join"
	guestPost := func(server http.Handler, target string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"audio":true,"protect_ip":true}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Guest-Session", secret)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	if r := guestPost(a, path); r.Code != http.StatusForbidden {
		t.Fatalf("waiting guest admitted:%d %s", r.Code, r.Body.String())
	}
	if r := doBearerJSON(t, b, http.MethodPost, "/api/v1/rooms/"+meeting.roomID+"/lobby/"+gid+"/admit", token, nil, nil); r.Code != http.StatusOK {
		t.Fatalf("admit:%d %s", r.Code, r.Body.String())
	}
	wrong := strings.Replace(path, meeting.roomID, "unrelated-room", 1)
	if r := guestPost(a, wrong); r.Code != http.StatusNotFound {
		t.Fatalf("wrong-room guest alias:%d %s", r.Code, r.Body.String())
	}
	r := guestPost(a, path)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "call_ws_path") || !strings.Contains(r.Body.String(), "livekit_token") {
		t.Fatalf("guest join:%d %s", r.Code, r.Body.String())
	}
	if r := guestPost(b, path); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("guest bypassed affinity:%d %s", r.Code, r.Body.String())
	}
	if r := guestPost(a, "/api/meet/"+meeting.token+"/call/join"); r.Code != http.StatusNotFound {
		t.Fatalf("token-only route bypassed affinity:%d %s", r.Code, r.Body.String())
	}
}
