package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
	"github.com/google/uuid"
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
	a, b, st, _ := newReplicas(t, withKyCalendar, func(c *config.Config) {
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

func TestHostedMeetingCloseRetainsMediaCleanupAndRevokesAdmissions(t *testing.T) {
	var fail atomic.Bool
	var mu sync.Mutex
	var deleted []string
	sfu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/DeleteRoom") {
			var in struct {
				Room string `json:"room"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			deleted = append(deleted, in.Room)
			mu.Unlock()
			if fail.Swap(false) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer sfu.Close()
	a, _, st, _ := newReplicas(t, withKyCalendar, func(c *config.Config) {
		c.RTC.LiveKitURL = sfu.URL
		c.RTC.LiveKitAPIKey = "test"
		c.RTC.LiveKitAPISecret = "test-secret"
	})
	host, token := createOrgUser(t, st, "close-host", "closehost", "user", replicaOrgA)
	other, otherToken := createOrgUser(t, st, "close-other", "closeother", "user", replicaOrgB)
	meeting := putMeeting(t, a, "closing", replicaOrgA, host.SSOSubject)
	otherMeeting := putMeeting(t, a, "closing", replicaOrgB, other.SSOSubject)
	gid, _ := guestKnock(t, a, meeting.token)
	if r := doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms/"+meeting.roomID+"/lobby/"+gid+"/admit", token, nil, nil); r.Code != http.StatusOK {
		t.Fatal(r.Code)
	}
	for _, entry := range []struct{ room, token string }{{meeting.roomID, token}, {otherMeeting.roomID, otherToken}} {
		r := doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms/"+entry.room+"/calls/join", entry.token, map[string]bool{"audio": true, "protect_ip": true}, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("join:%d %s", r.Code, r.Body.String())
		}
	}
	ctx := context.Background()
	old, err := st.Chat().GetActiveCallSession(ctx, replicaOrgA, meeting.roomID)
	if err != nil {
		t.Fatal(err)
	}
	otherBefore, err := st.Chat().GetActiveCallSession(ctx, replicaOrgB, otherMeeting.roomID)
	if err != nil {
		t.Fatal(err)
	}
	event := uuid.NewString()
	closeMeeting := func() *httptest.ResponseRecorder {
		raw := []byte(`{"id":"closing","org_id":"` + replicaOrgA + `"}`)
		request := httptest.NewRequest(http.MethodDelete, "/api/meetings/closing", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		headers, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "kycalendar.meeting.close", event, raw)
		if err != nil {
			t.Fatal(err)
		}
		headers.Apply(request)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		return response
	}
	fail.Store(true)
	if r := closeMeeting(); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete close acknowledged:%d %s", r.Code, r.Body.String())
	}
	if exists, err := st.GuestSessions().Exists(ctx, gid); err != nil || exists {
		t.Fatalf("closed admission can revive:%v %v", exists, err)
	}
	if seats, err := st.Chat().CallSeats(ctx, replicaOrgA, meeting.roomID); err != nil || len(seats) != 0 {
		t.Fatalf("closed seats remain:%+v %v", seats, err)
	}
	if _, err := st.Chat().GetActiveCallSession(ctx, replicaOrgA, meeting.roomID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("closed call remains active:%v", err)
	}
	if r := doBearerJSON(t, a, http.MethodGet, "/api/v1/rooms/"+meeting.roomID+"/calls/state", token, nil, nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"call":null`) {
		t.Fatalf("closed state:%d %s", r.Code, r.Body.String())
	}
	for range 2 {
		if r := closeMeeting(); r.Code != http.StatusOK {
			t.Fatalf("close retry/replay:%d %s", r.Code, r.Body.String())
		}
	}
	otherAfter, err := st.Chat().GetActiveCallSession(ctx, replicaOrgB, otherMeeting.roomID)
	if err != nil || otherAfter.Epoch != otherBefore.Epoch || otherAfter.LiveKitRoom != otherBefore.LiveKitRoom {
		t.Fatalf("other org's call changed:%+v %v", otherAfter, err)
	}
	if pending, err := st.Chat().PendingCallEvictions(ctx, replicaOrgA, "", 200); err != nil || len(pending) != 0 {
		t.Fatalf("close cleanup remains:%+v %v", pending, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) < 2 {
		t.Fatal("cleanup not retried")
	}
	for _, target := range deleted {
		if target != old.LiveKitRoom {
			t.Fatalf("close retired another media target:%v", deleted)
		}
	}
}

type failedGuestLookup struct{ store.ChatStore }

func (s failedGuestLookup) GetMeetingGuestByTokenHash(context.Context, string) (*store.MeetingGuest, *store.Meeting, []store.MeetingWindow, error) {
	return nil, nil, nil, errors.New("private database lookup failure")
}

type failedGuestLookupStore struct{ store.Store }

func (s failedGuestLookupStore) Chat() store.ChatStore {
	return failedGuestLookup{ChatStore: s.Store.Chat()}
}

func TestGuestLookupFailureReturnsErrorWithoutPanic(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	srv := api.NewServer(cfg, failedGuestLookupStore{Store: st})
	for _, entry := range []struct{ method, suffix, body string }{{http.MethodGet, "", ""}, {http.MethodPost, "/knock", `{"display_name":"Visitor"}`}, {http.MethodGet, "/messages", ""}} {
		t.Run(entry.method+entry.suffix, func(t *testing.T) {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("lookup error panicked: %v", value)
				}
			}()
			req := httptest.NewRequest(entry.method, "/api/meet/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+entry.suffix, strings.NewReader(entry.body))
			req.Header.Set("Content-Type", "application/json")
			out := httptest.NewRecorder()
			srv.ServeHTTP(out, req)
			if out.Code != http.StatusInternalServerError || strings.Contains(out.Body.String(), "private database") {
				t.Fatalf("unsafe lookup error: %d %s", out.Code, out.Body.String())
			}
		})
	}
}

func TestP2PReconciliationPublishesRosterAfterRemoteMemberRemoval(t *testing.T) {
	a, b, st, _ := newReplicas(t)
	alice, token := createOrgUser(t, st, "roster-alice", "rosteralice", "user", replicaOrgA)
	bob, bobToken := createOrgUser(t, st, "roster-bob", "rosterbob", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": "channel", "name": "Roster", "member_ids": []string{bob.ID}}, nil))
	path := "/api/v1/rooms/" + room + "/calls/"
	for _, userToken := range []string{token, bobToken} {
		response := doBearerJSON(t, a, http.MethodPost, path+"join", userToken, map[string]bool{"audio": true}, nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"mode":"p2p_mesh"`) {
			t.Fatalf("P2P join: %d %s", response.Code, response.Body.String())
		}
	}
	server := httptest.NewServer(a)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+path+"ws", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	if event := readWSEvent(t, socket); event.Type != chat.EventHello {
		t.Fatalf("hello: %+v", event)
	}
	removed := doBearerJSON(t, b, http.MethodDelete, "/api/v1/rooms/"+room+"/members/"+bob.ID, token, nil, nil)
	if removed.Code != http.StatusOK {
		t.Fatalf("remote removal: %d %s", removed.Code, removed.Body.String())
	}
	// Room-state acquisition runs the same primary reconciliation as the owner tick.
	response := doBearerJSON(t, a, http.MethodGet, path+"state", token, nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("reconcile: %d %s", response.Code, response.Body.String())
	}
	event := readWSEvent(t, socket)
	var state chat.CallStatePayload
	if err := json.Unmarshal(event.Data, &state); err != nil {
		t.Fatal(err)
	}
	if event.Type != chat.EventCallState || state.Mode != store.CallModeP2PMesh || len(state.Peers) != 1 || state.Peers[0].UserID != alice.ID {
		t.Fatalf("survivor roster: %+v %+v", event, state)
	}
}
