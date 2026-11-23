package chat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/coder/websocket"
)

// Suspending an org on one pod evicts that org's admitted guests on another: their sessions,
// sockets and call seats all go, and another org's guest stays.
func TestRevokeTenantEvictsGuestsOnEveryPod(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	bus := &podBus{}
	webhookPod, guestPod := NewHub(bus), NewHub(bus)
	bus.pods = []*Hub{webhookPod, guestPod}
	defer guestPod.Close()
	calls := NewCallManager(st.Chat(), guestPod, fakeLiveKitClient(t), nil)
	lobby := NewLobbyManager(guestPod, calls)
	guestPod.SetTenantRevokeHandler(func(tenantID string) { lobby.RevokeTenant(ctx, tenantID) })

	now := time.Now().UTC()
	windows := []store.MeetingWindow{{StartsAt: now.Add(-time.Minute).UnixMilli(), EndsAt: now.Add(time.Hour).UnixMilli()}}
	admit := func(tenant, key string) (*GuestSession, string) {
		if _, err := st.Chat().EnsureTenant(ctx, tenant); err != nil {
			t.Fatalf("EnsureTenant: %v", err)
		}
		room := &store.Room{TenantID: tenant, Kind: store.RoomKindChannel, Name: "meet-" + key, CreatedBy: "u_host"}
		if err := st.Chat().CreateRoom(ctx, room, []string{"u_host"}); err != nil {
			t.Fatalf("CreateRoom: %v", err)
		}
		meeting := &store.Meeting{ID: "mtg_" + key, TenantID: tenant, RoomID: room.ID}
		s, err := lobby.Knock(ctx, &store.MeetingGuest{ID: "gst_" + key, MeetingID: meeting.ID, GuestKey: key}, meeting, windows, key)
		if err != nil {
			t.Fatalf("Knock(%s): %v", key, err)
		}
		if _, err := lobby.Decide(ctx, room.ID, s.GuestID, "u_host", true); err != nil {
			t.Fatalf("Decide(%s): %v", key, err)
		}
		if _, err := calls.Join(ctx, JoinCallRequest{TenantID: tenant, RoomID: room.ID, UserID: s.GuestID, DisplayName: key, IsGuest: true, Audio: true}); err != nil {
			t.Fatalf("Join(%s): %v", key, err)
		}
		return s, room.ID
	}
	a1, roomA1 := admit("org-a", "a1")
	a2, roomA2 := admit("org-a", "a2")
	b1, roomB1 := admit("org-b", "b1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		q := r.URL.Query()
		guestPod.ServeGuestConn(r.Context(), conn, q.Get("t"), q.Get("g"), []string{q.Get("r")})
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dial := func(tenant, room string, s *GuestSession) *websocket.Conn {
		c := dialTestWS(t, wsURL+"?t="+tenant+"&g="+s.GuestID+"&r="+room)
		if ev := readEvent(t, c); ev.Type != EventHello {
			t.Fatalf("first frame = %+v, want hello", ev)
		}
		return c
	}
	sockA1, sockA2, sockB1 := dial("org-a", roomA1, a1), dial("org-a", roomA2, a2), dial("org-b", roomB1, b1)

	if err := webhookPod.RevokeTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}

	for _, c := range []*websocket.Conn{sockA1, sockA2} {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		for {
			if _, _, err := c.Read(rctx); err != nil {
				if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
					t.Fatalf("org-a guest socket ended with %v, want policy violation", err)
				}
				break
			}
		}
		cancel()
	}
	for _, s := range []*GuestSession{a1, a2} {
		if _, ok := lobby.GetBySecret(s.SessionSecret); ok {
			t.Fatalf("org-a guest %s still has a lobby session", s.GuestID)
		}
	}
	for _, room := range []string{roomA1, roomA2} {
		if state := calls.GetState(room); state != nil && len(state.Peers) != 0 {
			t.Fatalf("org-a call %s still has peers %+v", room, state.Peers)
		}
	}

	if _, ok := lobby.GetBySecret(b1.SessionSecret); !ok {
		t.Fatal("org-b guest lost its lobby session")
	}
	if state := calls.GetState(roomB1); state == nil || len(state.Peers) != 1 {
		t.Fatalf("org-b call = %+v, want its guest still seated", state)
	}
	guestPod.Dispatch(Event{Type: EventReadSync, UserID: b1.GuestID})
	if ev := readEvent(t, sockB1); ev.Type != EventReadSync {
		t.Fatalf("org-b guest socket got %+v, want it still open", ev)
	}
}
