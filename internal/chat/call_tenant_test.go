package chat

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/coder/websocket"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// suspendsMidJoin reports the tenant active on the first read and suspended after: a suspension
// that commits between a join's authorization and its registration.
type suspendsMidJoin struct {
	store.ChatStore
	activeReads int32 // reads that still see the org active
	reads       atomic.Int32
}

func (s *suspendsMidJoin) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	t, err := s.ChatStore.GetTenant(ctx, id)
	if err == nil && s.reads.Add(1) > s.activeReads {
		t.Status = store.TenantStatusSuspended
	}
	return t, err
}

func TestCallJoinFencedByTenantSuspension(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: "org-a", Kind: store.RoomKindChannel, Name: "standup", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1"}); err != nil {
		t.Fatal(err)
	}
	join := func(mgr *CallManager, user string, guest bool) (*JoinCallResponse, error) {
		return mgr.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: user, DisplayName: user, IsGuest: guest, Audio: true, Video: true, ProtectIP: true})
	}

	// Suspended between authorization and registration (activeReads 1), or during persistence
	// and LiveKit setup (activeReads 2): no token, no surviving peer.
	for _, activeReads := range []int32{1, 2} {
		for _, guest := range []bool{false, true} {
			racing := NewCallManager(&suspendsMidJoin{ChatStore: st.Chat(), activeReads: activeReads}, NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
			resp, err := join(racing, "u1", guest)
			if !errors.Is(err, ErrTenantInactive) || resp != nil {
				t.Fatalf("activeReads=%d guest=%v join racing a suspension = %+v, %v; want ErrTenantInactive and no token", activeReads, guest, resp, err)
			}
			if state := racing.GetState(room.ID); state != nil && len(state.Peers) != 0 {
				t.Fatalf("activeReads=%d guest=%v: peer survived the suspension: %+v", activeReads, guest, state.Peers)
			}
		}
	}

	// Already suspended: refused before anything is registered.
	mgr := NewCallManager(st.Chat(), NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
	if err := st.Chat().SetTenantStatus(ctx, "org-a", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	for _, guest := range []bool{false, true} {
		if _, err := join(mgr, "u1", guest); !errors.Is(err, ErrTenantInactive) {
			t.Fatalf("guest=%v join on a suspended org = %v, want ErrTenantInactive", guest, err)
		}
	}
	if state := mgr.GetState(room.ID); state != nil && len(state.Peers) != 0 {
		t.Fatalf("peers on a suspended org's call: %+v", state.Peers)
	}

	// Active again: joins work and get a media token.
	if err := st.Chat().SetTenantStatus(ctx, "org-a", store.TenantStatusActive); err != nil {
		t.Fatal(err)
	}
	if resp, err := join(mgr, "u1", false); err != nil || resp.LiveKitToken == "" {
		t.Fatalf("join on an active org = %+v, %v; want a LiveKit token", resp, err)
	}
}

// Suspension on one pod takes a member out of a call held on another pod, and out of the SFU,
// even though that member has no chat socket anywhere.
func TestRevokeTenantRemovesSocketlessCallMembersOnEveryPod(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: "org-a", Kind: store.RoomKindChannel, Name: "sfu", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1"}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var removed []string
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/RemoveParticipant") {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			removed = append(removed, string(body))
			mu.Unlock()
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()

	bus := &podBus{}
	webhookPod, callPod := NewHub(bus), NewHub(bus)
	bus.pods = []*Hub{webhookPod, callPod}
	calls := NewCallManager(st.Chat(), callPod, rtc.NewClient(lk.URL, "testkey", "testsecret1234567890"), nil)
	callPod.SetTenantRevokeHandler(func(tenantID string) { calls.RevokeTenant(ctx, tenantID) })
	resp, err := calls.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: "u1", DisplayName: "u1", Audio: true, ProtectIP: true})
	if err != nil || resp.LiveKitToken == "" {
		t.Fatalf("join = %+v, %v", resp, err)
	}

	if err := webhookPod.RevokeTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	if state := calls.GetState(room.ID); state != nil && len(state.Peers) != 0 {
		t.Fatalf("member still in the call after suspension: %+v", state.Peers)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(removed) == 0 || !strings.Contains(removed[0], resp.PeerID) {
		t.Fatalf("SFU removals = %v, want peer %s", removed, resp.PeerID)
	}
}

// A guest socket that registers after its lobby session was swept is closed at once, and an
// admitted guest's socket closes on the next ping once its session is gone.
func TestGuestSocketRevalidatedAgainstItsSession(t *testing.T) {
	var live atomic.Bool
	serve := func(ping time.Duration) string {
		hub := NewHub(&captureBus{})
		hub.pingInterval = ping
		hub.SetGuestCheck(func(string) bool { return live.Load() })
		t.Cleanup(hub.Close)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			hub.ServeGuestConn(r.Context(), conn, "org-a", "gst_1", []string{"rm_1"})
		}))
		t.Cleanup(srv.Close)
		return "ws" + strings.TrimPrefix(srv.URL, "http")
	}
	closed := func(c *websocket.Conn) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for {
			if _, _, err := c.Read(ctx); err != nil {
				if websocket.CloseStatus(err) == -1 {
					t.Fatalf("guest socket ended with %v, want a close frame", err)
				}
				return
			}
		}
	}

	// Swept before it registered: refused at registration, long before any ping.
	closed(dialTestWS(t, serve(time.Hour)))

	// Admitted and connected, then swept: the next ping closes it.
	live.Store(true)
	c := dialTestWS(t, serve(20*time.Millisecond))
	if ev := readEvent(t, c); ev.Type != EventHello {
		t.Fatalf("first frame = %+v, want hello", ev)
	}
	live.Store(false)
	closed(c)
}

// leavesMidJoin removes the joining peer during setup, as a concurrent Leave or a replacing join
// would, while the org stays active.
type leavesMidJoin struct {
	store.ChatStore
	reads  atomic.Int32
	onRead func(n int32)
}

func (s *leavesMidJoin) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	n := s.reads.Add(1)
	if s.onRead != nil {
		s.onRead(n)
	}
	return s.ChatStore.GetTenant(ctx, id)
}

func TestCallJoinSeatLostIsNotASuspension(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: "org-a", Kind: store.RoomKindChannel, Name: "seat", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1", "u2"}); err != nil {
		t.Fatal(err)
	}
	wrapped := &leavesMidJoin{ChatStore: st.Chat()}
	mgr := NewCallManager(wrapped, NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
	if _, err := mgr.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: "u2", DisplayName: "u2", Audio: true, ProtectIP: true}); err != nil {
		t.Fatal(err)
	}
	wrapped.reads.Store(0)
	wrapped.onRead = func(n int32) {
		if n == 3 { // the final check, after setup
			mgr.Leave(ctx, room.ID, "u1")
		}
	}
	resp, err := mgr.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: "u1", DisplayName: "u1", Audio: true, ProtectIP: true})
	if !errors.Is(err, ErrCallSeatLost) || resp != nil {
		t.Fatalf("join whose seat vanished = %+v, %v; want ErrCallSeatLost and no token", resp, err)
	}
	if state := mgr.GetState(room.ID); state == nil || len(state.Peers) != 1 || state.Peers[0].UserID != "u2" {
		t.Fatalf("other member's seat disturbed: %+v", state)
	}
}

// A call whose org went inactive without a tenant.revoked reaching this pod is emptied by the
// reconcile sweep.
func TestReconcileTenantsEmptiesInactiveOrgCalls(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	for _, org := range []string{"org-a", "org-b"} {
		if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
			t.Fatal(err)
		}
	}
	mgr := NewCallManager(st.Chat(), NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
	rooms := map[string]string{}
	for _, org := range []string{"org-a", "org-b"} {
		room := &store.Room{TenantID: org, Kind: store.RoomKindChannel, Name: org, CreatedBy: "u-" + org}
		if err := st.Chat().CreateRoom(ctx, room, []string{"u-" + org}); err != nil {
			t.Fatal(err)
		}
		rooms[org] = room.ID
		if _, err := mgr.Join(ctx, JoinCallRequest{TenantID: org, RoomID: room.ID, UserID: "u-" + org, DisplayName: org, Audio: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Chat().SetTenantStatus(ctx, "org-a", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	mgr.ReconcileTenants(ctx)
	if state := mgr.GetState(rooms["org-a"]); state != nil && len(state.Peers) != 0 {
		t.Fatalf("suspended org's call still seated: %+v", state.Peers)
	}
	if state := mgr.GetState(rooms["org-b"]); state == nil || len(state.Peers) != 1 {
		t.Fatalf("active org's call disturbed: %+v", state)
	}
}

// The guest check closes a guest whose org went inactive, and keeps one open through an outage.
func TestGuestCheckFollowsOrgStatus(t *testing.T) {
	ctx := context.Background()
	lobby := NewLobbyManager(nil, nil)
	now := time.Now().UTC()
	s, err := lobby.Knock(ctx, &store.MeetingGuest{ID: "gst", MeetingID: "mtg", GuestKey: "k"},
		&store.Meeting{ID: "mtg", TenantID: "org-a", RoomID: "rm"},
		[]store.MeetingWindow{{StartsAt: now.Add(-time.Minute).UnixMilli(), EndsAt: now.Add(time.Hour).UnixMilli()}}, "g")
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]bool{"org-a": true}
	var lookupErr error
	check := lobby.GuestCheck(func(_ context.Context, tenantID string) (bool, error) { return status[tenantID], lookupErr })
	if !check(s.GuestID) {
		t.Fatal("guest of an active org refused")
	}
	if check("gst-unknown") {
		t.Fatal("guest without a session accepted")
	}
	status["org-a"] = false
	if check(s.GuestID) {
		t.Fatal("guest of an inactive org accepted")
	}
	lookupErr = errors.New("database unavailable")
	if !check(s.GuestID) {
		t.Fatal("an outage closed the guest")
	}
}
