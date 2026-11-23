package chat

import (
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

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

const routedOrg = "00000000-0000-4000-8000-000000000081"

func seedRoutedCall(t *testing.T) (store.Store, string, []JoinCallRequest) {
	t.Helper()
	ctx := context.Background()
	st := openChatTestStore(t)
	if err := st.Settings().SetSetting(ctx, "tenancy.mode", "multi"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().EnsureTenant(ctx, routedOrg); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().ApplyTenantDirectory(ctx, store.TenantDirectoryEntry{TenantID: routedOrg, Status: store.TenantStatusActive, Enabled: true, Valid: true, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	var requests []JoinCallRequest
	for _, id := range []string{"routed-alice", "routed-bob"} {
		u := &store.User{ID: id, Username: id, SSOProvider: "kyidentity", SSOSubject: id, OrgID: routedOrg, Role: "user", Status: "active"}
		if err := st.Users().CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		hash := "session-" + id
		if err := st.Sessions().CreateSession(ctx, &store.Session{TokenHash: hash, UserID: id, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}, u.PasswordHash); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, JoinCallRequest{TenantID: routedOrg, UserID: id, SessionHash: hash, DisplayName: id, Audio: true})
	}
	room := &store.Room{TenantID: routedOrg, Kind: store.RoomKindChannel, CreatedBy: requests[0].UserID, Name: "Room routed"}
	if err := st.Chat().CreateRoom(ctx, room, []string{requests[1].UserID}); err != nil {
		t.Fatal(err)
	}
	for i := range requests {
		requests[i].RoomID = room.ID
	}
	return st, room.ID, requests
}

func TestRoomOwnerRecoveryRetiresOldMediaBeforeFreshCredentials(t *testing.T) {
	ctx := context.Background()
	st, room, requests := seedRoutedCall(t)
	var fail atomic.Bool
	var mu sync.Mutex
	var deleted []string
	sfu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/DeleteRoom") {
			var request struct {
				Room string `json:"room"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			mu.Lock()
			deleted = append(deleted, request.Room)
			mu.Unlock()
			if fail.Swap(false) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer sfu.Close()
	makeManager := func() *CallManager {
		m := NewCallManager(st.Chat(), NewHub(&captureBus{}), rtc.NewClient(sfu.URL, "test", "test-secret"), nil)
		m.EnableRoomRouting()
		return m
	}
	a, b := makeManager(), makeManager()
	requests[0].ProtectIP = true
	first, err := a.Join(ctx, requests[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.LiveKitToken == "" {
		t.Fatal("missing SFU bearer")
	}
	old, err := st.Chat().GetActiveCallSession(ctx, routedOrg, room)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ClaimRoom(ctx, routedOrg, room); !errors.Is(err, store.ErrCallOwnerLost) {
		t.Fatalf("competing owner admitted: %v", err)
	}
	a.mu.Lock()
	session := a.calls[room].session
	a.mu.Unlock()
	// Expiring the exact lease is deterministic; no wall-clock delay is involved.
	if err := st.Chat().ReleaseCallRoom(ctx, store.CallLease{TenantID: routedOrg, RoomID: room, Holder: session.OwnerID, Generation: session.OwnerGeneration}); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := b.ClaimRoom(ctx, routedOrg, room); err == nil {
		t.Fatal("failed old-media deletion acknowledged")
	}
	if _, err := b.Join(ctx, requests[0]); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	recovered := b.GetState(room)
	if recovered == nil || recovered.CallID != first.CallID || recovered.Epoch <= first.Epoch {
		t.Fatalf("call record not reconstructed: %+v", recovered)
	}
	if len(recovered.Peers) != 1 || recovered.Peers[0].PeerID == first.PeerID {
		t.Fatalf("old peer revived: %+v", recovered)
	}
	if _, err := a.Join(ctx, requests[1]); !errors.Is(err, store.ErrCallOwnerLost) {
		t.Fatalf("stale process issued a competing call: %v", err)
	}
	current, err := st.Chat().GetActiveCallSession(ctx, routedOrg, room)
	if err != nil {
		t.Fatal(err)
	}
	if current.LiveKitRoom == old.LiveKitRoom {
		t.Fatal("old bearer target reused")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) < 2 {
		t.Fatalf("old room was not retried: %v", deleted)
	}
	for _, target := range deleted {
		if target != old.LiveKitRoom {
			t.Fatalf("cleanup touched replacement: %v", deleted)
		}
	}
}

func TestRoomOwnerConcurrentJoinsAndSessionConfinement(t *testing.T) {
	ctx := context.Background()
	st, room, requests := seedRoutedCall(t)
	bus := &captureBus{}
	m := NewCallManager(st.Chat(), NewHub(bus), fakeLiveKitClient(t), nil)
	m.EnableRoomRouting()
	start := make(chan struct{})
	results := make(chan *JoinCallResponse, 2)
	errs := make(chan error, 2)
	for _, request := range requests {
		go func(req JoinCallRequest) {
			<-start
			response, err := m.Join(ctx, req)
			results <- response
			errs <- err
		}(request)
	}
	close(start)
	one, two := <-results, <-results
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if one.CallID != two.CallID || len(m.GetState(room).Peers) != 2 {
		t.Fatalf("concurrent call split: %+v %+v", one, two)
	}
	state := m.GetState(room)
	frame := ClientFrame{Type: ClientFrameCallSignal, RoomID: room, CallID: state.CallID, Kind: "offer", Data: MustMarshalData(map[string]string{"sdp": "private"})}
	var target string
	for _, p := range state.Peers {
		if p.UserID == requests[1].UserID {
			target = p.PeerID
		}
	}
	frame.ToPeerID = target
	before := len(bus.snapshot())
	frame.SessionHash = "another-session"
	m.HandleClientFrame(ctx, requests[0].UserID, false, frame)
	if len(bus.snapshot()) != before {
		t.Fatal("another session controlled the call")
	}
	frame.SessionHash = requests[0].SessionHash
	m.HandleClientFrame(ctx, requests[0].UserID, false, frame)
	events := bus.snapshot()
	if len(events) != before+1 || events[len(events)-1].UserID != requests[1].UserID || events[len(events)-1].SessionHash != requests[1].SessionHash {
		t.Fatalf("signal recipient fence missing: %+v", events)
	}
	if err := st.Sessions().DeleteSession(ctx, requests[0].SessionHash); err != nil {
		t.Fatal(err)
	}
	before = len(events)
	m.HandleClientFrame(ctx, requests[0].UserID, false, frame)
	if len(bus.snapshot()) != before {
		t.Fatal("revoked session signaled")
	}
	if len(m.GetState(room).Peers) != 1 {
		t.Fatal("primary revocation did not remove cached peer")
	}
}

func TestRoomCallDelayedDisconnectCannotEvictReconnectedSession(t *testing.T) {
	ctx := context.Background()
	st, room, requests := seedRoutedCall(t)
	hub := NewHub(&captureBus{})
	m := NewCallManager(st.Chat(), hub, nil, nil)
	m.EnableRoomRouting()
	response, err := m.Join(ctx, requests[0])
	if err != nil {
		t.Fatal(err)
	}
	// A callback captured zero sockets, but has to wait behind an in-flight room operation.
	unlock := m.lockRoom(room)
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		m.HandleRoomDisconnect(requests[0].UserID, room, requests[0].SessionHash)
	}()
	replacement := &Client{hub: hub, userID: requests[0].UserID, tenantID: routedOrg, sessionHash: requests[0].SessionHash, callRoomID: room, rooms: map[string]struct{}{}, stop: make(chan struct{})}
	if !hub.register(replacement, []string{room}) {
		t.Fatal("replacement refused")
	}
	unlock()
	<-completed
	state := m.GetState(room)
	if state == nil || len(state.Peers) != 1 || state.Peers[0].PeerID != response.PeerID {
		t.Fatalf("late disconnect removed current seat:%+v", state)
	}
	seats, err := st.Chat().CallSeats(ctx, routedOrg, room)
	if err != nil || len(seats) != 1 {
		t.Fatalf("reconnected durable seat lost:%+v %v", seats, err)
	}
}

func TestRoomCallHybridEpochsPersistAcrossEscalationAndStepDown(t *testing.T) {
	ctx := context.Background()
	st, room, requests := seedRoutedCall(t)
	bus := &captureBus{}
	m := NewCallManager(st.Chat(), NewHub(bus), fakeLiveKitClient(t), nil)
	m.EnableRoomRouting()
	m.SetStepDownDelay(time.Hour)
	first, err := m.Join(ctx, requests[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.Mode != store.CallModeP2PMesh {
		t.Fatal(first.Mode)
	}
	requests[1].ProtectIP = true
	second, err := m.Join(ctx, requests[1])
	if err != nil {
		t.Fatal(err)
	}
	if second.Mode != store.CallModeSFULiveKit || second.Epoch <= first.Epoch || second.LiveKitToken == "" {
		t.Fatalf("privacy did not escalate:%+v", second)
	}
	sent := false
	for _, ev := range bus.snapshot() {
		if ev.Type == EventCallMigrate && ev.UserID == requests[0].UserID {
			sent = ev.SessionHash == requests[0].SessionHash
		}
	}
	if !sent {
		t.Fatal("existing peer did not get a session-confined migration")
	}
	no := false
	m.HandleClientFrame(ctx, requests[1].UserID, false, ClientFrame{Type: ClientFrameCallMedia, RoomID: room, CallID: second.CallID, SessionHash: requests[1].SessionHash, ProtectIP: &no})
	// Invoke the scheduled action directly; the production delay stays an hour in this test.
	m.executeStepDown(room, second.CallID)
	state := m.GetState(room)
	if state == nil || state.Mode != store.CallModeP2PMesh || state.Epoch <= second.Epoch || len(state.Peers) != 2 {
		t.Fatalf("step down:%+v", state)
	}
	durable, err := st.Chat().GetActiveCallSession(ctx, routedOrg, room)
	if err != nil || durable.Epoch != state.Epoch || durable.Mode != state.Mode {
		t.Fatalf("durable epoch drift:%+v %v", durable, err)
	}
	if _, err := m.ForceEscalate(ctx, room, requests[0].UserID, "ice_failed"); err != nil {
		t.Fatal(err)
	}
	state = m.GetState(room)
	if !state.SFUSticky {
		t.Fatal("ICE failure did not keep SFU sticky")
	}
	m.executeStepDown(room, state.CallID)
	if state = m.GetState(room); state.Mode != store.CallModeSFULiveKit {
		t.Fatal("sticky SFU stepped down")
	}
	m.mu.Lock()
	m.calls[room].stopStepDownLocked()
	m.mu.Unlock()
}

func TestRoomCallStaleJoinRollbackCannotRetireReplacementOwnerSeat(t *testing.T) {
	ctx := context.Background()
	st, room, requests := seedRoutedCall(t)
	requests[0].ProtectIP = true
	entered, release := make(chan struct{}), make(chan struct{})
	var held atomic.Bool
	sfu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/CreateRoom") && held.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer sfu.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	makeManager := func() *CallManager {
		m := NewCallManager(st.Chat(), NewHub(&captureBus{}), rtc.NewClient(sfu.URL, "test", "test-secret"), nil)
		m.EnableRoomRouting()
		return m
	}
	a, b := makeManager(), makeManager()
	done := make(chan error, 1)
	go func() { _, err := a.Join(ctx, requests[0]); done <- err }()
	<-entered
	lease, err := st.Chat().AcquireCallRoom(ctx, routedOrg, room, a.routing.holder, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().ReleaseCallRoom(ctx, lease); err != nil {
		t.Fatal(err)
	}
	replacement, err := b.Join(ctx, requests[0])
	if err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; !errors.Is(err, store.ErrCallOwnerLost) {
		t.Fatalf("old owner issued a grant:%v", err)
	}
	seats, err := st.Chat().CallSeats(ctx, routedOrg, room)
	if err != nil || len(seats) != 1 || seats[0].PeerID != replacement.PeerID {
		t.Fatalf("late rollback retired the replacement:%+v %v", seats, err)
	}
	state := b.GetState(room)
	current, err := st.Chat().GetActiveCallSession(ctx, routedOrg, room)
	if err != nil || current.Epoch != state.Epoch {
		t.Fatalf("late rollback advanced current media:%+v %+v %v", current, state, err)
	}
	if pending, err := st.Chat().PendingCallEvictions(ctx, routedOrg, "", 200); err != nil || len(pending) != 0 {
		t.Fatalf("late rollback queued current media:%+v %v", pending, err)
	}
}
