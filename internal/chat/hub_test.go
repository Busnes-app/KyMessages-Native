package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func dialTestWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func readEvent(t *testing.T, conn *websocket.Conn) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read: %v", err)
	}
	var ev Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	return ev
}

func TestHubFanoutMembershipAndRevocation(t *testing.T) {
	hub := NewHub(NewMemoryBus())
	defer hub.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Query().Get("u")
		roomsParam := r.URL.Query().Get("rooms")
		var rooms []string
		if roomsParam != "" {
			rooms = strings.Split(roomsParam, ",")
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		hub.ServeConn(r.Context(), conn, "default", uid, "sess_"+uid, rooms)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	alice := dialTestWS(t, wsURL+"?u=alice&rooms=r1")
	bob := dialTestWS(t, wsURL+"?u=bob")

	// Both receive hello frames.
	if ev := readEvent(t, alice); ev.Type != EventHello {
		t.Fatalf("alice first frame = %+v, want hello", ev)
	}
	if ev := readEvent(t, bob); ev.Type != EventHello {
		t.Fatalf("bob first frame = %+v, want hello", ev)
	}

	// Add bob to r1 dynamically; both should receive room.member and subsequent messages.
	if err := hub.PublishRoom(context.Background(), "r1", Event{
		Type:   EventRoomMember,
		RoomID: "r1",
		Data:   MustMarshalData(RoomMemberDelta{Action: "added", UserID: "bob", Role: "member"}),
	}); err != nil {
		t.Fatal(err)
	}
	if ev := readEvent(t, alice); ev.Type != EventRoomMember {
		t.Fatalf("alice member event = %+v", ev)
	}
	if ev := readEvent(t, bob); ev.Type != EventRoomMember {
		t.Fatalf("bob member event = %+v", ev)
	}

	// Publish a message to r1; both receive it.
	if err := hub.PublishRoom(context.Background(), "r1", Event{
		Type:   EventMessageNew,
		RoomID: "r1",
		Seq:    1,
		Data:   MustMarshalData(map[string]string{"body": "hello"}),
	}); err != nil {
		t.Fatal(err)
	}
	if ev := readEvent(t, alice); ev.Type != EventMessageNew || ev.Seq != 1 {
		t.Fatalf("alice message = %+v", ev)
	}
	if ev := readEvent(t, bob); ev.Type != EventMessageNew || ev.Seq != 1 {
		t.Fatalf("bob message = %+v", ev)
	}

	// Remove bob from r1; bob gets the removal event, then stops receiving r1 messages.
	if err := hub.PublishRoom(context.Background(), "r1", Event{
		Type:   EventRoomMember,
		RoomID: "r1",
		Data:   MustMarshalData(RoomMemberDelta{Action: "removed", UserID: "bob"}),
	}); err != nil {
		t.Fatal(err)
	}
	_ = readEvent(t, alice)
	_ = readEvent(t, bob)

	if err := hub.PublishRoom(context.Background(), "r1", Event{
		Type:   EventMessageNew,
		RoomID: "r1",
		Seq:    2,
	}); err != nil {
		t.Fatal(err)
	}
	if ev := readEvent(t, alice); ev.Type != EventMessageNew || ev.Seq != 2 {
		t.Fatalf("alice seq 2 = %+v", ev)
	}

	// Bob's ping still works and arrives BEFORE any phantom seq 2 (proving bob was unsubscribed).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bob.Write(ctx, websocket.MessageText, []byte(`{"t":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	if ev := readEvent(t, bob); ev.Type != EventPong {
		t.Fatalf("bob expected pong (not r1 seq 2), got %+v", ev)
	}

	// Instant revocation closes Alice's WebSocket immediately.
	if err := hub.RevokeUser(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	// Alice either receives auth.revoked then close, or immediate close.
	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rcancel()
	for {
		_, data, err := alice.Read(rctx)
		if err != nil {
			break
		}
		var ev Event
		_ = json.Unmarshal(data, &ev)
		if ev.Type != EventAuthRevoked {
			t.Fatalf("unexpected frame after revoke: %+v", ev)
		}
	}
}

func TestPostgresBusPayloadFallbackAndShards(t *testing.T) {
	ch := ShardChannel("rm_test_123")
	if !strings.HasPrefix(ch, "km_bus_") {
		t.Fatalf("unexpected shard channel %q", ch)
	}
	if ShardChannel("rm_test_123") != ch {
		t.Fatal("ShardChannel is not deterministic")
	}

	small, err := encodeNotifyPayload(Event{Type: EventMessageNew, RoomID: "r1", Seq: 5, Data: MustMarshalData(map[string]string{"body": "hi"})})
	if err != nil || !strings.Contains(small, `"body":"hi"`) {
		t.Fatalf("small payload = %q (err=%v)", small, err)
	}

	hugeBody := strings.Repeat("x", MaxNotifyBytes+2048)
	slim, err := encodeNotifyPayload(Event{Type: EventMessageNew, RoomID: "r1", Seq: 6, Data: MustMarshalData(map[string]string{"body": hugeBody})})
	if err != nil {
		t.Fatalf("encode oversized: %v", err)
	}
	if len(slim) > MaxNotifyBytes {
		t.Fatalf("slim payload still too large: %d > %d", len(slim), MaxNotifyBytes)
	}
	if !strings.Contains(slim, `"refetch":true`) || !strings.Contains(slim, `"seq":6`) {
		t.Fatalf("unexpected slim fallback: %s", slim)
	}
}

// Phase 1 resource gate: 500 concurrent WebSockets + fan-out must stay well below 100 MiB heap.
func TestHub500ConcurrentClientsMemoryGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 500-client load gate in -short mode")
	}
	hub := NewHub(NewMemoryBus())
	defer hub.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Query().Get("u")
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		hub.ServeConn(r.Context(), conn, "default", uid, "sess_"+uid, []string{"room_load"})
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	const n = 500

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	conns := make([]*websocket.Conn, n)
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, _, err := websocket.Dial(ctx, fmt.Sprintf("%s?u=u_%d", wsURL, idx), nil)
			if err != nil {
				errCh <- err
				return
			}
			// Consume hello frame.
			if _, _, err := c.Read(ctx); err != nil {
				_ = c.CloseNow()
				errCh <- err
				return
			}
			conns[idx] = c
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("dial/hello failed: %v", err)
	}
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.CloseNow()
			}
		}
	}()

	clients, users, rooms := hub.Stats()
	if clients != n || users != n || rooms != 1 {
		t.Fatalf("hub stats = (%d, %d, %d), want (%d, %d, 1)", clients, users, rooms, n, n)
	}

	// Broadcast one message to all 500 clients and verify every client receives it.
	if err := hub.PublishRoom(context.Background(), "room_load", Event{
		Type:   EventMessageNew,
		RoomID: "room_load",
		Seq:    1,
		Data:   MustMarshalData(map[string]string{"body": "load gate ping"}),
	}); err != nil {
		t.Fatal(err)
	}

	recvErr := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(c *websocket.Conn) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, data, err := c.Read(ctx)
			if err != nil {
				recvErr <- err
				return
			}
			if !strings.Contains(string(data), "load gate ping") {
				recvErr <- fmt.Errorf("unexpected payload: %s", string(data))
			}
		}(conns[i])
	}
	wg.Wait()
	close(recvErr)
	for err := range recvErr {
		t.Fatalf("broadcast receive failed: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	deltaMiB := float64(0)
	if after.HeapAlloc > before.HeapAlloc {
		deltaMiB = float64(after.HeapAlloc-before.HeapAlloc) / (1024 * 1024)
	}
	t.Logf("500 concurrent WS clients heap delta: %.2f MiB (total heap: %.2f MiB)", deltaMiB, float64(after.HeapAlloc)/(1024*1024))
	if deltaMiB > 100.0 {
		t.Fatalf("heap delta %.2f MiB exceeded 100 MiB Phase 1 gate", deltaMiB)
	}
}

func TestHubSessionCheckClosesRevokedSocket(t *testing.T) {
	hub := NewHub(NewMemoryBus())
	defer hub.Close()
	hub.pingInterval = 20 * time.Millisecond
	var revoked sync.Map
	hub.SetSessionCheck(func(_ context.Context, userID, sessionHash string) bool {
		_, gone := revoked.Load(sessionHash)
		return userID == "alice" && !gone
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		hub.ServeConn(r.Context(), conn, "default", "alice", r.URL.Query().Get("s"), nil)
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	kept, dropped := dialTestWS(t, wsURL+"?s=keep"), dialTestWS(t, wsURL+"?s=drop")
	for _, c := range []*websocket.Conn{kept, dropped} {
		if ev := readEvent(t, c); ev.Type != EventHello {
			t.Fatalf("first frame = %+v, want hello", ev)
		}
	}
	// Revoked out of band (expiry, CLI reset): no hub call, only the store changes.
	revoked.Store("drop", true)
	if ev := readEvent(t, dropped); ev.Type != EventAuthRevoked {
		t.Fatalf("revoked socket got %+v, want auth.revoked", ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := dropped.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked socket close = %v, want policy violation", err)
	}

	time.Sleep(100 * time.Millisecond) // several ticks
	if clients, _, _ := hub.Stats(); clients != 1 {
		t.Fatalf("live clients = %d, want only the valid session", clients)
	}
}
