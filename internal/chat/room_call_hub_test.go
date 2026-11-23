package chat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRoomCallSocketConfinesRoomAndVerifiedSession(t *testing.T) {
	hub := NewHub(NewMemoryBus())
	defer hub.Close()
	disconnected := make(chan string, 4)
	hub.EnableRoomCalls(func(user, room, session string) { disconnected <- user + ":" + room + ":" + session })
	var revoked atomic.Bool
	hub.SetSessionCheck(func(_ context.Context, _ string, hash string) (bool, error) {
		return hash != "session-a" || !revoked.Load(), nil
	})
	hub.SetRoomSource(func(context.Context, string, string) ([]string, error) { return []string{"r1", "r2"}, nil })
	frames := make(chan ClientFrame, 4)
	hub.SetCallFrameHandler(func(_ context.Context, _ string, _ bool, f ClientFrame) { frames <- f })
	done := map[string]chan struct{}{"global": make(chan struct{}), "one": make(chan struct{}), "two": make(chan struct{}), "other-session": make(chan struct{})}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		mu.Lock()
		closed := done[id]
		mu.Unlock()
		defer close(closed)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		room := r.URL.Query().Get("room")
		hash := r.URL.Query().Get("session")
		if room == "" {
			hub.ServeConn(r.Context(), conn, "org", "alice", hash, []string{"r1", "r2"})
		} else {
			hub.ServeRoomCallConn(r.Context(), conn, "org", "alice", hash, room)
		}
	}))
	defer srv.Close()
	base := "ws" + strings.TrimPrefix(srv.URL, "http")
	global := dialTestWS(t, base+"?id=global&session=session-a")
	one := dialTestWS(t, base+"?id=one&room=r1&session=session-a")
	two := dialTestWS(t, base+"?id=two&room=r2&session=session-a")
	other := dialTestWS(t, base+"?id=other-session&room=r1&session=session-b")
	for _, c := range []*websocket.Conn{global, one, two, other} {
		if ev := readEvent(t, c); ev.Type != EventHello {
			t.Fatal(ev.Type)
		}
	}
	send := func(c *websocket.Conn, v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.Write(ctx, websocket.MessageText, raw); err != nil {
			t.Fatal(err)
		}
	}
	ping := func(c *websocket.Conn) {
		t.Helper()
		send(c, ClientFrame{Type: ClientFramePing})
		if ev := readEvent(t, c); ev.Type != EventPong {
			t.Fatalf("unexpected frame before socket barrier: %+v", ev)
		}
	}
	send(global, ClientFrame{Type: ClientFrameCallSignal, RoomID: "r1"})
	ping(global)
	send(two, ClientFrame{Type: ClientFrameCallSignal, RoomID: "r1"})
	ping(two)
	if len(frames) != 0 {
		t.Fatal("global or wrong-room socket controlled a call")
	}
	send(one, map[string]any{"t": ClientFrameCallMedia, "room": "r1", "session_hash": "forged"})
	ping(one)
	select {
	case f := <-frames:
		if f.SessionHash != "session-a" || f.RoomID != "r1" {
			t.Fatalf("unverified frame origin: %+v", f)
		}
	default:
		t.Fatal("room-scoped control was not delivered")
	}
	ev := Event{Type: EventCallMigrate, RoomID: "r1", UserID: "alice", SessionHash: "session-a", Data: MustMarshalData(map[string]string{"token": "private"})}
	if err := hub.PublishUser(context.Background(), "alice", ev); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, raw, err := one.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "session_hash") || strings.Contains(string(raw), "session-a") {
		t.Fatal("internal recipient hash leaked to client")
	}
	var got Event
	if err := json.Unmarshal(raw, &got); err != nil || got.Type != EventCallMigrate {
		t.Fatalf("migration: %+v %v", got, err)
	}
	ping(global)
	ping(two)
	ping(other)
	if err := hub.PublishRoom(context.Background(), "r1", Event{Type: EventMessageNew, Seq: 9}); err != nil {
		t.Fatal(err)
	}
	if ev := readEvent(t, global); ev.Type != EventMessageNew || ev.Seq != 9 {
		t.Fatalf("global chat changed: %+v", ev)
	}
	ping(one)
	ping(other)

	if err := hub.PublishRoom(context.Background(), "r1", Event{Type: EventRoomClosed}); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []*websocket.Conn{global, one, other} {
		if ev := readEvent(t, conn); ev.Type != EventRoomClosed {
			t.Fatalf("room closure not delivered:%+v", ev)
		}
	}
	ping(two)
	// Closing a room call socket is independent of an ordinary chat socket or another room.
	_ = one.CloseNow()
	_ = other.CloseNow()
	<-done["one"]
	<-done["other-session"]
	if len(disconnected) != 2 {
		t.Fatalf("room departure callbacks=%d want2", len(disconnected))
	}
	left := map[string]bool{<-disconnected: true, <-disconnected: true}
	if !left["alice:r1:session-a"] || !left["alice:r1:session-b"] {
		t.Fatalf("wrong departures: %v", left)
	}
	revoked.Store(true)
	if err := hub.PublishUser(context.Background(), "alice", Event{Type: EventCallMigrate, RoomID: "r2", UserID: "alice", SessionHash: "session-a", Data: MustMarshalData(map[string]string{"token": "must not arrive"})}); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := two.Read(ctx); err == nil {
		t.Fatalf("revoked session received credentials: %s", raw)
	}
}

func TestRoomCallSocketCountIsBoundedPerUserAndRoom(t *testing.T) {
	h := NewHub(NewMemoryBus())
	h.EnableRoomCalls(nil)
	for i := range 9 {
		c := &Client{userID: "alice", callRoomID: "r1", rooms: map[string]struct{}{}}
		got := h.register(c, []string{"r1"})
		if got != (i < 8) {
			t.Fatalf("socket%d admitted=%v", i, got)
		}
	}
	for _, c := range []*Client{{userID: "bob", callRoomID: "r1", rooms: map[string]struct{}{}}, {userID: "alice", callRoomID: "r2", rooms: map[string]struct{}{}}, {userID: "alice", rooms: map[string]struct{}{}}} {
		if !h.register(c, []string{"r1"}) {
			t.Fatal("one room's limit blocked another scope")
		}
	}
}
