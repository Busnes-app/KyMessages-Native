package chat

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

func TestPostgresReplicasDeliverFullCallSignalOnlyToItsUser(t *testing.T) {
	cfg := testdb.Config(t)
	if cfg.Driver != "postgres" {
		t.Skip("requires PostgreSQL LISTEN/NOTIFY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, b := NewPostgresBus(cfg.DSN, st), NewPostgresBus(cfg.DSN, st)
	a.EnableCallFragments()
	b.EnableCallFragments()
	ha, hb := NewHub(a), NewHub(b)
	done := make(chan struct{}, 2)
	for _, h := range []*Hub{ha, hb} {
		go func(h *Hub) { defer func() { done <- struct{}{} }(); _ = h.Run(ctx) }(h)
	}
	defer func() { cancel(); <-done; <-done }()
	for _, h := range []*Hub{ha, hb} {
		if err := h.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
	}
	room := "call-notify-" + uuid.NewString()
	target := "target-" + uuid.NewString()
	serve := func(h *Hub) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			h.ServeConn(r.Context(), conn, "default", r.URL.Query().Get("u"), "session", []string{room})
		}))
	}
	sa, sb := serve(ha), serve(hb)
	defer sa.Close()
	defer sb.Close()
	defer ha.Close()
	defer hb.Close()
	alice := dialTestWS(t, "ws"+strings.TrimPrefix(sa.URL, "http")+"?u=alice")
	bob := dialTestWS(t, "ws"+strings.TrimPrefix(sb.URL, "http")+"?u="+target)
	bob.SetReadLimit(maxCallNotifyBytes)
	carol := dialTestWS(t, "ws"+strings.TrimPrefix(sb.URL, "http")+"?u=carol")
	for _, conn := range []*websocket.Conn{alice, bob, carol} {
		if ev := readEvent(t, conn); ev.Type != EventHello {
			t.Fatal(ev.Type)
		}
	}
	ev := largeCallEvent()
	ev.RoomID = room
	ev.UserID = target
	if err := a.PublishUser(ctx, target, ev); err != nil {
		t.Fatal(err)
	}
	if got := readEvent(t, bob); got.Type != EventCallSignal || got.UserID != target || got.RoomID != room || !bytes.Equal(got.Data, ev.Data) {
		t.Fatalf("remote signal was truncated or changed: type=%s size=%d", got.Type, len(got.Data))
	}
	// A room barrier proves both remote and local nonrecipients saw no call fragments/signal.
	if err := a.PublishRoom(ctx, room, Event{Type: EventMessageNew, Seq: 314}); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []*websocket.Conn{alice, bob, carol} {
		if got := readEvent(t, conn); got.Type != EventMessageNew || got.Seq != 314 {
			t.Fatalf("nonrecipient received call data before barrier: %+v", got)
		}
	}
}
