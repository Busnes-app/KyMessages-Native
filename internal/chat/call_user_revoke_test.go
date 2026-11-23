package chat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// A user revoked on one replica loses a call seat held on another replica that has none of the
// user's sockets: the bus's auth.revoked drops the seat there and removes the LiveKit participant.
// Reconciliation removes a peer whose account stopped serving when the event was missed.
func TestUserRevocationDropsRemoteCallSeats(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: "org-a", Kind: store.RoomKindChannel, Name: "r", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1", "u2"}); err != nil {
		t.Fatal(err)
	}
	var removed atomic.Int32
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/RemoveParticipant") {
			removed.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()
	hub := NewHub(&captureBus{})
	mgr := NewCallManager(st.Chat(), hub, rtc.NewClient(lk.URL, "testkey", "testsecret1234567890"), nil)
	hub.SetUserRevokeHandler(func(uid string) { mgr.HandleDisconnect(uid, 0) })
	for _, u := range []string{"u1", "u2"} {
		if _, err := mgr.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: u, DisplayName: u, Audio: true, ProtectIP: true}); err != nil {
			t.Fatal(err)
		}
	}
	seated := func(uid string) bool {
		state := mgr.GetState(room.ID)
		if state == nil {
			return false
		}
		for _, p := range state.Peers {
			if p.UserID == uid {
				return true
			}
		}
		return false
	}
	// A session-scoped revocation (a logout) leaves the call alone.
	hub.Dispatch(Event{Type: EventAuthRevoked, UserID: "u1", Data: MustMarshalData(sessionRevoke{Session: "s"})})
	time.Sleep(50 * time.Millisecond)
	if !seated("u1") {
		t.Fatal("a one-session revocation ended the call seat")
	}
	hub.Dispatch(Event{Type: EventAuthRevoked, UserID: "u1"}) // as delivered by the bus
	deadline := time.Now().Add(2 * time.Second)
	for seated("u1") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if seated("u1") || removed.Load() == 0 {
		t.Fatalf("revoked user still seated=%v, LiveKit removals %d", seated("u1"), removed.Load())
	}
	// Missed event: reconciliation removes u2 once its account stops serving.
	mgr.SetUserCheck(func(_ context.Context, uid string) (bool, error) { return uid != "u2", nil })
	mgr.ReconcileTenants(ctx)
	if seated("u2") {
		t.Fatal("reconciliation kept an inactive account's seat")
	}
}
