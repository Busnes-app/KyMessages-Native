package chat

import (
	"context"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// Two replicas share lobby sessions. A guest who drops its socket on one and reconnects to the
// other inside the grace keeps its session; one who never returns loses it.
func TestSharedLobbyLeaveGraceAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: "org-a", OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	replica := func() *LobbyManager {
		l := NewLobbyManager(NewHub(&captureBus{}), nil)
		l.UseShared(st.GuestSessions())
		l.SetLeaveGrace(40 * time.Millisecond)
		return l
	}
	a, b := replica(), replica()
	s, err := a.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.GetBySecret(s.SessionSecret); !ok || got.GuestID != s.GuestID || got.TenantID != "org-a" {
		t.Fatalf("b does not know a's guest: %+v %v", got, ok)
	}
	time.Sleep(2 * time.Millisecond)
	a.HandleDisconnect(s.GuestID, 0)
	time.Sleep(5 * time.Millisecond)
	b.MarkConnected(s.GuestID)
	time.Sleep(80 * time.Millisecond)
	if _, ok := b.GetBySecret(s.SessionSecret); !ok {
		t.Fatal("a's leave timer ended a session that reconnected on b")
	}
	b.HandleDisconnect(s.GuestID, 0)
	time.Sleep(80 * time.Millisecond)
	if _, ok := a.GetBySecret(s.SessionSecret); ok {
		t.Fatal("a guest that never came back kept its session")
	}
	if len(a.ListWaiting(res.Meeting.RoomID)) != 0 {
		t.Fatal("left guest still listed")
	}
}
