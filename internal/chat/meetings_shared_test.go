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
		l.SetLeaveGrace(400 * time.Millisecond)
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
	a.HandleDisconnect(s.GuestID, 0)
	time.Sleep(20 * time.Millisecond)
	b.MarkConnected(s.GuestID)
	time.Sleep(800 * time.Millisecond)
	if _, ok := b.GetBySecret(s.SessionSecret); !ok {
		t.Fatal("a's leave timer ended a session that reconnected on b")
	}
	b.HandleDisconnect(s.GuestID, 0)
	time.Sleep(time.Second)
	if _, ok := a.GetBySecret(s.SessionSecret); ok {
		t.Fatal("a guest that never came back kept its session")
	}
	if len(a.ListWaiting(res.Meeting.RoomID)) != 0 {
		t.Fatal("left guest still listed")
	}
}

// A guest with sockets on two replicas keeps its session when one of them closes: the other
// replica's heartbeat refreshes it. When the last closes, the session ends after the grace.
func TestSharedLobbyOverlappingSocketsAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	replica := func() *LobbyManager {
		l := NewLobbyManager(NewHub(&captureBus{}), nil)
		l.UseShared(st.GuestSessions())
		l.SetLeaveGrace(400 * time.Millisecond)
		return l
	}
	a, b := replica(), replica()
	s, err := a.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	a.MarkConnected(s.GuestID)
	b.MarkConnected(s.GuestID)
	time.Sleep(300 * time.Millisecond) // b's last touch is now older than a's disconnect
	a.HandleDisconnect(s.GuestID, 0)
	time.Sleep(800 * time.Millisecond)
	if _, ok := b.GetBySecret(s.SessionSecret); !ok {
		t.Fatal("a's leave timer ended a session still connected on b")
	}
	b.HandleDisconnect(s.GuestID, 0)
	time.Sleep(time.Second)
	if _, ok := a.GetBySecret(s.SessionSecret); ok {
		t.Fatal("session outlived its last socket")
	}
}

// A replica that exits runs no leave timer. The admission still lapses: every read applies the
// presence rule on the database clock, so a guest no replica refreshed for longer than the grace
// must knock and be admitted again.
func TestSharedLobbyAdmissionLapsesWithoutAnyReplica(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLobbyManager(NewHub(&captureBus{}), nil)
	l.UseShared(st.GuestSessions())
	l.SetLeaveGrace(400 * time.Millisecond) // presence window 500 ms
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Decide(ctx, res.Meeting.RoomID, s.GuestID, "host", true); err != nil {
		t.Fatal(err)
	}
	if got, ok := l.GetBySecret(s.SessionSecret); !ok || got.Status != "admitted" {
		t.Fatalf("fresh admission: %+v %v", got, ok)
	}
	// No socket anywhere, no timer: the replica that held it is gone.
	time.Sleep(time.Second)
	if _, ok := l.GetBySecret(s.SessionSecret); ok {
		t.Fatal("an admission nobody refreshed outlived the leave grace")
	}
	if len(l.ListWaiting(res.Meeting.RoomID)) != 0 {
		t.Fatal("lapsed guest still listed")
	}
	if _, err := l.Decide(ctx, res.Meeting.RoomID, s.GuestID, "host", true); err != ErrGuestNotFound {
		t.Fatalf("admitting a lapsed guest: %v", err)
	}
	// A fresh knock and admission work again.
	s2, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.GetBySecret(s2.SessionSecret); !ok {
		t.Fatal("new knock not found")
	}
}

// A waiting guest who polls over HTTP without a socket stays in the lobby: each authenticated
// request refreshes its presence, as an open socket does.
func TestSharedLobbyPollingGuestStaysWaiting(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLobbyManager(NewHub(&captureBus{}), nil)
	l.UseShared(st.GuestSessions())
	l.SetLeaveGrace(400 * time.Millisecond)
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	for range 12 { // 1.2 s, well past the 500 ms presence window
		time.Sleep(100 * time.Millisecond)
		if _, ok := l.GetBySecret(s.SessionSecret); !ok {
			t.Fatal("a polling guest lapsed")
		}
	}
	if len(l.ListWaiting(res.Meeting.RoomID)) != 1 {
		t.Fatal("a polling guest left the lobby")
	}
	if _, err := l.Decide(ctx, res.Meeting.RoomID, s.GuestID, "host", true); err != nil {
		t.Fatalf("admitting a polling guest: %v", err)
	}
}

// A guest whose socket closed but who keeps polling keeps the session past the leave timer:
// the timer and reads apply the same inactivity window.
func TestSharedLobbyPollingAfterDisconnect(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLobbyManager(NewHub(&captureBus{}), nil)
	l.UseShared(st.GuestSessions())
	l.SetLeaveGrace(400 * time.Millisecond) // presence window 500 ms
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	l.MarkConnected(s.GuestID)
	l.HandleDisconnect(s.GuestID, 0)
	for range 6 { // polls every 200 ms across the timer at 500 ms
		time.Sleep(200 * time.Millisecond)
		if _, ok := l.GetBySecret(s.SessionSecret); !ok {
			t.Fatal("a polling guest lost the session to the leave timer")
		}
	}
	time.Sleep(time.Second) // no polls, no socket: the window passes and the timer has no hold
	if _, ok := l.GetBySecret(s.SessionSecret); ok {
		t.Fatal("an idle guest kept the session")
	}
}

// After an outage longer than the presence window (no heartbeat landed), a guest whose socket
// is still open on this replica passes the socket check: the check itself is presence.
func TestSharedLobbyConnectedGuestSurvivesAnOutage(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLobbyManager(NewHub(&captureBus{}), nil)
	l.UseShared(st.GuestSessions())
	l.SetLeaveGrace(400 * time.Millisecond) // presence window 500 ms
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	// A socket open here whose heartbeats all failed during the outage: connected, never refreshed.
	l.mu.Lock()
	l.live[s.GuestID] = struct{}{}
	l.mu.Unlock()
	time.Sleep(700 * time.Millisecond)
	active := func(context.Context, string) (bool, error) { return true, nil }
	if !l.GuestCheck(active)(s.GuestID) {
		t.Fatal("a guest still connected here was dropped after the outage")
	}
	// A guest with no socket here gets no such refresh.
	s2, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k2"}, res.Meeting, nil, "Other")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if l.GuestCheck(active)(s2.GuestID) {
		t.Fatal("a guest with no socket here was kept alive by the check")
	}
}
