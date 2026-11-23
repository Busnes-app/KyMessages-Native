package chat

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	dbCfg := testdb.Config(t)
	st, err := store.Open(ctx, dbCfg)
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
	l.SetLeaveGrace(time.Hour) // expiry is controlled through the stored fixture
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
	ageSharedPresence(t, dbCfg, s.GuestID)
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
	dbCfg := testdb.Config(t)
	st, err := store.Open(ctx, dbCfg)
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
	l.SetLeaveGrace(time.Hour) // expiry is controlled through the stored fixture
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	// Run the timer's conditional delete explicitly after a poll, without a wall-clock wait.
	for range 6 {
		if _, ok := l.GetBySecret(s.SessionSecret); !ok {
			t.Fatal("poll lost the session")
		}
		rows, err := st.GuestSessions().DeleteIfUnseen(ctx, s.GuestID, l.presence())
		if err != nil || len(rows) > 0 {
			t.Fatalf("cleanup removed a polling guest: %v %v", rows, err)
		}
	}
	ageSharedPresence(t, dbCfg, s.GuestID)
	if _, ok := l.GetBySecret(s.SessionSecret); ok {
		t.Fatal("an idle guest kept the session")
	}
}

// After an outage longer than the presence window (no heartbeat landed), a guest whose socket
// is still open on this replica passes the socket check: the check itself is presence.
func TestSharedLobbyConnectedGuestSurvivesAnOutage(t *testing.T) {
	ctx := context.Background()
	dbCfg := testdb.Config(t)
	st, err := store.Open(ctx, dbCfg)
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
	l.SetLeaveGrace(time.Hour) // expiry is controlled through the stored fixture
	s, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k"}, res.Meeting, nil, "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	// A socket open here whose heartbeats all failed during the outage: connected, never refreshed.
	l.mu.Lock()
	l.live[s.GuestID] = struct{}{}
	l.mu.Unlock()
	ageSharedPresence(t, dbCfg, s.GuestID)
	active := func(context.Context, string) (bool, error) { return true, nil }
	if !l.GuestCheck(active)(s.GuestID) {
		t.Fatal("a guest still connected here was dropped after the outage")
	}
	// A guest with no socket here gets no such refresh.
	s2, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "m", GuestKey: "k2"}, res.Meeting, nil, "Other")
	if err != nil {
		t.Fatal(err)
	}
	ageSharedPresence(t, dbCfg, s2.GuestID)
	if l.GuestCheck(active)(s2.GuestID) {
		t.Fatal("a guest with no socket here was kept alive by the check")
	}
}

// A revoked invite removes a remote SFU seat even when that replica has no chat socket.
func TestSharedGuestRevocationRemovesRemoteCallWithoutSocket(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "remote", TenantID: store.DefaultTenantID, OrganizerSub: "host", Title: "Remote"})
	if err != nil {
		t.Fatal(err)
	}
	removed := make(chan string, 4)
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/RemoveParticipant") {
			b, _ := io.ReadAll(r.Body)
			removed <- string(b)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()
	bus := &podBus{}
	a, b := NewHub(bus), NewHub(bus)
	bus.pods = []*Hub{a, b}
	calls := NewCallManager(st.Chat(), b, rtc.NewClient(lk.URL, "testkey", "testsecret1234567890"), nil)
	b.SetUserRevokeHandler(func(id string) { calls.HandleDisconnect(id, 0) })
	lobby := NewLobbyManager(a, nil)
	lobby.UseShared(st.GuestSessions())
	s, err := lobby.Knock(ctx, &store.MeetingGuest{MeetingID: "remote", GuestKey: "guest"}, res.Meeting, nil, "Guest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lobby.Decide(ctx, res.Meeting.RoomID, s.GuestID, "host", true); err != nil {
		t.Fatal(err)
	}
	joined, err := calls.Join(ctx, JoinCallRequest{TenantID: store.DefaultTenantID, RoomID: res.Meeting.RoomID, UserID: s.GuestID, IsGuest: true, Audio: true, ProtectIP: true})
	if err != nil {
		t.Fatal(err)
	}
	lobby.RevokeGuestKey(ctx, store.DefaultTenantID, "remote", "guest")
	select {
	case body := <-removed:
		if !strings.Contains(body, joined.PeerID) {
			t.Fatalf("removed wrong peer: %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote SFU participant was not removed")
	}
	if state := calls.GetState(res.Meeting.RoomID); state != nil && len(state.Peers) > 0 {
		t.Fatal("revoked guest still seated")
	}
}

// Backdate the database fixture to model elapsed presence without sleeps or scheduler margins.
func ageSharedPresence(t *testing.T, cfg config.DatabaseConfig, id string) {
	t.Helper()
	driver, ph := "sqlite", "?"
	if cfg.Driver == "postgres" {
		driver, ph = "pgx", "$1"
	}
	db, err := sql.Open(driver, cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE meeting_guest_sessions SET seen_at = 0 WHERE guest_id = "+ph, id); err != nil {
		t.Fatal(err)
	}
}

func TestSharedLobbyDepartureAfterPollingStops(t *testing.T) {
	ctx := context.Background()
	dbCfg := testdb.Config(t)
	st, err := store.Open(ctx, dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "departure", TenantID: store.DefaultTenantID, OrganizerSub: "host", Title: "Departure"})
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/RemoveParticipant") {
			removed++
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()
	bus := &captureBus{}
	hub := NewHub(bus)
	calls := NewCallManager(st.Chat(), hub, rtc.NewClient(lk.URL, "testkey", "testsecret1234567890"), nil)
	l := NewLobbyManager(hub, calls)
	l.UseShared(st.GuestSessions())
	l.SetLeaveGrace(time.Hour)
	var callbacks []func()
	l.afterFunc = func(_ time.Duration, f func()) *time.Timer {
		callbacks = append(callbacks, f)
		timer := time.AfterFunc(24*time.Hour, func() {})
		t.Cleanup(func() { timer.Stop() })
		return timer
	}
	guest, err := l.Knock(ctx, &store.MeetingGuest{MeetingID: "departure", GuestKey: "guest"}, res.Meeting, nil, "Guest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Decide(ctx, res.Meeting.RoomID, guest.GuestID, "host", true); err != nil {
		t.Fatal(err)
	}
	if _, err := calls.Join(ctx, JoinCallRequest{TenantID: store.DefaultTenantID, RoomID: res.Meeting.RoomID, UserID: guest.GuestID, IsGuest: true, Audio: true, ProtectIP: true}); err != nil {
		t.Fatal(err)
	}
	l.HandleDisconnect(guest.GuestID, 0)
	if _, ok := l.GetBySecret(guest.SessionSecret); !ok {
		t.Fatal("poll lost the session")
	}
	callbacks[0]() // first deadline while polling: it must schedule another deadline
	if len(callbacks) != 2 || removed != 0 {
		t.Fatalf("polling: scheduled %d timers, evicted %d", len(callbacks), removed)
	}
	ageSharedPresence(t, dbCfg, guest.GuestID)
	callbacks[1]() // polling stopped, presence elapsed
	callbacks[1]() // a stale callback cannot repeat the departure
	left := 0
	for _, ev := range bus.snapshot() {
		if ev.Type == EventLobbyKnock {
			var p LobbyKnockPayload
			if json.Unmarshal(ev.Data, &p) == nil && p.Status == "left" {
				left++
			}
		}
	}
	if left != 1 || removed != 1 {
		t.Fatalf("departure events=%d, SFU removals=%d; want one each", left, removed)
	}
	if state := calls.GetState(res.Meeting.RoomID); state != nil && len(state.Peers) > 0 {
		t.Fatal("departed guest retained call seat")
	}
	if _, ok := l.GetBySecret(guest.SessionSecret); ok {
		t.Fatal("departed session still resolves")
	}
}
