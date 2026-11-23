package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestSharedAttemptWindow(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for want := int64(1); want <= 3; want++ {
		if n, err := st.BumpAttempt(ctx, "login:192.0.2.1", time.Minute); err != nil || n != want {
			t.Fatalf("bump %d: %d %v", want, n, err)
		}
	}
	if n, left, err := st.AttemptState(ctx, "login:192.0.2.1"); err != nil || n != 3 || left <= 0 || left > time.Minute {
		t.Fatalf("state: %d %v %v", n, left, err)
	}
	if n, left, err := st.AttemptState(ctx, "login:unknown"); err != nil || n != 0 || left != 0 {
		t.Fatalf("unknown key: %d %v %v", n, left, err)
	}
	// An expired window restarts at one and reads as empty.
	if _, err := st.BumpAttempt(ctx, "short", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if n, _, err := st.AttemptState(ctx, "short"); err != nil || n != 0 {
		t.Fatalf("expired state: %d %v", n, err)
	}
	if n, err := st.BumpAttempt(ctx, "short", time.Minute); err != nil || n != 1 {
		t.Fatalf("bump after expiry: %d %v", n, err)
	}
	if err := st.PruneShared(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := st.AttemptState(ctx, "login:192.0.2.1"); n != 3 {
		t.Fatalf("prune removed a live window: %d", n)
	}
}

func TestSpendPoWOnce(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	exp := time.Now().Add(time.Minute).Unix()
	if ok, err := st.SpendPoW(ctx, "sig-1", exp); err != nil || !ok {
		t.Fatalf("first spend: %v %v", ok, err)
	}
	if ok, err := st.SpendPoW(ctx, "sig-1", exp); err != nil || ok {
		t.Fatalf("second spend: %v %v", ok, err)
	}
	if ok, _ := st.SpendPoW(ctx, "sig-2", time.Now().Add(-time.Minute).Unix()); !ok {
		t.Fatal("other signature")
	}
	if err := st.PruneShared(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.SpendPoW(ctx, "sig-1", exp); ok {
		t.Fatal("prune dropped an unexpired signature")
	}
}

func TestGuestSessionStore(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	chat := st.Chat()
	for _, org := range []string{"org-a", "org-b"} {
		if _, err := chat.EnsureTenant(ctx, org); err != nil {
			t.Fatal(err)
		}
		if _, err := chat.UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: org, OrganizerSub: "s", Title: "T"}); err != nil {
			t.Fatal(err)
		}
	}
	a, _, _, _ := chat.GetMeeting(ctx, "org-a", "m")
	b, _, _, _ := chat.GetMeeting(ctx, "org-b", "m")
	gs := st.GuestSessions()
	now := time.Now().UnixMilli()
	sess := func(m *store.Meeting, id string) store.GuestSession {
		return store.GuestSession{GuestID: id, TenantID: m.TenantID, MeetingID: m.ID, RoomID: m.RoomID, GuestKey: "k",
			DisplayName: "V", Status: "waiting", KnockedAt: now, SeenAt: now, ExpiresAt: now + 60000}
	}
	if _, err := gs.Create(ctx, "secret-a1", sess(a, "ga1")); err != nil {
		t.Fatal(err)
	}
	// The same invite key in another org is another invite.
	if r, err := gs.Create(ctx, "secret-b1", sess(b, "gb1")); err != nil || len(r) != 0 {
		t.Fatalf("org b knock replaced %v %v", r, err)
	}
	// A second knock with org A's invite replaces org A's session only.
	r, err := gs.Create(ctx, "secret-a2", sess(a, "ga2"))
	if err != nil || len(r) != 1 || r[0].GuestID != "ga1" {
		t.Fatalf("replace: %v %v", r, err)
	}
	if _, err := gs.BySecret(ctx, "secret-a1", now, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("replaced secret still resolves")
	}
	if g, err := gs.BySecret(ctx, "secret-b1", now, time.Hour); err != nil || g.TenantID != "org-b" {
		t.Fatalf("org b session: %+v %v", g, err)
	}
	// Admission needs the guest's own room.
	if _, err := gs.Admit(ctx, b.RoomID, "ga2", "host", now, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("admitted through another org's room")
	}
	if g, err := gs.Admit(ctx, a.RoomID, "ga2", "host", now, time.Hour); err != nil || g.Status != "admitted" {
		t.Fatalf("admit: %+v %v", g, err)
	}
	// A session touched within the idle window stays; one left idle goes.
	if err := gs.Touch(ctx, "ga2", "gb1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := gs.DeleteIfUnseen(ctx, "ga2", time.Minute); len(r) != 0 {
		t.Fatal("touched session deleted")
	}
	time.Sleep(30 * time.Millisecond)
	if r, _ := gs.DeleteIfUnseen(ctx, "ga2", 10*time.Millisecond); len(r) != 1 {
		t.Fatal("idle session kept")
	}
	// Expired sessions do not resolve, and closing one org's tenant leaves the other.
	if _, err := gs.BySecret(ctx, "secret-b1", now+60001, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired session resolves")
	}
	if r, _ := gs.DeleteTenant(ctx, "org-a"); len(r) != 0 {
		t.Fatalf("org a had sessions left: %v", r)
	}
	if r, _ := gs.DeleteTenant(ctx, "org-b"); len(r) != 1 {
		t.Fatalf("org b sessions: %v", r)
	}
}

func TestGuestAdmissionCannotRacePastHostedMeetingClosure(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "closing-org"); err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		meeting, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "closing", TenantID: "closing-org", OrganizerSub: "host", Title: "T"})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UnixMilli()
		session := store.GuestSession{GuestID: fmt.Sprintf("closing-guest-%d", i), TenantID: "closing-org", MeetingID: "closing", RoomID: meeting.Meeting.RoomID, GuestKey: "key", DisplayName: "Guest", Status: "waiting", KnockedAt: now, ExpiresAt: now + 3600000}
		start := make(chan struct{})
		var createErr, closeErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, createErr = st.GuestSessions().Create(ctx, "closing-secret", session)
		}()
		go func() { defer wg.Done(); <-start; _, closeErr = st.Chat().CloseMeeting(ctx, "closing-org", "closing") }()
		close(start)
		wg.Wait()
		if closeErr != nil || createErr != nil && !errors.Is(createErr, store.ErrNotFound) {
			t.Fatalf("concurrent close/knock:%v %v", closeErr, createErr)
		}
		if exists, err := st.GuestSessions().Exists(ctx, session.GuestID); err != nil || exists {
			t.Fatalf("closed meeting kept admission:%v %v", exists, err)
		}
		if _, err := st.GuestSessions().Create(ctx, "stale-secret", session); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("stale meeting model created a principal:%v", err)
		}
		if _, err := st.GuestSessions().Admit(ctx, session.RoomID, session.GuestID, "host", now, time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("closed principal admitted:%v", err)
		}
	}
}
