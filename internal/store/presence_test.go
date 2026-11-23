package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestPresenceStore(t *testing.T) {
	ctx := context.Background()
	base := newTestStore(t)
	for _, id := range []string{"u-a", "u-b"} {
		if err := base.Users().CreateUser(ctx, &store.User{ID: id, Username: id, Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
			t.Fatal(err)
		}
	}
	st := base.Presence()
	got, err := st.Presence(ctx, "t1", []string{"u-a"})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	busy := []store.BusyWindow{{Start: now, End: now.Add(time.Hour)}, {Start: now.Add(2 * time.Hour), End: now.Add(3 * time.Hour)}}
	if o, err := st.SetCalendar(ctx, "t1", "u-a", 10, busy); o != store.PresenceApplied || err != nil {
		t.Fatalf("calendar: %v %v", o, err)
	}
	if o, _ := st.SetCalendar(ctx, "t1", "u-a", 9, nil); o != store.PresenceStale {
		t.Fatalf("older revision: %v", o)
	}
	if o, _ := st.SetCalendar(ctx, "t1", "u-a", 10, busy); o != store.PresenceApplied {
		t.Fatalf("same revision is applied again: %v", o)
	}
	if o, _ := st.SetOutOfOffice(ctx, "t1", "u-a", 5, now, now.Add(24*time.Hour)); o != store.PresenceApplied {
		t.Fatalf("ooo: %v", o)
	}
	if err := st.SetManual(ctx, "t1", "u-a", "busy", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	p := mustPresence(t, st, "t1", "u-a")
	if p.ShareOff || len(p.Busy) != 2 || !p.Busy[1].End.Equal(now.Add(3*time.Hour)) || p.CalendarAt.IsZero() || p.CalendarRev != 10 ||
		!p.OOOEnd.Equal(now.Add(24*time.Hour)) || p.ManualState != "busy" || !p.ManualUntil.Equal(now.Add(time.Hour)) {
		t.Fatalf("stored: %+v", p)
	}

	// Off clears everything and refuses later inputs.
	if err := st.SetSharing(ctx, "t1", "u-a", false); err != nil {
		t.Fatal(err)
	}
	p = mustPresence(t, st, "t1", "u-a")
	if !p.ShareOff || p.Busy != nil || !p.CalendarAt.IsZero() || !p.OOOEnd.IsZero() || p.ManualState != "" {
		t.Fatalf("after off: %+v", p)
	}
	if o, _ := st.SetCalendar(ctx, "t1", "u-a", 11, busy); o != store.PresenceSharingOff {
		t.Fatalf("calendar while off: %v", o)
	}
	if o, _ := st.SetOutOfOffice(ctx, "t1", "u-a", 6, now, now.Add(time.Hour)); o != store.PresenceSharingOff {
		t.Fatalf("ooo while off: %v", o)
	}
	if err := st.SetManual(ctx, "t1", "u-a", "away", now.Add(time.Hour)); !errors.Is(err, store.ErrSharingOff) {
		t.Fatalf("manual while off: %v", err)
	}
	if p := mustPresence(t, st, "t1", "u-a"); p.Busy != nil || p.ManualState != "" {
		t.Fatalf("stored while off: %+v", p)
	}
	// Back on: a push older than the last stored one stays stale.
	if err := st.SetSharing(ctx, "t1", "u-a", true); err != nil {
		t.Fatal(err)
	}
	if o, _ := st.SetCalendar(ctx, "t1", "u-a", 9, busy); o != store.PresenceStale {
		t.Fatalf("old push after on: %v", o)
	}
	if o, _ := st.SetOutOfOffice(ctx, "t1", "u-a", 7, time.Time{}, time.Time{}); o != store.PresenceApplied {
		t.Fatalf("ooo off: %v", o)
	}
	if err := st.SetManual(ctx, "t1", "u-a", "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if p := mustPresence(t, st, "t1", "u-a"); p.ShareOff || !p.OOOEnd.IsZero() || p.ManualState != "" || !p.ManualUntil.IsZero() {
		t.Fatalf("cleared: %+v", p)
	}
	all, err := st.Presence(ctx, "t1", []string{"u-a", "u-none"})
	if err != nil || len(all) != 1 {
		t.Fatalf("batch: %v %v", all, err)
	}
	// Rows never cross tenants.
	if other, err := st.Presence(ctx, "t2", []string{"u-a"}); err != nil || len(other) != 0 {
		t.Fatalf("other tenant read: %v %v", other, err)
	}
	// Deleting the user deletes their row.
	if _, err := st.SetCalendar(ctx, "t1", "u-b", 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := base.Users().DeleteUser(ctx, "u-b"); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.Presence(ctx, "t1", []string{"u-b"}); len(left) != 0 {
		t.Fatalf("presence row outlived its user: %v", left)
	}
}

func mustPresence(t *testing.T, st store.PresenceStore, tenant, sub string) store.Presence {
	t.Helper()
	m, err := st.Presence(context.Background(), tenant, []string{sub})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := m[sub]
	if !ok {
		t.Fatalf("no row for %s", sub)
	}
	return p
}
