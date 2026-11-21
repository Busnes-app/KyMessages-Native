package chat

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestLobbyKnockAdmitSingleSessionAndLeaveGrace(t *testing.T) {
	ctx := context.Background()
	bus := &captureBus{}
	hub := NewHub(bus)
	lobby := NewLobbyManager(hub, nil)
	lobby.SetLeaveGrace(35 * time.Millisecond)

	now := time.Now().UTC()
	meeting := &store.Meeting{
		ID:       "mtg_1",
		TenantID: store.DefaultTenantID,
		RoomID:   "rm_mtg_1",
		Title:    "Customer Sync",
	}
	windows := []store.MeetingWindow{
		{MeetingID: "mtg_1", StartsAt: now.Add(-5 * time.Minute).UnixMilli(), EndsAt: now.Add(30 * time.Minute).UnixMilli()},
	}
	guest := &store.MeetingGuest{
		ID:        "gst_1",
		MeetingID: "mtg_1",
		GuestKey:  "ext-1",
	}

	// Knock outside window must be rejected.
	expiredWins := []store.MeetingWindow{
		{MeetingID: "mtg_1", StartsAt: now.Add(-3 * time.Hour).UnixMilli(), EndsAt: now.Add(-2 * time.Hour).UnixMilli()},
	}
	if _, err := lobby.Knock(ctx, guest, meeting, expiredWins, "Sam"); !errors.Is(err, ErrMeetingNotInWindow) {
		t.Fatalf("expected ErrMeetingNotInWindow, got %v", err)
	}

	// Knock inside window succeeds.
	s1, err := lobby.Knock(ctx, guest, meeting, windows, "Sam")
	if err != nil {
		t.Fatalf("Knock: %v", err)
	}
	if s1.Status != "waiting" || s1.SessionSecret == "" {
		t.Fatalf("unexpected guest session: %+v", s1)
	}
	if len(lobby.ListWaiting(meeting.RoomID)) != 1 {
		t.Fatalf("expected 1 waiting guest")
	}

	// Knocking a second time with the same guest token evicts the first session (1 live session per token).
	s2, err := lobby.Knock(ctx, guest, meeting, windows, "Sam 2")
	if err != nil {
		t.Fatalf("second Knock: %v", err)
	}
	if _, ok := lobby.GetBySecret(s1.SessionSecret); ok {
		t.Fatalf("first guest session should have been evicted on second knock")
	}
	if _, ok := lobby.GetBySecret(s2.SessionSecret); !ok {
		t.Fatalf("second guest session should be active")
	}

	// Admit guest.
	admitted, err := lobby.Decide(ctx, meeting.RoomID, s2.GuestID, "u_host", true)
	if err != nil || admitted.Status != "admitted" {
		t.Fatalf("Decide admit failed: %+v err=%v", admitted, err)
	}

	// Disconnect triggers leave-means-wait-again after grace period.
	lobby.HandleDisconnect(s2.GuestID, 0)
	time.Sleep(70 * time.Millisecond)
	if _, ok := lobby.GetBySecret(s2.SessionSecret); ok {
		t.Fatalf("guest session should expire after leave grace period")
	}
}
