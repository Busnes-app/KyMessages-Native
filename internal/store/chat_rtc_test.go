package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestCallSessionLifecycleAndMediaPolicy(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// Update tenant media policy.
	tenant, err := st.Chat().UpdateTenantMediaPolicy(ctx, store.DefaultTenantID, store.P2PPolicySFUOnly, 3, 5, false)
	if err != nil {
		t.Fatalf("UpdateTenantMediaPolicy: %v", err)
	}
	if tenant.P2PPolicy != store.P2PPolicySFUOnly || tenant.P2PMaxVideo != 3 || tenant.P2PMaxAudio != 5 || tenant.GuestForceSFU {
		t.Fatalf("unexpected tenant policy: %+v", tenant)
	}

	room := &store.Room{Kind: store.RoomKindChannel, Name: "standup", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1", "u2"}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	cs := &store.CallSession{
		RoomID:    room.ID,
		Mode:      store.CallModeP2PMesh,
		Epoch:     1,
		StartedBy: "u1",
	}
	if err := st.Chat().CreateCallSession(ctx, cs); err != nil {
		t.Fatalf("CreateCallSession: %v", err)
	}

	got, err := st.Chat().GetActiveCallSession(ctx, store.DefaultTenantID, room.ID)
	if err != nil {
		t.Fatalf("GetActiveCallSession: %v", err)
	}
	if got.ID != cs.ID || got.Mode != store.CallModeP2PMesh || got.Epoch != 1 {
		t.Fatalf("unexpected call session: %+v", got)
	}

	got.Mode = store.CallModeSFULiveKit
	got.Epoch = 2
	got.SFUSticky = true
	got.LiveKitRoom = "ky_" + cs.ID
	if err := st.Chat().UpdateCallSession(ctx, got); err != nil {
		t.Fatalf("UpdateCallSession: %v", err)
	}

	updated, err := st.Chat().GetActiveCallSession(ctx, store.DefaultTenantID, room.ID)
	if err != nil {
		t.Fatalf("GetActiveCallSession after update: %v", err)
	}
	if updated.Mode != store.CallModeSFULiveKit || updated.Epoch != 2 || !updated.SFUSticky || updated.LiveKitRoom != "ky_"+cs.ID {
		t.Fatalf("update did not persist: %+v", updated)
	}

	if err := st.Chat().EndCallSession(ctx, store.DefaultTenantID, cs.ID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("EndCallSession: %v", err)
	}
	if _, err := st.Chat().GetActiveCallSession(ctx, store.DefaultTenantID, room.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after end, got %v", err)
	}
}

func TestMeetingUpsertReconcileAndClose(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().UnixMilli()

	// Create meeting with 2 internal members and 2 guests.
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{
		ID:            "cal_evt_1",
		OrganizerID:   "u_org",
		OrganizerSub:  "sub-org",
		Title:         "Q4 Roadmap Review",
		MemberUserIDs: []string{"u_org", "u_alice"},
		Windows: []store.MeetingWindow{
			{StartsAt: now - 60_000, EndsAt: now + 3_600_000},
		},
		NewGuestTokens: map[string]store.MeetingGuest{
			"g1": {GuestKey: "g1", TokenHash: "hash_g1_v1"},
			"g2": {GuestKey: "g2", TokenHash: "hash_g2_v1"},
		},
		KeepGuestKeys: map[string]struct{}{"g1": {}, "g2": {}},
	})
	if err != nil {
		t.Fatalf("UpsertMeeting create: %v", err)
	}
	if !res.Created || res.Room.Kind != store.RoomKindMeeting || len(res.IssuedGuestKeys) != 2 {
		t.Fatalf("unexpected create result: %+v", res)
	}

	// Lookup guest by token hash.
	g, m, wins, err := st.Chat().GetMeetingGuestByTokenHash(ctx, "hash_g1_v1")
	if err != nil {
		t.Fatalf("GetMeetingGuestByTokenHash: %v", err)
	}
	if g.GuestKey != "g1" || m.Title != "Q4 Roadmap Review" || len(wins) != 1 {
		t.Fatalf("unexpected guest lookup: g=%+v m=%+v wins=%+v", g, m, wins)
	}

	// Reconcile: rename, replace u_alice with u_bob, revoke g2, keep g1, add g3.
	res2, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{
		ID:            "cal_evt_1",
		OrganizerID:   "u_org",
		OrganizerSub:  "sub-org",
		Title:         "Q4 Roadmap Final",
		MemberUserIDs: []string{"u_org", "u_bob"},
		Windows: []store.MeetingWindow{
			{StartsAt: now, EndsAt: now + 7_200_000},
		},
		NewGuestTokens: map[string]store.MeetingGuest{
			"g1": {GuestKey: "g1", TokenHash: "hash_g1_ignored"},
			"g3": {GuestKey: "g3", TokenHash: "hash_g3_v1"},
		},
		KeepGuestKeys: map[string]struct{}{"g1": {}, "g3": {}},
	})
	if err != nil {
		t.Fatalf("UpsertMeeting reconcile: %v", err)
	}
	if res2.Created || res2.Room.Name != "Q4 Roadmap Final" {
		t.Fatalf("unexpected reconcile result: %+v", res2)
	}
	if len(res2.IssuedGuestKeys) != 1 || res2.IssuedGuestKeys[0] != "g3" {
		t.Fatalf("expected only g3 newly issued, got %v", res2.IssuedGuestKeys)
	}
	if len(res2.RevokedGuestKeys) != 1 || res2.RevokedGuestKeys[0] != "g2" {
		t.Fatalf("expected g2 revoked, got %v", res2.RevokedGuestKeys)
	}

	// Original g1 hash must remain unchanged.
	if _, _, _, err := st.Chat().GetMeetingGuestByTokenHash(ctx, "hash_g1_v1"); err != nil {
		t.Fatalf("g1 token hash should stay stable: %v", err)
	}
	// g2 should be marked revoked.
	g2, _, _, err := st.Chat().GetMeetingGuestByTokenHash(ctx, "hash_g2_v1")
	if err != nil || g2.RevokedAt == nil {
		t.Fatalf("expected g2 revoked, got g2=%+v err=%v", g2, err)
	}

	// Close meeting: room closed and all guests revoked.
	closed, err := st.Chat().CloseMeeting(ctx, store.DefaultTenantID, "cal_evt_1")
	if err != nil || closed.ClosedAt == nil {
		t.Fatalf("CloseMeeting: closed=%+v err=%v", closed, err)
	}
	g3, _, _, err := st.Chat().GetMeetingGuestByTokenHash(ctx, "hash_g3_v1")
	if err != nil || g3.RevokedAt == nil {
		t.Fatalf("expected g3 revoked on close, got %+v err=%v", g3, err)
	}
}
