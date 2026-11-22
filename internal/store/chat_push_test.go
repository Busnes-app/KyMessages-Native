package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestPushSubscriptionsLifecycleAndRevocation(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	u1 := &store.User{ID: "usr_push_1", Username: "pushalice", DisplayName: "Alice", Role: "user", Status: "active", CreatedAt: time.Now()}
	u2 := &store.User{ID: "usr_push_2", Username: "pushbob", DisplayName: "Bob", Role: "user", Status: "active", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u1); err != nil {
		t.Fatalf("create u1: %v", err)
	}
	if err := st.Users().CreateUser(ctx, u2); err != nil {
		t.Fatalf("create u2: %v", err)
	}

	// Upsert + cap enforcement (max 2 per user).
	for i := 1; i <= 3; i++ {
		_, err := st.Chat().UpsertPushSubscription(ctx, &store.PushSubscription{
			TenantID:   store.DefaultTenantID,
			UserID:     u1.ID,
			Endpoint:   fmt.Sprintf("https://fcm.googleapis.com/fcm/send/ep-%d", i),
			P256DH:     "p256dh-key",
			AuthSecret: "auth-secret",
			UserAgent:  "TestBrowser/1.0",
		}, 2)
		if err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	subs, err := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u1.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected cap=2 subscriptions, got %d", len(subs))
	}

	// Cross-user delete must NOT remove u1's subscription.
	if err := st.Chat().DeletePushSubscriptionByID(ctx, store.DefaultTenantID, u2.ID, subs[0].ID); err != nil {
		t.Fatalf("cross-user delete err: %v", err)
	}
	subsAfter, _ := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u1.ID)
	if len(subsAfter) != 2 {
		t.Fatalf("cross-user delete removed u1 subscription!")
	}

	// Add u2 subscription and test batch lookup.
	if _, err := st.Chat().UpsertPushSubscription(ctx, &store.PushSubscription{
		TenantID:   store.DefaultTenantID,
		UserID:     u2.ID,
		Endpoint:   "https://web.push.apple.com/bob-ep",
		P256DH:     "p256dh-bob",
		AuthSecret: "auth-bob",
	}, 20); err != nil {
		t.Fatalf("upsert u2: %v", err)
	}
	batch, err := st.Chat().ListPushSubscriptionsForUsers(ctx, store.DefaultTenantID, []string{u1.ID, u2.ID})
	if err != nil {
		t.Fatalf("batch list: %v", err)
	}
	if len(batch) != 3 {
		t.Fatalf("expected 3 batch subs, got %d", len(batch))
	}

	// DeleteUserSessions MUST atomically wipe u1's push subscriptions (offboarding guarantee).
	if err := st.Sessions().DeleteUserSessions(ctx, u1.ID); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	u1Subs, _ := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u1.ID)
	if len(u1Subs) != 0 {
		t.Fatalf("expected 0 push subs after DeleteUserSessions, got %d", len(u1Subs))
	}
	u2Subs, _ := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u2.ID)
	if len(u2Subs) != 1 {
		t.Fatalf("u2 subscriptions should be unaffected, got %d", len(u2Subs))
	}
}

func TestUpdateRoomNotifyMode(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	u := &store.User{ID: "usr_nm_1", Username: "notifyuser", DisplayName: "Notify", Role: "user", Status: "active", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rm := &store.Room{
		TenantID:  store.DefaultTenantID,
		Kind:      store.RoomKindChannel,
		Name:      "alerts",
		CreatedBy: u.ID,
	}
	if err := st.Chat().CreateRoom(ctx, rm, []string{u.ID}); err != nil {
		t.Fatalf("create room: %v", err)
	}

	if err := st.Chat().UpdateRoomNotifyMode(ctx, store.DefaultTenantID, rm.ID, u.ID, store.NotifyModeMentions); err != nil {
		t.Fatalf("UpdateRoomNotifyMode mentions: %v", err)
	}
	m, err := st.Chat().GetRoomMember(ctx, store.DefaultTenantID, rm.ID, u.ID)
	if err != nil || m.NotifyMode != store.NotifyModeMentions {
		t.Fatalf("expected mentions, got %+v (%v)", m, err)
	}

	if err := st.Chat().UpdateRoomNotifyMode(ctx, store.DefaultTenantID, rm.ID, u.ID, "bogus"); err == nil {
		t.Fatalf("expected error for invalid notify mode")
	}
}
