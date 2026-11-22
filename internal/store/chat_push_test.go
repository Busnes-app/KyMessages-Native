package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// liveSession signs userID in and returns the session's token hash.
func liveSession(t *testing.T, st store.Store, userID string) string {
	t.Helper()
	hash := fmt.Sprintf("sess-%s-%d", userID, time.Now().UnixNano())
	if err := st.Sessions().CreateSession(context.Background(), &store.Session{
		TokenHash: hash, UserID: userID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}, ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return hash
}

// A registration racing a grant revocation never leaves a subscription behind, and one made
// with a session that is already revoked is refused.
func TestPushRegistrationSerializesWithRevocation(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	u := &store.User{ID: "usr_push_race", Username: "pushrace", Role: "user", Status: "active", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	sub := func(i int) *store.PushSubscription {
		return &store.PushSubscription{TenantID: store.DefaultTenantID, UserID: u.ID,
			Endpoint: fmt.Sprintf("https://fcm.googleapis.com/fcm/send/race-%d", i), P256DH: "k", AuthSecret: "a"}
	}

	revoked := liveSession(t, st, u.ID)
	if err := st.Sessions().DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().UpsertPushSubscription(ctx, revoked, sub(0), 20); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("register with a revoked session = %v, want ErrNotFound", err)
	}

	for i := 1; i <= 20; i++ {
		hash := liveSession(t, st, u.ID)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := st.Chat().UpsertPushSubscription(ctx, hash, sub(i), 20); err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("register: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := st.Sessions().DeleteUserSessions(ctx, u.ID); err != nil {
				t.Errorf("revoke: %v", err)
			}
		}()
		wg.Wait()
		if subs, _ := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u.ID); len(subs) != 0 {
			t.Fatalf("round %d: %d subscriptions survived revocation", i, len(subs))
		}
	}
}

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
	u1Sess, u2Sess := liveSession(t, st, u1.ID), liveSession(t, st, u2.ID)
	for i := 1; i <= 3; i++ {
		_, err := st.Chat().UpsertPushSubscription(ctx, u1Sess, &store.PushSubscription{
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
	if _, err := st.Chat().UpsertPushSubscription(ctx, u2Sess, &store.PushSubscription{
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

// A browser that re-registers is the newest for the per-user cap, so an abandoned one goes first.
func TestPushCapEvictsTheLeastRecentlyRegistered(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	u := &store.User{ID: "usr_push_cap", Username: "pushcap", Role: "user", Status: "active", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	sess := liveSession(t, st, u.ID)
	register := func(ep string) {
		t.Helper()
		if _, err := st.Chat().UpsertPushSubscription(ctx, sess, &store.PushSubscription{
			TenantID: store.DefaultTenantID, UserID: u.ID, Endpoint: "https://fcm.googleapis.com/fcm/send/" + ep, P256DH: "k", AuthSecret: "a",
		}, 2); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	register("active")
	register("abandoned")
	register("active") // the active browser syncs on every load
	register("new")
	subs, err := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range subs {
		got[s.Endpoint[len("https://fcm.googleapis.com/fcm/send/"):]] = true
	}
	if len(subs) != 2 || !got["active"] || !got["new"] {
		t.Fatalf("kept %v, want active and new", got)
	}
}

// A long non-ASCII User-Agent is cut on a character boundary, so PostgreSQL accepts it.
func TestPushUserAgentTruncatesOnARuneBoundary(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	u := &store.User{ID: "usr_push_ua", Username: "pushua", Role: "user", Status: "active", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	ua := strings.Repeat("a", 254) + strings.Repeat("é", 10)
	if _, err := st.Chat().UpsertPushSubscription(ctx, liveSession(t, st, u.ID), &store.PushSubscription{
		TenantID: store.DefaultTenantID, UserID: u.ID, Endpoint: "https://fcm.googleapis.com/fcm/send/ua", P256DH: "k", AuthSecret: "a", UserAgent: ua,
	}, 20); err != nil {
		t.Fatal(err)
	}
	subs, err := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u.ID)
	if err != nil || len(subs) != 1 {
		t.Fatalf("list = %v, %v", subs, err)
	}
	if got := subs[0].UserAgent; !utf8.ValidString(got) || len(got) > 255 || got != strings.Repeat("a", 254) {
		t.Fatalf("stored user agent %q (%d bytes), want the 254 ASCII bytes", got, len(got))
	}
}
