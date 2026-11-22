package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// A lagging read replica that still lists a removed member and a deactivated account never makes
// them push recipients.
func TestPushRecipientsReadThePrimary(t *testing.T) {
	if os.Getenv("KY_TEST_POSTGRES_DSN") == "" {
		t.Skip("read replicas exist only on PostgreSQL")
	}
	ctx := context.Background()
	seed := func(st store.Store) {
		t.Helper()
		for _, id := range []string{"u_sender", "u_removed", "u_gone", "u_kept"} {
			if err := st.Users().CreateUser(ctx, &store.User{ID: id, Username: id, Role: "user", Status: "active", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Chat().CreateRoom(ctx, &store.Room{ID: "rm_lag", Kind: store.RoomKindChannel, Name: "lag", CreatedBy: "u_sender"},
			[]string{"u_sender", "u_removed", "u_gone", "u_kept"}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"u_removed", "u_gone", "u_kept"} {
			if _, err := st.Chat().UpsertPushSubscription(ctx, liveSession(t, st, id), &store.PushSubscription{
				TenantID: store.DefaultTenantID, UserID: id, Endpoint: "https://fcm.googleapis.com/fcm/send/" + id, P256DH: "k", AuthSecret: "a",
			}, 20); err != nil {
				t.Fatal(err)
			}
		}
	}

	replicaCfg := testdb.Config(t)
	replica, err := store.Open(ctx, replicaCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	seed(replica)

	cfg := testdb.Config(t)
	cfg.ReadReplicaDSN = replicaCfg.DSN
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seed(st)
	if _, err := st.Chat().RemoveRoomMember(ctx, store.DefaultTenantID, "rm_lag", "u_removed"); err != nil {
		t.Fatal(err)
	}
	gone, err := st.Users().GetUserByID(ctx, "u_gone")
	if err != nil {
		t.Fatal(err)
	}
	gone.Status = "inactive"
	if err := st.Users().UpdateUser(ctx, gone); err != nil {
		t.Fatal(err)
	}

	subs, err := st.Chat().ListPushRecipients(ctx, store.DefaultTenantID, "rm_lag", []string{"u_removed", "u_gone", "u_kept"})
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].UserID != "u_kept" {
		got := []string{}
		for _, s := range subs {
			got = append(got, s.UserID)
		}
		t.Fatalf("recipients = %v, want only u_kept", got)
	}
}
