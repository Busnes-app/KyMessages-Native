package store_test

import (
	"context"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// A replica that has not yet seen a removal must not extend the removed member's access.
func TestChatSearchAndRoomListIgnoreLaggingReplica(t *testing.T) {
	ctx := context.Background()
	primaryCfg := testdb.Config(t)
	if primaryCfg.Driver != "postgres" {
		t.Skip("read replicas exist only on Postgres; set KY_TEST_POSTGRES_DSN")
	}
	replicaCfg := testdb.Config(t)

	seed := func(cfg store.Store) {
		t.Helper()
		room := &store.Room{ID: "rm_lag", Kind: store.RoomKindChannel, Name: "ops", CreatedBy: "u_alice"}
		if err := cfg.Chat().CreateRoom(ctx, room, []string{"u_bob"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := cfg.Chat().CreateMessage(ctx, store.CreateMessageParams{ID: "msg_lag", RoomID: room.ID, SenderID: "u_alice", Body: "invoice"}); err != nil {
			t.Fatal(err)
		}
	}
	replica, err := store.Open(ctx, replicaCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	seed(replica)

	withReplica := primaryCfg
	withReplica.ReadReplicaDSN = replicaCfg.DSN
	st, err := store.Open(ctx, withReplica)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seed(st)
	if err := st.Chat().RemoveRoomMember(ctx, store.DefaultTenantID, "rm_lag", "u_bob"); err != nil {
		t.Fatal(err)
	}

	if hits, err := st.Chat().SearchMessages(ctx, store.DefaultTenantID, "u_bob", "", "invoice", 20); err != nil || len(hits) != 0 {
		t.Fatalf("removed member search = (%d hits, %v), want none", len(hits), err)
	}
	if hits, err := st.Chat().SearchMessages(ctx, store.DefaultTenantID, "u_bob", "rm_lag", "invoice", 20); err != nil || len(hits) != 0 {
		t.Fatalf("removed member room search = (%d hits, %v), want none", len(hits), err)
	}
	if rooms, err := st.Chat().ListUserRooms(ctx, store.DefaultTenantID, "u_bob"); err != nil || len(rooms) != 0 {
		t.Fatalf("removed member rooms = (%d, %v), want none", len(rooms), err)
	}
	// The member who stayed still finds it.
	if hits, err := st.Chat().SearchMessages(ctx, store.DefaultTenantID, "u_alice", "", "invoice", 20); err != nil || len(hits) != 1 {
		t.Fatalf("member search = (%d hits, %v), want 1", len(hits), err)
	}
}
