package store_test

import (
	"context"
	"sync"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestConcurrentErasuresLeaveOneSharedRoomOwner(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000f1"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	users := make([]*store.User, 3)
	for i, id := range []string{"erase-owner-a", "erase-owner-b", "survivor"} {
		u := &store.User{ID: id, Username: id, SSOProvider: "kyidentity", SSOSubject: id, OrgID: org, Role: "user", Status: "active"}
		users[i] = u
		if err := st.Users().CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"shared-a", "shared-b"} {
		r := &store.Room{ID: id, TenantID: org, Kind: store.RoomKindChannel, CreatedBy: users[0].ID}
		if err := st.Chat().CreateRoom(ctx, r, nil); err != nil {
			t.Fatal(err)
		}
		for i, u := range users[1:] {
			if err := st.Chat().AddRoomMember(ctx, &store.RoomMember{TenantID: org, RoomID: id, UserID: u.ID, Role: store.RoomRoleAdmin, JoinedAt: int64(i + 1)}); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := st.Chat().CreateMessage(ctx, store.CreateMessageParams{TenantID: org, RoomID: id, SenderID: users[2].ID, Body: "survives", Encoding: store.MessageEncodingPlainV1}); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users[:2] {
		if err := st.Chat().RememberErasedSubject(ctx, u.SSOSubject, org); err != nil {
			t.Fatal(err)
		}
		if err := st.Chat().DeactivateForErasure(ctx, org, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, u := range users[:2] {
		wg.Add(1)
		go func(u *store.User) { defer wg.Done(); <-start; _, err := st.Chat().EraseUser(ctx, org, u); errs <- err }(u)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		for _, u := range users[:2] {
			if _, err := st.Chat().EraseUser(ctx, org, u); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, id := range []string{"shared-a", "shared-b"} {
		r, err := st.Chat().GetRoom(ctx, org, id)
		if err != nil || r.CreatedBy != users[2].ID {
			t.Fatalf("room after concurrent erasure/replay: %+v %v", r, err)
		}
		msgs, _, err := st.Chat().ListMessages(ctx, store.MessagePageQuery{TenantID: org, RoomID: id})
		if err != nil || len(msgs) != 1 || msgs[0].Body != "survives" {
			t.Fatalf("concurrent erasure lost survivor content: %+v %v", msgs, err)
		}
		ms, err := st.Chat().ListRoomMembers(ctx, org, id)
		if err != nil || len(ms) != 1 || ms[0].UserID != users[2].ID || ms[0].Role != store.RoomRoleOwner {
			t.Fatalf("surviving owner: %+v %v", ms, err)
		}
	}
}
