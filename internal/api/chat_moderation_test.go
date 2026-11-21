package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestChatRoomKeepsAModerator(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	defer srv.CloseChat()
	ctx := context.Background()

	// IDs sort in join order, so ties on joined_at resolve the same way.
	_, aliceTok := createChatTestUser(t, st, "usr_mod_0_alice", "mod_alice", "user")
	dave, _ := createChatTestUser(t, st, "usr_mod_1_dave", "mod_dave", "user")
	bob, bobTok := createChatTestUser(t, st, "usr_mod_2_bob", "mod_bob", "user")
	carol, carolTok := createChatTestUser(t, st, "usr_mod_3_carol", "mod_carol", "user")
	erin, _ := createChatTestUser(t, st, "usr_mod_4_erin", "mod_erin", "user")

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"name": "ops"}, nil)
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	roomID := roomResp.Room.ID
	room := "/api/v1/rooms/" + roomID
	for _, m := range []struct{ id, role string }{{dave.ID, "member"}, {bob.ID, "member"}, {carol.ID, "member"}, {erin.ID, "admin"}} {
		if rec = doBearerJSON(t, srv, http.MethodPost, room+"/members", aliceTok, map[string]any{"user_id": m.id, "role": m.role}, nil); rec.Code != http.StatusCreated {
			t.Fatalf("add %s = %d (%s)", m.id, rec.Code, rec.Body)
		}
	}
	leave := func(id, tok string) {
		t.Helper()
		if rec := doBearerJSON(t, srv, http.MethodDelete, room+"/members/"+id, tok, nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("%s leaves = %d (%s)", id, rec.Code, rec.Body)
		}
	}
	roles := func() map[string]string {
		t.Helper()
		members, err := st.Chat().ListRoomMembers(ctx, store.DefaultTenantID, roomID)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, m := range members {
			got[m.UserID] = m.Role
		}
		return got
	}

	// Another moderator remains: nobody is promoted.
	leave("usr_mod_0_alice", aliceTok)
	if r := roles(); r[bob.ID] != store.RoomRoleMember || r[erin.ID] != store.RoomRoleAdmin {
		t.Fatalf("after owner left with an admin in the room: %v", r)
	}

	// The only admin left is suspended, so it does not count: when a member leaves, the
	// earliest-joined active member becomes owner, skipping suspended dave.
	for _, u := range []*store.User{dave, erin} {
		u.Status = "suspended"
		if err := st.Users().UpdateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	leave(carol.ID, carolTok)
	if r := roles(); r[bob.ID] != store.RoomRoleOwner || r[dave.ID] != store.RoomRoleMember || r[erin.ID] != store.RoomRoleAdmin {
		t.Fatalf("after a member left with only a suspended admin: %v", r)
	}
	if rec = doBearerJSON(t, srv, http.MethodPost, room+"/members", bobTok, map[string]any{"user_id": carol.ID}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("re-add carol = %d", rec.Code)
	}

	// Removing someone else leaves the remover moderating: no promotion.
	if rec = doBearerJSON(t, srv, http.MethodDelete, room+"/members/"+carol.ID, bobTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner removes carol = %d", rec.Code)
	}
	if rec = doBearerJSON(t, srv, http.MethodPost, room+"/members", bobTok, map[string]any{"user_id": carol.ID}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("re-add carol = %d", rec.Code)
	}
	if r := roles(); r[bob.ID] != store.RoomRoleOwner || r[carol.ID] != store.RoomRoleMember {
		t.Fatalf("after owner removed a member: %v", r)
	}

	leave(bob.ID, bobTok)
	if r := roles(); r[carol.ID] != store.RoomRoleOwner {
		t.Fatalf("after bob left: %v", r)
	}

	// Only suspended members remain: nobody is promoted, and leaving still works.
	leave(carol.ID, carolTok)
	if r := roles(); len(r) != 2 || r[dave.ID] != store.RoomRoleMember || r[erin.ID] != store.RoomRoleAdmin {
		t.Fatalf("with only suspended members left: %v", r)
	}
}
