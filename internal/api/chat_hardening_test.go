package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestChatInputHardening(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	defer srv.CloseChat()

	_, aliceTok := createChatTestUser(t, st, "usr_hd_alice", "hd_alice", "user")
	gone, _ := createChatTestUser(t, st, "usr_hd_gone", "hd_gone", "user")
	gone.Status = "suspended"
	if err := st.Users().UpdateUser(context.Background(), gone); err != nil {
		t.Fatal(err)
	}

	newRoom := func(name string) string {
		t.Helper()
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"name": name}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create room = %d (%s)", rec.Code, rec.Body)
		}
		var resp struct {
			Room store.Room `json:"room"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return "/api/v1/rooms/" + resp.Room.ID
	}
	send := func(room string, body map[string]any) (int, store.Message) {
		t.Helper()
		rec := doBearerJSON(t, srv, http.MethodPost, room+"/messages", aliceTok, body, nil)
		var resp struct {
			Message store.Message `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp.Message
	}
	roomA, roomB := newRoom("a"), newRoom("b")

	// Replies must point at a message in the same room.
	_, inB := send(roomB, sealed("elsewhere", nil))
	if code, _ := send(roomA, sealed("re", map[string]any{"reply_to_id": inB.ID})); code != http.StatusBadRequest {
		t.Fatalf("reply to another room's message = %d, want 400", code)
	}
	if code, _ := send(roomA, sealed("re", map[string]any{"reply_to_id": "msg_missing"})); code != http.StatusBadRequest {
		t.Fatalf("reply to a missing message = %d, want 400", code)
	}
	if code, _ := send(roomB, sealed("re", map[string]any{"reply_to_id": inB.ID})); code != http.StatusCreated {
		t.Fatalf("reply in the same room = %d, want 201", code)
	}

	// Suspended accounts cannot be put in rooms or DMs.
	if rec := doBearerJSON(t, srv, http.MethodPost, roomA+"/members", aliceTok, map[string]any{"user_id": gone.ID}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("add suspended member = %d, want 404", rec.Code)
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": "dm", "dm_user_id": gone.ID}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("DM a suspended user = %d, want 404", rec.Code)
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"name": "c", "member_ids": []string{gone.ID}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("create room with a suspended member = %d, want 400", rec.Code)
	}
}

func TestChatRoomActionsAreRateLimited(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	defer srv.CloseChat()
	_, tok := createChatTestUser(t, st, "usr_rl_alice", "rl_alice", "user")
	_, otherTok := createChatTestUser(t, st, "usr_rl_bob", "rl_bob", "user")

	create := func(tok string) int {
		return doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"name": "spam"}, nil).Code
	}
	for i := range 30 {
		if code := create(tok); code != http.StatusCreated {
			t.Fatalf("room %d = %d, want 201", i+1, code)
		}
	}
	if code := create(tok); code != http.StatusTooManyRequests {
		t.Fatalf("room 31 = %d, want 429", code)
	}
	// The limit is per user.
	if code := create(otherTok); code != http.StatusCreated {
		t.Fatalf("another user's room = %d, want 201", code)
	}
}
