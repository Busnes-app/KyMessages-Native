package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestChatWebhookStopsWhenCreatorLosesAccess(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	defer srv.CloseChat()

	alice, aliceTok := createChatTestUser(t, st, "usr_wh_alice", "wh_alice", "user")
	bob, bobTok := createChatTestUser(t, st, "usr_wh_bob", "wh_bob", "user")

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"name": "ops", "is_private": true}, nil)
	var roomResp struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &roomResp)
	room := "/api/v1/rooms/" + roomResp.Room.ID
	if rec = doBearerJSON(t, srv, http.MethodPost, room+"/members", aliceTok, map[string]any{"user_id": bob.ID, "role": "admin"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add admin = %d (%s)", rec.Code, rec.Body)
	}

	type hook struct {
		Webhook store.RoomWebhook `json:"webhook"`
		Token   string            `json:"token"`
	}
	create := func(tok string) hook {
		rec := doBearerJSON(t, srv, http.MethodPost, room+"/webhooks", tok, map[string]any{"name": "CI"}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create webhook = %d (%s)", rec.Code, rec.Body)
		}
		var h hook
		_ = json.Unmarshal(rec.Body.Bytes(), &h)
		return h
	}
	post := func(h hook) int {
		return doBearerJSON(t, srv, http.MethodPost, "/api/v1/webhooks/in/"+h.Webhook.ID, h.Token, map[string]any{"text": "hi"}, nil).Code
	}
	aliceHook, bobHook := create(aliceTok), create(bobTok)
	if a, b := post(aliceHook), post(bobHook); a != http.StatusCreated || b != http.StatusCreated {
		t.Fatalf("posts while creators moderate = %d, %d", a, b)
	}

	// Leaving the room ends the creator's webhook; the other stays.
	if rec = doBearerJSON(t, srv, http.MethodDelete, room+"/members/"+bob.ID, bobTok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("bob leaves = %d", rec.Code)
	}
	if code := post(bobHook); code != http.StatusForbidden {
		t.Fatalf("webhook of departed creator = %d, want 403", code)
	}
	if code := post(aliceHook); code != http.StatusCreated {
		t.Fatalf("webhook of remaining owner = %d, want 201", code)
	}

	// Offboarding the creator ends it too.
	alice.Status = "suspended"
	if err := st.Users().UpdateUser(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	if code := post(aliceHook); code != http.StatusForbidden {
		t.Fatalf("webhook of suspended creator = %d, want 403", code)
	}
}
