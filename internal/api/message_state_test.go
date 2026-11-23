package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// On-device search checks its hits against the server: only messages the caller can still read
// come back, with their deleted flag and edit time, and never their text.
func TestChatMessageStates(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	const orgA, orgB = "00000000-0000-4000-8000-00000000000a", "00000000-0000-4000-8000-00000000000b"
	_, aliceTok := createOrgUser(t, st, "usr_ms_alice", "msalice", "user", orgA)
	bob, bobTok := createOrgUser(t, st, "usr_ms_bob", "msbob", "user", orgA)
	_, carolTok := createOrgUser(t, st, "usr_ms_carol", "mscarol", "user", orgB)

	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"name": "states", "member_ids": []string{bob.ID}}, nil)
	var created struct{ Room struct{ ID string } }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	room := "/api/v1/rooms/" + created.Room.ID
	send := func(body string) string {
		rec := doBearerJSON(t, srv, http.MethodPost, room+"/messages", aliceTok, sealed(body, nil), nil)
		var m struct{ Message struct{ ID string } }
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if m.Message.ID == "" {
			t.Fatalf("send = %d %s", rec.Code, rec.Body.String())
		}
		return m.Message.ID
	}
	kept, edited, deleted := send("kept"), send("before edit"), send("to delete")
	if c := doBearerJSON(t, srv, http.MethodPatch, room+"/messages/"+edited, aliceTok, sealed("after edit", nil), nil).Code; c != http.StatusOK {
		t.Fatalf("edit = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodDelete, room+"/messages/"+deleted, aliceTok, nil, nil).Code; c != http.StatusOK {
		t.Fatalf("delete = %d", c)
	}

	states := func(tok string, ids ...string) map[string]map[string]any {
		t.Helper()
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/messages/state", tok, map[string]any{"ids": ids}, nil)
		var resp struct{ Messages []map[string]any }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("states = %d %s", rec.Code, rec.Body.String())
		}
		out := map[string]map[string]any{}
		for _, m := range resp.Messages {
			if _, ok := m["body"]; ok {
				t.Fatalf("state carries message text: %v", m)
			}
			out[m["id"].(string)] = m
		}
		return out
	}
	got := states(bobTok, kept, edited, deleted, "msg_unknown")
	if len(got) != 3 || got[kept]["deleted"] != false || got[kept]["edited_at"].(float64) != 0 ||
		got[edited]["edited_at"].(float64) == 0 || got[deleted]["deleted"] != true {
		t.Fatalf("member states = %v", got)
	}
	// Another org's member, or anyone outside the room, learns nothing.
	if got := states(carolTok, kept, edited, deleted); len(got) != 0 {
		t.Fatalf("cross-org states = %v", got)
	}
	// Leaving the room drops its messages from the answer.
	if c := doBearerJSON(t, srv, http.MethodDelete, room+"/members/"+bob.ID, bobTok, nil, nil).Code; c != http.StatusOK {
		t.Fatalf("leave = %d", c)
	}
	if got := states(bobTok, kept); len(got) != 0 {
		t.Fatalf("states after leaving = %v", got)
	}
	tooMany := make([]string, 51)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("m%d", i)
	}
	if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/messages/state", aliceTok, map[string]any{"ids": tooMany}, nil).Code; c != http.StatusBadRequest {
		t.Fatalf("51 IDs = %d", c)
	}
}
