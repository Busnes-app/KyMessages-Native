package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

func postErased(t *testing.T, srv http.Handler, sub, org string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "id": sub, "externalId": sub, "active": false, "org_id": org})
	req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "user.erased", uuid.NewString(), body)
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func roomOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var r struct {
		Room store.Room `json:"room"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.Room.ID == "" {
		t.Fatalf("room: %d %s", rec.Code, rec.Body.String())
	}
	return r.Room.ID
}

// user.erased deletes one person's data: their account, sessions, bots, staged and posted
// attachments (blobs first), and a DM nobody else uses; their messages elsewhere become
// tombstones. Others' data stays. A repeat, another org's person and single mode change nothing.
func TestUserErasedDeletesThePersonsData(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_er_alice", "eralice", "user", replicaOrgA)
	bob, bobTok := createOrgUser(t, st, "usr_er_bob", "erbob", "user", replicaOrgA)
	carol, _ := createOrgUser(t, st, "usr_er_carol", "ercarol", "user", replicaOrgA)
	other, _ := createOrgUser(t, st, "usr_er_other", "erother", "user", replicaOrgB)

	channel := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "shared", "member_ids": []string{bob.ID}}, nil))
	dmBob := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": "dm", "dm_user_id": bob.ID}, nil))
	dmCarol := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": "dm", "dm_user_id": carol.ID}, nil))
	upload := func(room string) string {
		rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "a.txt", []byte("alice's bytes"))
		var a struct {
			Attachment store.Attachment `json:"attachment"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &a)
		if a.Attachment.ID == "" {
			t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
		}
		return a.Attachment.ID
	}
	posted := upload(channel)
	staged := upload(channel)
	for room, msg := range map[string]map[string]any{
		channel: {"body": "alice in the channel", "attachment_ids": []string{posted}},
		dmBob:   {"body": "alice to bob"},
		dmCarol: {"body": "alice to carol"},
	} {
		if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, msg, nil); rec.Code != http.StatusCreated {
			t.Fatalf("send: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+channel+"/messages", bobTok, map[string]any{"body": "bob stays"}, nil); rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_er_bot", Username: "er_bot", Role: "bot", Status: "active", SSOProvider: "bot"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Agents().CreateAgent(ctx, &store.Agent{ID: "agt_er", UserID: "usr_er_bot", Username: "er_bot", OwnerUserID: alice.ID, TokenHash: "h", TokenState: store.AgentTokenActive, CreatedBy: alice.ID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Carol is gone, so the DM with her has no one left.
	if err := st.Users().UpdateProfile(ctx, &store.User{ID: carol.ID, Username: carol.Username, Email: carol.Email, DisplayName: carol.DisplayName, Role: "user", Status: "deleted"}); err != nil {
		t.Fatal(err)
	}
	blobDir := filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att")

	if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("user.erased = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := st.Users().GetUserByID(ctx, alice.ID); err == nil {
		t.Fatal("account kept")
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", aliceTok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("erased session = %d, want 401", rec.Code)
	}
	for _, id := range []string{posted, staged} {
		if _, err := os.Stat(filepath.Join(blobDir, id)); !os.IsNotExist(err) {
			t.Fatalf("blob %s kept: %v", id, err)
		}
	}
	if _, err := st.Agents().GetAgent(ctx, "agt_er"); err == nil {
		t.Fatal("bot kept")
	}
	if _, err := st.Chat().GetRoom(ctx, replicaOrgA, dmCarol); err == nil {
		t.Fatal("DM nobody uses kept")
	}
	// Bob still reads the channel and his DM; alice's messages there are tombstones.
	for _, room := range []string{channel, dmBob} {
		rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", bobTok, nil, nil)
		var page struct {
			Messages []store.Message `json:"messages"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &page)
		if rec.Code != http.StatusOK || len(page.Messages) == 0 {
			t.Fatalf("bob reads %s: %d %s", room, rec.Code, rec.Body.String())
		}
		tombstones := 0
		for _, m := range page.Messages {
			if m.SenderID == alice.ID {
				tombstones++
			}
			if m.SenderID == alice.ID && (m.Body != "" || m.SenderName != "" || m.DeletedAt == nil || len(m.Attachments) != 0) {
				t.Fatalf("not a tombstone: %+v", m)
			}
			if m.SenderID == bob.ID && m.Body != "bob stays" {
				t.Fatalf("bob's message changed: %+v", m)
			}
		}
		if tombstones != 1 {
			t.Fatalf("%s: %d tombstones of alice's, want 1 (the row keeps the thread's order)", room, tombstones)
		}
	}
	recs, _, err := st.Audit().ListAuditRecords(ctx, 0, 10, "sso.user_erased")
	if err != nil || len(recs) != 1 || recs[0].Resource != "user:"+alice.ID || recs[0].Details != "" {
		t.Fatalf("audit: %v %+v", err, recs)
	}

	// A repeat is acknowledged and changes nothing.
	if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("repeat = %d", rec.Code)
	}
	// Another org's person named under the wrong org is not touched.
	if rec := postErased(t, srv, other.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("wrong org = %d", rec.Code)
	}
	if _, err := st.Users().GetUserByID(ctx, other.ID); err != nil {
		t.Fatal("another org's person erased")
	}
	// A body without a canonical org is refused.
	if rec := postErased(t, srv, bob.SSOSubject, "not-an-org"); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", rec.Code)
	}
}

func TestUserErasedIsIgnoredInSingleMode(t *testing.T) {
	ctx := context.Background()
	_, st, cfg := setupTestServer(t)
	cfg.SSO.KyIdentityHMACSecret = testMultiTenantHMAC
	srv := api.NewServer(cfg, st)
	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_single", Username: "single", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "sub-single"}); err != nil {
		t.Fatal(err)
	}
	if rec := postErased(t, srv, "sub-single", replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("single-mode user.erased = %d", rec.Code)
	}
	if _, err := st.Users().GetUserByID(ctx, "usr_single"); err != nil {
		t.Fatal("single mode erased an account")
	}
}
