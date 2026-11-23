package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/blobs"
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

// spyBlobs runs check on the first delete, while the erasure is cleaning up blobs.
type spyBlobs struct {
	blobs.Backend
	once  sync.Once
	check func()
}

func (b *spyBlobs) Delete(tenantID, key string) error {
	b.once.Do(b.check)
	return b.Backend.Delete(tenantID, key)
}

// The person loses access before anything is disconnected or deleted: by the time blobs are
// cleaned up, their session no longer signs in to anything, a call join included.
func TestUserErasedRevokesAccessFirst(t *testing.T) {
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_ef_alice", "efalice", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "c"}, nil))
	if rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "a.txt", []byte("x")); rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	during := 0
	api.SetBlobsForTest(srv, &spyBlobs{Backend: api.BlobsForTest(srv), check: func() {
		during = doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/calls/join", aliceTok, map[string]any{"audio": true}, nil).Code
	}})
	if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("user.erased = %d", rec.Code)
	}
	if during != http.StatusUnauthorized {
		t.Fatalf("call join during blob cleanup = %d, want 401", during)
	}
}

// user.deleted removes the account row first; a later user.erased still finds the person's
// messages and files through the kept subject mapping.
func TestUserErasedAfterUserDeleted(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_ed_alice", "edalice", "user", replicaOrgA)
	bob, bobTok := createOrgUser(t, st, "usr_ed_bob", "edbob", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "c", "member_ids": []string{bob.ID}}, nil))
	up := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "a.txt", []byte("alice"))
	var a struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(up.Body.Bytes(), &a)
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, map[string]any{"body": "mine", "attachment_ids": []string{a.Attachment.ID}}, nil); rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	del := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + alice.SSOSubject + `","externalId":"x","userName":"edalice","active":false,"org_id":"` + replicaOrgA + `","meta":{"resourceType":"User","version":"W/\"5\""}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", bytes.NewReader(del))
	req.Header.Set("Content-Type", "application/scim+json")
	h, _ := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "user.deleted", uuid.NewString(), del)
	h.Apply(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("user.deleted = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.Users().GetUserByID(ctx, alice.ID); err == nil {
		t.Fatal("user.deleted kept the row; this test needs it gone")
	}
	if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("user.erased = %d", rec.Code)
	}
	page := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", bobTok, nil, nil)
	var p struct {
		Messages []store.Message `json:"messages"`
	}
	_ = json.Unmarshal(page.Body.Bytes(), &p)
	if len(p.Messages) != 1 || p.Messages[0].Body != "" || p.Messages[0].DeletedAt == nil || len(p.Messages[0].Attachments) != 0 {
		t.Fatalf("after deletion then erasure: %+v", p.Messages)
	}
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att", a.Attachment.ID)); !os.IsNotExist(err) {
		t.Fatal("blob kept")
	}
}

// erasingStore runs hook once when a call join loads its room: the join is authenticated, and
// the erasure completes before the peer registers.
type erasingStore struct {
	store.Store
	hook func()
	once sync.Once
}

type erasingChat struct {
	store.ChatStore
	s *erasingStore
}

func (e *erasingStore) Chat() store.ChatStore { return erasingChat{e.Store.Chat(), e} }

func (c erasingChat) GetRoom(ctx context.Context, tenantID, roomID string) (*store.Room, error) {
	c.s.once.Do(c.s.hook)
	return c.ChatStore.GetRoom(ctx, tenantID, roomID)
}

// A call join already past authentication when the erasure completes gets no seat and no
// credentials.
func TestCallJoinOverlappingErasureIsRefused(t *testing.T) {
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_cj_alice", "cjalice", "user", replicaOrgA)
	bob, bobTok := createOrgUser(t, st, "usr_cj_bob", "cjbob", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "c", "member_ids": []string{bob.ID}}, nil))
	api.SetStoreForTest(srv, &erasingStore{Store: st, hook: func() {
		if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
			t.Errorf("user.erased = %d", rec.Code)
		}
	}})
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/calls/join", aliceTok, map[string]any{"audio": true}, nil)
	if rec.Code != http.StatusUnauthorized || bytes.Contains(rec.Body.Bytes(), []byte("token")) {
		t.Fatalf("join overlapping erasure = %d %s", rec.Code, rec.Body.String())
	}
	state := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/calls/state", bobTok, nil, nil)
	if bytes.Contains(state.Body.Bytes(), []byte(alice.ID)) {
		t.Fatalf("an erased person kept a call seat: %s", state.Body.String())
	}
}

// Blobs of rows an erasure deleted are queued with the delete; if removing them fails then, the
// attachment sweep finishes the job.
func TestErasureQueuesStragglerBlobs(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_q_alice", "qalice", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "c"}, nil))
	up := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "a.txt", []byte("late"))
	var a struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(up.Body.Bytes(), &a)
	// The rows go without the blob, as when an upload committed after ErasureBlobs and the
	// blob delete then failed.
	late, err := st.Chat().EraseUser(ctx, replicaOrgA, alice)
	if err != nil || len(late) != 1 {
		t.Fatalf("EraseUser: %v %v", late, err)
	}
	if q, _ := st.Chat().PendingBlobDeletes(ctx, 10); len(q) != 1 || q[0].Key != a.Attachment.ID {
		t.Fatalf("queue: %v", q)
	}
	blob := filepath.Join(cfg.Database.DataDir, "attachments", "orgs", replicaOrgA, "att", a.Attachment.ID)
	if _, err := os.Stat(blob); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blob); !os.IsNotExist(err) {
		t.Fatal("queued blob kept after the sweep")
	}
	if q, _ := st.Chat().PendingBlobDeletes(ctx, 10); len(q) != 0 {
		t.Fatalf("queue after sweep: %v", q)
	}
}

// A subject deleted and then recreated under a new local ID: user.erased erases both accounts.
func TestUserErasedCoversARecreatedAccount(t *testing.T) {
	ctx := context.Background()
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	old, oldTok := createOrgUser(t, st, "usr_rc_old", "rcold", "user", replicaOrgA)
	bob, bobTok := createOrgUser(t, st, "usr_rc_bob", "rcbob", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", oldTok, map[string]any{"kind": store.RoomKindChannel, "name": "c", "member_ids": []string{bob.ID}}, nil))
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", oldTok, map[string]any{"body": "from the first account"}, nil); rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	// user.deleted, then the same subject comes back as a new account.
	if _, err := st.Users().DeleteDirectoryUser(ctx, old, store.DirectoryEvent{ID: "ev-del", Revision: 5}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_rc_new", Username: "rcnew", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: old.SSOSubject, OrgID: replicaOrgA}); err != nil {
		t.Fatal(err)
	}
	if rec := postErased(t, srv, old.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("user.erased = %d", rec.Code)
	}
	if _, err := st.Users().GetUserByID(ctx, "usr_rc_new"); err == nil {
		t.Fatal("the recreated account was kept")
	}
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms/"+room+"/messages", bobTok, nil, nil)
	var p struct {
		Messages []store.Message `json:"messages"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if len(p.Messages) != 1 || p.Messages[0].Body != "" || p.Messages[0].DeletedAt == nil {
		t.Fatalf("the first account's message survived: %+v", p.Messages)
	}
}

// failKey fails every delete of one key.
type failKey struct {
	blobs.Backend
	key string
}

func (f *failKey) Delete(tenantID, key string) error {
	if key == f.key {
		return errors.New("injected")
	}
	return f.Backend.Delete(tenantID, key)
}

// One blob that keeps failing to delete does not hold back the rest of the queue.
func TestQueuedBlobDeletesAreIndependent(t *testing.T) {
	ctx := context.Background()
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, aliceTok := createOrgUser(t, st, "usr_qi_alice", "qialice", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", aliceTok, map[string]any{"kind": store.RoomKindChannel, "name": "c"}, nil))
	var ids []string
	for i := range 3 {
		up := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", aliceTok, "file", "f.txt", []byte(fmt.Sprintf("blob %d", i)))
		var a struct {
			Attachment store.Attachment `json:"attachment"`
		}
		_ = json.Unmarshal(up.Body.Bytes(), &a)
		ids = append(ids, a.Attachment.ID)
	}
	if _, err := st.Chat().EraseUser(ctx, replicaOrgA, alice); err != nil {
		t.Fatal(err)
	}
	api.SetBlobsForTest(srv, &failKey{Backend: api.BlobsForTest(srv), key: ids[0]})
	if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	q, _ := st.Chat().PendingBlobDeletes(ctx, 10)
	if len(q) != 1 || q[0].Key != ids[0] {
		t.Fatalf("queue after a sweep with one failing blob: %v", q)
	}
}
