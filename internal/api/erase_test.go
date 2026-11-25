package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/blobs"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

func postErased(t *testing.T, srv http.Handler, sub, org string, eventIDs ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "id": sub, "externalId": sub, "active": false, "org_id": org})
	req := httptest.NewRequest(http.MethodPost, "/api/sso/kyidentity/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	eventID := uuid.NewString()
	if len(eventIDs) > 0 {
		eventID = eventIDs[0]
	}
	h, err := syncauth.Sign([]byte(testMultiTenantHMAC), time.Now(), "user.erased", eventID, body)
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
		channel: sealed("alice in the channel", map[string]any{"attachment_ids": []string{posted}}),
		dmBob:   sealed("alice to bob", nil),
		dmCarol: sealed("alice to carol", nil),
	} {
		if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, msg, nil); rec.Code != http.StatusCreated {
			t.Fatalf("send: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+channel+"/messages", bobTok, sealed("bob stays", nil), nil); rec.Code != http.StatusCreated {
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
			if m.SenderID == bob.ID && m.Body != testEnvelope("bob stays") {
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

// spyBlobs runs check on the first erase, while the erasure is cleaning up blobs.
type spyBlobs struct {
	blobs.Backend
	once  sync.Once
	check func()
}

func (b *spyBlobs) Erase(tenantID, key string) error {
	b.once.Do(b.check)
	return b.Backend.Erase(tenantID, key)
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
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", aliceTok, sealed("mine", map[string]any{"attachment_ids": []string{a.Attachment.ID}}), nil); rec.Code != http.StatusCreated {
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
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", oldTok, sealed("from the first account", nil), nil); rec.Code != http.StatusCreated {
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

// failKey fails every erase of one key.
type failKey struct {
	blobs.Backend
	key string
}

func (f *failKey) Erase(tenantID, key string) error {
	if key == f.key {
		return errors.New("injected")
	}
	return f.Backend.Erase(tenantID, key)
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

type failSecondBlobDelete struct {
	blobs.Backend
	calls int
}

func (b *failSecondBlobDelete) Erase(tenant, key string) error {
	b.calls++
	if b.calls == 2 {
		return errors.New("injected post-commit blob failure")
	}
	return b.Backend.Erase(tenant, key)
}

func TestErasureCompletionAuditSurvivesReplayAndCleanupRetry(t *testing.T) {
	ctx := context.Background()
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	user, tok := createOrgUser(t, st, "usr_completion", "completion", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": store.RoomKindChannel, "name": "completion"}, nil))
	if rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", tok, "file", "file.txt", []byte("erase me")); rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	api.SetBlobsForTest(srv, &failSecondBlobDelete{Backend: api.BlobsForTest(srv)})
	auditCount := func(want int) {
		t.Helper()
		_, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased")
		if err != nil || n != want {
			t.Fatalf("completed audit count = %d, want %d: %v", n, want, err)
		}
	}
	event := uuid.NewString()
	if rec := postErased(t, srv, user.SSOSubject, replicaOrgA, event); rec.Code < 500 {
		t.Fatalf("failed cleanup acknowledged: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.Users().GetUserByID(ctx, user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rows did not commit before failure: %v", err)
	}
	auditCount(0)
	pending, err := st.Chat().PendingBlobDeletes(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("cleanup lost: %+v %v", pending, err)
	}
	for _, id := range []string{event, event, uuid.NewString()} {
		if rec := postErased(t, srv, user.SSOSubject, replicaOrgA, id); rec.Code != http.StatusOK {
			t.Fatalf("retry/replay: %d %s", rec.Code, rec.Body.String())
		}
		auditCount(1)
	}
	if pending, err := st.Chat().PendingBlobDeletes(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending after retry: %+v %v", pending, err)
	}
	if _, err := srv.SweepOrphanAttachments(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	auditCount(1)
}

func TestErasureIncludesOwnedBotContentAcrossCleanupRetry(t *testing.T) {

	for _, removed := range []bool{false, true} {
		name := "registered"
		if removed {
			name = "previously_removed"
		}
		t.Run(name, func(t *testing.T) {
			orgID := replicaOrgA
			if removed {
				orgID = testStaffOrg
			}
			ctx := context.Background()
			srv, _, st, cfg := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
			owner, _ := createOrgUser(t, st, "usr_bot_owner", "botowner", "user", orgID)
			bob, bobToken := createOrgUser(t, st, "usr_bot_bob", "botbob", "user", orgID)
			bot := &store.User{ID: "usr_owned_bot", Username: "agent-owned", Role: "bot", Status: "active", SSOProvider: "bot", OrgID: orgID}
			if err := st.Users().CreateUser(ctx, bot); err != nil {
				t.Fatal(err)
			}
			agentID := uuid.NewString()
			botToken := auth.AgentTokenPrefix + "owned-erasure-test"
			if err := st.Agents().CreateAgent(ctx, &store.Agent{ID: agentID, UserID: bot.ID, Username: bot.Username, OwnerUserID: owner.ID, TokenHash: crypto.SHA256Hex([]byte(botToken)), TokenState: store.AgentTokenActive, CreatedBy: owner.ID, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", bobToken, map[string]any{"kind": store.RoomKindChannel, "name": "bots-shared", "member_ids": []string{owner.ID, bot.ID}}, nil))
			upload := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", botToken, "file", "bot.txt", []byte("owned bot bytes"))
			var up struct {
				Attachment store.Attachment `json:"attachment"`
			}
			if err := json.Unmarshal(upload.Body.Bytes(), &up); err != nil || upload.Code != http.StatusCreated {
				t.Fatalf("bot upload: %d %s %v", upload.Code, upload.Body.String(), err)
			}
			if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", botToken, map[string]any{"body": "owned bot message", "attachment_ids": []string{up.Attachment.ID}}, nil); r.Code != http.StatusCreated {
				t.Fatalf("bot message: %d %s", r.Code, r.Body.String())
			}
			bobUpload := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", bobToken, "file", "kept.txt", []byte("other member file"))
			var kept struct {
				Attachment store.Attachment `json:"attachment"`
			}
			if err := json.Unmarshal(bobUpload.Body.Bytes(), &kept); err != nil || bobUpload.Code != http.StatusCreated {
				t.Fatalf("other upload: %d %v", bobUpload.Code, err)
			}
			if r := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", bobToken, sealed("other member keeps this", map[string]any{"attachment_ids": []string{kept.Attachment.ID}}), nil); r.Code != http.StatusCreated {
				t.Fatal(r.Code)
			}
			if r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+up.Attachment.ID, bobToken, nil, nil); r.Code != http.StatusOK {
				t.Fatalf("attachment was not readable before erasure: %d", r.Code)
			}
			if removed {
				_, adminToken := createOrgUser(t, st, "usr_bot_admin", "botadmin", "admin", orgID)
				rec := doBearerJSON(t, srv, http.MethodDelete, "/api/admin/agents/"+agentID, adminToken, nil, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("ordinary bot removal: %d %s", rec.Code, rec.Body.String())
				}
				if _, err := st.Agents().GetAgent(ctx, agentID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("ordinary removal kept registry: %v", err)
				}
				if saved, err := st.Users().GetUserByID(ctx, bot.ID); err != nil || saved.Status != "deleted" {
					t.Fatalf("ordinary removal must keep attribution account: %+v %v", saved, err)
				}
			}
			api.SetBlobsForTest(srv, &failSecondBlobDelete{Backend: api.BlobsForTest(srv)})
			event := uuid.NewString()
			if r := postErased(t, srv, owner.SSOSubject, orgID, event); r.Code < 500 {
				t.Fatalf("expected retryable cleanup failure: %d %s", r.Code, r.Body.String())
			}
			// Ownership/account rows are gone after the committed cleanup. Durable actor IDs and the
			// owner's pending blob work must still make retry possible.
			if _, err := st.Agents().GetAgent(ctx, agentID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("agent row: %v", err)
			}
			if _, err := st.Users().GetUserByID(ctx, bot.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("bot account: %v", err)
			}
			if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 0 {
				t.Fatalf("premature completion audit: %d %v", n, err)
			}
			for _, id := range []string{event, event, uuid.NewString()} {
				if r := postErased(t, srv, owner.SSOSubject, orgID, id); r.Code != http.StatusOK {
					t.Fatalf("replay: %d %s", r.Code, r.Body.String())
				}
			}
			if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments", "orgs", orgID, "att", up.Attachment.ID)); !os.IsNotExist(err) {
				t.Fatalf("bot blob remains: %v", err)
			}
			if r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+up.Attachment.ID, bobToken, nil, nil); r.Code != http.StatusNotFound {
				t.Fatalf("other member can still download erased bot file: %d", r.Code)
			}
			msgs, _, err := st.Chat().ListMessages(ctx, store.MessagePageQuery{TenantID: orgID, RoomID: room, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			botSeen, bobSeen := false, false
			for _, m := range msgs {
				if m.SenderID == bot.ID {
					botSeen = true
					if m.Body != "" || m.DeletedAt == nil || len(m.Attachments) != 0 {
						t.Fatalf("bot message not tombstoned: %+v", m)
					}
				}
				if m.SenderID == bob.ID && m.Body == testEnvelope("other member keeps this") {
					bobSeen = true
				}
			}
			if r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/attachments/"+kept.Attachment.ID, bobToken, nil, nil); r.Code != http.StatusOK || r.Body.String() != "other member file" {
				t.Fatalf("other member file changed: %d %s", r.Code, r.Body.String())
			}
			if !botSeen || !bobSeen {
				t.Fatalf("bot tombstone=%v, other member content=%v", botSeen, bobSeen)
			}
			members, err := st.Chat().ListRoomMembers(ctx, orgID, room)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range members {
				if m.UserID == bot.ID {
					t.Fatal("bot membership remains")
				}
			}
			if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 1 {
				t.Fatalf("completion audit count: %d %v", n, err)
			}
			if refs, err := st.Chat().PendingBlobDeletes(ctx, 100); err != nil || len(refs) != 0 {
				t.Fatalf("pending cleanup: %+v %v", refs, err)
			}
		})
	}
}

func TestErasedUnknownSubjectCannotSignInLater(t *testing.T) {
	ctx := context.Background()
	srv, _, st, cfg := newReplicas(t)
	const sub = "never-held-erased"
	if r := postErased(t, srv, sub, replicaOrgA); r.Code != http.StatusOK {
		t.Fatalf("unknown subject: %d %s", r.Code, r.Body.String())
	}
	admitOrg(t, st, replicaOrgA)
	cfg.SSO.Enabled = true
	cfg.SSO.AutoProvision = true
	idp := newFakeIdP(t, cfg)
	fresh := api.NewServer(cfg, st)
	t.Cleanup(fresh.CloseChat)
	r := idp.signIn(fresh, map[string]any{"sub": sub, "preferred_username": "new-after-erasure", "org_id": replicaOrgA})
	if r.Code != http.StatusForbidden || sessionCookie(r) != nil {
		t.Fatalf("erased subject sign-in: %d %s", r.Code, r.Body.String())
	}
	if _, err := st.Users().GetUserBySSO(ctx, "kyidentity", sub); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("erased subject provisioned: %v", err)
	}
}

func TestWrongOrgErasureDoesNotRecordASubjectFence(t *testing.T) {
	ctx := context.Background()
	srv, _, st, _ := newReplicas(t)
	u, tok := createOrgUser(t, st, "wrong-fence", "wrongfence", "user", replicaOrgA)
	if r := postErased(t, srv, u.SSOSubject, replicaOrgB); r.Code != http.StatusOK {
		t.Fatalf("wrong-org delivery: %d", r.Code)
	}
	if err := st.Users().UpdateProfile(ctx, u); err != nil {
		t.Fatalf("wrong-org delivery fenced profile: %v", err)
	}
	if r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); r.Code != http.StatusOK {
		t.Fatalf("wrong-org delivery changed access: %d %s", r.Code, r.Body.String())
	}
}

// versioningBlobs stands in for a versioned bucket over the disk store: every Put gets a
// version, Delete keeps the bytes (the retained copy) and only Erase removes them.
type versioningBlobs struct {
	blobs.Backend
	mu     sync.Mutex
	erased []string
}

func (b *versioningBlobs) Put(tenantID, key string, r io.Reader, maxBytes int64) (blobs.PutResult, error) {
	res, err := b.Backend.Put(tenantID, key, r, maxBytes)
	res.VersionID = "v1/" + key
	return res, err
}

func (b *versioningBlobs) Delete(string, string) error { return nil }

func (b *versioningBlobs) Erase(tenantID, key string) error {
	b.mu.Lock()
	b.erased = append(b.erased, key)
	b.mu.Unlock()
	return b.Backend.Erase(tenantID, key)
}

// A posted file the member deletes stays charged to the org as a retained version, and the
// member's erasure later erases every version of it and ends the charge.
func TestDeletedFileVersionIsRetainedThenErased(t *testing.T) {
	ctx := context.Background()
	srv, _, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	alice, tok := createOrgUser(t, st, "usr_rv_alice", "rvalice", "user", replicaOrgA)
	vb := &versioningBlobs{Backend: api.BlobsForTest(srv)}
	api.SetBlobsForTest(srv, vb)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": store.RoomKindChannel, "name": "rv"}, nil))
	rec := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", tok, "file", "a.txt", []byte("retain me"))
	var up struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &up)
	sent := doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", tok, sealed("file", map[string]any{"attachment_ids": []string{up.Attachment.ID}}), nil)
	var msg struct {
		Message store.Message `json:"message"`
	}
	if err := json.Unmarshal(sent.Body.Bytes(), &msg); err != nil || sent.Code != http.StatusCreated || msg.Message.ID == "" {
		t.Fatalf("send: %d %s", sent.Code, sent.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/rooms/"+room+"/messages/"+msg.Message.ID, tok, nil, nil); rec.Code/100 != 2 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	v, err := st.Chat().RetainedAttachmentVersions(ctx, replicaOrgA, alice.ID)
	if err != nil || len(v) != 1 || v[0].VersionID != "v1/"+up.Attachment.ID || v[0].SizeBytes != int64(len("retain me")) {
		t.Fatalf("deleted file not retained with its version: %+v %v", v, err)
	}
	if len(vb.erased) != 0 {
		t.Fatalf("a member's own delete erased versions: %v", vb.erased)
	}
	if rec := postErased(t, srv, alice.SSOSubject, replicaOrgA); rec.Code != http.StatusOK {
		t.Fatalf("user.erased = %d: %s", rec.Code, rec.Body.String())
	}
	if !slices.Contains(vb.erased, up.Attachment.ID) {
		t.Fatalf("erasure did not erase the retained file: %v", vb.erased)
	}
	if v, err := st.Chat().RetainedAttachmentVersions(ctx, replicaOrgA, alice.ID); err != nil || len(v) != 0 {
		t.Fatalf("erased file still charged: %+v %v", v, err)
	}
}
