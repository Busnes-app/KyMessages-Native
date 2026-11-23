package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

func TestCallErasureRetainsSFUCleanupAcrossOwnerFailure(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var deleted []string
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/DeleteRoom") {
			t.Errorf("unexpected SFU operation: %s", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		var in struct {
			Room string `json:"room"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		deleted = append(deleted, in.Room)
		if fail {
			fail = false
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()
	srv, _, st, _ := newReplicas(t, func(c *config.Config) {
		c.RTC.LiveKitURL = lk.URL
		c.RTC.LiveKitAPIKey = "test"
		c.RTC.LiveKitAPISecret = "test-secret"
	})
	ctx := context.Background()
	u, tok := createOrgUser(t, st, "media-erased", "mediaerased", "user", replicaOrgA)
	other, _ := createOrgUser(t, st, "media-stays", "mediastays", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": "channel", "name": "shared media", "member_ids": []string{other.ID}}, nil))
	lease, err := st.Chat().AcquireCallRoom(ctx, replicaOrgA, room, "failed-owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cs := &store.CallSession{ID: "call_media_erasure", TenantID: replicaOrgA, RoomID: room, Mode: store.CallModeSFULiveKit, Epoch: 1, LiveKitRoom: "retired-media-room", StartedBy: u.ID, OwnerID: lease.Holder, OwnerGeneration: lease.Generation}
	if err := st.Chat().CreateCallSession(ctx, cs); err != nil {
		t.Fatal(err)
	}
	for _, user := range []*store.User{u, other} {
		if err := st.Chat().PutCallSeat(ctx, cs, user.ID, "peer-"+user.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	// Neither receiving replica has the original owner's in-memory peer map.
	event := uuid.NewString()
	if r := postErased(t, srv, u.SSOSubject, replicaOrgA, event); r.Code < 500 {
		t.Fatalf("failed media cleanup acknowledged: %d %s", r.Code, r.Body.String())
	}
	if _, err := st.Users().GetUserByID(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("account deletion lost: %v", err)
	}
	if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 0 {
		t.Fatalf("premature completion audit: %d %v", n, err)
	}
	if pending, err := st.Chat().PendingCallEvictions(ctx, replicaOrgA, u.ID, 10); err != nil || len(pending) != 1 {
		t.Fatalf("retry linkage lost: %+v %v", pending, err)
	}
	fresh, err := st.Chat().GetActiveCallSession(ctx, replicaOrgA, room)
	if err != nil || fresh.Epoch <= cs.Epoch || fresh.LiveKitRoom == cs.LiveKitRoom {
		t.Fatalf("old media token still targets current epoch: %+v %v", fresh, err)
	}
	if err := st.Chat().UpdateCallSession(ctx, cs); !errors.Is(err, store.ErrCallStateStale) {
		t.Fatalf("old owner restored old media epoch: %v", err)
	}
	for _, id := range []string{event, event, uuid.NewString()} {
		if r := postErased(t, srv, u.SSOSubject, replicaOrgA, id); r.Code != http.StatusOK {
			t.Fatalf("retry: %d %s", r.Code, r.Body.String())
		}
	}
	if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 1 {
		t.Fatalf("completion audit: %d %v", n, err)
	}
	if _, err := st.Users().GetUserByID(ctx, other.ID); err != nil {
		t.Fatalf("other member removed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 2 || deleted[0] != cs.LiveKitRoom || deleted[1] != cs.LiveKitRoom {
		t.Fatalf("wrong media cleanup: %+v", deleted)
	}
}

func TestCallPurgeRetriesSFURoomAfterRowsDisappear(t *testing.T) {
	var mu sync.Mutex
	fail := true
	lk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			fail = false
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer lk.Close()
	srv, _, st, _ := newReplicas(t, func(c *config.Config) {
		c.RTC.LiveKitURL = lk.URL
		c.RTC.LiveKitAPIKey = "test"
		c.RTC.LiveKitAPISecret = "test-secret"
	})
	ctx := context.Background()
	u, tok := createOrgUser(t, st, "purge-media", "purgemedia", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": "channel", "name": "purged media"}, nil))
	l, err := st.Chat().AcquireCallRoom(ctx, replicaOrgA, room, "failed-owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cs := &store.CallSession{ID: "call_purged_media", TenantID: replicaOrgA, RoomID: room, Mode: store.CallModeSFULiveKit, Epoch: 1, LiveKitRoom: "purged-sfu-room", StartedBy: u.ID, OwnerID: l.Holder, OwnerGeneration: l.Generation}
	if err := st.Chat().CreateCallSession(ctx, cs); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().ApplyTenantLifecycle(ctx, replicaOrgA, store.TenantStatusDeleted, 2); err != nil {
		t.Fatal(err)
	}
	if err := srv.PurgeDeletedOrgs(ctx, func() bool { return true }); err == nil {
		t.Fatal("failed SFU purge acknowledged")
	}
	if _, err := st.Chat().GetRoom(ctx, replicaOrgA, room); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("room rows did not commit: %v", err)
	}
	if ids, err := st.Chat().DeletedUnpurgedTenants(ctx); err != nil || len(ids) != 1 {
		t.Fatalf("failed purge hidden: %+v %v", ids, err)
	}
	for range 2 {
		if err := srv.PurgeDeletedOrgs(ctx, func() bool { return true }); err != nil {
			t.Fatal(err)
		}
	}
	if ids, err := st.Chat().DeletedUnpurgedTenants(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("completed purge still pending: %+v %v", ids, err)
	}
	if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 100, "tenancy.org_purged"); err != nil || n != 1 {
		t.Fatalf("purge audit: %d %v", n, err)
	}
}
