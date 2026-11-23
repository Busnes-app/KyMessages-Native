package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/sso"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

type listedOrg struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Revision int64  `json:"revision"`
	Enabled  bool   `json:"enabled"`
	Quotas   struct {
	} `json:"quotas"`
}

type erasedSubject struct {
	Sub      string `json:"sub"`
	OrgID    string `json:"org_id"`
	Revision int64  `json:"revision"`
}

// fakeDirectory is KyIdentity's org list, erased list and storage pool.
type fakeDirectory struct {
	pool   fakePool
	mu     sync.Mutex
	orgs   []listedOrg
	erased []erasedSubject
	down   bool
}

func (f *fakeDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/suite/storage" {
		f.pool.ServeHTTP(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	switch r.URL.Path {
	case "/api/suite/orgs":
		out := []listedOrg{}
		for _, o := range f.orgs {
			if o.Revision > since {
				out = append(out, o)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"orgs": out})
	case "/api/suite/erased":
		out := []erasedSubject{}
		for _, s := range f.erased {
			if s.Revision > since {
				out = append(out, s)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"subjects": out})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDirectory) list(orgs ...listedOrg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgs = orgs
}

func syncOrgID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", 100+i) }

type syncEnv struct {
	srv  *api.Server
	st   store.Store
	cfg  *config.Config
	kyid *sso.KyIdentityClient
	dir  *fakeDirectory
}

func newSyncEnv(t *testing.T) *syncEnv {
	t.Helper()
	dir := &fakeDirectory{pool: fakePool{headroom: 1 << 20}}
	idp := httptest.NewServer(dir)
	t.Cleanup(idp.Close)
	a, _, st, cfg := newReplicas(t, func(cfg *config.Config) {
		cfg.SSO.Enabled = true
		cfg.SSO.KyIdentityIssuer = idp.URL
		cfg.SSO.KyIdentityClientID = "kymessages"
		cfg.SSO.KyIdentitySecret = "client-secret"
	})
	kyid := sso.NewKyIdentityClient(cfg.SSO, st)
	kyid.SetTenancy(cfg.Tenancy)
	return &syncEnv{srv: a, st: st, cfg: cfg, kyid: kyid, dir: dir}
}

func (e *syncEnv) status(t *testing.T, id string) string {
	t.Helper()
	tn, err := e.st.Chat().GetTenant(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tn.Status
}

func (e *syncEnv) activeCount(t *testing.T) int {
	t.Helper()
	ids, err := e.st.Chat().ActiveTenantIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(ids)
}

func listedAll(n int, skip ...int) []listedOrg {
	skipped := map[int]bool{}
	for _, s := range skip {
		skipped[s] = true
	}
	var out []listedOrg
	for i := range n {
		if !skipped[i] {
			out = append(out, listedOrg{ID: syncOrgID(i), Status: "active", Revision: int64(10 + i), Enabled: true})
		}
	}
	return out
}

// A short or empty org list never takes orgs offline wholesale, never purges, and a start-up or
// incremental read holds none offline. One missing org of ten is held offline, keeps its data,
// and serves again (with its lifecycle revision untouched) once a full read lists it.
func TestTenancySyncMissingOrgGuards(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	for i := range 10 {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	victim, victimTok := createOrgUser(t, e.st, "usr_sync_v", "syncv", "user", syncOrgID(3))
	_ = victim

	e.dir.list() // empty answer
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.activeCount(t) != 10 {
		t.Fatal("an empty list took orgs offline")
	}
	recs, _, _ := e.st.Audit().ListAuditRecords(ctx, 0, 10, "tenancy.sync_aborted")
	if len(recs) != 1 {
		t.Fatalf("sync_aborted audits: %d", len(recs))
	}
	e.dir.list(listedAll(10, 1, 2, 3, 4)...) // four missing: past the guard
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.activeCount(t) != 10 {
		t.Fatalf("four of ten missing: %v, active %d", err, e.activeCount(t))
	}
	e.dir.list(listedAll(10, 3)...)
	if err := e.kyid.SyncTenancy(ctx, true, true); err != nil || e.activeCount(t) != 10 {
		t.Fatalf("start-up read held an org offline: %v", err)
	}
	if err := e.kyid.SyncTenancy(ctx, false, false); err != nil || e.activeCount(t) != 10 {
		t.Fatalf("incremental read held an org offline: %v", err)
	}
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, syncOrgID(3)) != store.TenantStatusSuspended || e.activeCount(t) != 9 {
		t.Fatalf("one missing of ten: status %q, active %d", e.status(t, syncOrgID(3)), e.activeCount(t))
	}
	if rec := doBearerJSON(t, e.srv, http.MethodGet, "/api/v1/rooms", victimTok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing org's session = %d, want 401", rec.Code)
	}
	if _, err := e.st.Users().GetUserByID(ctx, "usr_sync_v"); err != nil {
		t.Fatal("a missing org lost data")
	}
	// Listed active again: serves, and an older lifecycle event still cannot change it.
	e.dir.list(listedAll(10)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, syncOrgID(3)) != store.TenantStatusActive {
		t.Fatal("found org not serving")
	}
	if changed, _ := e.st.Chat().ApplyTenantLifecycle(ctx, syncOrgID(3), store.TenantStatusSuspended, 13); changed {
		t.Fatal("the missing flag rewound the org's lifecycle revision")
	}
	if recs, _, _ := e.st.Audit().ListAuditRecords(ctx, 0, 10, "tenancy.org_"); len(recs) != 2 {
		t.Fatalf("org_missing/org_found audits: %d", len(recs))
	}
}

// An explicit deleted status purges exactly that org: blobs and rows, its prefix, and nothing of
// any other org. The tenants row stays as a tombstone. A lost lease stops the purge.
func TestTenancySyncDeletedOrgIsPurged(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	gone, keep := syncOrgID(0), syncOrgID(1)
	upload := func(org, user string) string {
		_, tok := createOrgUser(t, e.st, "usr_"+user, user, "user", org)
		rec := doBearerJSON(t, e.srv, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": store.RoomKindChannel, "name": user}, nil)
		room := roomOf(t, rec)
		if rec := doBearerJSON(t, e.srv, http.MethodPost, "/api/v1/rooms/"+room+"/messages", tok, map[string]any{"body": "hi"}, nil); rec.Code != http.StatusCreated {
			t.Fatal(rec.Code)
		}
		up := doMultipartUpload(t, e.srv, "/api/v1/rooms/"+room+"/attachments", tok, "file", "f.txt", []byte("bytes of "+user))
		if up.Code != http.StatusCreated {
			t.Fatalf("upload: %d %s", up.Code, up.Body.String())
		}
		return room
	}
	upload(gone, "purgeme")
	keepRoom := upload(keep, "keepme")
	orgDir := func(org string) string { return filepath.Join(e.cfg.Database.DataDir, "attachments", "orgs", org) }

	e.dir.list(listedOrg{ID: gone, Status: "deleted", Revision: 50}, listedOrg{ID: keep, Status: "active", Revision: 51})
	if err := e.kyid.SyncTenancy(ctx, false, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, gone) != store.TenantStatusDeleted {
		t.Fatal("deleted status not applied")
	}
	// A lost lease purges nothing.
	if err := e.srv.PurgeDeletedOrgs(ctx, func() bool { return false }); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Users().GetUserByID(ctx, "usr_purgeme"); err != nil {
		t.Fatal("purged without the lease")
	}
	if err := e.srv.PurgeDeletedOrgs(ctx, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Users().GetUserByID(ctx, "usr_purgeme"); err == nil {
		t.Fatal("deleted org's user kept")
	}
	if _, err := os.Stat(orgDir(gone)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted org's blobs kept")
	}
	if e.status(t, gone) != store.TenantStatusDeleted {
		t.Fatal("tombstone lost")
	}
	if _, err := e.st.Users().GetUserByID(ctx, "usr_keepme"); err != nil {
		t.Fatal("another org's user purged")
	}
	if _, err := os.Stat(orgDir(keep)); err != nil {
		t.Fatal("another org's blobs purged")
	}
	if _, err := e.st.Chat().GetRoom(ctx, keep, keepRoom); err != nil {
		t.Fatal("another org's room purged")
	}
	// A late event cannot revive the tombstone, and a rerun is a no-op.
	if changed, _ := e.st.Chat().ApplyTenantLifecycle(ctx, gone, store.TenantStatusActive, 999); changed {
		t.Fatal("deleted org revived")
	}
	if err := e.srv.PurgeDeletedOrgs(ctx, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
}

// The erased list erases each listed person, incrementally from the stored revision; rewinding
// that revision (a restore) replays the erasures.
func TestTenancySyncErasedList(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	e.kyid.OnUserErased(func(ctx context.Context, u *store.User) error {
		_, err := e.st.Chat().EraseUser(ctx, u.OrgID, u)
		return err
	})
	org := syncOrgID(0)
	u, _ := createOrgUser(t, e.st, "usr_erlist", "erlist", "user", org)
	e.dir.list(listedOrg{ID: org, Status: "active", Revision: 1})
	e.dir.mu.Lock()
	e.dir.erased = []erasedSubject{{Sub: u.SSOSubject, OrgID: org, Revision: 7}}
	e.dir.mu.Unlock()
	if err := e.kyid.SyncTenancy(ctx, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Users().GetUserByID(ctx, u.ID); err == nil {
		t.Fatal("listed person not erased")
	}
	// A restore brings the person back and rewinds the stored revision: the next run erases again.
	createOrgUser(t, e.st, "usr_erlist", "erlist", "user", org)
	if err := e.st.Settings().SetSetting(ctx, "tenancy.erased_revision", "0"); err != nil {
		t.Fatal(err)
	}
	if err := e.kyid.SyncTenancy(ctx, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Users().GetUserByID(ctx, u.ID); err == nil {
		t.Fatal("restored person not erased again")
	}
}

// A replica starts when the start-up read succeeds, or when KyIdentity is down but the database
// records a sync from the last 24 hours. Otherwise it refuses.
func TestTenancyStartupSync(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	e.dir.mu.Lock()
	e.dir.down = true
	e.dir.mu.Unlock()
	if err := e.kyid.StartupSync(ctx); err == nil {
		t.Fatal("started with KyIdentity down and no sync on record")
	}
	set := func(at time.Time) {
		if err := e.st.Settings().SetSetting(ctx, sso.SettingSyncedAt, strconv.FormatInt(at.Unix(), 10)); err != nil {
			t.Fatal(err)
		}
	}
	set(time.Now().Add(-25 * time.Hour))
	if err := e.kyid.StartupSync(ctx); err == nil {
		t.Fatal("started on a sync older than a day")
	}
	set(time.Now().Add(-time.Hour))
	if err := e.kyid.StartupSync(ctx); err != nil {
		t.Fatalf("refused on a recent sync: %v", err)
	}
	e.dir.mu.Lock()
	e.dir.down = false
	e.dir.mu.Unlock()
	if err := e.kyid.StartupSync(ctx); err != nil {
		t.Fatalf("KyIdentity up: %v", err)
	}
	if e.kyid.FullSyncDue(ctx) {
		t.Fatal("a successful start-up read did not record the full sync")
	}
}
