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
	"sort"
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
	page   int // entries per page when set: answers carry next, and a cursor resumes
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
	if c := r.URL.Query().Get("cursor"); c != "" {
		since, _ = strconv.ParseInt(c, 10, 64)
	}
	page := func(n int) (int, string) {
		if f.page == 0 || n <= f.page {
			return n, ""
		}
		return f.page, "more"
	}
	switch r.URL.Path {
	case "/api/suite/orgs":
		out := []listedOrg{}
		for _, o := range f.orgs {
			if o.Revision > since {
				out = append(out, o)
			}
		}
		n, next := page(len(out))
		out = out[:n]
		if next != "" {
			next = strconv.FormatInt(out[n-1].Revision, 10)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"orgs": out, "next": next})
	case "/api/suite/erased":
		out := []erasedSubject{}
		for _, s := range f.erased {
			if s.Revision > since {
				out = append(out, s)
			}
		}
		n, next := page(len(out))
		out = out[:n]
		if next != "" {
			next = strconv.FormatInt(out[n-1].Revision, 10)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"subjects": out, "next": next})
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
			out = append(out, listedOrg{ID: syncOrgID(i), Status: "active", Enabled: true, Revision: int64(10 + i)})
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

	e.dir.list(listedOrg{ID: gone, Status: "deleted", Revision: 50}, listedOrg{ID: keep, Status: "active", Enabled: true, Revision: 51})
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
	e.dir.list(listedOrg{ID: org, Status: "active", Enabled: true, Revision: 1})
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
	if !e.kyid.FullSyncDue(ctx) {
		t.Fatal("a successful startup read postponed enforcing background reconciliation")
	}
	if at, err := e.st.Settings().GetSetting(ctx, sso.SettingSyncedAt); err != nil || at == "" {
		t.Fatalf("successful startup did not retain sync freshness: %q %v", at, err)
	}
}

// A newer lifecycle event wins over a missing org's stale "active" listing.
func TestTenancySyncStaleListingCannotUndoANewerSuspension(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	for i := range 10 {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.list(listedAll(10)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	e.dir.list(listedAll(10, 3)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.status(t, syncOrgID(3)) != store.TenantStatusSuspended {
		t.Fatalf("missing org not held: %v", err)
	}
	// A real suspension, newer than the list's revision 13, lands while it is missing.
	if changed, err := e.st.Chat().ApplyTenantLifecycle(ctx, syncOrgID(3), store.TenantStatusSuspended, 999); err != nil || !changed {
		t.Fatalf("suspension: %v %v", changed, err)
	}
	e.dir.list(listedAll(10)...) // the stale snapshot lists it active at 13
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, syncOrgID(3)) != store.TenantStatusSuspended {
		t.Fatal("a stale active listing undid a newer suspension")
	}
}

// failOnceSessions fails the first session revocation.
type failOnceSessions struct {
	store.SessionStore
	failed bool
}

func (f *failOnceSessions) DeleteUserSessions(ctx context.Context, userID string) error {
	if !f.failed {
		f.failed = true
		return errors.New("injected")
	}
	return f.SessionStore.DeleteUserSessions(ctx, userID)
}

type failOnceStore struct {
	store.Store
	sessions *failOnceSessions
}

func (f *failOnceStore) Sessions() store.SessionStore { return f.sessions }

// A revocation that failed after the status committed is retried on the next read of the same
// listing: revocation follows the resulting status, not whether this read changed it.
func TestTenancySyncRetriesAFailedRevocation(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	org := syncOrgID(0)
	_, tok := createOrgUser(t, e.st, "usr_rv", "rvuser", "user", org)
	kyid := sso.NewKyIdentityClient(e.cfg.SSO, &failOnceStore{Store: e.st, sessions: &failOnceSessions{SessionStore: e.st.Sessions()}})
	kyid.SetTenancy(e.cfg.Tenancy)
	e.dir.list(listedOrg{ID: org, Status: "suspended", Revision: 20})
	if err := kyid.SyncTenancy(ctx, false, false); err == nil {
		t.Fatal("a failed revocation reported success")
	}
	if err := kyid.SyncTenancy(ctx, false, false); err != nil {
		t.Fatal(err)
	}
	if rec := doBearerJSON(t, e.srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after the retried revocation = %d, want 401", rec.Code)
	}
	if err := e.st.Chat().SetTenantStatus(ctx, org, store.TenantStatusActive); err != nil {
		t.Fatal(err)
	}
	if rec := doBearerJSON(t, e.srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatal("the surviving session came back when the org resumed")
	}
}

// Both lists are read to their end, however many pages: a person on the 101st page of the erased
// list is erased, and an org on a page past suitedir's bound is not taken for missing.
func TestTenancySyncReadsEveryPage(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	e.kyid.OnUserErased(func(ctx context.Context, u *store.User) error {
		_, err := e.st.Chat().EraseUser(ctx, u.OrgID, u)
		return err
	})
	org := syncOrgID(0)
	last, _ := createOrgUser(t, e.st, "usr_last", "lastpage", "user", org)
	var subjects []erasedSubject
	for i := range 100 {
		subjects = append(subjects, erasedSubject{Sub: fmt.Sprintf("sub-never-held-%d", i), OrgID: org, Revision: int64(i + 1)})
	}
	subjects = append(subjects, erasedSubject{Sub: last.SSOSubject, OrgID: org, Revision: 101})
	var orgs []listedOrg
	for i := range 102 { // suitedir stops after 100 pages; 2 past it fit inside the guard
		orgs = append(orgs, listedOrg{ID: syncOrgID(i), Status: "active", Enabled: true, Revision: int64(i + 1)})
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.mu.Lock()
	e.dir.page, e.dir.erased, e.dir.orgs = 1, subjects, orgs
	e.dir.mu.Unlock()
	if err := e.kyid.StartupSync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Users().GetUserByID(ctx, last.ID); err == nil {
		t.Fatal("the person on the 101st page was not erased")
	}
	if e.activeCount(t) != 102 {
		t.Fatalf("orgs past the page bound were taken for missing: %d active", e.activeCount(t))
	}
}

// On a small install (three customer orgs) an empty list, or one that names none of them, holds
// no org offline.
func TestTenancySyncSmallInstallGuard(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	for i := range 3 {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.list()
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.activeCount(t) != 3 {
		t.Fatalf("empty list on a small install: %v, active %d", err, e.activeCount(t))
	}
	e.dir.list(listedOrg{ID: syncOrgID(9), Status: "active", Enabled: true, Revision: 1}) // names none of ours
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if e.status(t, syncOrgID(i)) != store.TenantStatusActive {
			t.Fatalf("a list naming none of ours held org %d offline", i)
		}
	}
	// One of three missing is still held.
	e.dir.list(listedAll(3, 1)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.status(t, syncOrgID(1)) != store.TenantStatusSuspended {
		t.Fatalf("one of three missing not held: %v", err)
	}
}

// A stale non-active listing of a missing org changes nothing; the current active listing
// still brings it back.
func TestTenancySyncStaleSuspendedListingKeepsRecovery(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	for i := range 10 {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.list(listedAll(10)...) // org 3 active at revision 13
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	e.dir.list(listedAll(10, 3)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.status(t, syncOrgID(3)) != store.TenantStatusSuspended {
		t.Fatalf("not held: %v", err)
	}
	stale := listedAll(10, 3)
	stale = append(stale, listedOrg{ID: syncOrgID(3), Status: "suspended", Revision: 12})
	sort.Slice(stale, func(i, j int) bool { return stale[i].Revision < stale[j].Revision })
	e.dir.list(stale...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if missing, _ := e.st.Chat().TenantMissing(ctx, syncOrgID(3)); !missing {
		t.Fatal("a stale suspended listing dropped the missing flag")
	}
	e.dir.list(listedAll(10)...)
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil || e.status(t, syncOrgID(3)) != store.TenantStatusActive {
		t.Fatalf("the active listing did not bring it back: %v %q", err, e.status(t, syncOrgID(3)))
	}
}

// A failed missing-org revocation remains work even though the org is no longer active.
func TestTenancySyncRetriesMissingOrgRevocationBeforeRecovery(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	org := syncOrgID(0)
	user, tok := createOrgUser(t, e.st, "usr_missing_retry", "missingretry", "user", org)
	for i := 1; i < 10; i++ {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	kyid := sso.NewKyIdentityClient(e.cfg.SSO, &failOnceStore{Store: e.st, sessions: &failOnceSessions{SessionStore: e.st.Sessions()}})
	kyid.SetTenancy(e.cfg.Tenancy)
	e.dir.list(listedAll(10, 0)...)
	if err := kyid.SyncTenancy(ctx, true, false); err == nil {
		t.Fatal("failed missing revocation reported success")
	}
	pending, err := e.st.Chat().PendingTenantRevocations(ctx)
	if err != nil || len(pending) != 1 || pending[0] != org {
		t.Fatalf("missing revocation not durable: %v %v", pending, err)
	}
	// A concurrent lifecycle resume cannot bypass the cleanup fence.
	if err := e.st.Chat().SetTenantStatus(ctx, org, store.TenantStatusActive); err != nil {
		t.Fatal(err)
	}
	if e.status(t, org) == store.TenantStatusActive {
		t.Fatal("resume restored access before revocation completed")
	}
	if err := e.st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "missing-retry-session", UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}, user.PasswordHash); err == nil {
		t.Fatal("pending cleanup admitted a new session")
	}
	// Even an incremental read, which cannot discover missing orgs, must finish the queued work.
	e.dir.list(listedAll(10)...)
	if err := kyid.SyncTenancy(ctx, false, false); err != nil {
		t.Fatal(err)
	}
	if pending, err := e.st.Chat().PendingTenantRevocations(ctx); err != nil || len(pending) != 0 {
		t.Fatalf("pending after retry: %v %v", pending, err)
	}
	if rec := doBearerJSON(t, e.srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("surviving session after recovery: %d", rec.Code)
	}
}

func TestTenancySyncStopsServingADisabledApp(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	org := syncOrgID(0)
	_, tok := createOrgUser(t, e.st, "usr_disabled_app", "disabledapp", "user", org)
	e.dir.list(listedOrg{ID: org, Status: "active", Revision: 10, Enabled: false})
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, org) != store.TenantStatusSuspended {
		t.Fatal("disabled app stayed active")
	}
	e.dir.list(listedOrg{ID: org, Status: "active", Revision: 11, Enabled: true})
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if e.status(t, org) != store.TenantStatusActive {
		t.Fatal("re-enabled app did not recover")
	}
	if rec := doBearerJSON(t, e.srv, http.MethodGet, "/api/v1/rooms", tok, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled app revived prior session: %d", rec.Code)
	}
}

// Startup alerts without enforcing missing orgs, so it cannot renew the background job's
// reconciliation deadline. Repeated successful restarts must leave that work due.
func TestTenancyStartupDoesNotDeferMissingReconciliation(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	for i := range 10 {
		if _, err := e.st.Chat().EnsureTenant(ctx, syncOrgID(i)); err != nil {
			t.Fatal(err)
		}
	}
	e.dir.list(listedAll(10, 3)...)
	if err := e.st.Settings().SetSetting(ctx, sso.SettingFullSyncAt, "1"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := e.kyid.StartupSync(ctx); err != nil {
			t.Fatal(err)
		}
		if got, err := e.st.Settings().GetSetting(ctx, sso.SettingFullSyncAt); err != nil || got != "1" {
			t.Fatalf("startup renewed enforcing timestamp: %q %v", got, err)
		}
		if !e.kyid.FullSyncDue(ctx) || e.status(t, syncOrgID(3)) != store.TenantStatusActive {
			t.Fatal("startup either enforced or postponed missing-org reconciliation")
		}
	}
	elected, err := e.st.AcquireLease(ctx, "tenancy_sync", "elected-background", time.Minute)
	if err != nil || !elected {
		t.Fatalf("background election: %v %v", elected, err)
	}
	other, err := e.st.AcquireLease(ctx, "tenancy_sync", "other-background", time.Minute)
	if err != nil || other {
		t.Fatalf("second background worker also elected: %v %v", other, err)
	}
	if err := e.kyid.SyncTenancy(ctx, e.kyid.FullSyncDue(ctx), false); err != nil {
		t.Fatal(err)
	}
	if e.kyid.FullSyncDue(ctx) || e.status(t, syncOrgID(3)) != store.TenantStatusSuspended {
		t.Fatal("background full read did not enforce missing org and renew its deadline")
	}
}
