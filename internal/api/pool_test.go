package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// fakePool is KyIdentity's POST /api/suite/storage: it grants up to headroom bytes beyond the
// reported usage, or answers as configured.
type fakePool struct {
	mu       sync.Mutex
	headroom int64
	answer   string // "" (ok), "stale", "unknown_org", "down", "wrong_seq"
	staleSeq int64
	reports  []map[string]any
	calls    atomic.Int64
}

func (f *fakePool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if r.URL.Path != "/api/suite/storage" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != "kymessages" || p != "client-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		Reports []map[string]any `json:"reports"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.answer == "down" {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var results []map[string]any
	for _, rep := range body.Reports {
		f.reports = append(f.reports, rep)
		used, seq := int64(rep["used_bytes"].(float64)), int64(rep["seq"].(float64))
		switch f.answer {
		case "stale":
			results = append(results, map[string]any{"org_id": rep["org_id"], "result": "stale", "seq": f.staleSeq, "ceiling_bytes": used + f.headroom, "ttl_seconds": 900})
		case "unknown_org":
			results = append(results, map[string]any{"org_id": rep["org_id"], "result": "unknown_org"})
		case "wrong_seq":
			seq++
			fallthrough
		default:
			results = append(results, map[string]any{"org_id": rep["org_id"], "result": "ok", "seq": seq, "ceiling_bytes": used + f.headroom, "ttl_seconds": 900})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}

func (f *fakePool) set(answer string, headroom int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer, f.headroom = answer, headroom
}

type poolEnv struct {
	a, b   *api.Server
	st     store.Store
	cfg    *config.Config
	pool   *fakePool
	tok    string
	roomID string
}

// withPool points the replicas at a fake KyIdentity storage pool.
func withPool(t *testing.T, pool *fakePool) func(*config.Config) {
	idp := httptest.NewServer(pool)
	t.Cleanup(idp.Close)
	return func(cfg *config.Config) {
		cfg.SSO.Enabled = true
		cfg.SSO.KyIdentityIssuer = idp.URL
		cfg.SSO.KyIdentityClientID = "kymessages"
		cfg.SSO.KyIdentitySecret = "client-secret"
	}
}

func newPoolEnv(t *testing.T) *poolEnv {
	t.Helper()
	pool := &fakePool{headroom: 4096}
	a, b, st, cfg := newReplicas(t, withPool(t, pool), func(cfg *config.Config) {
		cfg.Attachments.MaxUploadBytes = 8192
		cfg.Attachments.MaxPendingUserBytes = 1 << 20
		cfg.Attachments.MaxTotalBytes = 1024 // ignored in multi mode
		cfg.Attachments.PendingTTL = time.Hour
	})
	_, tok := createOrgUser(t, st, "usr_pool", "pooluser", "user", replicaOrgA)
	rec := doBearerJSON(t, a, http.MethodPost, "/api/v1/rooms", tok, map[string]any{"kind": store.RoomKindChannel, "name": "pool"}, nil)
	var room struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &room)
	return &poolEnv{a: a, b: b, st: st, cfg: cfg, pool: pool, tok: tok, roomID: room.Room.ID}
}

func (e *poolEnv) upload(t *testing.T, srv *api.Server, n int) *httptest.ResponseRecorder {
	t.Helper()
	return doMultipartUpload(t, srv, "/api/v1/rooms/"+e.roomID+"/attachments", e.tok, "file", "f.txt", bytes.Repeat([]byte("p"), n))
}

func wantPool(t *testing.T, rec *httptest.ResponseRecorder, status int, code, what string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != status || body.Code != code {
		t.Fatalf("%s = %d %s, want %d %q", what, rec.Code, rec.Body.String(), status, code)
	}
}

// A new org has no grant: its first upload reports once and is admitted; with KyIdentity down
// it is refused (503), never admitted unchecked.
func TestPoolFirstUploadFetchesAGrant(t *testing.T) {
	e := newPoolEnv(t)
	e.pool.set("down", 0)
	wantPool(t, e.upload(t, e.a, 100), http.StatusServiceUnavailable, "pool_unavailable", "first upload with KyIdentity down")
	e.pool.set("", 4096)
	if rec := e.upload(t, e.a, 2000); rec.Code != http.StatusCreated {
		t.Fatalf("first upload with KyIdentity up = %d: %s", rec.Code, rec.Body.String())
	}
	if len(e.pool.reports) != 1 || e.pool.reports[0]["org_id"] != replicaOrgA || e.pool.reports[0]["used_bytes"].(float64) != 0 {
		t.Fatalf("reports: %v", e.pool.reports)
	}
}

// The ceiling is exact: an upload that reaches it passes, one byte over is refused, and the
// per-tenant install cap (1 KiB here) does not apply in multi mode.
func TestPoolCeilingIsExact(t *testing.T) {
	e := newPoolEnv(t)
	e.pool.set("", 3000)
	if rec := e.upload(t, e.a, 2000); rec.Code != http.StatusCreated {
		t.Fatalf("upload under the ceiling = %d: %s", rec.Code, rec.Body.String())
	}
	// 1000 bytes of room are left in the pool; an upload of exactly that fits.
	e.pool.set("", 1000)
	if rec := e.upload(t, e.a, 1000); rec.Code != http.StatusCreated {
		t.Fatalf("upload to the ceiling = %d: %s", rec.Code, rec.Body.String())
	}
	e.pool.set("", 0) // KyIdentity has no more room
	wantPool(t, e.upload(t, e.a, 1), http.StatusRequestEntityTooLarge, "org_storage_full", "one byte over")
}

// A grant is trusted until it expires; after that, with KyIdentity unreachable, writes that add
// bytes are refused and writes that free bytes still pass.
func TestPoolStaleGrantFailsClosed(t *testing.T) {
	e := newPoolEnv(t)
	ctx := context.Background()
	e.pool.set("", 1<<20)
	rec := e.upload(t, e.a, 500)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d", rec.Code)
	}
	var att struct {
		Attachment store.Attachment `json:"attachment"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &att)
	e.pool.set("down", 0)
	if rec := e.upload(t, e.b, 500); rec.Code != http.StatusCreated {
		t.Fatalf("upload within the grant's lifetime, KyIdentity down = %d", rec.Code)
	}
	// Age the grant past its lifetime.
	seq, _, _ := e.st.Chat().NextPoolReport(ctx, replicaOrgA)
	if err := e.st.Chat().SetPoolGrant(ctx, replicaOrgA, seq, 1000, 1<<20, time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	wantPool(t, e.upload(t, e.a, 10), http.StatusServiceUnavailable, "pool_unavailable", "upload on an expired grant")
	if rec := doBearerJSON(t, e.a, http.MethodDelete, "/api/v1/attachments/"+att.Attachment.ID, e.tok, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete on an expired grant = %d", rec.Code)
	}
	if rec := doBearerJSON(t, e.a, http.MethodGet, "/api/v1/rooms/"+e.roomID+"/messages", e.tok, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("reading on an expired grant = %d", rec.Code)
	}
	if rec := doBearerJSON(t, e.a, http.MethodPost, "/api/v1/rooms/"+e.roomID+"/messages", e.tok, map[string]any{"body": "text still works"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("sending text on an expired grant = %d", rec.Code)
	}
}

// Two replicas uploading at once cannot together pass the ceiling: the tenant lock serialises
// their checks.
func TestPoolConcurrentUploadsOnTwoReplicas(t *testing.T) {
	e := newPoolEnv(t)
	e.pool.set("", 1500)
	if rec := e.upload(t, e.a, 1); rec.Code != http.StatusCreated { // takes the grant: ceiling 1501
		t.Fatalf("seed upload = %d", rec.Code)
	}
	e.pool.set("", 0)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, srv := range []*api.Server{e.a, e.b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = e.upload(t, srv, 1000).Code
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent uploads = %v, want exactly one 201", codes)
	}
}

// The reporter sends absolute totals with a sequence that only rises, follows KyIdentity past a
// stale sequence (a restored database), and holds no grant for an org KyIdentity does not know.
func TestPoolReporter(t *testing.T) {
	e := newPoolEnv(t)
	ctx := context.Background()
	e.pool.set("", 4096)
	if rec := e.upload(t, e.a, 700); rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	if err := e.a.RefreshPool(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	last := e.pool.reports[len(e.pool.reports)-1]
	if last["used_bytes"].(float64) != 700 || last["want_bytes"].(float64) <= 0 {
		t.Fatalf("report: %v", last)
	}
	n := len(e.pool.reports)
	if err := e.b.RefreshPool(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(e.pool.reports) != n {
		t.Fatal("an unchanged org with a fresh grant was reported again")
	}
	// A report answered for another sequence is not this report's grant.
	e.pool.set("wrong_seq", 1<<30)
	if err := e.b.RefreshPool(ctx, time.Now().Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantPool(t, e.upload(t, e.a, 8000), http.StatusRequestEntityTooLarge, "org_storage_full", "upload after a mismatched answer")
	// stale: the next sequence starts above KyIdentity's.
	e.pool.mu.Lock()
	e.pool.answer, e.pool.staleSeq = "stale", 1000
	e.pool.mu.Unlock()
	if err := e.a.RefreshPool(ctx, time.Now().Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.pool.set("", 4096)
	if err := e.a.RefreshPool(ctx, time.Now().Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if seq := e.pool.reports[len(e.pool.reports)-1]["seq"].(float64); seq <= 1000 {
		t.Fatalf("seq after stale = %v, want above 1000", seq)
	}
	// unknown_org: nothing may be added.
	e.pool.set("unknown_org", 0)
	if err := e.a.RefreshPool(ctx, time.Now().Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantPool(t, e.upload(t, e.a, 10), http.StatusRequestEntityTooLarge, "org_storage_full", "upload for an org KyIdentity does not know")
}

// The staff org is in no pool: it is never reported and its uploads are not checked.
func TestPoolSkipsTheStaffOrg(t *testing.T) {
	e := newPoolEnv(t)
	e.pool.set("down", 0)
	_, staffTok := createOrgUser(t, e.st, "usr_pool_staff", "poolstaff", "user", testStaffOrg)
	rec := doBearerJSON(t, e.a, http.MethodPost, "/api/v1/rooms", staffTok, map[string]any{"kind": store.RoomKindChannel, "name": "ops"}, nil)
	var room struct {
		Room store.Room `json:"room"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &room)
	if rec := doMultipartUpload(t, e.a, "/api/v1/rooms/"+room.Room.ID+"/attachments", staffTok, "file", "s.txt", []byte("staff file")); rec.Code != http.StatusCreated {
		t.Fatalf("staff upload with KyIdentity down = %d: %s", rec.Code, rec.Body.String())
	}
	e.pool.set("", 4096)
	if err := e.a.RefreshPool(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.pool.reports {
		if r["org_id"] == testStaffOrg {
			t.Fatal("staff org reported")
		}
	}
}

// A grant with some room but less than the file needs is refreshed before the upload is
// refused, so a file that fits the pool is not turned away by a small grant.
func TestPoolShortGrantIsRefreshed(t *testing.T) {
	e := newPoolEnv(t)
	e.pool.set("", 1000) // first grant: 1000 bytes
	if rec := e.upload(t, e.a, 500); rec.Code != http.StatusCreated {
		t.Fatalf("seed = %d", rec.Code)
	}
	e.pool.set("", 1<<20) // KyIdentity now has room
	if rec := e.upload(t, e.a, 2000); rec.Code != http.StatusCreated {
		t.Fatalf("upload larger than the remaining grant = %d: %s", rec.Code, rec.Body.String())
	}
}
