package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestDirectoryAdmissionCannotBeCreatedBySignIn(t *testing.T) {
	ctx := context.Background()
	_, _, st, cfg := newReplicas(t)
	cfg.SSO.Enabled = true
	cfg.SSO.AutoProvision = true
	idp := newFakeIdP(t, cfg)
	srv := api.NewServer(cfg, st)
	t.Cleanup(srv.CloseChat)
	claims := map[string]any{"sub": "new-authority", "preferred_username": "new-authority", "org_id": replicaOrgA}
	denied := func() {
		t.Helper()
		r := idp.signIn(srv, claims)
		if r.Code != http.StatusForbidden || sessionCookie(r) != nil {
			t.Fatalf("unadmitted sign-in: %d %s", r.Code, r.Body.String())
		}
	}
	denied()
	if _, err := st.Chat().GetTenant(ctx, replicaOrgA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("token created org: %v", err)
	}
	if _, err := st.Users().GetUserBySSO(ctx, "kyidentity", "new-authority"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("token provisioned user: %v", err)
	}
	// A signed user webhook may stage an org, but cannot admit it without an org listing.
	if _, err := st.Chat().EnsureTenant(ctx, replicaOrgA); err != nil {
		t.Fatal(err)
	}
	denied()
	admitOrg(t, st, replicaOrgB) // readiness from another org cannot be borrowed
	denied()
	e := store.TenantDirectoryEntry{TenantID: replicaOrgA, Revision: 1, Status: store.TenantStatusActive, Enabled: true, Valid: true}
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	r := idp.signIn(srv, claims)
	cookie := sessionCookie(r)
	if cookie == nil {
		t.Fatalf("admitted sign-in: %d %s", r.Code, r.Body.String())
	}
	e.Revision = 2
	e.Enabled = false
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if r := doBearerJSON(t, srv, http.MethodGet, "/api/v1/rooms", cookie.Value, nil, nil); r.Code != http.StatusForbidden {
		t.Fatalf("disabled app retained access: %d %s", r.Code, r.Body.String())
	}
	denied()
}

func TestDirectoryQuotasApplyAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	first, second, st, _ := newReplicas(t, withPool(t, &fakePool{headroom: 1 << 20}))
	user, token := createOrgUser(t, st, "usr_dir_quota", "dirquota", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, first, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "quotas"}, nil))
	e := store.TenantDirectoryEntry{TenantID: replicaOrgA, Revision: 1, Status: store.TenantStatusActive, Enabled: true, Valid: true, Quotas: store.TenantQuotas{MaxUploadBytes: 4096, MaxPendingUserBytes: 4096}}
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for _, srv := range []*api.Server{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", token, "file", "part.txt", make([]byte, 4096))
			results <- r.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	counts := map[int]int{}
	for code := range results {
		counts[code]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusRequestEntityTooLarge] != 1 {
		t.Fatalf("shared pending quota: %v", counts)
	}
	// Another org's lower upload limit cannot change this org's budget.
	_, otherToken := createOrgUser(t, st, "usr_dir_other", "dirother", "user", replicaOrgB)
	otherRoom := roomOf(t, doBearerJSON(t, second, http.MethodPost, "/api/v1/rooms", otherToken, map[string]any{"kind": store.RoomKindChannel, "name": "other"}, nil))
	e.TenantID = replicaOrgB
	e.Quotas.MaxUploadBytes = 1024
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if r := doMultipartUpload(t, second, "/api/v1/rooms/"+otherRoom+"/attachments", otherToken, "file", "large.txt", make([]byte, 2048)); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload quota: %d %s", r.Code, r.Body.String())
	}
	// Sending text remains possible at the pending attachment limit.
	if r := doBearerJSON(t, first, http.MethodPost, "/api/v1/rooms/"+room+"/messages", token, sealed("still here", nil), nil); r.Code != http.StatusCreated {
		t.Fatalf("text blocked by attachment limit for %s: %d", user.ID, r.Code)
	}
}

func TestDirectorySyncRejectsInvalidQuotasUntilNewRevision(t *testing.T) {
	ctx := context.Background()
	e := newSyncEnv(t)
	e.dir.list(listedOrg{ID: replicaOrgA, Revision: 1, Status: "active", Enabled: true, Quotas: map[string]any{"unknown": 1}})
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	got, err := e.st.Chat().GetTenant(ctx, replicaOrgA)
	if err != nil || got.Status != store.TenantStatusSuspended || got.DirectoryReady {
		t.Fatalf("invalid quotas admitted: %+v %v", got, err)
	}
	e.dir.list(listedOrg{ID: replicaOrgA, Revision: 2, Status: "active", Enabled: true, Quotas: map[string]any{"max_upload_bytes": 2048}})
	if err := e.kyid.SyncTenancy(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	got, err = e.st.Chat().GetTenant(ctx, replicaOrgA)
	if err != nil || got.Status != store.TenantStatusActive || !got.DirectoryReady {
		t.Fatalf("corrected snapshot not admitted: %+v %v", got, err)
	}
}

// Observe the database boundary rather than sleeping until the second replica has
// actually competed for the same cold pool grant.
type contendedPoolStore struct {
	store.Store
	contended chan<- struct{}
}

func (s contendedPoolStore) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	ok, err := s.Store.AcquireLease(ctx, name, holder, ttl)
	if !ok && err == nil && strings.HasPrefix(name, "pool-report:") {
		select {
		case s.contended <- struct{}{}:
		default:
		}
	}
	return ok, err
}

func TestDirectoryQuotaColdGrantOverlap(t *testing.T) {
	firstReport := make(chan struct{})
	competing := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblockFirst := func() { firstOnce.Do(func() { close(releaseFirst) }) }
	unblockSecond := func() { secondOnce.Do(func() { close(releaseSecond) }) }
	defer unblockFirst()
	defer unblockSecond()
	pool := &fakePool{headroom: 1 << 20, beforeReply: func(seq int64) {
		if seq == 1 {
			close(firstReport)
			<-releaseFirst
		} else if seq == 2 {
			// Before the fix, a second numbered report made the first response
			// inapplicable before any grant had been stored.
			select {
			case competing <- struct{}{}:
			default:
			}
			<-releaseSecond
		}
	}}
	first, second, st, _ := newReplicasWithStore(t, func(st store.Store) store.Store {
		return contendedPoolStore{Store: st, contended: competing}
	}, withPool(t, pool))
	_, token := createOrgUser(t, st, "usr_cold_quota", "coldquota", "user", replicaOrgA)
	room := roomOf(t, doBearerJSON(t, first, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "cold quota"}, nil))
	entry := store.TenantDirectoryEntry{TenantID: replicaOrgA, Revision: 1, Status: store.TenantStatusActive, Enabled: true, Valid: true, Quotas: store.TenantQuotas{MaxUploadBytes: 4096, MaxPendingUserBytes: 4096}}
	if err := st.Chat().ApplyTenantDirectory(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	upload := func(srv *api.Server, result chan<- *httptest.ResponseRecorder) {
		result <- doMultipartUpload(t, srv, "/api/v1/rooms/"+room+"/attachments", token, "file", "part.txt", make([]byte, 4096))
	}
	await := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	one, two := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	go upload(first, one)
	await(firstReport, "first pool request")
	go upload(second, two)
	await(competing, "second replica at the report boundary")
	unblockFirst()
	var a, b *httptest.ResponseRecorder
	select {
	case a = <-one:
	case <-time.After(10 * time.Second):
		t.Fatal("first upload did not complete")
	}
	unblockSecond()
	select {
	case b = <-two:
	case <-time.After(10 * time.Second):
		t.Fatal("second upload did not complete")
	}
	counts := map[int]int{a.Code: 1}
	counts[b.Code]++
	if counts[http.StatusCreated] != 1 || counts[http.StatusRequestEntityTooLarge] != 1 {
		t.Fatalf("cold shared quota: %v; first=%s second=%s", counts, a.Body.String(), b.Body.String())
	}
}

func TestPoolReportForAnotherOrgDoesNotWaitOnHeldExchange(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{headroom: 1 << 20}
	first, second, st, _ := newReplicas(t, withPool(t, pool))
	// A crashed reporter holds org A until its lease expires; org B must remain usable.
	if ok, err := st.AcquireLease(ctx, "pool-report:"+replicaOrgA, "unavailable-reporter", time.Minute); err != nil || !ok {
		t.Fatalf("held exchange: %v %v", ok, err)
	}
	_, token := createOrgUser(t, st, "usr_pool_independent", "poolindependent", "user", replicaOrgB)
	room := roomOf(t, doBearerJSON(t, first, http.MethodPost, "/api/v1/rooms", token, map[string]any{"kind": store.RoomKindChannel, "name": "independent"}, nil))
	if rec := doMultipartUpload(t, second, "/api/v1/rooms/"+room+"/attachments", token, "file", "ok.txt", []byte("other org")); rec.Code != http.StatusCreated {
		t.Fatalf("unrelated org blocked: %d %s", rec.Code, rec.Body.String())
	}
}

// Bound the old wait path deterministically without sleeping for its production deadline.
type observeHeldReportStore struct {
	store.Store
	held     string
	attempts *int
}

func (s observeHeldReportStore) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	if name == "pool-report:"+s.held {
		*s.attempts++
		if *s.attempts > 1 {
			return false, context.DeadlineExceeded
		}
	}
	return s.Store.AcquireLease(ctx, name, holder, ttl)
}

func TestPeriodicPoolReportSkipsContendedOrgAndRenewsOthers(t *testing.T) {
	for _, held := range []string{replicaOrgA, replicaOrgB} {
		t.Run(held, func(t *testing.T) {
			pool := &fakePool{headroom: 1 << 20}
			attempts := 0
			a, _, st, _ := newReplicasWithStore(t, func(s store.Store) store.Store {
				return observeHeldReportStore{Store: s, held: held, attempts: &attempts}
			}, withPool(t, pool))
			createOrgUser(t, st, "busy-a", "busya", "user", replicaOrgA)
			createOrgUser(t, st, "busy-b", "busyb", "user", replicaOrgB)
			// Use the embedded store to reserve the crashed reporter before observing contention.
			wrapped := st.(observeHeldReportStore)
			if ok, err := wrapped.Store.AcquireLease(context.Background(), "pool-report:"+held, "crashed", time.Minute); err != nil || !ok {
				t.Fatalf("reserve crashed report: %v %v", ok, err)
			}
			err := a.RefreshPool(context.Background(), time.Now())
			if !errors.Is(err, store.ErrPoolUnavailable) {
				t.Errorf("expected retryable contention: %v", err)
			}
			other := replicaOrgA
			if held == other {
				other = replicaOrgB
			}
			pool.mu.Lock()
			reports := append([]map[string]any(nil), pool.reports...)
			pool.mu.Unlock()
			if len(reports) != 1 || reports[0]["org_id"] != other {
				t.Fatalf("unrelated org was not reported: %+v", reports)
			}
			usage, err := st.Chat().PoolUsages(context.Background(), time.Now().UnixMilli(), other)
			if err != nil || len(usage) != 1 || usage[0].CeilingBytes == nil {
				t.Fatalf("unrelated grant not stored: %+v %v", usage, err)
			}
			if ok, err := st.AcquireLease(context.Background(), "pool-report:"+other, "next", time.Minute); err != nil || !ok {
				t.Fatalf("unrelated lease not released: %v %v", ok, err)
			}
			if attempts != 1 {
				t.Fatalf("periodic reporter waited on busy org: %d attempts", attempts)
			}
		})
	}
}
