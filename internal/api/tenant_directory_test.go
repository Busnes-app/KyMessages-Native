package api_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

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
	if r := doBearerJSON(t, first, http.MethodPost, "/api/v1/rooms/"+room+"/messages", token, map[string]any{"body": "still here"}, nil); r.Code != http.StatusCreated {
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
