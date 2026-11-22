package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// An org-bound account gets no new grant once its org is suspended, and a sign-in racing the
// suspension never leaves a session behind.
func TestGrantIssuanceFencedByOrgStatus(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, err := st.Chat().EnsureTenant(ctx, "org-x"); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "usr_fence", Username: "fence", Role: "admin", Status: "active", OrgID: "org-x", CreatedAt: time.Now()}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	issue := func(hash string) error {
		return st.Sessions().CreateSession(ctx, &store.Session{TokenHash: hash, UserID: u.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, "")
	}
	if err := issue("before"); err != nil {
		t.Fatalf("session for an active org: %v", err)
	}

	if err := st.Chat().SetTenantStatus(ctx, "org-x", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	if err := issue("after"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session for a suspended org = %v, want ErrNotFound", err)
	}
	if err := st.Devices().CreatePairing(ctx, &store.DevicePairing{Secret: "pair", UserID: u.ID, Status: "pending"}, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pairing for a suspended org = %v, want ErrNotFound", err)
	}

	for i := range 20 {
		if err := st.Chat().SetTenantStatus(ctx, "org-x", store.TenantStatusActive); err != nil {
			t.Fatal(err)
		}
		hash := fmt.Sprintf("race-%d", i)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := issue(hash); err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("issue: %v", err)
			}
		}()
		go func() { // what applyOrgLifecycle does: status first, then the grant sweep
			defer wg.Done()
			if err := st.Chat().SetTenantStatus(ctx, "org-x", store.TenantStatusSuspended); err != nil {
				t.Errorf("suspend: %v", err)
			}
			if err := st.Sessions().DeleteUserSessions(ctx, u.ID); err != nil {
				t.Errorf("revoke: %v", err)
			}
		}()
		wg.Wait()
		if _, err := st.Sessions().GetSession(ctx, hash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: a session survived the org's suspension (err %v)", i, err)
		}
	}
}
