package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestJobLeaseHandover(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	// Two replicas on one database.
	a, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	must := func(st store.Store, holder string, ttl time.Duration, want bool, what string) {
		t.Helper()
		got, err := st.AcquireLease(ctx, "sweep", holder, ttl)
		if err != nil || got != want {
			t.Fatalf("%s: got %v, %v; want %v", what, got, err, want)
		}
	}
	must(a, "replica-a", time.Minute, true, "a takes a free lease")
	must(b, "replica-b", time.Minute, false, "b while a holds it")
	must(a, "replica-a", time.Minute, true, "a renews")
	must(b, "replica-b", time.Minute, false, "b after a renewed")
	must(a, "replica-a", time.Millisecond, true, "a renews briefly, then dies")
	time.Sleep(20 * time.Millisecond)
	must(b, "replica-b", time.Minute, true, "b takes the expired lease")
	must(a, "replica-a", time.Minute, false, "a, back, finds b holding it")
	if ok, err := a.AcquireLease(ctx, "other-job", "replica-a", time.Minute); err != nil || !ok {
		t.Fatalf("leases are per job: %v %v", ok, err)
	}
}
