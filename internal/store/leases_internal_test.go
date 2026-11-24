package store

import (
	"context"
	"testing"
	"time"
)

func TestPruneSharedRemovesOnlyExpiredLeases(t *testing.T) {
	ctx := context.Background()
	st, _ := callRoutingStore(t)
	for name, ttl := range map[string]time.Duration{"expired": -time.Second, "live": time.Minute} {
		if ok, err := st.AcquireLease(ctx, "pool-report:"+name, "holder", ttl); err != nil || !ok {
			t.Fatalf("seed %s: %v %v", name, ok, err)
		}
	}
	if err := st.PruneShared(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE name = 'pool-report:expired'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired report lease retained: %d %v", count, err)
	}
	if ok, err := st.AcquireLease(ctx, "pool-report:live", "other", time.Minute); err != nil || ok {
		t.Fatalf("live lease lost: %v %v", ok, err)
	}
}
