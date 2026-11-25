package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// A snapshot from before migration 67 has no home_region. The next listing fills it in at an
// unchanged revision, after which the region is fixed: a different one is refused at any
// revision, and the org stays ready.
func TestHomeRegionBackfillsOnceThenStaysFixed(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	const org = "00000000-0000-4000-8000-000000000067"
	chat := st.Chat()
	if _, err := chat.EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	upgraded := TenantDirectoryEntry{TenantID: org, Revision: 5, Status: TenantStatusActive, Enabled: true, Valid: true}
	if err := chat.ApplyTenantDirectory(ctx, upgraded); err != nil {
		t.Fatal(err)
	}
	if err := chat.SetServedCells(ctx, []string{"us-east-2"}); err != nil {
		t.Fatal(err)
	}
	listed := upgraded
	listed.HomeRegion = "us-east-2"
	for range 2 { // the backfill, then the same listing again
		if err := chat.ApplyTenantDirectory(ctx, listed); err != nil {
			t.Fatalf("same-revision backfill refused: %v", err)
		}
	}
	if cell, err := chat.TenantHomeRegion(ctx, org); err != nil || cell != "us-east-2" {
		t.Fatalf("backfilled cell: %q %v", cell, err)
	}
	if tn, err := chat.GetTenant(ctx, org); err != nil || tn.Status != TenantStatusActive {
		t.Fatalf("backfilled org not served: %+v %v", tn, err)
	}
	for _, rev := range []int64{5, 6} {
		moved := listed
		moved.Revision, moved.HomeRegion = rev, "us-east-3"
		if err := chat.ApplyTenantDirectory(ctx, moved); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("region changed at revision %d: %v", rev, err)
		}
	}
	if cell, _ := chat.TenantHomeRegion(ctx, org); cell != "us-east-2" {
		t.Fatalf("region rewritten to %q", cell)
	}
}

// Replicas starting together with the same KY_CELLS all succeed, from an empty table each
// round, on separate database handles.
func TestServedCellsConcurrentStarts(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	var replicas []Store
	for range 4 {
		st, err := Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		replicas = append(replicas, st)
	}
	db := replicas[0].(*SQLStore).db
	for round := range 25 {
		if _, err := db.ExecContext(ctx, `DELETE FROM served_cells`); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2*len(replicas))
		var wg sync.WaitGroup
		for _, st := range replicas {
			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs <- st.Chat().SetServedCells(ctx, []string{"us-east-2", "us-east-3"})
				}()
			}
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: concurrent start failed: %v", round, err)
			}
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM served_cells`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("round %d: served cells %d %v", round, n, err)
		}
	}
}
