package store

import (
	"context"
	"errors"
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
