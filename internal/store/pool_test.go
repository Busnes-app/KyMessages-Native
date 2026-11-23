package store_test

import (
	"context"
	"sync"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Each report's sequence and usage come from one transaction, so concurrent reports for one
// org get distinct, rising sequences, and a later report never carries an older total.
func TestNextPoolReportOrdersSnapshots(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000c1"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().ReserveAttachmentQuota(ctx, org, "u", 1000, store.AttachmentQuotaLimits{}, 0); err != nil {
		t.Fatal(err)
	}
	s1, u1, err := st.Chat().NextPoolReport(ctx, org)
	if err != nil || s1 != 1 || u1 != 1000 {
		t.Fatalf("first report: seq %d used %d %v", s1, u1, err)
	}
	var wg sync.WaitGroup
	seqs := make(chan int64, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, _, err := st.Chat().NextPoolReport(ctx, org); err == nil {
				seqs <- s
			} else {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(seqs)
	seen := map[int64]bool{}
	for s := range seqs {
		if s <= s1 || seen[s] {
			t.Fatalf("sequence %d repeated or not rising", s)
		}
		seen[s] = true
	}
	if _, _, err := st.Chat().NextPoolReport(ctx, "00000000-0000-4000-8000-0000000000c9"); err != store.ErrNotFound {
		t.Fatalf("unknown org: %v", err)
	}
}
