package store_test

import (
	"context"
	"os"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// A lagging read replica never makes a suspended org look active.
func TestTenantStatusReadsThePrimary(t *testing.T) {
	if os.Getenv("KY_TEST_POSTGRES_DSN") == "" {
		t.Skip("read replicas exist only on PostgreSQL")
	}
	ctx := context.Background()
	replicaCfg := testdb.Config(t)
	replica, err := store.Open(ctx, replicaCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if _, err := replica.Chat().EnsureTenant(ctx, "org-lag"); err != nil {
		t.Fatal(err)
	}

	cfg := testdb.Config(t)
	cfg.ReadReplicaDSN = replicaCfg.DSN
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Chat().EnsureTenant(ctx, "org-lag"); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().SetTenantStatus(ctx, "org-lag", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	tenant, err := st.Chat().GetTenant(ctx, "org-lag")
	if err != nil || tenant.Status != store.TenantStatusSuspended {
		t.Fatalf("GetTenant = %+v (err %v), want the primary's suspended status", tenant, err)
	}
}
