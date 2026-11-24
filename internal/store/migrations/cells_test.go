package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store/migrations"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestCellsUpgradeLeavesEveryOrgWithoutACell(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	driver := cfg.Driver
	if driver == "postgres" {
		driver = "pgx"
	}
	db, err := sql.Open(driver, cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrations.RunThrough(ctx, db, cfg.Driver, 66); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO tenants(id,slug,display_name,plan,status,created_at) VALUES('org','org','org','business','active',1)`,
		`INSERT INTO tenant_directory(tenant_id,revision,status,enabled,valid,max_upload_bytes,max_pending_user_bytes) VALUES('org',3,'active',1,1,0,0)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := migrations.Run(ctx, db, cfg.Driver); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_directory WHERE tenant_id='org' AND revision=3 AND home_region=''`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("snapshot after upgrade: %d %v", n, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM served_cells`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("served cells after upgrade: %d %v", n, err)
		}
	}
}
