package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store/migrations"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestRetainedVersionUpgradePreservesLiveContentAndGrants(t *testing.T) {
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
	if err := migrations.RunThrough(ctx, db, cfg.Driver, 65); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,role,status,created_at,updated_at) VALUES('owner','owner','user','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES('session','owner',CURRENT_TIMESTAMP,'2099-01-01 00:00:00+00:00')`,
		`INSERT INTO rooms(id,tenant_id,kind,created_by,created_at) VALUES('room','default','channel','owner',1)`,
		`INSERT INTO attachments(id,tenant_id,room_id,uploader_id,blob_key,filename,mime_type,size_bytes,sha256_hex,created_at) VALUES('file','default','room','owner','key','name.bin','application/octet-stream',321,'digest',1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := migrations.Run(ctx, db, cfg.Driver); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			q    string
			want int
		}{
			{`SELECT COUNT(*) FROM sessions WHERE token_hash='session' AND user_id='owner'`, 1},
			{`SELECT COUNT(*) FROM attachments WHERE id='file' AND tenant_id='default' AND room_id='room' AND uploader_id='owner' AND blob_key='key' AND filename='name.bin' AND size_bytes=321 AND sha256_hex='digest'`, 1},
			{`SELECT COUNT(*) FROM retained_attachment_versions`, 0},
		} {
			var got int
			if err := db.QueryRowContext(ctx, check.q).Scan(&got); err != nil || got != check.want {
				t.Fatalf("upgrade changed %s: %d want %d %v", check.q, got, check.want, err)
			}
		}
	}
}
