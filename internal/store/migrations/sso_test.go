package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store/migrations"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestSSOLifecycleUpgradePreservesExistingGrants(t *testing.T) {
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
	if err := migrations.RunThrough(ctx, db, cfg.Driver, 30); err != nil {
		t.Fatal(err)
	}
	// SQL literals keep the exact same upgrade fixture on both engines.
	for _, q := range []string{
		`INSERT INTO users (id,username,sso_provider,created_at,updated_at) VALUES ('suite','suite','kyidentity',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP), ('local','local','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES ('suite','suite',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP), ('local','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO device_pairings (secret,user_id,created_at,expires_at,authenticated_at) VALUES ('suite','suite',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP), ('local','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO push_subscriptions (id,tenant_id,user_id,endpoint,p256dh,auth_secret,created_at) VALUES ('suite','default','suite','https://push.example/suite','key','secret',1), ('local','default','local','https://push.example/local','key','secret',1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrations.Run(ctx, db, cfg.Driver); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "device_pairings", "push_subscriptions"} {
		for user, want := range map[string]int{"suite": 1, "local": 1} {
			var got int
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE user_id = '"+user+"'").Scan(&got); err != nil || got != want {
				t.Fatalf("%s %s: got %d want %d (%v)", table, user, got, want, err)
			}
		}
	}
	for _, table := range []string{"sessions", "device_pairings"} {
		var unbound int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE sso_sid = '' AND sso_issued_at = 0 AND sso_generation = 0").Scan(&unbound); err != nil || unbound != 2 {
			t.Fatalf("%s legacy binding: %d (%v)", table, unbound, err)
		}
	}
	var users int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&users); err != nil || users != 2 {
		t.Fatal("accounts changed", err)
	}
}
