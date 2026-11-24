package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store/migrations"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestGuestInviteUpgradeRetiresUnknownBindingsAndKeepsHumanGrants(t *testing.T) {
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
	if err := migrations.RunThrough(ctx, db, cfg.Driver, 64); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO users(id,username,role,status,created_at,updated_at) VALUES('human','human','user','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES('human-session','human',CURRENT_TIMESTAMP,'2099-01-01 00:00:00+00:00')`,
		`INSERT INTO rooms(id,tenant_id,kind,created_by,created_at) VALUES('room','default','channel','human',1)`,
		`INSERT INTO meetings(id,tenant_id,room_id,organizer_sub,title,updated_at) VALUES('meeting','default','room','human','M',1)`,
		`INSERT INTO call_sessions(id,tenant_id,room_id,mode,epoch,livekit_room,started_by,started_at) VALUES('call','default','room','sfu_livekit',4,'old-media','human',1)`,
		`INSERT INTO call_seats(room_id,tenant_id,user_id,peer_id,session_hash,livekit_room,media_epoch,call_id) VALUES('room','default','human','human-peer','human-session','old-media',4,'call')`,
		`INSERT INTO call_seats(room_id,tenant_id,user_id,peer_id,session_hash,livekit_room,media_epoch,call_id) VALUES('room','default','guest','guest-peer','','old-media',4,'call')`,
		`INSERT INTO meeting_guest_sessions(secret_hash,guest_id,tenant_id,meeting_id,room_id,guest_key,display_name,status,knocked_at,decided_by,seen_at,expires_at) VALUES('old-secret','guest','default','meeting','room','key','Visitor','admitted',1,'human',1,9999999999999)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := migrations.Run(ctx, db, cfg.Driver); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			query string
			count int
		}{
			{`SELECT COUNT(*) FROM meeting_guest_sessions WHERE invite_hash=''`, 0},
			{`SELECT COUNT(*) FROM call_seats WHERE user_id='guest'`, 0},
			{`SELECT COUNT(*) FROM call_seats WHERE user_id='human' AND session_hash='human-session'`, 1},
			{`SELECT COUNT(*) FROM sessions WHERE token_hash='human-session' AND user_id='human'`, 1},
			{`SELECT COUNT(*) FROM pending_call_evictions WHERE tenant_id='default' AND livekit_room='old-media' AND user_id='guest' AND peer_id='guest-peer'`, 1},
			{`SELECT COUNT(*) FROM call_sessions WHERE id='call' AND epoch>4 AND livekit_room<>'old-media'`, 1},
		} {
			var got int
			if err := db.QueryRowContext(ctx, check.query).Scan(&got); err != nil || got != check.count {
				t.Fatalf("upgrade invariant %s=%d want%d: %v", check.query, got, check.count, err)
			}
		}
	}
}
