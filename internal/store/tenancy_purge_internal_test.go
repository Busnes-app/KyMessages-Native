package store

import (
	"context"
	"errors"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
	"testing"
)

func TestOrgPurgeClearsEveryErasureWorkflowTable(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	s := opened.(*SQLStore)
	const target = "00000000-0000-4000-8000-0000000000f1"
	const other = "00000000-0000-4000-8000-0000000000f2"
	for _, org := range []string{target, other} {
		if _, err := s.Chat().EnsureTenant(ctx, org); err != nil {
			t.Fatal(err)
		}
		owner, bot := org+"-owner", org+"-bot"
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rooms(id,tenant_id,kind,created_by,created_at) VALUES (?,?,'channel',?,123)`, []any{org + "-room", org, owner}},
			{`INSERT INTO call_sessions(id,tenant_id,room_id,mode,epoch,started_by,started_at) VALUES (?,?,?,'p2p_mesh',1,?,123)`, []any{org + "-call", org, org + "-room", owner}},
			{`INSERT INTO call_room_owners(room_id,tenant_id,holder,generation,expires_at) VALUES (?,?,'holder',1,123)`, []any{org + "-room", org}},
			{`INSERT INTO call_seats(room_id,tenant_id,user_id,peer_id,call_id) VALUES (?,?,?,?,?)`, []any{org + "-room", org, owner, org + "-peer", org + "-call"}},
			{`INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id) VALUES (?,'retired-media',?,?)`, []any{org, org + "-peer", owner}},
			{`INSERT INTO user_subjects(provider,subject,user_id,org_id) VALUES ('kyidentity',?,?,?)`, []any{org + "-subject", owner, org}},
			{`INSERT INTO user_erasure_state(user_id,tenant_id,completed_at) VALUES (?,?,123)`, []any{owner, org}},
			{`INSERT INTO pending_blob_deletes(user_id,tenant_id,blob_key) VALUES (?,?,?)`, []any{owner, org, org + "-blob"}},
			{`INSERT INTO user_erasure_actors(owner_user_id,tenant_id,user_id) VALUES (?,?,?)`, []any{owner, org, owner}},
			{`INSERT INTO user_erasure_actors(owner_user_id,tenant_id,user_id) VALUES (?,?,?)`, []any{owner, org, bot}},
		} {
			if _, err := s.db.ExecContext(ctx, s.rebind(q.sql), q.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.Chat().ApplyTenantLifecycle(ctx, target, TenantStatusDeleted, 1); err != nil {
		t.Fatal(err)
	}
	// These are prior-erasure records: no account/agent row remains from which to discover them.
	// Assert the whole explicit inventory after the terminal mark and again after replay.
	for replay := range 2 {
		if err := s.Chat().PurgeTenantRows(ctx, target); err != nil {
			t.Fatal(err)
		}
		if replay == 0 {
			if err := s.Chat().MarkTenantPurged(ctx, target); !errors.Is(err, ErrCallCleanupPending) {
				t.Fatalf("purge hid pending SFU work: %v", err)
			}
			pending, err := s.Chat().PendingCallEvictions(ctx, target, "", 10)
			if err != nil || len(pending) != 1 {
				t.Fatalf("pending cleanup: %+v %v", pending, err)
			}
			if err := s.Chat().ClearCallEviction(ctx, pending[0]); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Chat().MarkTenantPurged(ctx, target); err != nil {
			t.Fatal(err)
		}
		pending, err := s.Chat().DeletedUnpurgedTenants(ctx)
		if err != nil || len(pending) != 0 {
			t.Fatalf("purge did not complete: %v %v", pending, err)
		}
		for _, table := range []struct {
			name, column string
			otherCount   int
		}{
			{"call_room_owners", "tenant_id", 1},
			{"call_seats", "tenant_id", 1},
			{"pending_call_evictions", "tenant_id", 1},
			{"user_subjects", "org_id", 1},
			{"pending_blob_deletes", "tenant_id", 1},
			{"user_erasure_state", "tenant_id", 1},
			{"user_erasure_actors", "tenant_id", 2},
		} {
			for _, check := range []struct {
				org  string
				want int
			}{{target, 0}, {other, table.otherCount}} {
				var count int
				if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(*) FROM "+table.name+" WHERE "+table.column+" = ?"), check.org).Scan(&count); err != nil || count != check.want {
					t.Fatalf("%s org %s: count=%d want=%d err=%v", table.name, check.org, count, check.want, err)
				}
			}
		}
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 10, "tenancy.org_purged"); err != nil || n != 1 {
		t.Fatalf("completion audit: %d %v", n, err)
	}
	if got, err := s.Chat().GetTenant(ctx, target); err != nil || got.Status != TenantStatusDeleted {
		t.Fatalf("terminal org tombstone lost: %+v %v", got, err)
	}
}
