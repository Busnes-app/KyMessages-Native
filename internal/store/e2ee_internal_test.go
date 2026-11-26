package store

import (
	"context"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

// On PostgreSQL a message can commit after one with a higher ID. The recipient must still get
// it: an ack names only what was read, and a fetch has no cursor that could skip it.
func TestE2EEMailCommittedOutOfIDOrderIsDelivered(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	if cfg.Driver != "postgres" {
		t.Skip("SQLite serializes writers; IDs always commit in order")
	}
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	st := opened.(*SQLStore)
	for _, u := range []string{"u-a", "u-b"} {
		if err := st.Users().CreateUser(ctx, &User{ID: u, Username: u, Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []E2EEDevice{{TenantID: "t1", UserID: "u-a", DeviceID: "A1", Curve25519: "c", Ed25519: "e", Signature: "s"}, {TenantID: "t1", UserID: "u-b", DeviceID: "B1", Curve25519: "c2", Ed25519: "e2", Signature: "s2"}} {
		if err := st.E2EE().UpsertDevice(ctx, &d); err != nil {
			t.Fatal(err)
		}
	}
	insert := `INSERT INTO e2ee_to_device (tenant_id, recipient_user, recipient_device, sender_user, sender_device, sender_curve25519, sender_ed25519, sender_signature, type, content, created_at) VALUES ('t1', 'u-b', 'B1', 'u-a', 'A1', 'c', 'e', 's', 'olm.v1', $1, 1)`

	// Transaction A takes the lower ID and stays open; B takes the higher ID and commits first.
	txA, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txA.ExecContext(ctx, insert, "pre-key from A"); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().SendToDevice(ctx, []E2EEToDevice{{TenantID: "t1", RecipientUserID: "u-b", RecipientDeviceID: "B1", SenderUserID: "u-a", SenderDeviceID: "A1", Type: "olm.v1", Content: "room key from B"}}); err != nil {
		t.Fatal(err)
	}
	seen, err := st.E2EE().ToDevice(ctx, "u-b", "B1", 10)
	if err != nil || len(seen) != 1 || seen[0].Content != "room key from B" {
		t.Fatalf("first read = %+v %v", seen, err)
	}
	// A commits after the read but before the ack: an "up to ID" ack would delete it unseen.
	if err := txA.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().AckToDevice(ctx, "u-b", "B1", []int64{seen[0].ID}); err != nil {
		t.Fatal(err)
	}
	late, err := st.E2EE().ToDevice(ctx, "u-b", "B1", 10)
	if err != nil || len(late) != 1 || late[0].Content != "pre-key from A" || late[0].ID >= seen[0].ID {
		t.Fatalf("the lower-ID message committed late was lost: %+v %v", late, err)
	}
}

// A claim that finds every one-time key locked by another in-flight claim waits for it, rather
// than handing out the fallback key while a one-time key may still be free.
func TestE2EEClaimWaitsOutLockedKeysInsteadOfFallingBack(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	if cfg.Driver != "postgres" {
		t.Skip("SQLite serializes writers; no claim ever sees a locked key")
	}
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	st := opened.(*SQLStore)
	if err := st.Users().CreateUser(ctx, &User{ID: "u-a", Username: "u-a", Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().UpsertDevice(ctx, &E2EEDevice{TenantID: "t1", UserID: "u-a", DeviceID: "D1", Curve25519: "c", Ed25519: "e", Signature: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", []E2EEOneTimeKey{
		{KeyID: "k1", Key: "otk", Signature: "s"}, {KeyID: "fb", Key: "fallback", Signature: "s", Fallback: true},
	}, 100); err != nil {
		t.Fatal(err)
	}
	// Another claim holds the only one-time key's row lock for 100 ms, then gives up.
	holder, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(ctx, `SELECT 1 FROM e2ee_one_time_keys WHERE fallback = 0 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = holder.Rollback()
	}()
	k, err := st.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1")
	if err != nil || k.Fallback || k.Key != "otk" {
		t.Fatalf("claim during a held lock = %+v %v, want the one-time key once the lock is gone", k, err)
	}
}

// The key backup's key columns must compare bytewise on PostgreSQL whatever the database's
// default collation: the browser checks the page cursor bytewise.
func TestE2EEKeyBackupColumnsCollateC(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	if cfg.Driver != "postgres" {
		t.Skip("SQLite compares TEXT bytewise (BINARY) unless a column says otherwise")
	}
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	st := opened.(*SQLStore)
	rows, err := st.db.QueryContext(ctx, `SELECT column_name, COALESCE(collation_name, '') FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'e2ee_key_backup' AND column_name IN ('room_id', 'sender_key', 'session_id') ORDER BY column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var col, coll string
		if err := rows.Scan(&col, &coll); err != nil {
			t.Fatal(err)
		}
		got[col] = coll
	}
	if len(got) != 3 || got["room_id"] != "C" || got["sender_key"] != "C" || got["session_id"] != "C" {
		t.Fatalf("key backup collations %v, want C", got)
	}
}
