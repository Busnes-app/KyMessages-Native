package store

import (
	"context"
	"testing"

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
	insert := `INSERT INTO e2ee_to_device (tenant_id, recipient_user, recipient_device, sender_user, sender_device, type, content, created_at) VALUES ('t1', 'u-b', 'B1', 'u-a', 'A1', 'olm.v1', $1, 1)`

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
