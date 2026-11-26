package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestChatUploadCommitWaitsForSweepClaim(t *testing.T) {
	cfg := testdb.Config(t)
	if cfg.Driver != "postgres" {
		t.Skip("requires PostgreSQL row locks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	st := opened.(*SQLStore)
	chat := st.Chat()
	room := &Room{Kind: RoomKindChannel, Name: "uploads", CreatedBy: "uploader"}
	if err := chat.CreateRoom(ctx, room, nil); err != nil {
		t.Fatal(err)
	}
	const key = "att_sweep_claim"
	if err := chat.QueueUploadIntent(ctx, DefaultTenantID, key, 0); err != nil {
		t.Fatal(err)
	}

	// Hold open the same row update the sweep makes. Wait for the upload's DELETE
	// to block on it before letting the sweep commit.
	sweep, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sweep.Rollback()
	var sweepPID int
	if err := sweep.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&sweepPID); err != nil {
		t.Fatal(err)
	}
	if _, err := sweep.ExecContext(ctx, `UPDATE pending_blob_deletes SET user_id = $1 WHERE tenant_id = $2 AND blob_key = $3`, blobDeleteClaimed, DefaultTenantID, key); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- chat.CommitAttachmentWithQuota(ctx, "", &Attachment{
			ID: key, RoomID: room.ID, UploaderID: "uploader", Filename: "encrypted.bin",
			MimeType: "application/octet-stream", SizeBytes: 1, SHA256Hex: "hash",
		}, AttachmentQuotaLimits{})
	}()
	for {
		var blocked bool
		if err := st.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, sweepPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("commit finished before sweep released the intent: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := sweep.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrAttachmentInvalid) {
			t.Fatalf("commit after sweep claim = %v, want ErrAttachmentInvalid", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := chat.GetAttachment(ctx, DefaultTenantID, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attachment after sweep claim = %v, want ErrNotFound", err)
	}
}
