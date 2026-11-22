package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/backup"
)

func TestMirrorAttachmentsIdempotentPrunesAndAuthenticates(t *testing.T) {
	cfg, _ := payloadConfig(t)
	attDir := filepath.Join(t.TempDir(), "att")
	cfg.Attachments.Dir = attDir
	cfg.Backup.Dir = filepath.Join(t.TempDir(), "bak")
	if err := os.MkdirAll(attDir, 0o700); err != nil {
		t.Fatal(err)
	}

	k1 := "att_019a0000-0000-7000-8000-000000000101"
	k2 := "att_019a0000-0000-7000-8000-000000000102"
	if err := os.WriteFile(filepath.Join(attDir, k1), []byte("first payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, k2), []byte("second payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// First run copies both blobs.
	res1, err := backup.MirrorAttachments(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first MirrorAttachments: %v", err)
	}
	if res1.Copied != 2 || res1.Skipped != 0 || res1.Pruned != 0 {
		t.Fatalf("first run = %+v, want copied=2 skipped=0 pruned=0", res1)
	}

	// Second run skips both already-mirrored blobs.
	res2, err := backup.MirrorAttachments(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second MirrorAttachments: %v", err)
	}
	if res2.Copied != 0 || res2.Skipped != 2 || res2.Pruned != 0 {
		t.Fatalf("second run = %+v, want copied=0 skipped=2 pruned=0", res2)
	}

	// Deleting k2 from live storage prunes k2.enc on the next mirror sync.
	if err := os.Remove(filepath.Join(attDir, k2)); err != nil {
		t.Fatal(err)
	}
	res3, err := backup.MirrorAttachments(context.Background(), cfg)
	if err != nil {
		t.Fatalf("third MirrorAttachments: %v", err)
	}
	if res3.Copied != 0 || res3.Skipped != 1 || res3.Pruned != 1 {
		t.Fatalf("third run = %+v, want copied=0 skipped=1 pruned=1", res3)
	}
	mirrorDir := backup.AttachmentMirrorDir(cfg)
	if _, err := os.Stat(filepath.Join(mirrorDir, k2+".enc")); !os.IsNotExist(err) {
		t.Fatal("deleted blob should be pruned from mirror")
	}

	key, err := backup.LoadAttachmentKey(cfg.Database.DataDir)
	if err != nil {
		t.Fatalf("LoadAttachmentKey: %v", err)
	}

	// Wrong key must fail restore.
	wrongKey := bytes.Repeat([]byte{0x42}, 32)
	if _, err := backup.RestoreAttachments(mirrorDir, t.TempDir(), wrongKey); err == nil {
		t.Fatal("RestoreAttachments succeeded with wrong key")
	}

	// Renaming ciphertext to a different key must fail AAD verification.
	swappedDir := t.TempDir()
	encData, err := os.ReadFile(filepath.Join(mirrorDir, k1+".enc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(swappedDir, k2+".enc"), encData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestoreAttachments(swappedDir, t.TempDir(), key); err == nil {
		t.Fatal("RestoreAttachments succeeded with renamed blob key (AAD mismatch)")
	}

	// Bit-flipping ciphertext must fail GCM authentication.
	tamperedDir := t.TempDir()
	tampered := append([]byte(nil), encData...)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(tamperedDir, k1+".enc"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestoreAttachments(tamperedDir, t.TempDir(), key); err == nil {
		t.Fatal("RestoreAttachments succeeded on tampered ciphertext")
	}
}
