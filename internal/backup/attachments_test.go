package backup_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// Before any capsule carries a key, the mirror mints none and writes nothing.
	res0, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0, backup.DefaultMirrorPruneRetention)
	if err != nil || !res0.KeyMissing || res0.Copied != 0 {
		t.Fatalf("keyless mirror = (%+v, %v), want KeyMissing and nothing copied", res0, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments.key")); !os.IsNotExist(err) {
		t.Fatalf("mirror created the key: %v", err)
	}
	// The next capsule creates the key and seals it.
	payload, err := backup.Collect(context.Background(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := backup.LoadAttachmentKey(cfg.Database.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := false
	for _, f := range payload.Files {
		sealed = sealed || f.Path == backup.AttachmentKeyPath && strings.TrimSpace(string(f.Data)) == hex.EncodeToString(key)
	}
	if !sealed {
		t.Fatal("the capsule does not carry the attachment key the mirror uses")
	}

	// First run copies both blobs.
	res1, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0, backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("first MirrorAttachments: %v", err)
	}
	if res1.Copied != 2 || res1.Skipped != 0 || res1.Pruned != 0 {
		t.Fatalf("first run = %+v, want copied=2 skipped=0 pruned=0", res1)
	}

	// Second run skips both already-mirrored blobs.
	res2, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0.Add(time.Minute), backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("second MirrorAttachments: %v", err)
	}
	if res2.Copied != 0 || res2.Skipped != 2 || res2.Pruned != 0 {
		t.Fatalf("second run = %+v, want copied=0 skipped=2 pruned=0", res2)
	}

	// Deleting k2 from live storage moves k2.enc into .pruned/ for the retention window.
	if err := os.Remove(filepath.Join(attDir, k2)); err != nil {
		t.Fatal(err)
	}
	res3, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0.Add(2*time.Minute), backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("third MirrorAttachments: %v", err)
	}
	if res3.Copied != 0 || res3.Skipped != 1 || res3.Pruned != 1 || res3.Expired != 0 {
		t.Fatalf("third run = %+v, want copied=0 skipped=1 pruned=1 expired=0", res3)
	}
	mirrorDir := backup.AttachmentMirrorDir(cfg)
	if _, err := os.Stat(filepath.Join(mirrorDir, k2+".enc")); !os.IsNotExist(err) {
		t.Fatal("deleted blob should move out of active mirror directory")
	}
	prunedPath := filepath.Join(mirrorDir, backup.AttachmentMirrorPrunedDirName, k2+".enc")
	if _, err := os.Stat(prunedPath); err != nil {
		t.Fatalf("soft-pruned blob should remain in %s during retention window: %v", backup.AttachmentMirrorPrunedDirName, err)
	}

	key, err = backup.LoadAttachmentKey(cfg.Database.DataDir)
	if err != nil {
		t.Fatalf("LoadAttachmentKey: %v", err)
	}

	// Within the retention window, RestoreAttachments on the top-level mirror recovers both
	// active blobs and soft-pruned blobs from .pruned/ without overwriting active blobs.
	restoredAll := t.TempDir()
	n, err := backup.RestoreAttachments(mirrorDir, restoredAll, key)
	if err != nil || n != 2 {
		t.Fatalf("RestoreAttachments(mirrorDir) = (%d, %v), want (2, nil)", n, err)
	}
	gotK1, err := os.ReadFile(filepath.Join(restoredAll, k1))
	if err != nil || string(gotK1) != "first payload" {
		t.Fatalf("restored active blob = %q (%v), want %q", string(gotK1), err, "first payload")
	}
	gotK2, err := os.ReadFile(filepath.Join(restoredAll, k2))
	if err != nil || string(gotK2) != "second payload" {
		t.Fatalf("restored pruned blob = %q (%v), want %q", string(gotK2), err, "second payload")
	}

	// A stale duplicate in .pruned/ must never overwrite an active top-level blob.
	if err := os.WriteFile(filepath.Join(mirrorDir, backup.AttachmentMirrorPrunedDirName, k1+".enc"), []byte("corrupt-stale-pruned"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoredPrecedence := t.TempDir()
	n, err = backup.RestoreAttachments(mirrorDir, restoredPrecedence, key)
	if err != nil || n != 2 {
		t.Fatalf("RestoreAttachments(mirrorDir with duplicate .pruned) = (%d, %v), want (2, nil)", n, err)
	}
	gotK1, err = os.ReadFile(filepath.Join(restoredPrecedence, k1))
	if err != nil || string(gotK1) != "first payload" {
		t.Fatalf("active blob overwritten by .pruned duplicate: %q (%v)", string(gotK1), err)
	}
	_ = os.Remove(filepath.Join(mirrorDir, backup.AttachmentMirrorPrunedDirName, k1+".enc"))

	// After the retention window elapses, k2.enc is permanently expired.
	res4, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0.Add(2*time.Minute+backup.DefaultMirrorPruneRetention), backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("fourth MirrorAttachments: %v", err)
	}
	if res4.Expired != 1 {
		t.Fatalf("fourth run = %+v, want expired=1", res4)
	}
	if _, err := os.Stat(prunedPath); !os.IsNotExist(err) {
		t.Fatal("expired soft-pruned blob should be removed after retention window")
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

func TestMirrorAttachmentsRefusesWipeWhenSourceEmptyAndRetainsPruned(t *testing.T) {
	cfg, _ := payloadConfig(t)
	attDir := filepath.Join(t.TempDir(), "att")
	cfg.Attachments.Dir = attDir
	cfg.Backup.Dir = filepath.Join(t.TempDir(), "bak")
	if err := os.MkdirAll(attDir, 0o700); err != nil {
		t.Fatal(err)
	}

	k1 := "att_019a0000-0000-7000-8000-000000000201"
	k2 := "att_019a0000-0000-7000-8000-000000000202"
	if err := os.WriteFile(filepath.Join(attDir, k1), []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, k2), []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}

	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if _, err := backup.EnsureAttachmentKey(cfg.Database.DataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0, backup.DefaultMirrorPruneRetention); err != nil {
		t.Fatalf("initial mirror: %v", err)
	}

	// Simulate starting the server after a DB restore before running restore-attachments:
	// the live attachments directory exists, is empty, and a scheduled backup runs.
	if err := os.Remove(filepath.Join(attDir, k1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(attDir, k2)); err != nil {
		t.Fatal(err)
	}

	res, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0.Add(time.Hour), backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("empty-source mirror: %v", err)
	}
	if !res.PruneSkipped || res.MirrorBlobs != 2 || res.Pruned != 0 {
		t.Fatalf("empty-source mirror = %+v, want PruneSkipped=true MirrorBlobs=2 Pruned=0", res)
	}

	mirrorDir := backup.AttachmentMirrorDir(cfg)
	key, err := backup.LoadAttachmentKey(cfg.Database.DataDir)
	if err != nil {
		t.Fatalf("LoadAttachmentKey: %v", err)
	}
	restoredDir := t.TempDir()
	n, err := backup.RestoreAttachments(mirrorDir, restoredDir, key)
	if err != nil || n != 2 {
		t.Fatalf("RestoreAttachments after empty-source backup = (%d, %v), want (2, nil)", n, err)
	}

	// Even if one new blob is uploaded before restore-attachments runs, existing blobs are
	// soft-pruned into .pruned/ (not destroyed) and the standard restore-attachments command
	// on the top-level mirror recovers both active and retained .pruned/ blobs.
	k3 := "att_019a0000-0000-7000-8000-000000000203"
	if err := os.WriteFile(filepath.Join(attDir, k3), []byte("gamma"), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := backup.MirrorAttachmentsAt(context.Background(), cfg, t0.Add(2*time.Hour), backup.DefaultMirrorPruneRetention)
	if err != nil {
		t.Fatalf("mirror after single upload: %v", err)
	}
	if res2.Copied != 1 || res2.Pruned != 2 || res2.Expired != 0 {
		t.Fatalf("mirror after single upload = %+v, want copied=1 pruned=2 expired=0", res2)
	}
	recovered := t.TempDir()
	n, err = backup.RestoreAttachments(mirrorDir, recovered, key)
	if err != nil || n != 3 {
		t.Fatalf("RestoreAttachments(mirrorDir) = (%d, %v), want (3, nil)", n, err)
	}
	for k, want := range map[string]string{k1: "alpha", k2: "beta", k3: "gamma"} {
		got, err := os.ReadFile(filepath.Join(recovered, k))
		if err != nil || string(got) != want {
			t.Fatalf("recovered %s = %q (%v), want %q", k, string(got), err, want)
		}
	}

	// Restoring into a live directory that already has a blob matching a .pruned key
	// preserves the existing live file rather than overwriting it from .pruned.
	prePopulated := t.TempDir()
	if err := os.WriteFile(filepath.Join(prePopulated, k1), []byte("live-k1"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err = backup.RestoreAttachments(mirrorDir, prePopulated, key)
	if err != nil || n != 2 {
		t.Fatalf("RestoreAttachments(prePopulated) = (%d, %v), want (2, nil)", n, err)
	}
	if got, err := os.ReadFile(filepath.Join(prePopulated, k1)); err != nil || string(got) != "live-k1" {
		t.Fatalf("pre-existing live blob overwritten by .pruned: %q (%v)", string(got), err)
	}

	// A symlinked .pruned directory must be rejected.
	symMirror := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(symMirror, backup.AttachmentMirrorPrunedDirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestoreAttachments(symMirror, t.TempDir(), key); err == nil {
		t.Fatal("RestoreAttachments accepted a symlinked .pruned directory")
	}
}
