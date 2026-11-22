package backup_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky_server_base/internal/backup"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// payloadConfig is a real SQLite store in a temp data dir: the collectors snapshot the live
// database, so there has to be one.
func payloadConfig(t *testing.T) (*config.Config, []byte) {
	t.Helper()
	cfg, _ := sqliteInstance(t)
	return cfg, cfg.Security.EncryptionKey
}

// The encryption key must ride in the capsule: users.totp_secret_enc is AES-GCM under it, so
// a restore without it hands the operator a database whose MFA secrets are gone for good.
func TestCollectCarriesTheEncryptionKey(t *testing.T) {
	cfg, key := payloadConfig(t)
	payload, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range payload.Files {
		if f.Path != "data/encryption.key" {
			continue
		}
		found = true
		if want := hex.EncodeToString(key) + "\n"; string(f.Data) != want {
			t.Errorf("content: got %q, want the lowercase hex keyfile reads", f.Data)
		}
		if f.Mode != 0600 {
			t.Errorf("mode: got %o, want 600", f.Mode)
		}
	}
	if !found {
		t.Fatal("payload has no data/encryption.key")
	}
	req, _ := payload.VerificationRecipe["required_files"].([]string)
	if !slices.Contains(req, "data/encryption.key") {
		t.Errorf("required_files: got %v, want data/encryption.key among them", req)
	}
}

// A restore must come back paired, not half-paired: recovery.pub is public and the capsule is
// sealed to that very key, so it rides along whenever the instance has one.
func TestCollectCarriesTheRecoveryPublicKeyWhenPaired(t *testing.T) {
	cfg, _ := payloadConfig(t)
	ctx := context.Background()

	unpaired, err := backup.Collect(ctx, cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if f := findFile(unpaired.Files, "data/recovery.pub"); f != nil {
		t.Error("unpaired instance shipped a recovery.pub")
	}
	if req, _ := unpaired.VerificationRecipe["required_files"].([]string); slices.Contains(req, "data/recovery.pub") {
		t.Errorf("unpaired required_files: got %v", req)
	}

	pubPath := recoveryclient.RecoveryKeyPath(cfg.Database.DataDir)
	if err := os.MkdirAll(filepath.Dir(pubPath), 0700); err != nil {
		t.Fatal(err)
	}
	pub := []byte("a-recovery-public-key")
	if err := os.WriteFile(pubPath, pub, 0600); err != nil {
		t.Fatal(err)
	}
	paired, err := backup.Collect(ctx, cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	f := findFile(paired.Files, "data/recovery.pub")
	if f == nil {
		t.Fatal("paired instance has no data/recovery.pub in the payload")
	}
	if string(f.Data) != string(pub) {
		t.Error("data/recovery.pub is not the pinned public key byte for byte")
	}
	if f.Mode != 0600 {
		t.Errorf("mode: got %o, want 600", f.Mode)
	}
	if req, _ := paired.VerificationRecipe["required_files"].([]string); !slices.Contains(req, "data/recovery.pub") {
		t.Errorf("required_files: got %v, want data/recovery.pub among them", req)
	}
}

func findFile(files []recoveryclient.File, path string) *recoveryclient.File {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}

func TestCollectRefusesAShortKey(t *testing.T) {
	cfg, _ := payloadConfig(t)
	cfg.Security.EncryptionKey = cfg.Security.EncryptionKey[:16]
	if _, err := backup.Collect(context.Background(), cfg, "1.0.0"); err == nil {
		t.Fatal("a 16-byte encryption key was accepted")
	}
}

// The store runs in WAL mode, so a plain read of the main file misses every commit still in
// the -wal. The snapshot must carry a row committed moments ago and never checkpointed.
func TestSnapshotSeesUncheckpointedCommit(t *testing.T) {
	cfg, st := sqliteInstance(t)
	ctx := context.Background()
	if err := st.Settings().SetSetting(ctx, "canary", "still-in-the-wal"); err != nil {
		t.Fatal(err)
	}
	payload, err := backup.Collect(ctx, cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	f := findFile(payload.Files, "data/ky_server.db")
	if f == nil {
		t.Fatal("no data/ky_server.db in the payload")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, f.Data, 0600); err != nil {
		t.Fatal(err)
	}
	copyStore, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: restored})
	if err != nil {
		t.Fatalf("snapshot does not open: %v", err)
	}
	defer copyStore.Close()
	if got, err := copyStore.Settings().GetSetting(ctx, "canary"); err != nil || got != "still-in-the-wal" {
		t.Fatalf("snapshot lacks the uncheckpointed row: %q, %v", got, err)
	}
	if check, _ := payload.VerificationRecipe["check_sqlite_integrity"].(bool); !check {
		t.Error("recipe does not ask the drill to check the database")
	}
}

// A driver the collectors cannot snapshot must refuse, not seal a keys-and-config capsule
// that a receipt would then call a backup.
func TestCollectRefusesADriverItCannotSnapshot(t *testing.T) {
	cfg, _ := payloadConfig(t)
	cfg.Database.Driver = "postgres"
	if _, err := backup.Collect(context.Background(), cfg, "1.0.0"); !errors.Is(err, backup.ErrNoDatabaseSnapshot) {
		t.Fatalf("got %v, want ErrNoDatabaseSnapshot", err)
	}
}

// A run that died mid-snapshot leaves a plaintext copy of the database behind; the next
// collection, under the backup lock, removes it before making its own.
func TestCollectSweepsStaleSnapshots(t *testing.T) {
	cfg, _ := payloadConfig(t)
	stale := filepath.Join(cfg.Database.DataDir, "snapshot-123")
	if err := os.MkdirAll(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "ky_server.db"), []byte("plaintext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Collect(context.Background(), cfg, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cfg.Database.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "snapshot-") {
			t.Errorf("snapshot left behind: %s", e.Name())
		}
	}
}

func TestCollectCarriesAttachmentBlobs(t *testing.T) {
	cfg, _ := payloadConfig(t)
	attDir := filepath.Join(cfg.Database.DataDir, "attachments")
	if err := os.MkdirAll(attDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantKey := "att_019a0000-0000-7000-8000-000000000001"
	wantBytes := []byte("hello attachment backup payload")
	if err := os.WriteFile(filepath.Join(attDir, wantKey), wantBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// Temp and empty files must be skipped so restore drills never fail on zero-byte files.
	if err := os.WriteFile(filepath.Join(attDir, ".upload-inprogress"), []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "att_019a0000-0000-7000-8000-000000000002"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantRel := "data/attachments/" + wantKey
	f := findFile(payload.Files, wantRel)
	if f == nil {
		t.Fatalf("payload missing %s", wantRel)
	}
	if string(f.Data) != string(wantBytes) {
		t.Errorf("blob data mismatch: got %q, want %q", f.Data, wantBytes)
	}
	if f.Mode != 0600 {
		t.Errorf("blob mode = %o, want 600", f.Mode)
	}
	if findFile(payload.Files, "data/attachments/.upload-inprogress") != nil {
		t.Error("temp upload file should not be packed into capsule")
	}
	if findFile(payload.Files, "data/attachments/att_019a0000-0000-7000-8000-000000000002") != nil {
		t.Error("empty file should not be packed into capsule")
	}
	req, _ := payload.VerificationRecipe["required_files"].([]string)
	if !slices.Contains(req, wantRel) {
		t.Errorf("required_files missing %s: %v", wantRel, req)
	}
	if !slices.Contains(backup.Members(cfg), "data/attachments/") {
		t.Errorf("backup.Members missing data/attachments/: %v", backup.Members(cfg))
	}
}
