package backup_test

import (
	"bytes"
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

func TestCollectCarriesVAPIDKeyWhenPresent(t *testing.T) {
	cfg, _ := payloadConfig(t)
	ctx := context.Background()

	withoutKey, err := backup.Collect(ctx, cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if f := findFile(withoutKey.Files, "data/vapid.key"); f != nil {
		t.Error("expected no data/vapid.key before key exists")
	}

	vapidPath := filepath.Join(cfg.Database.DataDir, "vapid.key")
	want := []byte("vapid-test-key-material\n")
	if err := os.WriteFile(vapidPath, want, 0600); err != nil {
		t.Fatal(err)
	}

	withKey, err := backup.Collect(ctx, cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	f := findFile(withKey.Files, "data/vapid.key")
	if f == nil {
		t.Fatal("payload missing data/vapid.key")
	}
	if string(f.Data) != string(want) || f.Mode != 0600 {
		t.Fatalf("unexpected vapid.key entry: mode=%o len=%d", f.Mode, len(f.Data))
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

func TestCollectIsolatesAttachmentsFromCapsuleBudget(t *testing.T) {
	cfg, _ := payloadConfig(t)
	// Use a custom KY_ATTACHMENTS_DIR outside <DataDir>/attachments and a separate backup dir.
	attDir := filepath.Join(t.TempDir(), "custom-attachments")
	cfg.Attachments.Dir = attDir
	cfg.Backup.Dir = filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(attDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Baseline capsule size (SQLite DB + config + keys) without attachments.
	baseline, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatalf("baseline Collect: %v", err)
	}
	var baseBytes int64
	for _, f := range baseline.Files {
		baseBytes += int64(len(f.Data))
	}

	// Shrink capsule expand limit so it comfortably fits DB + config + 65-byte attachment key,
	// while staged attachment blobs far exceed the reduced capsule budget.
	reducedLimit := baseBytes + 16*1024
	defer backup.SetExpandLimitForTest(reducedLimit)()

	blob1Key := "att_019a0000-0000-7000-8000-000000000001"
	blob2Key := "att_019a0000-0000-7000-8000-000000000002"
	blob1 := bytes.Repeat([]byte("A"), int(reducedLimit))
	blob2 := bytes.Repeat([]byte("B"), int(reducedLimit))
	if err := os.WriteFile(filepath.Join(attDir, blob1Key), blob1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, blob2Key), blob2, 0o600); err != nil {
		t.Fatal(err)
	}
	// Temp and empty files must be ignored by both Collect and MirrorAttachments.
	if err := os.WriteFile(filepath.Join(attDir, ".upload-inprogress"), []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "att_019a0000-0000-7000-8000-000000000003"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Server database/config backup MUST succeed even though staged blobs exceed reducedLimit.
	payload, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatalf("Collect failed despite attachment isolation: %v", err)
	}
	if findFile(payload.Files, "data/ky_server.db") == nil {
		t.Fatal("payload missing data/ky_server.db")
	}
	if findFile(payload.Files, "config/settings.json") == nil {
		t.Fatal("payload missing config/settings.json")
	}
	keyFile := findFile(payload.Files, backup.AttachmentKeyPath)
	if keyFile == nil {
		t.Fatalf("payload missing %s", backup.AttachmentKeyPath)
	}
	if keyFile.Mode != 0600 {
		t.Errorf("attachment key mode = %o, want 600", keyFile.Mode)
	}
	for _, f := range payload.Files {
		if strings.HasPrefix(f.Path, "data/attachments/") {
			t.Errorf("attachment blob %s should not be packed into server capsule", f.Path)
		}
	}
	if !slices.Contains(backup.Members(cfg), backup.AttachmentKeyPath) {
		t.Errorf("backup.Members missing %s: %v", backup.AttachmentKeyPath, backup.Members(cfg))
	}

	// Blobs are preserved separately in the encrypted mirror.
	mres, err := backup.MirrorAttachments(context.Background(), cfg)
	if err != nil {
		t.Fatalf("MirrorAttachments: %v", err)
	}
	if mres.Copied != 2 || mres.Skipped != 0 || mres.Pruned != 0 {
		t.Fatalf("unexpected mirror result: %+v", mres)
	}
	mirrorDir := backup.AttachmentMirrorDir(cfg)
	encBytes, err := os.ReadFile(filepath.Join(mirrorDir, blob1Key+".enc"))
	if err != nil {
		t.Fatalf("read mirrored blob: %v", err)
	}
	if bytes.Contains(encBytes, bytes.Repeat([]byte("A"), 64)) {
		t.Fatal("mirrored attachment blob must be encrypted on disk, not plaintext")
	}
	if _, err := os.Stat(filepath.Join(mirrorDir, ".upload-inprogress.enc")); !os.IsNotExist(err) {
		t.Fatal("temp upload file must not be mirrored")
	}

	// Restore into a fresh custom target directory using the key recovered from the capsule.
	restoredDataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(restoredDataDir, "attachments.key"), keyFile.Data, 0o600); err != nil {
		t.Fatal(err)
	}
	restoredKey, err := backup.LoadAttachmentKey(restoredDataDir)
	if err != nil {
		t.Fatalf("LoadAttachmentKey: %v", err)
	}
	restoredAttDir := filepath.Join(t.TempDir(), "restored-attachments")
	count, err := backup.RestoreAttachments(mirrorDir, restoredAttDir, restoredKey)
	if err != nil {
		t.Fatalf("RestoreAttachments: %v", err)
	}
	if count != 2 {
		t.Fatalf("restored count = %d, want 2", count)
	}
	got1, err := os.ReadFile(filepath.Join(restoredAttDir, blob1Key))
	if err != nil || !bytes.Equal(got1, blob1) {
		t.Fatalf("restored blob1 mismatch: err=%v len=%d", err, len(got1))
	}
	got2, err := os.ReadFile(filepath.Join(restoredAttDir, blob2Key))
	if err != nil || !bytes.Equal(got2, blob2) {
		t.Fatalf("restored blob2 mismatch: err=%v len=%d", err, len(got2))
	}
}
