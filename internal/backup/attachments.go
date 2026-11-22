package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/blobs"
	"github.com/Busnes-app/ky_server_base/internal/config"
)

// AttachmentKeyPath is the relative path inside a server capsule where the write-once
// attachment mirror key is stored, matching <DataDir>/attachments.key on disk.
const AttachmentKeyPath = "data/attachments.key"

// AttachmentMirrorPrunedDirName holds soft-pruned encrypted blobs inside the mirror directory
// for DefaultMirrorPruneRetention so an accidental wipe or out-of-order restore remains recoverable.
const AttachmentMirrorPrunedDirName = ".pruned"

// DefaultMirrorPruneRetention is how long unreferenced encrypted blobs stay in .pruned
// before being permanently deleted.
const DefaultMirrorPruneRetention = 7 * 24 * time.Hour

const (
	attachmentMirrorAADPrefix = "kymessages-attachments/v1\x00"
	attachmentNonceSize       = 12
	attachmentTagSize         = 16
)

// AttachmentMirrorResult summarizes a MirrorAttachments sync run.
type AttachmentMirrorResult struct {
	Copied       int
	Skipped      int
	Pruned       int
	Expired      int
	PruneSkipped bool
	MirrorBlobs  int
}

// EnsureAttachmentKey loads the 32-byte attachment mirror key from <dataDir>/attachments.key,
// or generates and persists a new write-once key (0600) if it does not yet exist.
func EnsureAttachmentKey(dataDir string) ([]byte, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("backup: data directory is required for attachment mirror key")
	}
	if key, err := LoadAttachmentKey(dataDir); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create data directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("backup: generate attachment mirror key: %w", err)
	}
	keyPath := filepath.Join(dataDir, "attachments.key")
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadAttachmentKey(dataDir)
		}
		return nil, fmt.Errorf("backup: create attachment mirror key: %w", err)
	}
	encoded := hex.EncodeToString(key) + "\n"
	if _, err := f.WriteString(encoded); err != nil {
		_ = f.Close()
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("backup: write attachment mirror key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("backup: sync attachment mirror key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("backup: close attachment mirror key: %w", err)
	}
	return key, nil
}

// LoadAttachmentKey reads and validates the 32-byte hex key at <dataDir>/attachments.key.
func LoadAttachmentKey(dataDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "attachments.key"))
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("backup: invalid attachment mirror key")
	}
	return key, nil
}

// AttachmentMirrorDir returns the encrypted attachment mirror directory under KY_BACKUP_DIR,
// or "" when local backups are not configured.
func AttachmentMirrorDir(cfg *config.Config) string {
	dir := strings.TrimSpace(cfg.Backup.Dir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "attachments")
}

// MirrorAttachments synchronizes regular attachment blobs from cfg.Attachments.Dir into an
// AES-256-GCM encrypted mirror at <KY_BACKUP_DIR>/attachments. Blobs are encrypted one at a
// time with the write-once attachment key and never consume the server capsule budget.
//
// Pruning refuses to run when the live directory is empty while the mirror still holds
// encrypted blobs (protecting against out-of-order restores or an unmounted volume), and
// unreferenced mirror blobs are moved to .pruned/ for DefaultMirrorPruneRetention before
// permanent deletion.
func MirrorAttachments(ctx context.Context, cfg *config.Config) (AttachmentMirrorResult, error) {
	return MirrorAttachmentsAt(ctx, cfg, time.Now(), DefaultMirrorPruneRetention)
}

// MirrorAttachmentsAt is the time- and retention-parameterized implementation of MirrorAttachments.
func MirrorAttachmentsAt(ctx context.Context, cfg *config.Config, now time.Time, retention time.Duration) (AttachmentMirrorResult, error) {
	var res AttachmentMirrorResult
	mirrorDir := AttachmentMirrorDir(cfg)
	if mirrorDir == "" {
		return res, nil
	}

	srcDir := attachmentsDir(cfg)
	srcEntries, err := os.ReadDir(srcDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("backup: read attachments directory: %w", err)
	}

	srcBlobs := make(map[string]int64)
	for _, entry := range srcEntries {
		name := entry.Name()
		if !blobs.ValidKey(name) || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			continue
		}
		srcBlobs[name] = info.Size()
	}

	if len(srcBlobs) == 0 {
		existing, err := os.ReadDir(mirrorDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return res, nil
			}
			return res, fmt.Errorf("backup: read attachment mirror directory: %w", err)
		}
		mirrorRoot, err := os.OpenRoot(mirrorDir)
		if err != nil {
			return res, fmt.Errorf("backup: open attachment mirror root: %w", err)
		}
		defer mirrorRoot.Close()

		mirrorCount := 0
		for _, e := range existing {
			name := e.Name()
			if strings.HasPrefix(name, ".tmp-") && e.Type().IsRegular() {
				_ = mirrorRoot.Remove(name)
				continue
			}
			if strings.HasSuffix(name, ".enc") && e.Type().IsRegular() && blobs.ValidKey(strings.TrimSuffix(name, ".enc")) {
				mirrorCount++
			}
		}
		if mirrorCount > 0 {
			// Guard against catastrophic mirror wipe when the live attachments directory is empty
			// (for example, starting the server after a DB restore before running restore-attachments,
			// or a mis-mounted volume). Never prune or expire in this state.
			res.PruneSkipped = true
			res.MirrorBlobs = mirrorCount
			return res, nil
		}
		res.Expired = expirePrunedAttachments(ctx, mirrorDir, mirrorRoot, now, retention)
		return res, nil
	}

	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return res, fmt.Errorf("backup: create attachment mirror directory: %w", err)
	}
	mirrorRoot, err := os.OpenRoot(mirrorDir)
	if err != nil {
		return res, fmt.Errorf("backup: open attachment mirror root: %w", err)
	}
	defer mirrorRoot.Close()

	// Clean any interrupted temp files from an earlier crashed run.
	if existing, err := os.ReadDir(mirrorDir); err == nil {
		for _, e := range existing {
			if strings.HasPrefix(e.Name(), ".tmp-") && e.Type().IsRegular() {
				_ = mirrorRoot.Remove(e.Name())
			}
		}
	}

	key, err := EnsureAttachmentKey(cfg.Database.DataDir)
	if err != nil {
		return res, err
	}
	gcm, err := newAttachmentGCM(key)
	if err != nil {
		return res, err
	}
	srcRoot, err := os.OpenRoot(srcDir)
	if err != nil {
		return res, fmt.Errorf("backup: open attachments root: %w", err)
	}
	defer srcRoot.Close()

	for name, srcSize := range srcBlobs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		encName := name + ".enc"
		// If this blob was previously soft-pruned and later reappeared (e.g. after restore),
		// remove the stale duplicate from .pruned/.
		_ = mirrorRoot.Remove(filepath.Join(AttachmentMirrorPrunedDirName, encName))

		expectedSize := srcSize + attachmentNonceSize + attachmentTagSize
		if info, err := mirrorRoot.Stat(encName); err == nil && info.Mode().IsRegular() && info.Size() == expectedSize {
			res.Skipped++
			continue
		}

		plain, err := srcRoot.ReadFile(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Deleted concurrently between ReadDir and ReadFile.
				continue
			}
			return res, fmt.Errorf("backup: read attachment %s: %w", name, err)
		}
		if len(plain) == 0 {
			continue
		}
		sealed, err := sealAttachmentBlob(gcm, name, plain)
		if err != nil {
			return res, fmt.Errorf("backup: encrypt attachment %s: %w", name, err)
		}
		if err := writeFileAtomicRoot(mirrorRoot, encName, sealed); err != nil {
			return res, fmt.Errorf("backup: write mirrored attachment %s: %w", name, err)
		}
		res.Copied++
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}
	if existing, err := os.ReadDir(mirrorDir); err == nil {
		prunedDirReady := false
		for _, e := range existing {
			name := e.Name()
			if !strings.HasSuffix(name, ".enc") || !e.Type().IsRegular() {
				continue
			}
			keyName := strings.TrimSuffix(name, ".enc")
			if !blobs.ValidKey(keyName) {
				continue
			}
			if _, ok := srcBlobs[keyName]; ok {
				continue
			}
			if retention > 0 {
				if !prunedDirReady {
					if err := mirrorRoot.Mkdir(AttachmentMirrorPrunedDirName, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
						return res, fmt.Errorf("backup: create pruned mirror directory: %w", err)
					}
					prunedDirReady = true
				}
				prunedRel := filepath.Join(AttachmentMirrorPrunedDirName, name)
				if err := mirrorRoot.Rename(name, prunedRel); err == nil {
					_ = mirrorRoot.Chtimes(prunedRel, now, now)
					res.Pruned++
				}
			} else if err := mirrorRoot.Remove(name); err == nil {
				res.Pruned++
			}
		}
	}
	res.Expired = expirePrunedAttachments(ctx, mirrorDir, mirrorRoot, now, retention)
	return res, nil
}

func expirePrunedAttachments(ctx context.Context, mirrorDir string, mirrorRoot *os.Root, now time.Time, retention time.Duration) int {
	if retention <= 0 {
		return 0
	}
	prunedPath := filepath.Join(mirrorDir, AttachmentMirrorPrunedDirName)
	entries, err := os.ReadDir(prunedPath)
	if err != nil {
		return 0
	}
	expired := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".enc") || !e.Type().IsRegular() {
			continue
		}
		if !blobs.ValidKey(strings.TrimSuffix(name, ".enc")) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if now.Sub(info.ModTime()) >= retention {
			if err := mirrorRoot.Remove(filepath.Join(AttachmentMirrorPrunedDirName, name)); err == nil {
				expired++
			}
		}
	}
	return expired
}

// RestoreAttachments decrypts all mirrored attachment blobs from mirrorDir using the 32-byte
// key (restored from data/attachments.key) into targetDir (the deployment's KY_ATTACHMENTS_DIR).
func RestoreAttachments(mirrorDir, targetDir string, key []byte) (int, error) {
	gcm, err := newAttachmentGCM(key)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(mirrorDir)
	if err != nil {
		return 0, fmt.Errorf("backup: read attachment mirror: %w", err)
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return 0, fmt.Errorf("backup: create restore attachments directory: %w", err)
	}
	mirrorRoot, err := os.OpenRoot(mirrorDir)
	if err != nil {
		return 0, fmt.Errorf("backup: open attachment mirror root: %w", err)
	}
	defer mirrorRoot.Close()

	targetRoot, err := os.OpenRoot(targetDir)
	if err != nil {
		return 0, fmt.Errorf("backup: open restore attachments root: %w", err)
	}
	defer targetRoot.Close()

	restored := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".enc") || !entry.Type().IsRegular() {
			continue
		}
		blobKey := strings.TrimSuffix(name, ".enc")
		if !blobs.ValidKey(blobKey) {
			continue
		}
		sealed, err := mirrorRoot.ReadFile(name)
		if err != nil {
			return restored, fmt.Errorf("backup: read mirrored blob %s: %w", blobKey, err)
		}
		plain, err := openAttachmentBlob(gcm, blobKey, sealed)
		if err != nil {
			return restored, fmt.Errorf("backup: decrypt mirrored blob %s: %w", blobKey, err)
		}
		if err := writeFileAtomicRoot(targetRoot, blobKey, plain); err != nil {
			return restored, fmt.Errorf("backup: restore blob %s: %w", blobKey, err)
		}
		restored++
	}
	return restored, nil
}

func newAttachmentGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("backup: attachment mirror key is %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealAttachmentBlob(gcm cipher.AEAD, blobKey string, plain []byte) ([]byte, error) {
	nonce := make([]byte, attachmentNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := []byte(attachmentMirrorAADPrefix + blobKey)
	out := make([]byte, attachmentNonceSize, attachmentNonceSize+len(plain)+attachmentTagSize)
	copy(out, nonce)
	return gcm.Seal(out, nonce, plain, aad), nil
}

func openAttachmentBlob(gcm cipher.AEAD, blobKey string, sealed []byte) ([]byte, error) {
	if len(sealed) <= attachmentNonceSize+attachmentTagSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := sealed[:attachmentNonceSize]
	ciphertext := sealed[attachmentNonceSize:]
	aad := []byte(attachmentMirrorAADPrefix + blobKey)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func writeFileAtomicRoot(root *os.Root, targetName string, data []byte) error {
	var suffix [8]byte
	if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
		return err
	}
	tmpName := ".tmp-" + hex.EncodeToString(suffix[:])
	f, err := root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = f.Close()
		_ = root.Remove(tmpName)
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmpName)
		return err
	}
	if err := root.Rename(tmpName, targetName); err != nil {
		_ = root.Remove(tmpName)
		return err
	}
	return nil
}

func hasAttachmentBlobs(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if blobs.ValidKey(entry.Name()) && entry.Type().IsRegular() {
			if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
				return true
			}
		}
	}
	return false
}

func attachmentKeyNeeded(cfg *config.Config) bool {
	if _, err := os.Stat(filepath.Join(cfg.Database.DataDir, "attachments.key")); err == nil {
		return true
	}
	return hasAttachmentBlobs(attachmentsDir(cfg))
}
