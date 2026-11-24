package backup_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/backup"
)

func TestRestoreLegacyAttachmentMirrorAfterCodecMove(t *testing.T) {
	// Fixed independent v1 fixture: key bytes 0..31, nonce bytes 0..11.
	const encrypted = "000102030405060708090a0b0c7b9b7eb696a37ce832b7e7d48e190efaf6e640841a3c1455028bf1c9c8345169d8aa4b8fe6e981cf606a82"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := hex.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	mirror, target := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(mirror, "att_legacy_fixture.enc"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := backup.RestoreAttachments(mirror, target, key)
	if err != nil || n != 1 {
		t.Fatalf("restore legacy file: %d %v", n, err)
	}
	got, err := os.ReadFile(filepath.Join(target, "att_legacy_fixture"))
	if err != nil || string(got) != "KyMessages legacy attachment" {
		t.Fatalf("restored bytes: %q %v", got, err)
	}
}
