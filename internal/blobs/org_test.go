package blobs_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/blobs"
)

const (
	orgA = "00000000-0000-4000-8000-0000000000aa"
	orgB = "00000000-0000-4000-8000-0000000000bb"
	key  = "att_019a0000-0000-7000-8000-000000000001"
)

func read(t *testing.T, st *blobs.Store, tenant, k string) (string, error) {
	t.Helper()
	f, _, err := st.Open(tenant, k)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}

func TestOrgLayoutKeepsOrgsApart(t *testing.T) {
	dir := t.TempDir()
	st, err := blobs.NewOrgStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.RelocationDone()
	if _, err := st.Put(orgA, key, strings.NewReader("alpha"), 64); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "orgs", orgA, "att", key)); err != nil {
		t.Fatalf("blob not under its org prefix: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("org blob also written flat")
	}
	// The same key under another org is another object; org B never reads org A's bytes.
	if _, err := read(t, st, orgB, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("org B read org A's blob: %v", err)
	}
	if _, err := st.Put(orgB, key, strings.NewReader("beta"), 64); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(t, st, orgA, key); got != "alpha" {
		t.Fatalf("org A blob = %q", got)
	}
	// Bad org names never reach the filesystem.
	for _, bad := range []string{"", "../x", "a/b", "ORG", strings.Repeat("a", 65)} {
		if _, err := st.Put(bad, key, strings.NewReader("x"), 64); !errors.Is(err, blobs.ErrInvalidKey) {
			t.Errorf("Put(%q) = %v", bad, err)
		}
		if err := st.DeletePrefix(bad); !errors.Is(err, blobs.ErrInvalidKey) {
			t.Errorf("DeletePrefix(%q) = %v", bad, err)
		}
	}
	// The purge removes one org, orphans included.
	if err := os.WriteFile(filepath.Join(dir, "orgs", orgA, "att", "att_orphan_without_row"), []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePrefix(orgA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "orgs", orgA)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("org A prefix survived its purge")
	}
	if got, _ := read(t, st, orgB, key); got != "beta" {
		t.Fatal("org B lost a blob to org A's purge")
	}
}

func TestFlatStoreRefusesDeletePrefix(t *testing.T) {
	st, err := blobs.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePrefix(orgA); !errors.Is(err, blobs.ErrInvalidKey) {
		t.Fatalf("flat DeletePrefix = %v", err)
	}
}

// A multi install may hold blobs written flat before the org layout. Reads find them until the
// relocation moves them; a rerun is harmless.
func TestRelocationOfFlatBlobs(t *testing.T) {
	dir := t.TempDir()
	flat, err := blobs.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flat.Put(orgA, key, strings.NewReader("old"), 64); err != nil {
		t.Fatal(err)
	}
	st, err := blobs.NewOrgStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := read(t, st, orgA, key); err != nil || got != "old" {
		t.Fatalf("fallback read = %q %v", got, err)
	}
	for range 2 {
		if err := st.Relocate(orgA, key); err != nil {
			t.Fatal(err)
		}
	}
	st.RelocationDone()
	if got, err := read(t, st, orgA, key); err != nil || got != "old" {
		t.Fatalf("relocated read = %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("flat copy left behind")
	}
	// After the relocation a flat file is never served.
	if err := os.WriteFile(filepath.Join(dir, "att_019a0000-0000-7000-8000-000000000002"), []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t, st, orgA, "att_019a0000-0000-7000-8000-000000000002"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("flat fallback still on after RelocationDone")
	}
}

func TestStoreIDNamesTheSharedVolume(t *testing.T) {
	shared := t.TempDir()
	var recorded string
	claim := func(id string) (string, error) {
		if recorded == "" {
			recorded = id
		}
		return recorded, nil
	}
	for i := range 2 { // two replicas on one volume
		st, err := blobs.NewOrgStore(shared)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.EnsureStoreID(claim); err != nil {
			t.Fatalf("replica %d on the shared volume: %v", i, err)
		}
	}
	private, err := blobs.NewOrgStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := private.EnsureStoreID(claim); err == nil || !strings.Contains(err.Error(), "KY_ATTACHMENTS_DIR") {
		t.Fatalf("replica on a private disk: %v", err)
	}
}
