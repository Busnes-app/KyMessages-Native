package blobs

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/ky-primitives/s3"
)

const objectOrgA = "00000000-0000-4000-8000-0000000000a1"
const objectOrgB = "00000000-0000-4000-8000-0000000000b1"

type fakeVersion struct {
	id     string
	body   []byte
	marker bool
}

// versionedBucket is a small in-memory versioned S3 bucket ("bucket", path style).
type versionedBucket struct {
	mu          sync.Mutex
	keys        map[string][]fakeVersion // oldest first
	seq, puts   int
	omitVersion bool
	nullVersion bool // versioning suspended: every write answers version "null"
	corrupt     bool
	substitute  map[string]string // GET of key serves another key
}

func (b *versionedBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/bucket"), "/")
	q := r.URL.Query()
	b.seq++
	id := "v" + strconv.Itoa(b.seq) + "/+opaque"
	if b.nullVersion {
		id = "null"
	}
	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("versions"):
		type entry struct {
			XMLName   xml.Name
			Key       string
			VersionId string
			IsLatest  bool
			Size      *int64 `xml:",omitempty"`
			ETag      string `xml:",omitempty"`
		}
		var out struct {
			XMLName     xml.Name `xml:"ListVersionsResult"`
			IsTruncated bool
			Entries     []entry
		}
		names := make([]string, 0, len(b.keys))
		for k := range b.keys {
			if strings.HasPrefix(k, q.Get("prefix")) {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			vs := b.keys[k]
			for i := len(vs) - 1; i >= 0; i-- {
				e := entry{Key: k, VersionId: vs[i].id, IsLatest: i == len(vs)-1}
				if vs[i].marker {
					e.XMLName.Local = "DeleteMarker"
				} else {
					n := int64(len(vs[i].body))
					e.XMLName.Local, e.Size, e.ETag = "Version", &n, `"e"`
				}
				out.Entries = append(out.Entries, e)
			}
		}
		_ = xml.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPut:
		b.puts++
		vs := b.keys[key]
		if r.Header.Get("If-None-Match") == "*" && len(vs) > 0 && !vs[len(vs)-1].marker {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		b.keys[key] = append(vs, fakeVersion{id: id, body: body})
		w.Header().Set("ETag", `"e"`)
		if !b.omitVersion {
			w.Header().Set("X-Amz-Version-Id", id)
		}
	case r.Method == http.MethodGet:
		if alt, ok := b.substitute[key]; ok {
			key = alt
		}
		vs := b.keys[key]
		if len(vs) == 0 || vs[len(vs)-1].marker {
			http.NotFound(w, r)
			return
		}
		v := vs[len(vs)-1]
		body := bytes.Clone(v.body)
		if b.corrupt {
			body[len(body)-1] ^= 1
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Amz-Version-Id", v.id)
		w.Header().Set("ETag", `"e"`)
		_, _ = w.Write(body)
	case r.Method == http.MethodDelete:
		vs := b.keys[key]
		if want := q.Get("versionId"); want != "" {
			for i, v := range vs {
				if v.id == want {
					b.keys[key] = append(vs[:i:i], vs[i+1:]...)
				}
			}
			if len(b.keys[key]) == 0 {
				delete(b.keys, key)
			}
			w.Header().Set("X-Amz-Version-Id", want)
		} else {
			b.keys[key] = append(vs, fakeVersion{id: id, marker: true})
			w.Header().Set("X-Amz-Version-Id", id)
			w.Header().Set("X-Amz-Delete-Marker", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (b *versionedBucket) versions(key string) []fakeVersion {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]fakeVersion(nil), b.keys[cellPath(key)]...)
}

// Org A lives in cell us-east-2, org B in us-east-3; any other org has no known cell.
func fixtureCell(tenantID string) (string, error) {
	switch tenantID {
	case objectOrgA:
		return "us-east-2", nil
	case objectOrgB:
		return "us-east-3", nil
	}
	return "", os.ErrNotExist
}

// cellPath is the bucket key of "<org>/att/<key>".
func cellPath(orgKey string) string {
	cell, _ := fixtureCell(orgKey[:36])
	return "cells/" + cell + "/orgs/" + orgKey
}

func s3Fixture(t *testing.T) (*S3Store, *versionedBucket, string) {
	t.Helper()
	bucket := &versionedBucket{keys: map[string][]fakeVersion{}, substitute: map[string]string{}}
	server := httptest.NewTLSServer(bucket)
	t.Cleanup(server.Close)
	client, err := s3.New(s3.Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "test-access", SecretKey: "test-secret", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	st, err := NewS3Store(client, bytes.Repeat([]byte{1}, 32), fixtureCell, scratch, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return st, bucket, scratch
}

func assertNoScratch(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("scratch left behind: %v %v", entries, err)
	}
}

func TestS3StoreSealsAndServesVerifiedRanges(t *testing.T) {
	st, bucket, scratch := s3Fixture(t)
	plain := []byte("<html>untrusted upload must stay an opaque download</html>")
	res, err := st.Put(objectOrgA, "att_example", bytes.NewReader(plain), 1<<20, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.SizeBytes != int64(len(plain)) || res.MimeType != "application/octet-stream" || res.VersionID == "" || len(res.SHA256Hex) != 64 {
		t.Fatalf("receipt: %+v", res)
	}
	vs := bucket.versions(objectOrgA + "/att/att_example")
	if len(vs) != 1 || bytes.Contains(vs[0].body, plain) || len(vs[0].body) != len(plain)+SealedOverhead {
		t.Fatal("the provider holds plaintext or an unexpected object")
	}
	f, size, err := st.Open(objectOrgA, "att_example", int64(len(plain)))
	if err != nil || size != int64(len(plain)) {
		t.Fatal(size, err)
	}
	if _, err := f.Seek(6, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(f, got); err != nil || !bytes.Equal(got, plain[6:15]) {
		t.Fatalf("range: %q %v", got, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoScratch(t, scratch)
	// A key is written once: a second write never adds a version or erases the first.
	if _, err := st.Put(objectOrgA, "att_example", bytes.NewReader(plain), 1<<20, PutOptions{}); !errors.Is(err, s3.ErrAlreadyExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if len(bucket.versions(objectOrgA+"/att/att_example")) != 1 {
		t.Fatal("refused write changed the object")
	}
}

// Client ciphertext (E5) gets the same outer seal as any upload, and is never sniffed: bytes that
// happen to form a PNG stay an opaque download.
func TestS3StoreSealsOpaqueUploadsWithoutSniffing(t *testing.T) {
	st, bucket, scratch := s3Fixture(t)
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var looksLikePNG bytes.Buffer
	if err := png.Encode(&looksLikePNG, img); err != nil {
		t.Fatal(err)
	}
	ciphertext := looksLikePNG.Bytes()
	res, err := st.Put(objectOrgA, "att_sealed", bytes.NewReader(ciphertext), 1<<20, PutOptions{Opaque: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.MimeType != "application/octet-stream" || res.SizeBytes != int64(len(ciphertext)) {
		t.Fatalf("receipt: %+v", res)
	}
	if plain, err := st.Put(objectOrgA, "att_sniffed", bytes.NewReader(ciphertext), 1<<20, PutOptions{}); err != nil || plain.MimeType != "image/png" {
		t.Fatalf("control: the same bytes without Opaque are sniffed: %+v %v", plain, err)
	}
	vs := bucket.versions(objectOrgA + "/att/att_sealed")
	if len(vs) != 1 || bytes.Contains(vs[0].body, ciphertext[:16]) || len(vs[0].body) != len(ciphertext)+SealedOverhead {
		t.Fatal("the provider holds the client's bytes without the outer seal")
	}
	f, _, err := st.Open(objectOrgA, "att_sealed", int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("opened bytes differ: %v", err)
	}
	assertNoScratch(t, scratch)
}

func TestS3StoreRefusesCrossOrgAndTamperedObjects(t *testing.T) {
	st, bucket, scratch := s3Fixture(t)
	if _, err := st.Put(objectOrgA, "att_example", strings.NewReader("org A's file"), 1<<20, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	// org B's path serving org A's sealed bytes: the org-bound tag refuses it.
	bucket.mu.Lock()
	bucket.substitute[cellPath(objectOrgB+"/att/att_example")] = cellPath(objectOrgA + "/att/att_example")
	bucket.mu.Unlock()
	if f, _, err := st.Open(objectOrgB, "att_example", int64(len("org A's file"))); !errors.Is(err, errObjectIntegrity) || f != nil {
		t.Fatalf("cross-org substitution: %v", err)
	}
	bucket.mu.Lock()
	bucket.corrupt = true
	bucket.mu.Unlock()
	if f, _, err := st.Open(objectOrgA, "att_example", int64(len("org A's file"))); !errors.Is(err, errObjectIntegrity) || f != nil {
		t.Fatalf("tampered object: %v", err)
	}
	for _, org := range []string{"default", "../escape", "", "00000000-0000-4000-8000-0000000000c1"} {
		if _, err := st.Put(org, "att_example", strings.NewReader("x"), 1<<20, PutOptions{}); err == nil {
			t.Fatalf("org %q: %v", org, err)
		}
	}
	if _, err := st.Put(objectOrgA, "att_too_large", bytes.NewReader(make([]byte, 1025)), 1<<20, PutOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if bucket.puts != 1 {
		t.Fatalf("refused uploads reached the provider: %d", bucket.puts)
	}
	assertNoScratch(t, scratch)
}

func TestS3StoreDeleteRetainsEraseAndPrefixRemoveEveryVersion(t *testing.T) {
	st, bucket, _ := s3Fixture(t)
	for _, k := range []struct{ org, key string }{{objectOrgA, "att_keep"}, {objectOrgA, "att_gone"}, {objectOrgA, "att_gone2"}, {objectOrgB, "att_other"}} {
		if _, err := st.Put(k.org, k.key, strings.NewReader("bytes of "+k.key), 1<<20, PutOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// A user's delete hides the file but keeps the bucket's copy.
	if err := st.Delete(objectOrgA, "att_gone"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Open(objectOrgA, "att_gone", int64(len("bytes of att_gone"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted file still served: %v", err)
	}
	if vs := bucket.versions(objectOrgA + "/att/att_gone"); len(vs) != 2 || vs[0].marker || !vs[1].marker {
		t.Fatalf("delete did not retain the version: %+v", vs)
	}
	// Erase removes the data version and the marker, and only that key.
	if err := st.Erase(objectOrgA, "att_gone"); err != nil {
		t.Fatal(err)
	}
	if vs := bucket.versions(objectOrgA + "/att/att_gone"); len(vs) != 0 {
		t.Fatalf("erase left versions: %+v", vs)
	}
	if len(bucket.versions(objectOrgA+"/att/att_gone2")) != 1 || len(bucket.versions(objectOrgA+"/att/att_keep")) != 1 {
		t.Fatal("erase touched a neighbour")
	}
	if err := st.Delete(objectOrgA, "att_gone2"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePrefix(objectOrgA); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"att_keep", "att_gone2"} {
		if vs := bucket.versions(objectOrgA + "/att/" + k); len(vs) != 0 {
			t.Fatalf("purge left %s: %+v", k, vs)
		}
	}
	if f, _, err := st.Open(objectOrgB, "att_other", int64(len("bytes of att_other"))); err != nil {
		t.Fatal("purge reached another org", err)
	} else {
		f.Close()
	}
	if err := st.DeletePrefix("default"); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
}

// A write that may have landed without a usable version receipt leaves nothing behind.
func TestS3StoreErasesAWriteWithoutVersion(t *testing.T) {
	st, bucket, scratch := s3Fixture(t)
	bucket.omitVersion = true
	if _, err := st.Put(objectOrgA, "att_unversioned", strings.NewReader("must not linger"), 1<<20, PutOptions{}); !errors.Is(err, errObjectReceipt) {
		t.Fatal(err)
	}
	if vs := bucket.versions(objectOrgA + "/att/att_unversioned"); len(vs) != 0 {
		t.Fatalf("unaccounted object remains: %+v", vs)
	}
	assertNoScratch(t, scratch)
}

func TestS3StoreSweepsStaleScratch(t *testing.T) {
	st, _, scratch := s3Fixture(t)
	for _, name := range []string{".upload-1", ".verified-2"} {
		if err := os.Mkdir(scratch+"/"+name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if n := st.SweepStaleTemps(-1); n != 2 {
		t.Fatal(fmt.Sprint("swept ", n))
	}
	assertNoScratch(t, scratch)
}

// A suspended-versioning bucket answers "null": the write is refused and erased, since no
// retained version could ever be recorded for it.
func TestS3StoreRefusesANullVersion(t *testing.T) {
	st, bucket, scratch := s3Fixture(t)
	bucket.nullVersion = true
	if _, err := st.Put(objectOrgA, "att_nullversion", strings.NewReader("must not linger"), 1<<20, PutOptions{}); !errors.Is(err, errObjectReceipt) {
		t.Fatal(err)
	}
	if vs := bucket.versions(objectOrgA + "/att/att_nullversion"); len(vs) != 0 {
		t.Fatalf("unaccounted object remains: %+v", vs)
	}
	assertNoScratch(t, scratch)
}

// A local copy that cannot be written (scratch full) fails the download and leaves nothing.
func TestS3StoreOpenFailsWhenScratchWriteFails(t *testing.T) {
	st, _, scratch := s3Fixture(t)
	if _, err := st.Put(objectOrgA, "att_scratchfull", strings.NewReader("verified bytes"), 1<<20, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	createVerified = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		f.Close()
		return os.Open(f.Name()) // read-only: every Write fails
	}
	t.Cleanup(func() { createVerified = os.CreateTemp })
	if f, _, err := st.Open(objectOrgA, "att_scratchfull", int64(len("verified bytes"))); err == nil || f != nil {
		t.Fatalf("download succeeded without its local copy: %v", err)
	}
	assertNoScratch(t, scratch)
}

// Lowering KY_MAX_UPLOAD_BYTES restricts new uploads only: an existing file stays readable,
// bounded by its recorded size, and a size that does not match the object is refused.
func TestS3StoreLowerUploadLimitKeepsExistingFiles(t *testing.T) {
	st, _, _ := s3Fixture(t)
	body := bytes.Repeat([]byte("k"), 1000)
	if _, err := st.Put(objectOrgA, "att_bigger", bytes.NewReader(body), 1<<20, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	lowered, err := NewS3Store(st.client, bytes.Repeat([]byte{1}, 32), fixtureCell, t.TempDir(), 16)
	if err != nil {
		t.Fatal(err)
	}
	f, size, err := lowered.Open(objectOrgA, "att_bigger", int64(len(body)))
	if err != nil || size != int64(len(body)) {
		t.Fatalf("existing file unreadable after a lower limit: %d %v", size, err)
	}
	f.Close()
	if _, err := lowered.Put(objectOrgA, "att_new_big", bytes.NewReader(body), 1<<20, PutOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("lowered limit not applied to a new upload: %v", err)
	}
	for _, wrong := range []int64{999, 1001, 0, 200 << 20} {
		if f, _, err := lowered.Open(objectOrgA, "att_bigger", wrong); !errors.Is(err, errObjectIntegrity) || f != nil {
			t.Fatalf("recorded size %d: %v", wrong, err)
		}
	}
}
