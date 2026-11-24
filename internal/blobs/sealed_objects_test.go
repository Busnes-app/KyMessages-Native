package blobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/Busnes-app/ky-primitives/s3"
)

const objectOrgA = "00000000-0000-4000-8000-0000000000a1"
const objectOrgB = "00000000-0000-4000-8000-0000000000b1"

type wireObject struct {
	body          []byte
	etag, version string
}
type objectWire struct {
	mu                   sync.Mutex
	objects              map[string]wireObject
	puts                 int
	corrupt, omitVersion bool
	substitute           string
}

func (f *objectWire) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[r.URL.Path]
	switch r.Method {
	case http.MethodPut:
		f.puts++
		predecessor := `"predecessor"`
		if exists {
			predecessor = object.etag
		}
		if r.Header.Get("If-Match") != predecessor {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		object = wireObject{body: body, etag: fmt.Sprintf(`"data-%d"`, f.puts), version: "version/1+opaque"}
		f.objects[r.URL.Path] = object
		w.Header().Set("ETag", object.etag)
		if !f.omitVersion {
			w.Header().Set("X-Amz-Version-Id", object.version)
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if !exists && f.substitute != "" {
			object, exists = f.objects[f.substitute]
		}
		if !exists || r.URL.Query().Get("versionId") != object.version {
			http.NotFound(w, r)
			return
		}
		body := bytes.Clone(object.body)
		if f.corrupt {
			body[len(body)-1] ^= 1
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Amz-Version-Id", object.version)
		w.Header().Set("ETag", object.etag)
		w.Write(body)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func objectFixture(t *testing.T) (*sealedObjects, *objectWire) {
	t.Helper()
	wire := &objectWire{objects: make(map[string]wireObject)}
	server := httptest.NewTLSServer(wire)
	t.Cleanup(server.Close)
	client, err := s3.New(s3.Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "test-access", SecretKey: "test-secret", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := newSealedObjects(client, bytes.Repeat([]byte{1}, 32), t.TempDir(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.close(); err != nil {
			t.Error(err)
		}
	})
	return objects, wire
}

func TestSealedObjectsConditionalWriteAndVerifiedRanges(t *testing.T) {
	o, wire := objectFixture(t)
	ctx := context.Background()
	plain := []byte("<html>untrusted upload must stay an opaque download</html>")
	receipt, err := o.writeIfMatch(ctx, objectOrgA, "att_example", `"predecessor"`, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SizeBytes != int64(len(plain)) || receipt.MimeType != "application/octet-stream" || receipt.versionID != "version/1+opaque" {
		t.Fatalf("receipt:%+v", receipt)
	}
	objectPath := "/bucket/orgs/" + objectOrgA + "/att/att_example"
	wire.mu.Lock()
	remote := wire.objects[objectPath]
	wire.mu.Unlock()
	if bytes.Contains(remote.body, plain) || len(remote.body) != len(plain)+SealedOverhead {
		t.Fatal("provider bytes were not sealed")
	}
	opened, err := o.openVersion(ctx, objectOrgA, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Seek(6, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(opened, got); err != nil || !bytes.Equal(got, plain[6:15]) {
		t.Fatalf("range:%q %v", got, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(o.scratch); err != nil || len(entries) != 0 {
		t.Fatalf("scratch leak:%v %v", entries, err)
	}
	// An old predecessor must not add a new remote data version.
	if _, err := o.writeIfMatch(ctx, objectOrgA, "att_example", `"predecessor"`, bytes.NewReader(plain)); !errors.Is(err, s3.ErrPrecondition) {
		t.Fatalf("stale overwrite:%v", err)
	}
	wire.mu.Lock()
	unchanged := bytes.Equal(remote.body, wire.objects[objectPath].body)
	wire.mu.Unlock()
	if !unchanged {
		t.Fatal("stale write replaced content")
	}
}

func TestSealedObjectsRefuseCrossOrgTamperingAndWrongMetadata(t *testing.T) {
	o, wire := objectFixture(t)
	ctx := context.Background()
	receipt, err := o.writeIfMatch(ctx, objectOrgA, "att_example", `"predecessor"`, bytes.NewBufferString("verified bytes"))
	if err != nil {
		t.Fatal(err)
	}
	wire.mu.Lock()
	wire.substitute = "/bucket/orgs/" + objectOrgA + "/att/att_example"
	wire.mu.Unlock()
	if f, err := o.openVersion(ctx, objectOrgB, receipt); err == nil || f != nil {
		t.Fatalf("cross-org substitution:%v %v", f, err)
	}
	wire.mu.Lock()
	wire.corrupt = true
	wire.mu.Unlock()
	if f, err := o.openVersion(ctx, objectOrgA, receipt); err == nil || f != nil {
		t.Fatalf("bad tag exposed a file:%v %v", f, err)
	}
	wire.mu.Lock()
	wire.corrupt = false
	wire.mu.Unlock()
	wrong := receipt
	wrong.SHA256Hex = "not the expected digest"
	if f, err := o.openVersion(ctx, objectOrgA, wrong); err == nil || f != nil {
		t.Fatalf("bad digest exposed a file:%v %v", f, err)
	}
	wrong = receipt
	wrong.versionID = "missing-version"
	if f, err := o.openVersion(ctx, objectOrgA, wrong); !errors.Is(err, s3.ErrNotFound) || f != nil {
		t.Fatalf("version fallback:%v %v", f, err)
	}
	if entries, err := os.ReadDir(o.scratch); err != nil || len(entries) != 0 {
		t.Fatalf("unauthenticated scratch:%v %v", entries, err)
	}
}

func TestSealedObjectsBoundWritesAndRetainUncertainReceipt(t *testing.T) {
	o, wire := objectFixture(t)
	ctx := context.Background()
	if _, err := o.writeIfMatch(ctx, objectOrgA, "att_too_large", `"predecessor"`, bytes.NewReader(make([]byte, 1025))); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	for _, org := range []string{"default", "../escape", ""} {
		if _, err := o.writeIfMatch(ctx, org, "att_example", `"predecessor"`, bytes.NewBufferString("x")); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("org %q:%v", org, err)
		}
	}
	wire.mu.Lock()
	puts := wire.puts
	wire.omitVersion = true
	wire.mu.Unlock()
	if puts != 0 {
		t.Fatalf("invalid upload made %d remote writes", puts)
	}
	receipt, err := o.writeIfMatch(ctx, objectOrgA, "att_uncertain", `"predecessor"`, bytes.NewBufferString("must remain charged"))
	if !errors.Is(err, errObjectReceipt) || receipt.SizeBytes == 0 || receipt.etag == "" {
		t.Fatalf("lost partial receipt:%+v %v", receipt, err)
	}
	wire.mu.Lock()
	_, stored := wire.objects["/bucket/orgs/"+objectOrgA+"/att/att_uncertain"]
	puts = wire.puts
	wire.mu.Unlock()
	if !stored || puts != 1 {
		t.Fatal("receipt failure was incorrectly treated as no write")
	}
	if entries, err := os.ReadDir(o.scratch); err != nil || len(entries) != 0 {
		t.Fatalf("failed write scratch:%v %v", entries, err)
	}
}
