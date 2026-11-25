package blobs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/s3"
	"github.com/google/uuid"
)

// TestS3StoreVersionedIntegration runs the backend against a disposable loopback S3 server
// with versioning on (CI: the pinned SeaweedFS fixture). A verified TLS proxy keeps the
// client on HTTPS while the server checks the real request signatures.
func TestS3StoreVersionedIntegration(t *testing.T) {
	endpoint := os.Getenv("KY_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set KY_TEST_S3_* for the disposable versioned S3 fixture")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("integration fixture must be loopback HTTP, never a live store")
	}
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	defer proxy.Close()
	client, err := s3.New(s3.Config{Endpoint: proxy.URL, Bucket: os.Getenv("KY_TEST_S3_BUCKET"), Region: "us-east-1", AccessKey: os.Getenv("KY_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KY_TEST_S3_SECRET_KEY"), HTTP: proxy.Client()})
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewS3Store(client, bytes.Repeat([]byte{7}, 32), t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	orgA, orgB := uuid.NewString(), uuid.NewString()
	t.Cleanup(func() { _ = st.DeletePrefix(orgA); _ = st.DeletePrefix(orgB) })
	versions := func(org, key string) []s3.Object {
		t.Helper()
		page, err := client.ListObjectVersions(t.Context(), "orgs/"+org+"/att/"+key, s3.VersionCursor{})
		if err != nil {
			t.Fatal(err)
		}
		return page.Objects
	}
	png := []byte("\x89PNG\r\n\x1a\nnot really an image")
	for _, k := range []struct{ org, key string }{{orgA, "att_first"}, {orgA, "att_second"}, {orgB, "att_first"}} {
		res, err := st.Put(k.org, k.key, bytes.NewReader(png), 1<<20)
		if err != nil || res.VersionID == "" || res.MimeType != "application/octet-stream" {
			t.Fatalf("put %v: %+v %v", k, res, err)
		}
	}
	if _, err := st.Put(orgA, "att_first", bytes.NewReader(png), 1<<20); !errors.Is(err, s3.ErrAlreadyExists) {
		t.Fatal("a key was written twice", err)
	}
	body, _, err := client.Get(t.Context(), "orgs/"+orgA+"/att/att_first", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(body)
	body.Close()
	if bytes.Contains(raw, png[8:]) {
		t.Fatal("the provider holds plaintext")
	}
	f, size, err := st.Open(orgA, "att_first", int64(len(png)))
	if err != nil || size != int64(len(png)) {
		t.Fatal(size, err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, png) {
		t.Fatal("round trip changed the bytes")
	}
	// Org A's sealed bytes copied under org B's key never authenticate.
	if _, err := client.Put(t.Context(), "orgs/"+orgB+"/att/att_copied1", bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Open(orgB, "att_copied1", int64(len(png))); !errors.Is(err, errObjectIntegrity) {
		t.Fatal("cross-org copy served", err)
	}
	// A member's delete keeps the data version; Erase removes it and the marker.
	if err := st.Delete(orgA, "att_first"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Open(orgA, "att_first", int64(len(png))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted file served", err)
	}
	if v := versions(orgA, "att_first"); len(v) != 2 {
		t.Fatalf("delete did not retain the version: %+v", v)
	}
	if err := st.Erase(orgA, "att_first"); err != nil {
		t.Fatal(err)
	}
	if v := versions(orgA, "att_first"); len(v) != 0 {
		t.Fatalf("erase left versions: %+v", v)
	}
	if err := st.Delete(orgA, "att_second"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePrefix(orgA); err != nil {
		t.Fatal(err)
	}
	if v := versions(orgA, ""); len(v) != 0 {
		t.Fatalf("purge left versions: %+v", v)
	}
	if f, _, err := st.Open(orgB, "att_first", int64(len(png))); err != nil {
		t.Fatal("purge reached another org", err)
	} else {
		f.Close()
	}
}
