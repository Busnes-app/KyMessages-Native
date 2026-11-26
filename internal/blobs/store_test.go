package blobs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/blobs"
)

func makePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeGIF(t *testing.T) []byte {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, 2, 2), color.Palette{color.Black, color.White})
	var buf bytes.Buffer
	if err := gif.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestStorePutOpenDeleteAndSHA256(t *testing.T) {
	st, err := blobs.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := makePNG(t)
	wantHash := sha256.Sum256(payload)

	res, err := st.Put("default", "att_019a0000-0000-7000-8000-000000000001", bytes.NewReader(payload), 1024*1024, blobs.PutOptions{})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if res.SizeBytes != int64(len(payload)) {
		t.Errorf("SizeBytes = %d, want %d", res.SizeBytes, len(payload))
	}
	if res.SHA256Hex != hex.EncodeToString(wantHash[:]) {
		t.Errorf("SHA256Hex = %q, want %q", res.SHA256Hex, hex.EncodeToString(wantHash[:]))
	}
	if res.MimeType != "image/png" {
		t.Errorf("MimeType = %q, want image/png", res.MimeType)
	}
	if !blobs.IsInlineSafeImage(res.MimeType) {
		t.Error("image/png should be inline safe")
	}

	f, size, err := st.Open("default", res.Key, res.SizeBytes)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if size != int64(len(payload)) {
		t.Errorf("Open size = %d, want %d", size, len(payload))
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("round-trip bytes mismatch")
	}

	if err := st.Delete("default", res.Key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := st.Delete("default", res.Key); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if _, _, err := st.Open("default", res.Key, res.SizeBytes); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open after Delete = %v, want os.ErrNotExist", err)
	}
}

func TestStoreEnforcesSizeAndKeyBounds(t *testing.T) {
	st, err := blobs.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.Put("default", "att_empty_0001", bytes.NewReader(nil), 1024, blobs.PutOptions{}); !errors.Is(err, blobs.ErrEmpty) {
		t.Errorf("empty Put = %v, want ErrEmpty", err)
	}
	if _, err := st.Put("default", "att_large_0001", bytes.NewReader(make([]byte, 17)), 16, blobs.PutOptions{}); !errors.Is(err, blobs.ErrTooLarge) {
		t.Errorf("oversized Put = %v, want ErrTooLarge", err)
	}

	badKeys := []string{"", "../etc/passwd", "a/b/c/d/e/f", "short", "att..evil1234", "att\x00null1234"}
	for _, k := range badKeys {
		if _, err := st.Put("default", k, strings.NewReader("hi"), 64, blobs.PutOptions{}); !errors.Is(err, blobs.ErrInvalidKey) {
			t.Errorf("Put(%q) = %v, want ErrInvalidKey", k, err)
		}
		if _, _, err := st.Open("default", k, 1); !errors.Is(err, blobs.ErrInvalidKey) {
			t.Errorf("Open(%q) = %v, want ErrInvalidKey", k, err)
		}
		if err := st.Delete("default", k); !errors.Is(err, blobs.ErrInvalidKey) {
			t.Errorf("Delete(%q) = %v, want ErrInvalidKey", k, err)
		}
	}
}

func TestStoreMIMESniffingAndXSSDowngrade(t *testing.T) {
	st, err := blobs.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		body         []byte
		wantMIME     string
		wantInlineOK bool
	}{
		{"valid_png", makePNG(t), "image/png", true},
		{"valid_jpeg", makeJPEG(t), "image/jpeg", true},
		{"valid_gif", makeGIF(t), "image/gif", true},
		{"valid_webp_header", append([]byte("RIFF\x18\x00\x00\x00WEBPVP8 "), make([]byte, 16)...), "image/webp", true},
		{"corrupt_png_magic", []byte("\x89PNG\r\n\x1a\n<script>alert(1)</script>"), "application/octet-stream", false},
		{"svg_xss", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`), "application/octet-stream", false},
		{"xml_svg", []byte(`<?xml version="1.0"?><svg></svg>`), "application/octet-stream", false},
		{"html_xss", []byte(`<!DOCTYPE html><html><body><script>alert(1)</script></body></html>`), "application/octet-stream", false},
		{"plain_text", []byte("Hello team, meeting notes attached.\n"), "text/plain; charset=utf-8", false},
		{"pdf_header", []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"), "application/pdf", false},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := "att_mime_test_" + string(rune('a'+i)) + "00001"
			res, err := st.Put("default", key, bytes.NewReader(tc.body), 1024*1024, blobs.PutOptions{})
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if res.MimeType != tc.wantMIME {
				t.Errorf("MimeType = %q, want %q", res.MimeType, tc.wantMIME)
			}
			if got := blobs.IsInlineSafeImage(res.MimeType); got != tc.wantInlineOK {
				t.Errorf("IsInlineSafeImage(%q) = %v, want %v", res.MimeType, got, tc.wantInlineOK)
			}
		})
	}
}

func TestStoreOpaqueUploadIsNeverSniffed(t *testing.T) {
	st, err := blobs.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	png := makePNG(t)
	res, err := st.Put("default", "att_opaque_00001", bytes.NewReader(png), 1024*1024, blobs.PutOptions{Opaque: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.MimeType != "application/octet-stream" || res.SizeBytes != int64(len(png)) {
		t.Fatalf("opaque Put = %+v, want application/octet-stream of %d bytes", res, len(png))
	}
	if _, err := st.Put("default", "att_opaque_00002", bytes.NewReader(nil), 1024, blobs.PutOptions{Opaque: true}); !errors.Is(err, blobs.ErrEmpty) {
		t.Fatalf("empty opaque Put = %v, want ErrEmpty", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{`C:\Users\alice\secret\notes.txt`, "notes.txt"},
		{"photo\r\nContent-Type: text/html.png", "html.png"},
		{"photo\r\nX-Header: 1.png", "photoX-Header: 1.png"},
		{"evil\u202egnp.exe", "evilgnp.exe"},
		{"...", "attachment"},
		{"", "attachment"},
		{`quoted"name.txt`, "quotedname.txt"},
	}
	for _, tc := range cases {
		got := blobs.SanitizeFilename(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	longName := strings.Repeat("a", 250) + ".png"
	sanitized := blobs.SanitizeFilename(longName)
	if len(sanitized) > 200 || !strings.HasSuffix(sanitized, ".png") {
		t.Errorf("long filename sanitized to len=%d %q", len(sanitized), sanitized)
	}
}

func TestNewStoreFailsOnUnwritablePath(t *testing.T) {
	// A regular file path cannot be used as a directory.
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.NewStore(filePath); err == nil {
		t.Fatal("NewStore succeeded on regular file path")
	}

	// An existing read-only directory must fail the writability probe when not running as root.
	if os.Geteuid() != 0 {
		roDir := filepath.Join(t.TempDir(), "readonly")
		if err := os.Mkdir(roDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
		if _, err := blobs.NewStore(roDir); err == nil {
			t.Fatal("NewStore succeeded on read-only directory")
		}
	}
}
