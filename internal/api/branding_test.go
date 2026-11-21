package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/branding"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetRGBA(x, y, color.RGBA{R: 12, G: 34, B: 56, A: 255})
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// withTextChunk inserts a tEXt chunk before IEND so the test can confirm normalisation drops it.
func withTextChunk(src []byte) []byte {
	data := []byte("Comment\x00kymessages-secret")
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(data)))
	chunk.WriteString("tEXt")
	chunk.Write(data)
	_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(chunk.Bytes()[4:]))
	iend := len(src) - 12
	return append(append(append([]byte{}, src[:iend]...), chunk.Bytes()...), src[iend:]...)
}

func rawDo(t *testing.T, srv *api.Server, session *http.Cookie, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
	req.Header.Set(auth.HeaderCSRF, "test-csrf")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

type brandingBody struct {
	Name        string `json:"name"`
	StoredName  string `json:"stored_name"`
	DefaultName string `json:"default_name"`
	Logo        struct {
		Custom bool   `json:"custom"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	} `json:"logo"`
}

func TestBrandNameRenamesTheApp(t *testing.T) {
	ctx := context.Background()
	srv, st, cfg := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	path := "/api/admin/branding/name"
	got := decode[brandingBody](t, adminDo(t, srv, admin, "PUT", path, map[string]string{"name": "  Acme Chat  "}))
	if got.Name != "Acme Chat" || got.StoredName != "Acme Chat" || got.DefaultName != cfg.Server.AppName {
		t.Fatalf("%+v", got)
	}
	if s := decode[map[string]any](t, do(t, srv, "GET", "/api/settings", nil)); s["app_name"] != "Acme Chat" {
		t.Fatalf("login page name: %v", s["app_name"])
	}
	rows := auditRows(t, st, "admin.brand_name")
	if want := fmt.Sprintf(`outcome="saved" old=%q new="Acme Chat"`, cfg.Server.AppName); len(rows) != 1 || rows[0].Details != want || rows[0].UserID != "usr_root" {
		t.Fatalf("audit %+v", rows)
	}
	// Blank resets to KY_APP_NAME.
	got = decode[brandingBody](t, adminDo(t, srv, admin, "PUT", path, map[string]string{"name": " "}))
	if got.Name != cfg.Server.AppName || got.StoredName != "" {
		t.Fatalf("after reset: %+v", got)
	}
	if _, err := st.Settings().GetSetting(ctx, "brand_name"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reset left brand_name: %v", err)
	}
	if w := adminDo(t, srv, admin, "GET", "/api/admin/branding", nil); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET branding: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestBrandNameRefusals(t *testing.T) {
	ctx := context.Background()
	srv, st, _ := setupTestServer(t)
	path := "/api/admin/branding/name"
	if w := adminDo(t, srv, staleAdmin(t, st), "PUT", path, map[string]string{"name": "Acme"}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), `"code":"reauthentication_required"`) {
		t.Fatalf("stale admin: %d %s", w.Code, w.Body.String())
	}
	admin := loginAs(t, srv, st, "root", "admin")
	for _, bad := range []string{strings.Repeat("x", 65), "Acme\u202eChat", "Ac\nme"} {
		if w := adminDo(t, srv, admin, "PUT", path, map[string]string{"name": bad}); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", bad, w.Code)
		}
	}
	for _, body := range []any{map[string]any{"name": 5}, map[string]any{"name": "A", "extra": 1}, map[string]any{}} {
		if w := adminDo(t, srv, admin, "PUT", path, body); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, w.Code)
		}
	}
	if _, err := st.Settings().GetSetting(ctx, "brand_name"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused name was saved: %v", err)
	}
	rows := auditRows(t, st, "admin.brand_name")
	if len(rows) != 3 {
		t.Fatalf("want the 3 invalid names audited, not the stale session or the malformed bodies: %+v", rows)
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.Details, `outcome="refused: the name `) {
			t.Errorf("details %q", r.Details)
		}
	}
}

func TestLogoUploadNormalisesServesAndResets(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	admin := loginAs(t, srv, st, "root", "admin")
	saved := decode[brandingBody](t, rawDo(t, srv, admin, "PUT", "/api/admin/branding/logo", "image/png", withTextChunk(testPNG(t, 32, 32))))
	if !saved.Logo.Custom || len(saved.Logo.SHA256) != 64 || saved.Logo.Size == 0 {
		t.Fatalf("%+v", saved)
	}
	icon := do(t, srv, "GET", "/app-icon.png", nil) // public: the login page shows it
	body := icon.Body.Bytes()
	sum := sha256.Sum256(body)
	h := icon.Header()
	if icon.Code != http.StatusOK || h.Get("Content-Type") != "image/png" || h.Get("Cache-Control") != "no-cache" ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("ETag") != `"`+saved.Logo.SHA256+`"` ||
		hex.EncodeToString(sum[:]) != saved.Logo.SHA256 || len(body) != saved.Logo.Size {
		t.Fatalf("served logo: %d %v", icon.Code, h)
	}
	if bytes.Contains(body, []byte("tEXt")) || bytes.Contains(body, []byte("kymessages-secret")) {
		t.Fatal("the text chunk was served")
	}
	if _, err := png.Decode(bytes.NewReader(body)); err != nil {
		t.Fatalf("served logo does not decode: %v", err)
	}
	revalidate := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/app-icon.png", nil)
		req.Header.Set("If-None-Match", `"`+saved.Logo.SHA256+`"`)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	if w := revalidate(); w.Code != http.StatusNotModified {
		t.Fatalf("revalidation with the current ETag: %d", w.Code)
	}
	if strings.Contains(do(t, srv, "GET", "/api/settings", admin).Body.String(), "brand_logo") {
		t.Fatal("the logo rides on /api/settings")
	}
	// Reset: a browser revalidating its custom copy must get the stamp back.
	if got := decode[brandingBody](t, adminDo(t, srv, admin, "DELETE", "/api/admin/branding/logo", nil)); got.Logo.Custom {
		t.Fatalf("after reset: %+v", got)
	}
	embedded, err := os.ReadFile("../../web/dist/app-icon.png")
	if err != nil {
		t.Fatal(err)
	}
	if w := revalidate(); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), embedded) || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("after reset: %d, %d bytes, Cache-Control %q", w.Code, w.Body.Len(), w.Header().Get("Cache-Control"))
	}
	rows := auditRows(t, st, "admin.brand_logo")
	if len(rows) != 2 || rows[0].Details != `outcome="reset"` ||
		rows[1].Details != fmt.Sprintf(`outcome="saved" sha256=%q size="%d"`, saved.Logo.SHA256, saved.Logo.Size) {
		t.Fatalf("audit %+v", rows)
	}
}

func TestLogoUploadRefusals(t *testing.T) {
	ctx := context.Background()
	srv, st, _ := setupTestServer(t)
	path := "/api/admin/branding/logo"
	if w := rawDo(t, srv, staleAdmin(t, st), "PUT", path, "image/png", testPNG(t, 4, 4)); w.Code != http.StatusForbidden {
		t.Fatalf("stale admin: %d", w.Code)
	}
	admin := loginAs(t, srv, st, "root", "admin")
	var jpg bytes.Buffer
	if err := jpeg.Encode(&jpg, image.NewRGBA(image.Rect(0, 0, 4, 4)), nil); err != nil {
		t.Fatal(err)
	}
	signed := func(n int) []byte {
		b := make([]byte, n)
		copy(b, "\x89PNG\r\n\x1a\n")
		return b
	}
	for name, tc := range map[string]struct {
		contentType string
		body        []byte
		code        int
		outcome     string
	}{
		"SVG":            {"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 415, "refused: the logo must be a PNG image (image/png)"},
		"no type":        {"", testPNG(t, 4, 4), 415, "refused: the logo must be a PNG image (image/png)"},
		"JPEG as PNG":    {"image/png", jpg.Bytes(), 400, "refused: " + branding.ErrNotPNG.Error()},
		"1025 px":        {"image/png", testPNG(t, 1025, 1), 400, "refused: " + branding.ErrLogoDimensions.Error()},
		"exactly 1 MiB":  {"image/png", signed(1 << 20), 400, "refused: " + branding.ErrNotPNG.Error()},
		"1 MiB + 1 byte": {"image/png", signed(1<<20 + 1), 413, "refused: " + branding.ErrLogoTooLarge.Error()},
	} {
		if w := rawDo(t, srv, admin, "PUT", path, tc.contentType, tc.body); w.Code != tc.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
		if rows := auditRows(t, st, "admin.brand_logo"); len(rows) == 0 || rows[0].Details != fmt.Sprintf("outcome=%q", tc.outcome) {
			t.Errorf("%s: newest audit row %+v", name, rows)
		}
	}
	if _, err := st.Settings().GetSetting(ctx, "brand_logo"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused logo was stored: %v", err)
	}
}
