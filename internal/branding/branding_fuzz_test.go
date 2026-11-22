package branding_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Busnes-app/ky_server_base/internal/branding"
)

// FuzzValidateName checks product name validation: accepted names are trimmed, valid UTF-8,
// 1..MaxNameRunes runes, free of control/format/separator characters, and idempotent.
func FuzzValidateName(f *testing.F) {
	for _, s := range []string{
		"",
		"   ",
		"KyMessages",
		"  Acme Chat  ",
		strings.Repeat("a", branding.MaxNameRunes),
		strings.Repeat("a", branding.MaxNameRunes+1),
		"Acme\nChat",
		"Acme\x00Chat",
		"Acme\u202eChat",
		"Acme\u200bChat",
		"Acme\ufeffChat",
		string([]byte{0xff, 0xfe}),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := branding.ValidateName(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("ValidateName(%q) failed (%v) but returned %q", raw, err, got)
			}
			return
		}
		if !utf8.ValidString(got) {
			t.Fatalf("ValidateName(%q) returned invalid UTF-8: %q", raw, got)
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("ValidateName(%q) returned untrimmed name %q", raw, got)
		}
		n := utf8.RuneCountInString(got)
		if n < 1 || n > branding.MaxNameRunes {
			t.Fatalf("ValidateName(%q) returned %d runes", raw, n)
		}
		for _, r := range got {
			if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
				t.Fatalf("ValidateName(%q) accepted forbidden rune U+%04X", raw, r)
			}
		}
		again, err := branding.ValidateName(got)
		if err != nil || again != got {
			t.Fatalf("ValidateName is not idempotent on %q: (%q, %v)", got, again, err)
		}
	})
}

// FuzzNormalizePNG feeds arbitrary bytes into NormalizePNG. Accepted outputs must be valid
// PNGs within size and dimension caps and must decode cleanly on a second pass.
func FuzzNormalizePNG(f *testing.F) {
	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.NRGBA{R: 10, G: 20, B: 30, A: 255})
	var valid bytes.Buffer
	if err := png.Encode(&valid, img); err != nil {
		f.Fatalf("seed png encode: %v", err)
	}
	for _, b := range [][]byte{
		nil,
		{},
		[]byte("<svg xmlns='http://www.w3.org/2000/svg'/>"),
		[]byte("\x89PNG\r\n\x1a\n"),
		valid.Bytes(),
	} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := branding.NormalizePNG(raw)
		if err != nil {
			if out != nil {
				t.Fatalf("NormalizePNG failed (%v) but returned %d bytes", err, len(out))
			}
			return
		}
		if len(out) == 0 || len(out) > branding.MaxLogoBytes {
			t.Fatalf("NormalizePNG returned %d bytes (cap %d)", len(out), branding.MaxLogoBytes)
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("NormalizePNG returned unreadable PNG: %v", err)
		}
		if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > branding.MaxLogoSide || cfg.Height > branding.MaxLogoSide {
			t.Fatalf("NormalizePNG returned out-of-bounds dimensions %dx%d", cfg.Width, cfg.Height)
		}
	})
}
