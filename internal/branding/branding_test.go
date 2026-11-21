package branding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Chat":             "Acme Chat",
		"  Acme  ":              "Acme",
		strings.Repeat("é", 64): strings.Repeat("é", 64),
		"Ünïcode 会話 🙂":          "Ünïcode 会話 🙂",
	} {
		if got, err := ValidateName(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for name, in := range map[string]string{
		"empty":            "",
		"blank":            " \t ",
		"65 characters":    strings.Repeat("é", 65),
		"newline":          "Acme\nChat",
		"tab":              "Acme\tChat",
		"NUL":              "Acme\x00",
		"DEL":              "Acme\x7f",
		"C1 control (NEL)": "Ac\u0085me",
		"bidi override":    "\u202eAcme",
		"bidi isolate":     "Acme\u2066x",
		"zero-width space": "Ac\u200bme",
		"ZWJ":              "Ac\u200dme",
		"BOM":              "\ufeffAcme",
		"line separator":   "Acme\u2028Chat",
		"invalid UTF-8":    "Acme\xff",
	} {
		if _, err := ValidateName(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func encode(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.NRGBA{R: 191, G: 63, B: 24, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// chunk is one PNG chunk: length, type, data, and the CRC over type and data.
func chunk(typ string, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	out = append(out, typ...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

// afterIHDR inserts c after the signature (8 bytes) and the IHDR chunk (25 bytes).
func afterIHDR(p, c []byte) []byte {
	return append(append(append([]byte{}, p[:33]...), c...), p[33:]...)
}

// withSize rewrites IHDR's width and height and fixes its CRC; the pixels stay as they were.
func withSize(p []byte, w, h uint32) []byte {
	p = append([]byte{}, p...)
	binary.BigEndian.PutUint32(p[16:], w)
	binary.BigEndian.PutUint32(p[20:], h)
	binary.BigEndian.PutUint32(p[29:], crc32.ChecksumIEEE(p[12:29]))
	return p
}

func TestNormalizePNGStripsAncillaryChunks(t *testing.T) {
	in := afterIHDR(encode(t, 16, 16), chunk("tEXt", []byte("Comment\x00kymessages-secret")))
	if _, err := png.Decode(bytes.NewReader(in)); err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	out, err := NormalizePNG(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("tEXt")) || bytes.Contains(out, []byte("kymessages-secret")) {
		t.Fatal("the tEXt chunk survived")
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil || img.Bounds().Dx() != 16 || img.Bounds().Dy() != 16 {
		t.Fatalf("re-encoding does not decode as the same image: %v", err)
	}
	if _, err := NormalizePNG(encode(t, MaxLogoSide, MaxLogoSide)); err != nil {
		t.Fatalf("1024×1024 refused: %v", err)
	}
}

func TestNormalizePNGRefuses(t *testing.T) {
	var jpg bytes.Buffer
	if err := jpeg.Encode(&jpg, image.NewRGBA(image.Rect(0, 0, 4, 4)), nil); err != nil {
		t.Fatal(err)
	}
	small := encode(t, 4, 4)
	oversize := make([]byte, MaxLogoBytes+1)
	copy(oversize, small)
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"JPEG":                     {jpg.Bytes(), ErrNotPNG},
		"SVG":                      {[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), ErrNotPNG},
		"empty":                    {nil, ErrNotPNG},
		"signature only":           {small[:8], ErrNotPNG},
		"truncated pixels":         {small[:len(small)-20], ErrNotPNG},
		"zero width":               {withSize(small, 0, 4), ErrNotPNG},
		"1025 px wide":             {encode(t, 1025, 1), ErrLogoDimensions},
		"1025 px high":             {encode(t, 1, 1025), ErrLogoDimensions},
		"bomb: header says 50000²": {withSize(small, 50000, 50000), ErrLogoDimensions},
		"1 MiB + 1 byte":           {oversize, ErrLogoTooLarge},
	} {
		if _, err := NormalizePNG(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}
