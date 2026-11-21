// Package branding holds the pure checks behind the product name and logo:
// name validation and PNG normalisation.
package branding

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxNameRunes bounds the product name, in characters after trimming.
	MaxNameRunes = 64
	// MaxLogoBytes bounds an upload and its re-encoding.
	MaxLogoBytes = 1 << 20
	// MaxLogoSide bounds each dimension, checked before any pixel is decoded.
	MaxLogoSide = 1024
)

var (
	ErrNotPNG         = errors.New("the logo is not a PNG image")
	ErrLogoTooLarge   = errors.New("the logo is larger than 1 MiB")
	ErrLogoDimensions = fmt.Errorf("the logo must be between 1×1 and %d×%d pixels", MaxLogoSide, MaxLogoSide)
)

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// ValidateName trims s and accepts 1 to MaxNameRunes characters of valid UTF-8 with no
// control, format (bidi overrides, zero-width characters) or line/paragraph separator
// character: the name lands in page titles and headers, where those reorder or hide text.
func ValidateName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", errors.New("the name is not valid UTF-8")
	}
	switch n := utf8.RuneCountInString(s); {
	case n == 0:
		return "", errors.New("the name is empty")
	case n > MaxNameRunes:
		return "", fmt.Errorf("the name is longer than %d characters", MaxNameRunes)
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", fmt.Errorf("the name contains an invisible or control character (U+%04X)", r)
		}
	}
	return s, nil
}

// NormalizePNG returns b decoded and re-encoded, so no ancillary chunk (text, EXIF, colour
// profile, animation) survives. The header's dimensions are refused before any pixel is
// decoded, which bounds the decode at MaxLogoSide² pixels whatever the header claims.
func NormalizePNG(b []byte) ([]byte, error) {
	if len(b) > MaxLogoBytes {
		return nil, ErrLogoTooLarge
	}
	if !bytes.HasPrefix(b, pngSignature) {
		return nil, ErrNotPNG
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, ErrNotPNG
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxLogoSide || cfg.Height > MaxLogoSide {
		return nil, ErrLogoDimensions
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, ErrNotPNG
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	if out.Len() > MaxLogoBytes {
		return nil, ErrLogoTooLarge
	}
	return out.Bytes(), nil
}
