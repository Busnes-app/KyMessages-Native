package blobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	// ErrInvalidKey is returned when a blob key does not match the strict flat identifier pattern.
	ErrInvalidKey = errors.New("blobs: invalid key")
	// ErrEmpty is returned when an uploaded payload has zero bytes.
	ErrEmpty = errors.New("blobs: empty payload")
	// ErrTooLarge is returned when an uploaded payload exceeds the configured maximum size.
	ErrTooLarge = errors.New("blobs: payload exceeds size limit")
)

// validKey restricts blob keys to flat, URL- and filesystem-safe identifiers (no slashes or dots).
var validKey = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,128}$`)

// PutResult describes a stored blob written by Put.
type PutResult struct {
	Key       string
	SizeBytes int64
	SHA256Hex string
	MimeType  string
}

// Store persists attachment bytes in a dedicated local directory outside the web root.
// All file access is confined through os.OpenRoot and strict flat key validation.
type Store struct {
	dir string
}

// NewStore creates a Store rooted at dir, creating the directory (0700) if needed.
func NewStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("blobs: directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("blobs: resolve directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("blobs: create directory: %w", err)
	}
	return &Store{dir: abs}, nil
}

// Dir returns the absolute root directory backing this store.
func (s *Store) Dir() string {
	return s.dir
}

// ValidKey reports whether key is a safe flat blob identifier.
func ValidKey(key string) bool {
	return validKey.MatchString(key)
}

// Put streams r into the store under key, enforcing 1 <= size <= maxBytes, computing SHA-256,
// sniffing and validating a safe MIME type, and atomically moving the file into place (mode 0600).
func (s *Store) Put(key string, r io.Reader, maxBytes int64) (PutResult, error) {
	if !ValidKey(key) {
		return PutResult{}, ErrInvalidKey
	}
	if maxBytes <= 0 {
		return PutResult{}, ErrTooLarge
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return PutResult{}, fmt.Errorf("blobs: ensure directory: %w", err)
	}

	tmp, err := os.CreateTemp(s.dir, ".upload-*")
	if err != nil {
		return PutResult{}, fmt.Errorf("blobs: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return PutResult{}, fmt.Errorf("blobs: chmod temp file: %w", err)
	}

	hasher := sha256.New()
	limited := io.LimitReader(r, maxBytes+1)
	n, err := io.Copy(io.MultiWriter(tmp, hasher), limited)
	if err != nil {
		return PutResult{}, err
	}
	if n == 0 {
		return PutResult{}, ErrEmpty
	}
	if n > maxBytes {
		return PutResult{}, ErrTooLarge
	}

	mimeType := detectSafeMIME(tmp, n)

	if err := tmp.Sync(); err != nil {
		return PutResult{}, fmt.Errorf("blobs: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return PutResult{}, fmt.Errorf("blobs: close temp file: %w", err)
	}

	destPath := filepath.Join(s.dir, key)
	if err := os.Rename(tmpPath, destPath); err != nil {
		return PutResult{}, fmt.Errorf("blobs: commit file: %w", err)
	}
	committed = true

	return PutResult{
		Key:       key,
		SizeBytes: n,
		SHA256Hex: hex.EncodeToString(hasher.Sum(nil)),
		MimeType:  mimeType,
	}, nil
}

// Open opens an existing blob strictly confined to the store root directory.
func (s *Store) Open(key string) (*os.File, int64, error) {
	if !ValidKey(key) {
		return nil, 0, ErrInvalidKey
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()

	f, err := root.Open(key)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, os.ErrNotExist
	}
	return f, info.Size(), nil
}

// Delete removes a blob if present. Missing files are not an error.
func (s *Store) Delete(key string) error {
	if !ValidKey(key) {
		return ErrInvalidKey
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()

	err = root.Remove(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// IsInlineSafeImage reports whether mimeType is a verified raster image format safe to render
// inline in an <img> element without active-content (XSS) risk. SVG is intentionally excluded.
func IsInlineSafeImage(mimeType string) bool {
	switch mimeType {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}

// SafeServeMIME returns a Content-Type header value safe to send on attachment downloads.
// Active web content types (HTML, SVG, XML, JS) always downgrade to application/octet-stream.
func SafeServeMIME(mimeType string) string {
	switch mimeType {
	case "image/png", "image/jpeg", "image/gif", "image/webp",
		"application/pdf", "application/zip", "application/gzip",
		"audio/mpeg", "audio/ogg", "audio/wav",
		"video/mp4", "video/webm",
		"text/plain; charset=utf-8":
		return mimeType
	default:
		return "application/octet-stream"
	}
}

// detectSafeMIME sniffs magic bytes from f and validates raster image headers so spoofed or
// active-content uploads (HTML, SVG, XML, polyglots) downgrade to application/octet-stream.
func detectSafeMIME(f *os.File, size int64) string {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "application/octet-stream"
	}
	header := make([]byte, 512)
	n, _ := io.ReadFull(f, header)
	header = header[:n]
	if len(header) == 0 {
		return "application/octet-stream"
	}

	detected := http.DetectContentType(header)
	switch {
	case detected == "image/png":
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			if cfg, err := png.DecodeConfig(f); err == nil && cfg.Width > 0 && cfg.Height > 0 {
				return "image/png"
			}
		}
		return "application/octet-stream"

	case detected == "image/jpeg":
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			if cfg, err := jpeg.DecodeConfig(f); err == nil && cfg.Width > 0 && cfg.Height > 0 {
				return "image/jpeg"
			}
		}
		return "application/octet-stream"

	case detected == "image/gif":
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			if cfg, err := gif.DecodeConfig(f); err == nil && cfg.Width > 0 && cfg.Height > 0 {
				return "image/gif"
			}
		}
		return "application/octet-stream"

	case detected == "image/webp":
		if isValidWebPHeader(header, size) {
			return "image/webp"
		}
		return "application/octet-stream"

	case detected == "application/pdf",
		detected == "application/zip",
		detected == "application/x-gzip",
		detected == "audio/mpeg",
		detected == "audio/wave",
		detected == "application/ogg",
		detected == "video/mp4",
		detected == "video/webm":
		switch detected {
		case "application/x-gzip":
			return "application/gzip"
		case "audio/wave":
			return "audio/wav"
		case "application/ogg":
			return "audio/ogg"
		default:
			return detected
		}

	case strings.HasPrefix(detected, "text/plain"):
		// Guard against XML/SVG/HTML fragments that happen to miss DetectContentType's prefix table.
		trimmed := bytes.TrimSpace(header)
		lower := strings.ToLower(string(trimmed))
		if strings.HasPrefix(lower, "<svg") ||
			strings.HasPrefix(lower, "<?xml") ||
			strings.HasPrefix(lower, "<!doctype") ||
			strings.HasPrefix(lower, "<html") ||
			strings.HasPrefix(lower, "<script") {
			return "application/octet-stream"
		}
		return "text/plain; charset=utf-8"

	default:
		return "application/octet-stream"
	}
}

// isValidWebPHeader checks RIFF....WEBP followed by a recognized VP8/VP8L/VP8X chunk tag.
func isValidWebPHeader(header []byte, totalSize int64) bool {
	if len(header) < 16 || totalSize < 20 {
		return false
	}
	if string(header[0:4]) != "RIFF" || string(header[8:12]) != "WEBP" {
		return false
	}
	chunk := string(header[12:16])
	return chunk == "VP8 " || chunk == "VP8L" || chunk == "VP8X"
}

// SanitizeFilename strips directory components, control characters, null bytes, and bidi
// overrides from an uploaded filename so it is safe in JSON metadata and Content-Disposition.
func SanitizeFilename(raw string) string {
	// Normalize Windows separators before extracting base name so traversal prefixes drop cleanly.
	s := strings.ReplaceAll(raw, "\\", "/")
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) || isBidiControl(r) || r == '"' {
			continue
		}
		b.WriteRune(r)
	}
	clean := strings.TrimSpace(b.String())
	clean = strings.TrimLeft(clean, ".")
	if clean == "" {
		return "attachment"
	}
	const maxLen = 200
	if len(clean) > maxLen {
		ext := filepath.Ext(clean)
		if len(ext) > 0 && len(ext) <= 20 && len(ext) < maxLen {
			stem := trimUTF8(clean[:len(clean)-len(ext)], maxLen-len(ext))
			if stem != "" {
				return stem + ext
			}
		}
		clean = trimUTF8(clean, maxLen)
	}
	if clean == "" {
		return "attachment"
	}
	return clean
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

func trimUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	n := 0
	for i := range s {
		if i > maxBytes {
			break
		}
		n = i
	}
	return s[:n]
}
