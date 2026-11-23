package blobs

import (
	"bytes"
	"crypto/rand"
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
	"sync/atomic"
	"time"
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

// Backend is what the attachment routes need from blob storage. Every call names the blob's
// org: a backend with the org layout keeps each org under orgs/<tenant_id>/att/, so one org's
// blobs are one prefix (DeletePrefix), and a flat backend ignores it.
type Backend interface {
	Put(tenantID, key string, r io.Reader, maxBytes int64) (PutResult, error)
	Open(tenantID, key string) (io.ReadSeekCloser, int64, error)
	Delete(tenantID, key string) error
	DeletePrefix(tenantID string) error
	SweepStaleTemps(olderThan time.Duration) int
}

// Store persists attachment bytes in a dedicated local directory outside the web root.
// All file access is confined through os.OpenRoot and strict key validation. Single mode keeps
// every blob flat in the directory; multi mode (NewOrgStore) uses the org layout.
type Store struct {
	dir  string
	orgs bool
	// flatFallback lets an org-layout read find a blob the relocation has not moved yet.
	flatFallback atomic.Bool
}

var _ Backend = (*Store)(nil)

// validTenant restricts org directory names (canonical UUIDs, or "default").
var validTenant = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// NewOrgStore is NewStore with the org layout, for multi mode. Reads fall back to the flat
// path until RelocationDone.
func NewOrgStore(dir string) (*Store, error) {
	s, err := NewStore(dir)
	if err != nil {
		return nil, err
	}
	s.orgs = true
	s.flatFallback.Store(true)
	return s, nil
}

// RelocationDone stops the flat-path fallback once every flat blob has moved.
func (s *Store) RelocationDone() { s.flatFallback.Store(false) }

// OrgLayout reports whether this store keeps each org under its own prefix.
func (s *Store) OrgLayout() bool { return s.orgs }

// rel is key's path inside the store: flat, or orgs/<tenant>/att/<key>.
func (s *Store) rel(tenantID, key string) (string, error) {
	if !ValidKey(key) {
		return "", ErrInvalidKey
	}
	if !s.orgs {
		return key, nil
	}
	if !validTenant.MatchString(tenantID) {
		return "", ErrInvalidKey
	}
	return "orgs/" + tenantID + "/att/" + key, nil
}

// NewStore creates a Store rooted at dir, creating the directory (0700) if needed
// and verifying that it is writable.
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
	probe, err := os.CreateTemp(abs, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("blobs: directory %q is not writable: %w", abs, err)
	}
	probePath := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probePath)
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
func (s *Store) Put(tenantID, key string, r io.Reader, maxBytes int64) (PutResult, error) {
	rel, err := s.rel(tenantID, key)
	if err != nil {
		return PutResult{}, err
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

	if s.orgs {
		if err := s.commitOrg(filepath.Base(tmpPath), rel); err != nil {
			return PutResult{}, err
		}
	} else if err := os.Rename(tmpPath, filepath.Join(s.dir, key)); err != nil {
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

// commitOrg moves a finished temp file into its org directory, inside the root.
func (s *Store) commitOrg(tmpName, rel string) error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return fmt.Errorf("blobs: create org directory: %w", err)
	}
	if err := root.Rename(tmpName, rel); err != nil {
		return fmt.Errorf("blobs: commit file: %w", err)
	}
	return nil
}

// Open opens an existing blob strictly confined to the store root directory.
func (s *Store) Open(tenantID, key string) (io.ReadSeekCloser, int64, error) {
	rel, err := s.rel(tenantID, key)
	if err != nil {
		return nil, 0, err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()

	f, err := root.Open(rel)
	if errors.Is(err, os.ErrNotExist) && s.orgs && s.flatFallback.Load() {
		f, err = root.Open(key)
	}
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
func (s *Store) Delete(tenantID, key string) error {
	rel, err := s.rel(tenantID, key)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()

	if s.orgs && s.flatFallback.Load() {
		// Flat copy first: a relocation that moves the blob between the two removes then finds
		// no source, and one that moved it earlier left it at rel, which is removed next.
		if err := root.Remove(key); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	err = root.Remove(rel)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// DeletePrefix removes every blob of tenantID, orphans included (org layout only; a flat
// store has no per-org prefix and refuses).
func (s *Store) DeletePrefix(tenantID string) error {
	if !s.orgs || !validTenant.MatchString(tenantID) {
		return ErrInvalidKey
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll("orgs/" + tenantID)
}

// Relocate moves one flat blob to its org path. Renames on one volume are atomic, and a blob
// already moved (or gone) is not an error, so a rerun after a crash is safe.
func (s *Store) Relocate(tenantID, key string) error {
	rel, err := s.rel(tenantID, key)
	if err != nil || !s.orgs {
		return ErrInvalidKey
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(key); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return err
	}
	if err := root.Rename(key, rel); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err // gone meanwhile: deleted, nothing to move
	}
	return nil
}

// SweepStaleTemps removes crashed .upload-* temp files older than olderThan inside the store.
func (s *Store) SweepStaleTemps(olderThan time.Duration) int {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return 0
	}
	defer root.Close()
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".upload-") || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := root.Remove(name); err == nil {
			removed++
		}
	}
	return removed
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

// storeIDFile names the volume: every replica must find the same ID in its directory as the
// database records, so a replica on a private disk refuses to start instead of losing blobs.
const storeIDFile = ".store-id"

// EnsureStoreID reads (or, on an empty volume, creates) the directory's store ID and passes it
// to claim, which returns the ID the database holds (the first replica's). A mismatch is an
// error: this directory is not the volume the other replicas share.
func (s *Store) EnsureStoreID(claim func(id string) (string, error)) error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	raw, err := root.ReadFile(storeIDFile)
	if errors.Is(err, os.ErrNotExist) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		// Written whole, then linked into place: no replica ever reads a partial ID.
		tmp := storeIDFile + "." + hex.EncodeToString(b[:4])
		cerr := root.WriteFile(tmp, []byte(hex.EncodeToString(b[:])), 0o600)
		if cerr == nil {
			cerr = root.Link(tmp, storeIDFile)
		}
		_ = root.Remove(tmp)
		if cerr != nil && !errors.Is(cerr, os.ErrExist) {
			return fmt.Errorf("blobs: write store ID: %w", cerr)
		}
		raw, err = root.ReadFile(storeIDFile) // ours, or a replica's that won the create
	}
	if err != nil {
		return fmt.Errorf("blobs: read store ID: %w", err)
	}
	id := strings.TrimSpace(string(raw))
	want, err := claim(id)
	if err != nil {
		return fmt.Errorf("blobs: record store ID: %w", err)
	}
	if want != id {
		return errors.New("blobs: KY_ATTACHMENTS_DIR is not the volume the other replicas use (its store ID differs from the database's); mount the shared volume")
	}
	return nil
}
