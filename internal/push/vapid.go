package push

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VAPIDKey holds the server's P-256 VAPID signing key pair (RFC 8292).
type VAPIDKey struct {
	private *ecdsa.PrivateKey
	rawPriv []byte // 32-byte big-endian scalar
	rawPub  []byte // 65-byte uncompressed SEC 1 point (0x04 || X || Y)
	pubB64  string // RawURLEncoding of rawPub (applicationServerKey)
}

// GenerateVAPIDKey creates a new P-256 VAPID key pair.
func GenerateVAPIDKey() (*VAPIDKey, error) {
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("push: generate vapid key: %w", err)
	}
	return ParseVAPIDPrivateKey(base64.RawURLEncoding.EncodeToString(ecdhKey.Bytes()))
}

// ParseVAPIDPrivateKey decodes a base64url-encoded (raw or padded) 32-byte P-256 private scalar.
func ParseVAPIDPrivateKey(encoded string) (*VAPIDKey, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, errors.New("push: empty vapid private key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("push: decode vapid private key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("push: vapid private key must be 32 bytes, got %d", len(raw))
	}
	ecdhKey, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("push: invalid P-256 scalar: %w", err)
	}
	pubBytes := ecdhKey.PublicKey().Bytes()
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return nil, errors.New("push: unexpected P-256 public key encoding")
	}
	d := new(big.Int).SetBytes(raw)
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}
	privCopy := make([]byte, 32)
	copy(privCopy, raw)
	pubCopy := make([]byte, 65)
	copy(pubCopy, pubBytes)
	return &VAPIDKey{
		private: priv,
		rawPriv: privCopy,
		rawPub:  pubCopy,
		pubB64:  base64.RawURLEncoding.EncodeToString(pubCopy),
	}, nil
}

// PublicKeyBase64 returns the uncompressed P-256 public key as base64url (no padding),
// suitable for PushManager.subscribe({ applicationServerKey }).
func (k *VAPIDKey) PublicKeyBase64() string {
	if k == nil {
		return ""
	}
	return k.pubB64
}

// PrivateKeyBase64 returns the 32-byte raw scalar encoded as base64url (no padding).
func (k *VAPIDKey) PrivateKeyBase64() string {
	if k == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(k.rawPriv)
}

// LoadOrCreateVAPIDKey loads a persisted VAPID private key from path, or atomically generates
// and persists a new key (mode 0600) if path does not yet exist.
func LoadOrCreateVAPIDKey(path string) (*VAPIDKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		return ParseVAPIDPrivateKey(string(raw))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("push: read vapid key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("push: create vapid key dir: %w", err)
	}

	key, err := GenerateVAPIDKey()
	if err != nil {
		return nil, err
	}
	content := []byte(key.PrivateKeyBase64() + "\n")

	// Write a synced temp file and hard-link it into place, so a crash never leaves a partial key.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vapid-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("push: create vapid key file: %w", err)
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("push: write vapid key file: %w", err)
	}
	if err := os.Link(tmp.Name(), path); errors.Is(err, os.ErrExist) {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("push: read raced vapid key: %w", readErr)
		}
		return ParseVAPIDPrivateKey(string(raw))
	} else if err != nil {
		return nil, fmt.Errorf("push: link vapid key file: %w", err)
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return key, nil
}

// DefaultVAPIDSubject derives a valid RFC 8292 subject ("mailto:..." or "https://...")
// from the configured subject override or the application URL.
func DefaultVAPIDSubject(configured, appURL string) string {
	s := strings.TrimSpace(configured)
	if validVAPIDSubject(s) {
		return s
	}
	if u, err := url.Parse(strings.TrimSpace(appURL)); err == nil && u.Host != "" {
		if u.Scheme == "https" {
			return "https://" + u.Host
		}
		host := u.Hostname()
		if host != "" && !strings.Contains(host, ":") {
			return "mailto:admin@" + host
		}
	}
	return "mailto:admin@localhost"
}

func validVAPIDSubject(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	if strings.HasPrefix(s, "mailto:") {
		addr := strings.TrimPrefix(s, "mailto:")
		return strings.Contains(addr, "@") && !strings.ContainsAny(addr, " \t\r\n")
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// AuthorizationHeader signs an RFC 8292 VAPID Authorization header ("vapid t=<jwt>, k=<pub>")
// scoped to endpoint's origin with the provided subject and lifetime.
func (k *VAPIDKey) AuthorizationHeader(endpoint *url.URL, subject string, ttl time.Duration, now time.Time) (string, error) {
	if k == nil || k.private == nil {
		return "", errors.New("push: vapid key not initialized")
	}
	if endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", errors.New("push: invalid endpoint for vapid audience")
	}
	if !validVAPIDSubject(subject) {
		return "", errors.New("push: invalid vapid subject")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 12 * time.Hour
	}

	aud := endpoint.Scheme + "://" + endpoint.Host
	headerJSON := `{"typ":"JWT","alg":"ES256"}`
	claimsBytes, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{
		Aud: aud,
		Exp: now.Add(ttl).Unix(),
		Sub: subject,
	})
	if err != nil {
		return "", fmt.Errorf("push: marshal vapid claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." +
		base64.RawURLEncoding.EncodeToString(claimsBytes)

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", fmt.Errorf("push: sign vapid jwt: %w", err)
	}

	// RFC 7515 ES256 requires fixed 64-byte IEEE P1363 format (r || s, each 32 bytes big-endian).
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return "vapid t=" + token + ", k=" + k.pubB64, nil
}
