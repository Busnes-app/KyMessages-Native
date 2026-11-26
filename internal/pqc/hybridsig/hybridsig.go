// Package hybridsig is the Ky hybrid signature: ML-DSA-65 (crypto/mldsa, empty context) and
// pure Ed25519, both over the same domain-separated SHA-256 digest, and both required to
// verify. It is the construction of kyguard-server internal/pqcrypto/sig.go, which the
// ky-primitives `hybridsig` plan lifts (PQC Stack Plan, ky-primitives#80); it is a Ky-internal
// format, not the RFC 10073 X.509 composite. Once ky-primitives ships `hybridsig`, this package
// is replaced by that import.
package hybridsig

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	// Alg names the algorithm in every signed statement and on the wire.
	Alg = "mldsa65+ed25519"
	// SeedBytes is one private key's seed: the ML-DSA-65 seed then the Ed25519 seed.
	SeedBytes = mldsa.PrivateKeySize + ed25519.SeedSize
	// MLDSA65PublicKeyBytes and MLDSA65SignatureBytes are ML-DSA-65's sizes (FIPS 204).
	MLDSA65PublicKeyBytes = 1952
	MLDSA65SignatureBytes = 3309
)

var (
	// ErrKey reports a seed or public key of the wrong length or encoding.
	ErrKey = errors.New("hybridsig: invalid key")
	// ErrSignature reports a signature that does not verify, in either half.
	ErrSignature = errors.New("hybridsig: invalid signature")
	// ErrDomain reports an empty domain or one containing NUL.
	ErrDomain = errors.New("hybridsig: invalid domain")
)

var opts = &mldsa.Options{Context: ""}

// Digest is SHA-256(domain ‖ 0x00 ‖ msg): what both halves sign.
func Digest(domain string, msg []byte) ([32]byte, error) {
	if domain == "" || strings.IndexByte(domain, 0) >= 0 {
		return [32]byte{}, ErrDomain
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(msg)
	var d [32]byte
	h.Sum(d[:0])
	return d, nil
}

// PublicKey is a hybrid public key.
type PublicKey struct {
	MLDSA65 []byte
	Ed25519 []byte
}

// Signature carries both halves over the same digest.
type Signature struct {
	MLDSA65 []byte
	Ed25519 []byte
}

// Check reports whether p has the right sizes and a valid ML-DSA-65 encoding.
func (p PublicKey) Check() error {
	if len(p.MLDSA65) != MLDSA65PublicKeyBytes || len(p.Ed25519) != ed25519.PublicKeySize {
		return ErrKey
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), p.MLDSA65); err != nil {
		return ErrKey
	}
	return nil
}

// Verify checks both halves of sig over Digest(domain, msg). Both are always computed;
// either failing rejects.
func (p PublicKey) Verify(domain string, msg []byte, sig Signature) error {
	if len(p.MLDSA65) != MLDSA65PublicKeyBytes || len(p.Ed25519) != ed25519.PublicKeySize {
		return ErrKey
	}
	if len(sig.MLDSA65) != MLDSA65SignatureBytes || len(sig.Ed25519) != ed25519.SignatureSize {
		return ErrSignature
	}
	d, err := Digest(domain, msg)
	if err != nil {
		return err
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), p.MLDSA65)
	if err != nil {
		return ErrKey
	}
	errM := mldsa.Verify(pk, d[:], sig.MLDSA65, opts)
	okE := ed25519.Verify(ed25519.PublicKey(p.Ed25519), d[:], sig.Ed25519)
	if errM != nil || !okE {
		return ErrSignature
	}
	return nil
}

// PrivateKey is a hybrid signing key.
type PrivateKey struct {
	mldsa *mldsa.PrivateKey
	ed    ed25519.PrivateKey
}

// Generate makes a fresh key.
func Generate() (*PrivateKey, error) {
	m, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	_, ed, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	return &PrivateKey{mldsa: m, ed: ed}, nil
}

// FromSeed rebuilds a key from Seed's 64 bytes.
func FromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedBytes {
		return nil, ErrKey
	}
	m, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:mldsa.PrivateKeySize])
	if err != nil {
		return nil, ErrKey
	}
	return &PrivateKey{mldsa: m, ed: ed25519.NewKeyFromSeed(seed[mldsa.PrivateKeySize:])}, nil
}

// Seed returns the ML-DSA-65 seed followed by the Ed25519 seed.
func (k *PrivateKey) Seed() []byte {
	return append(k.mldsa.Bytes(), k.ed.Seed()...)
}

// Public returns the hybrid public key.
func (k *PrivateKey) Public() PublicKey {
	return PublicKey{
		MLDSA65: k.mldsa.PublicKey().Bytes(),
		Ed25519: append([]byte(nil), k.ed.Public().(ed25519.PublicKey)...),
	}
}

// Sign signs Digest(domain, msg) with both halves: hedged ML-DSA-65 and pure Ed25519.
func (k *PrivateKey) Sign(domain string, msg []byte) (Signature, error) {
	d, err := Digest(domain, msg)
	if err != nil {
		return Signature{}, err
	}
	m, err := k.mldsa.Sign(nil, d[:], opts)
	if err != nil {
		return Signature{}, fmt.Errorf("hybridsig: %w", err)
	}
	return Signature{MLDSA65: m, Ed25519: ed25519.Sign(k.ed, d[:])}, nil
}
