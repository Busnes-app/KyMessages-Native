// Package xwing seals messages to an X-Wing public key: HPKE base mode with KEM 0x647A
// (ML-KEM-768 with X25519, crypto/hpke.MLKEM768X25519), HKDF-SHA256 and AES-256-GCM.
//
// It follows the ky-primitives `xwing` plan (PQC Stack Plan, ky-primitives#80, "Shared code"):
// a keypair rebuilt from a 32-byte seed, as ky-primitives/recoverykey does, and
// Seal(pub, info, aad, msg) / Open(priv, info, aad, sealed) with the wire format
// version (1 byte) ‖ enc (1120 bytes) ‖ ciphertext. Once ky-primitives ships `xwing`, this
// package is replaced by that import.
package xwing

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"fmt"
)

const (
	// SeedBytes is the private key seed length.
	SeedBytes = 32
	// PublicKeyBytes is an ML-KEM-768 encapsulation key plus an X25519 point.
	PublicKeyBytes = 1184 + 32
	// EncBytes is an ML-KEM-768 ciphertext plus an X25519 point.
	EncBytes = 1088 + 32
	// Version is the first byte of every sealed message.
	Version byte = 1
	// Overhead is what Seal adds to a message: the version, enc and the AES-GCM tag.
	Overhead = 1 + EncBytes + 16
)

var (
	// ErrKey reports a seed or public key of the wrong length or encoding.
	ErrKey = errors.New("xwing: invalid key")
	// ErrOpen is every failure to open: a wrong key, info or AAD, a bad version or tampering.
	ErrOpen = errors.New("xwing: cannot open")
)

func kem() hpke.KEM   { return hpke.MLKEM768X25519() }
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.AES256GCM() }

// PrivateKey is an X-Wing private key and the seed it was built from.
type PrivateKey struct {
	seed [SeedBytes]byte
	key  hpke.PrivateKey
}

// PublicKey is an X-Wing public key.
type PublicKey struct {
	key hpke.PublicKey
}

// Generate makes a fresh keypair.
func Generate() (PrivateKey, error) {
	k, err := kem().GenerateKey()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("xwing: %w", err)
	}
	seed, err := k.Bytes()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("xwing: %w", err)
	}
	return FromSeed(seed)
}

// FromSeed rebuilds a private key from its 32-byte seed.
func FromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedBytes {
		return PrivateKey{}, ErrKey
	}
	k, err := kem().NewPrivateKey(seed)
	if err != nil {
		return PrivateKey{}, ErrKey
	}
	p := PrivateKey{key: k}
	copy(p.seed[:], seed)
	return p, nil
}

// ParsePublicKey reads a 1216-byte public key.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyBytes {
		return PublicKey{}, ErrKey
	}
	k, err := kem().NewPublicKey(b)
	if err != nil {
		return PublicKey{}, ErrKey
	}
	return PublicKey{key: k}, nil
}

// Seed returns a copy of the seed.
func (k PrivateKey) Seed() []byte { return bytes.Clone(k.seed[:]) }

// Public returns the matching public key.
func (k PrivateKey) Public() PublicKey {
	if k.key == nil {
		return PublicKey{}
	}
	return PublicKey{key: k.key.PublicKey()}
}

// Bytes returns the 1216-byte encoding, or nil for the zero key.
func (p PublicKey) Bytes() []byte {
	if p.key == nil {
		return nil
	}
	return bytes.Clone(p.key.Bytes())
}

// Seal encrypts msg to pub under info (a versioned label naming the use) and aad. One message
// per HPKE context, so each seal has its own encapsulation.
func Seal(pub PublicKey, info, aad, msg []byte) ([]byte, error) {
	if pub.key == nil {
		return nil, ErrKey
	}
	enc, s, err := hpke.NewSender(pub.key, kdf(), aead(), info)
	if err != nil {
		return nil, fmt.Errorf("xwing: %w", err)
	}
	ct, err := s.Seal(aad, msg)
	if err != nil {
		return nil, fmt.Errorf("xwing: %w", err)
	}
	out := make([]byte, 0, 1+len(enc)+len(ct))
	out = append(out, Version)
	out = append(out, enc...)
	return append(out, ct...), nil
}

// Open decrypts what Seal made for priv under the same info and aad.
func Open(priv PrivateKey, info, aad, sealed []byte) ([]byte, error) {
	if priv.key == nil || len(sealed) < Overhead || sealed[0] != Version {
		return nil, ErrOpen
	}
	r, err := hpke.NewRecipient(sealed[1:1+EncBytes], priv.key, kdf(), aead(), info)
	if err != nil {
		return nil, ErrOpen
	}
	msg, err := r.Open(aad, sealed[1+EncBytes:])
	if err != nil {
		return nil, ErrOpen
	}
	return msg, nil
}
