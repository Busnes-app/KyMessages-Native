package blobs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	sealAADPrefix = "kymessages-attachments/v1\x00"
	sealNonceSize = 12
	sealTagSize   = 16
	// SealedOverhead is the nonce and authentication tag in a v1 sealed blob.
	SealedOverhead = sealNonceSize + sealTagSize
)

// Sealer preserves the attachment mirror's v1 AES-256-GCM encoding. The identity
// is authenticated with the content: backup mirrors use the flat blob key;
// org-scoped objects must use their complete org/object key.
type Sealer struct{ aead cipher.AEAD }

func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("blobs: seal key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) Seal(identity string, plain []byte) ([]byte, error) {
	nonce := make([]byte, sealNonceSize, sealNonceSize+len(plain)+sealTagSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(sealAADPrefix+identity)), nil
}

// Open releases no plaintext unless both the complete content and its identity
// authenticate. Empty/truncated blobs retain the legacy mirror refusal.
func (s *Sealer) Open(identity string, sealed []byte) ([]byte, error) {
	if len(sealed) <= SealedOverhead {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, sealed[:sealNonceSize], sealed[sealNonceSize:], []byte(sealAADPrefix+identity))
}
