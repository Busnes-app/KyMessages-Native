package push

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// maxWebPushPlaintextBytes leaves comfortable headroom under the 4096-byte RFC 8291 record size
	// (header 86B + delimiter 1B + GCM tag 16B = 103B overhead).
	maxWebPushPlaintextBytes = 3800
	aes128GCMRecordSize      = 4096
	aes128GCMHeaderSize      = 16 + 4 + 1 + 65 // salt(16) || rs(4) || idlen(1) || as_public(65)
)

// ValidateSubscriptionKeys validates base64url-encoded Web Push p256dh (65-byte uncompressed P-256
// public key) and auth (16-byte authentication secret) keys from a browser PushSubscription.
func ValidateSubscriptionKeys(p256dhB64, authB64 string) (*ecdh.PublicKey, []byte, error) {
	p256dh, err := decodeBase64URL(p256dhB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid p256dh encoding: %w", err)
	}
	if len(p256dh) != 65 || p256dh[0] != 0x04 {
		return nil, nil, errors.New("p256dh must be a 65-byte uncompressed P-256 public key")
	}
	uaPub, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid p256dh public key: %w", err)
	}

	authSecret, err := decodeBase64URL(authB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid auth secret encoding: %w", err)
	}
	if len(authSecret) != 16 {
		return nil, nil, errors.New("auth secret must be 16 bytes")
	}
	return uaPub, authSecret, nil
}

// EncryptPayload encrypts plaintext for a Web Push subscription using RFC 8291 (aes128gcm).
func EncryptPayload(plaintext []byte, p256dhB64, authB64 string) ([]byte, error) {
	uaPub, authSecret, err := ValidateSubscriptionKeys(p256dhB64, authB64)
	if err != nil {
		return nil, err
	}
	asPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("push: generate ephemeral key: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("push: generate salt: %w", err)
	}
	return encryptPayloadWithParams(plaintext, uaPub, authSecret, asPriv, salt)
}

// encryptPayloadWithParams allows deterministic verification against RFC 8291 Section 5 test vectors.
func encryptPayloadWithParams(plaintext []byte, uaPub *ecdh.PublicKey, authSecret []byte, asPriv *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > maxWebPushPlaintextBytes {
		return nil, fmt.Errorf("push: plaintext too large (%d bytes, max %d)", len(plaintext), maxWebPushPlaintextBytes)
	}
	if len(salt) != 16 {
		return nil, errors.New("push: salt must be 16 bytes")
	}

	ecdhSecret, err := asPriv.ECDH(uaPub)
	if err != nil {
		return nil, fmt.Errorf("push: ecdh failed: %w", err)
	}

	uaPubBytes := uaPub.Bytes()
	asPubBytes := asPriv.PublicKey().Bytes()

	cek, nonce, err := deriveAES128GCMKeys(ecdhSecret, authSecret, salt, uaPubBytes, asPubBytes)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("push: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("push: aes-gcm: %w", err)
	}

	// RFC 8188 / RFC 8291: append 0x02 final-record delimiter.
	padded := make([]byte, len(plaintext)+1)
	copy(padded, plaintext)
	padded[len(plaintext)] = 0x02

	ciphertext := gcm.Seal(nil, nonce, padded, nil)

	out := make([]byte, aes128GCMHeaderSize+len(ciphertext))
	copy(out[0:16], salt)
	binary.BigEndian.PutUint32(out[16:20], aes128GCMRecordSize)
	out[20] = byte(len(asPubBytes)) // 65
	copy(out[21:86], asPubBytes)
	copy(out[86:], ciphertext)
	return out, nil
}

// deriveAES128GCMKeys computes the 16-byte CEK and 12-byte nonce per RFC 8291 Section 3.3 & 3.4.
func deriveAES128GCMKeys(ecdhSecret, authSecret, salt, uaPubBytes, asPubBytes []byte) (cek, nonce []byte, err error) {
	// key_info = "WebPush: info" || 0x00 || ua_public || as_public
	keyInfo := make([]byte, 0, len("WebPush: info")+1+len(uaPubBytes)+len(asPubBytes))
	keyInfo = append(keyInfo, "WebPush: info"...)
	keyInfo = append(keyInfo, 0x00)
	keyInfo = append(keyInfo, uaPubBytes...)
	keyInfo = append(keyInfo, asPubBytes...)

	ikm, err := hkdf.Key(sha256.New, ecdhSecret, authSecret, string(keyInfo), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("push: derive ikm: %w", err)
	}
	cek, err = hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, nil, fmt.Errorf("push: derive cek: %w", err)
	}
	nonce, err = hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, nil, fmt.Errorf("push: derive nonce: %w", err)
	}
	return cek, nonce, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty value")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
