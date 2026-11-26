// Package e2eeid is KyMessages' post-quantum identity and recovery layer (E3 of
// docs/superpowers/specs/2026-11-22-e2ee-design.md, §3 and §9): the statements a user's hybrid
// master key signs, its fingerprint, the recovery key and what it wraps, the key backup seal and
// the two-layer QR secret transfer. The server and the browser run this same Go code (the
// browser through web/pqc-wasm), so neither side re-implements an encoding.
//
// Every signed or authenticated field list goes through Fields, which length-prefixes each
// field, so no two lists share bytes, and every use has its own versioned label.
package e2eeid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"

	"github.com/Busnes-app/ky_server_base/internal/pqc/hybridsig"
	"github.com/Busnes-app/ky_server_base/internal/pqc/xwing"
)

// Labels. Each is a domain (signatures), an HKDF info or an HPKE info, never two of these.
const (
	DomainMaster      = "kymessages.master.v1"
	DomainDevice      = "kymessages.device.v2"
	DomainBackupKey   = "kymessages.backup-key.v1"
	DomainDeviceList  = "kymessages.device-list.v1"
	DomainPinsWrite   = "kymessages.pins-write.v1"
	DomainBackupWrite = "kymessages.backup-write.v1"
	labelFingerprint  = "kymessages.master-fingerprint.v1"
	labelRecovery     = "kymessages.recovery.v1"
	LabelRecoveryMKey = "kymessages.recovery.v1/master-key"
	LabelRecoveryBKey = "kymessages.recovery.v1/backup-key"
	labelRecoveryCode = "kymessages.recovery-key.v1"
	InfoBackup        = "kymessages.backup.v1"
	InfoQRTransfer    = "kymessages.qr-transfer.v1"
	infoQRInner       = "kymessages.qr-transfer.v1/inner"
	labelQRCode       = "kymessages.qr-transfer.v1/code"
	labelPins         = "kymessages.pins.v1"
	labelBackupMAC    = "kymessages.backup.v1/mac"
)

const (
	// SecretBytes is the recovery key's and the QR secret's length.
	SecretBytes = 32
	// FingerprintBytes is the master key fingerprint's length.
	FingerprintBytes = 32
	// PairingIDBytes is a QR pairing session ID's raw length.
	PairingIDBytes = 16
	wrapVersion    = 1
	nonceBytes     = 12
	// MaxSealedSession bounds one key backup entry (a sealed export is about 1.5 KB).
	MaxSealedSession = 4 << 10
)

var (
	// ErrOpen is every failure to unwrap or open: wrong key, wrong binding or tampering.
	ErrOpen = errors.New("e2eeid: cannot open")
	// ErrRecoveryKey reports a recovery key that does not parse or whose checksum fails.
	ErrRecoveryKey = errors.New("e2eeid: invalid recovery key")
	// ErrQR reports a QR payload that does not parse.
	ErrQR = errors.New("e2eeid: invalid verification code")
	// ErrDeviceList reports a device list that is not sorted and distinct.
	ErrDeviceList = errors.New("e2eeid: device list must be sorted and distinct")
)

// Fields is the canonical encoding of a field list: each field as a big-endian uint32 length
// and its bytes.
func Fields(fields ...[]byte) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	b := make([]byte, 0, n)
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func s(v string) []byte { return []byte(v) }

// MasterSeedBytes is a master key's seed as KyMessages stores and transfers it: the ML-DSA-65
// seed followed by the Ed25519 seed.
const MasterSeedBytes = 2 * hybridsig.SeedBytes

// MasterFromSeed rebuilds a master key from its 64-byte seed.
func MasterFromSeed(seed []byte) (*hybridsig.PrivateKey, error) {
	if len(seed) != MasterSeedBytes {
		return nil, hybridsig.ErrLength
	}
	return hybridsig.FromSeeds(seed[:hybridsig.SeedBytes], seed[hybridsig.SeedBytes:])
}

// MasterSeed is MasterFromSeed's input for k.
func MasterSeed(k *hybridsig.PrivateKey) []byte {
	m, e := k.Seeds()
	return append(m, e...)
}

// MasterSelfMessage is what a master key signs to bind itself to one user in one org.
func MasterSelfMessage(tenantID, userID string, pub *hybridsig.PublicKey) []byte {
	return Fields(s(hybridsig.Alg), s(tenantID), s(userID), pub.Bytes())
}

// DeviceMessage is what a master key signs to vouch for one of its user's devices: the
// device's vodozemac identity keys (unpadded base64, as vodozemac writes them).
func DeviceMessage(tenantID, userID, deviceID, curve25519, ed25519 string) []byte {
	return Fields(s(hybridsig.Alg), s(tenantID), s(userID), s(deviceID), s(curve25519), s(ed25519))
}

// BackupKeyMessage is what a master key signs to publish the user's X-Wing backup key.
func BackupKeyMessage(tenantID, userID string, version int64, pub []byte) []byte {
	return Fields(s(hybridsig.Alg), s(tenantID), s(userID), s(strconv.FormatInt(version, 10)), pub)
}

// DeviceListMessage is what a master key signs to name the user's devices at one epoch.
// deviceIDs must be sorted and distinct, so each list has one encoding. Clients trust only
// devices on the newest list they have seen, so a removed device stays removed even if the
// server lists its old row and cross-signature again.
func DeviceListMessage(tenantID, userID string, version, epoch int64, deviceIDs []string) ([]byte, error) {
	if !slices.IsSorted(deviceIDs) || len(slices.Compact(slices.Clone(deviceIDs))) != len(deviceIDs) {
		return nil, ErrDeviceList
	}
	fields := [][]byte{s(hybridsig.Alg), s(tenantID), s(userID), s(strconv.FormatInt(version, 10)), s(strconv.FormatInt(epoch, 10))}
	for _, id := range deviceIDs {
		fields = append(fields, s(id))
	}
	return Fields(fields...), nil
}

// DeviceListDigest names one proposed device list: lowercase hex SHA-256 of
// Fields("kymessages.device-list", ids...), the browser's pqc.hash of the same. A device
// reserves its digest before signing, so a proposal that loses the race is never signed.
func DeviceListDigest(deviceIDs []string) string {
	f := [][]byte{s("kymessages.device-list")}
	for _, id := range deviceIDs {
		f = append(f, s(id))
	}
	h := sha256.Sum256(Fields(f...))
	return hex.EncodeToString(h[:])
}

// PinsWriteMessage is what the master key signs to replace the sealed pin set: it names the
// org, user, identity version and new counter, and the SHA-256 of the sealed set, so the server
// stores only what a verified device wrote, at exactly that place.
func PinsWriteMessage(tenantID, userID string, version, counter int64, sealed []byte) []byte {
	d := sha256.Sum256(sealed)
	return Fields(s(hybridsig.Alg), s(tenantID), s(userID), s(strconv.FormatInt(version, 10)), s(strconv.FormatInt(counter, 10)), d[:])
}

// BackupWriteMessage is what the master key signs over one key backup write: the org, user,
// identity version, backup generation (bumped by each deletion, so an old write cannot refill
// a deleted backup) and each entry's (room, sender key, session, first index) with the SHA-256
// of its sealed bytes, in the order sent.
func BackupWriteMessage(tenantID, userID string, version, generation int64, entries []BackupEntry, sealed [][]byte) []byte {
	f := [][]byte{s(hybridsig.Alg), s(tenantID), s(userID), s(strconv.FormatInt(version, 10)), s(strconv.FormatInt(generation, 10)), s(strconv.Itoa(len(entries)))}
	for i, e := range entries {
		d := sha256.Sum256(sealed[i])
		f = append(f, e.fields(), d[:])
	}
	return Fields(f...)
}

// Fingerprint is SHA-256 over a label and the full hybrid master public key (its tagged
// encoding, which names the algorithm). Clients pin it.
func Fingerprint(pub *hybridsig.PublicKey) [FingerprintBytes]byte {
	h := sha256.New()
	h.Write([]byte(labelFingerprint))
	h.Write([]byte{0})
	h.Write(pub.Bytes())
	var out [FingerprintBytes]byte
	h.Sum(out[:0])
	return out
}

// --- Recovery key ---

// Crockford base32, which has no I, L, O or U, so a typed key survives common misreadings.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewSecret returns 32 random bytes: a recovery key or a QR secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretBytes)
	_, err := rand.Read(b)
	return b, err
}

func recoveryChecksum(key []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelRecoveryCode))
	h.Write([]byte{0})
	h.Write(key)
	return h.Sum(nil)[:2]
}

// FormatRecoveryKey writes a recovery key for a person to save: version 1, the key and a
// 2-byte checksum (35 bytes), as 56 Crockford base32 characters in groups of four.
func FormatRecoveryKey(key []byte) (string, error) {
	if len(key) != SecretBytes {
		return "", ErrRecoveryKey
	}
	raw := append(append([]byte{1}, key...), recoveryChecksum(key)...)
	var out []byte
	var acc uint64
	bits := 0
	for _, c := range raw {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			if len(out) > 0 && len(out)%5 == 4 {
				out = append(out, ' ')
			}
			out = append(out, crockford[(acc>>uint(bits))&31])
		}
	}
	return string(out), nil
}

// ParseRecoveryKey reads what FormatRecoveryKey wrote, ignoring case, spaces and dashes and
// reading O as 0 and I or L as 1. A wrong checksum or version is ErrRecoveryKey.
func ParseRecoveryKey(text string) ([]byte, error) {
	var raw []byte
	var acc uint64
	bits, n := 0, 0
	for _, r := range text {
		switch r {
		case ' ', '-', '\t', '\n', '\r':
			continue
		case 'o', 'O':
			r = '0'
		case 'i', 'I', 'l', 'L':
			r = '1'
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		v := -1
		for i := range len(crockford) {
			if rune(crockford[i]) == r {
				v = i
				break
			}
		}
		if v < 0 || n >= 56 {
			return nil, ErrRecoveryKey
		}
		n++
		acc = acc<<5 | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			raw = append(raw, byte(acc>>uint(bits)))
		}
	}
	if n != 56 || len(raw) != 35 || raw[0] != 1 {
		return nil, ErrRecoveryKey
	}
	key := raw[1:33]
	if !hmac.Equal(recoveryChecksum(key), raw[33:]) {
		return nil, ErrRecoveryKey
	}
	return key, nil
}

// --- AES-256-GCM under a derived key ---

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// sealSym is version ‖ nonce ‖ AES-256-GCM(HKDF-SHA256(secret, info), aad, msg). The
// secret is at least 32 random bytes.
func sealSym(secret []byte, info string, aad, msg []byte) ([]byte, error) {
	if len(secret) < SecretBytes {
		return nil, ErrOpen
	}
	key, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return nil, err
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceBytes, 1+nonceBytes+len(msg)+g.Overhead())
	out[0] = wrapVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return g.Seal(out, out[1:], msg, aad), nil
}

func openSym(secret []byte, info string, aad, sealed []byte) ([]byte, error) {
	if len(secret) < SecretBytes || len(sealed) < 1+nonceBytes+16 || sealed[0] != wrapVersion {
		return nil, ErrOpen
	}
	key, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return nil, ErrOpen
	}
	g, err := gcm(key)
	if err != nil {
		return nil, ErrOpen
	}
	msg, err := g.Open(nil, sealed[1:1+nonceBytes], sealed[1+nonceBytes:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return msg, nil
}

func recoveryLabel(purpose string) (string, error) {
	switch purpose {
	case "master-key":
		return LabelRecoveryMKey, nil
	case "backup-key":
		return LabelRecoveryBKey, nil
	}
	return "", ErrOpen
}

// WrapRecovery encrypts one private key seed under a subkey of the recovery key. purpose is
// "master-key" or "backup-key"; the AAD names the version, the purpose, the org and the user.
func WrapRecovery(recoveryKey []byte, purpose, tenantID, userID string, seed []byte) ([]byte, error) {
	label, err := recoveryLabel(purpose)
	if err != nil {
		return nil, err
	}
	return sealSym(recoveryKey, label, Fields(s(labelRecovery), s(label), s(tenantID), s(userID)), seed)
}

// UnwrapRecovery reverses WrapRecovery.
func UnwrapRecovery(recoveryKey []byte, purpose, tenantID, userID string, wrapped []byte) ([]byte, error) {
	label, err := recoveryLabel(purpose)
	if err != nil {
		return nil, err
	}
	return openSym(recoveryKey, label, Fields(s(labelRecovery), s(label), s(tenantID), s(userID)), wrapped)
}

// --- Pinned identities ---

func pinsAAD(tenantID, userID string, counter int64) []byte {
	return Fields(s(labelPins), s(tenantID), s(userID), s(strconv.FormatInt(counter, 10)))
}

// SealPins encrypts the user's set of pinned colleague fingerprints under a key derived from
// the master key seed, so only the user's verified devices can read or replace it. counter
// is the blob's version on the server, bound in, so a blob cannot be replayed at another one.
func SealPins(masterSeed []byte, tenantID, userID string, counter int64, pins []byte) ([]byte, error) {
	return sealSym(masterSeed, labelPins, pinsAAD(tenantID, userID, counter), pins)
}

// OpenPins reverses SealPins.
func OpenPins(masterSeed []byte, tenantID, userID string, counter int64, sealed []byte) ([]byte, error) {
	return openSym(masterSeed, labelPins, pinsAAD(tenantID, userID, counter), sealed)
}

// --- Key backup ---

// BackupEntry names one sealed session: its room, its sender's curve25519 key, its session ID
// and the first ratchet index the export covers. All four are bound into the AAD and the MAC.
type BackupEntry struct {
	RoomID, SenderKey, SessionID string
	FirstIndex                   int64
}

func (b BackupEntry) fields() []byte {
	return Fields(s(b.RoomID), s(b.SenderKey), s(b.SessionID), s(strconv.FormatInt(b.FirstIndex, 10)))
}

// backupMAC authenticates one entry under a key derived from the master key seed. Anyone with
// the backup public key (the server too) can seal to it; only the user's verified devices,
// which hold the master seed, can make an entry a restore accepts.
func backupMAC(masterSeed []byte, b BackupEntry, session []byte) ([]byte, error) {
	if len(masterSeed) != MasterSeedBytes {
		return nil, ErrOpen
	}
	k, err := hkdf.Key(sha256.New, masterSeed, nil, labelBackupMAC, 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write(Fields(b.fields(), session))
	return m.Sum(nil), nil
}

// SealBackup seals one Megolm session export to the user's X-Wing backup key, with info
// kymessages.backup.v1 and AAD Fields(room ID, sender key, session ID, first index); the
// plaintext is Fields(session, MAC).
func SealBackup(pub xwing.PublicKey, masterSeed []byte, b BackupEntry, session []byte) ([]byte, error) {
	mac, err := backupMAC(masterSeed, b, session)
	if err != nil {
		return nil, err
	}
	return xwing.Seal(pub, []byte(InfoBackup), b.fields(), Fields(session, mac))
}

// OpenBackup reverses SealBackup with the backup private key and checks the MAC.
func OpenBackup(priv xwing.PrivateKey, masterSeed []byte, b BackupEntry, sealed []byte) ([]byte, error) {
	out, err := xwing.Open(priv, []byte(InfoBackup), b.fields(), sealed)
	if err != nil || len(out) < 4+4+sha256.Size {
		return nil, ErrOpen
	}
	n := int(binary.BigEndian.Uint32(out))
	if n != len(out)-8-sha256.Size || binary.BigEndian.Uint32(out[4+n:]) != sha256.Size {
		return nil, ErrOpen
	}
	session, mac := out[4:4+n], out[8+n:]
	want, err := backupMAC(masterSeed, b, session)
	if err != nil || !hmac.Equal(mac, want) {
		return nil, ErrOpen
	}
	return session, nil
}

// --- QR verification and secret transfer ---

// QRCode is what a verified device shows: the pairing session, the one-time secret and the
// master key fingerprint. It never carries a public key.
type QRCode struct {
	PairingID   []byte
	Secret      []byte
	Fingerprint []byte
}

// QR payloads start with this version byte.
const qrVersion = 1

// Bytes is version ‖ pairing ID (16) ‖ secret (32) ‖ fingerprint (32).
func (q QRCode) Bytes() ([]byte, error) {
	if len(q.PairingID) != PairingIDBytes || len(q.Secret) != SecretBytes || len(q.Fingerprint) != FingerprintBytes {
		return nil, ErrQR
	}
	b := append([]byte{qrVersion}, q.PairingID...)
	b = append(b, q.Secret...)
	return append(b, q.Fingerprint...), nil
}

// ParseQRCode reverses Bytes.
func ParseQRCode(b []byte) (QRCode, error) {
	if len(b) != 1+PairingIDBytes+SecretBytes+FingerprintBytes || b[0] != qrVersion {
		return QRCode{}, ErrQR
	}
	return QRCode{
		PairingID:   append([]byte(nil), b[1:17]...),
		Secret:      append([]byte(nil), b[17:49]...),
		Fingerprint: append([]byte(nil), b[49:]...),
	}, nil
}

func transferAAD(pairingID, verifiedDevice, newDevice string) []byte {
	return Fields(s(InfoQRTransfer), s(pairingID), s(verifiedDevice), s(newDevice))
}

// ComparisonCode is the six digits both screens show before the verified device sends its
// keys: an HMAC under the QR secret of the pairing, the joining device's ID and its ephemeral
// key, so the server, which never sees the secret, cannot grind a substitute key or swap in
// another of the user's devices and show the same code.
func ComparisonCode(secret []byte, pairingID, newDevice string, ephemeralPub []byte) (string, error) {
	if len(secret) != SecretBytes || newDevice == "" {
		return "", ErrQR
	}
	m := hmac.New(sha256.New, secret)
	m.Write(Fields(s(labelQRCode), s(pairingID), s(newDevice), ephemeralPub))
	v := binary.BigEndian.Uint32(m.Sum(nil)) % 1_000_000
	code := strconv.FormatUint(uint64(v), 10)
	for len(code) < 6 {
		code = "0" + code
	}
	return code, nil
}

// SealTransfer is the two-layer transfer: AES-256-GCM under HKDF(secret, info
// kymessages.qr-transfer.v1/inner), then xwing.Seal (info kymessages.qr-transfer.v1) to
// the new device's ephemeral key. Either layer alone keeps the keys from the server.
func SealTransfer(ephemeral xwing.PublicKey, secret []byte, pairingID, verifiedDevice, newDevice string, keys []byte) ([]byte, error) {
	aad := transferAAD(pairingID, verifiedDevice, newDevice)
	inner, err := sealSym(secret, infoQRInner, aad, keys)
	if err != nil {
		return nil, err
	}
	return xwing.Seal(ephemeral, []byte(InfoQRTransfer), aad, inner)
}

// OpenTransfer reverses SealTransfer on the new device.
func OpenTransfer(ephemeral xwing.PrivateKey, secret []byte, pairingID, verifiedDevice, newDevice string, sealed []byte) ([]byte, error) {
	aad := transferAAD(pairingID, verifiedDevice, newDevice)
	inner, err := xwing.Open(ephemeral, []byte(InfoQRTransfer), aad, sealed)
	if err != nil {
		return nil, ErrOpen
	}
	return openSym(secret, infoQRInner, aad, inner)
}
