package e2eeid

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/Busnes-app/ky_server_base/internal/pqc/hybridsig"
	"github.com/Busnes-app/ky_server_base/internal/pqc/xwing"
)

// Call is the string API the browser reaches through web/pqc-wasm: every key, signature and
// ciphertext is unpadded standard base64, pairing IDs and QR text are unpadded base64url, and
// a result is a string, a bool or an object of strings. Native tests run the same table, so the
// shared vectors (testdata/vectors.json) pin both builds to the same bytes.
func Call(name string, args []string) (any, error) {
	c, ok := calls[name]
	if !ok {
		return nil, fmt.Errorf("e2eeid: unknown call %q", name)
	}
	if len(args) != c.n {
		return nil, fmt.Errorf("e2eeid: %s takes %d arguments", name, c.n)
	}
	return c.fn(args)
}

var (
	b64    = base64.RawStdEncoding
	b64url = base64.RawURLEncoding
	errArg = errors.New("e2eeid: invalid argument")
)

func dec(v string) ([]byte, error) {
	b, err := b64.DecodeString(v)
	if err != nil {
		return nil, errArg
	}
	return b, nil
}

func decAll(vs ...string) ([][]byte, error) {
	out := make([][]byte, len(vs))
	for i, v := range vs {
		b, err := dec(v)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func master(seed string) (*hybridsig.PrivateKey, error) {
	b, err := dec(seed)
	if err != nil {
		return nil, err
	}
	return MasterFromSeed(b)
}

// masterKey reads a public key in hybridsig's tagged encoding.
func masterKey(v string) (*hybridsig.PublicKey, error) {
	b, err := dec(v)
	if err != nil {
		return nil, err
	}
	return hybridsig.ParsePublicKey(b)
}

func pubObj(p *hybridsig.PublicKey) map[string]string {
	fp := Fingerprint(p)
	return map[string]string{"public_key": b64.EncodeToString(p.Bytes()), "fingerprint": hex.EncodeToString(fp[:])}
}

// A statement builder takes the signing key's public half and the statement's fields.
type statement func(pub *hybridsig.PublicKey, fields []string) ([]byte, error)

// verifyWith(domain, msg) takes (public_key, fields..., signature), each key and signature in
// hybridsig's tagged encoding.
func verifyWith(domain string, msg statement) func(a []string) (any, error) {
	return func(a []string) (any, error) {
		pub, err := masterKey(a[0])
		if err != nil {
			return false, nil
		}
		sig, err := dec(a[len(a)-1])
		if err != nil {
			return false, nil
		}
		m, err := msg(pub, a[1:len(a)-1])
		if err != nil {
			return false, nil
		}
		return pub.Verify(domain, m, sig) == nil, nil
	}
}

// signWith(domain, msg) takes (seed, fields...).
func signWith(domain string, msg statement) func(a []string) (any, error) {
	return func(a []string) (any, error) {
		k, err := master(a[0])
		if err != nil {
			return nil, err
		}
		m, err := msg(k.Public(), a[1:])
		if err != nil {
			return nil, err
		}
		sg, err := k.Sign(domain, m)
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(sg), nil
	}
}

func masterMsg(pub *hybridsig.PublicKey, a []string) ([]byte, error) {
	return MasterSelfMessage(a[0], a[1], pub), nil
}

func deviceMsg(_ *hybridsig.PublicKey, a []string) ([]byte, error) {
	return DeviceMessage(a[0], a[1], a[2], a[3], a[4]), nil
}

func backupKeyMsg(_ *hybridsig.PublicKey, a []string) ([]byte, error) {
	v, err := strconv.ParseInt(a[2], 10, 64)
	if err != nil || v < 1 {
		return nil, errArg
	}
	pub, err := dec(a[3])
	if err != nil {
		return nil, err
	}
	return BackupKeyMessage(a[0], a[1], v, pub), nil
}

func xwPub(v string) (xwing.PublicKey, error) {
	b, err := dec(v)
	if err != nil {
		return xwing.PublicKey{}, err
	}
	return xwing.ParsePublicKey(b)
}

func xwPriv(v string) (xwing.PrivateKey, error) {
	b, err := dec(v)
	if err != nil {
		return xwing.PrivateKey{}, err
	}
	return xwing.FromSeed(b)
}

type call struct {
	n  int
	fn func(a []string) (any, error)
}

var calls = map[string]call{
	// Master key (hybridsig ML-DSA-65 + Ed25519). Keys and signatures are hybridsig's tagged
	// encodings; the seed is MasterSeedBytes.
	"masterGenerate": {0, func([]string) (any, error) {
		k, err := hybridsig.Generate()
		if err != nil {
			return nil, err
		}
		out := pubObj(k.Public())
		out["seed"] = b64.EncodeToString(MasterSeed(k))
		return out, nil
	}},
	"masterPublic": {1, func(a []string) (any, error) {
		k, err := master(a[0])
		if err != nil {
			return nil, err
		}
		return pubObj(k.Public()), nil
	}},
	"fingerprint": {1, func(a []string) (any, error) {
		pub, err := masterKey(a[0])
		if err != nil {
			return nil, err
		}
		fp := Fingerprint(pub)
		return hex.EncodeToString(fp[:]), nil
	}},
	// signMaster(seed, tenant, user): the master key's self-binding.
	"signMaster": {3, signWith(DomainMaster, masterMsg)},
	// verifyMaster(public_key, tenant, user, signature)
	"verifyMaster": {4, verifyWith(DomainMaster, masterMsg)},
	// signDevice(seed, tenant, user, device, curve25519, ed25519)
	"signDevice": {6, signWith(DomainDevice, deviceMsg)},
	// verifyDevice(public_key, tenant, user, device, curve25519, ed25519, signature)
	"verifyDevice": {7, verifyWith(DomainDevice, deviceMsg)},
	// signBackupKey(seed, tenant, user, version, backup_public_key)
	"signBackupKey": {5, signWith(DomainBackupKey, backupKeyMsg)},
	// verifyBackupKey(public_key, tenant, user, version, backup_public_key, signature)
	"verifyBackupKey": {6, verifyWith(DomainBackupKey, backupKeyMsg)},

	// pinsSeal(master_seed, tenant, user, counter, plaintext) and pinsOpen(..., sealed).
	"pinsSeal": {5, pinsCall(SealPins)},
	"pinsOpen": {5, pinsCall(OpenPins)},

	// X-Wing keys and the key backup.
	"xwingGenerate": {0, func([]string) (any, error) {
		k, err := xwing.Generate()
		if err != nil {
			return nil, err
		}
		return map[string]string{"seed": b64.EncodeToString(k.Seed()), "public": b64.EncodeToString(k.Public().Bytes())}, nil
	}},
	"xwingPublic": {1, func(a []string) (any, error) {
		k, err := xwPriv(a[0])
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(k.Public().Bytes()), nil
	}},
	// backupSeal(backup_public_key, master_seed, room_id, session_id, plaintext)
	"backupSeal": {5, func(a []string) (any, error) {
		pub, err := xwPub(a[0])
		if err != nil {
			return nil, err
		}
		k, err := decAll(a[1], a[4])
		if err != nil {
			return nil, err
		}
		out, err := SealBackup(pub, k[0], a[2], a[3], k[1])
		return b64.EncodeToString(out), err
	}},
	// backupOpen(backup_seed, master_seed, room_id, session_id, sealed)
	"backupOpen": {5, func(a []string) (any, error) {
		k, err := xwPriv(a[0])
		if err != nil {
			return nil, err
		}
		b, err := decAll(a[1], a[4])
		if err != nil {
			return nil, err
		}
		out, err := OpenBackup(k, b[0], a[2], a[3], b[1])
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(out), nil
	}},

	// The recovery key and what it wraps.
	"recoveryGenerate": {0, func([]string) (any, error) {
		k, err := NewSecret()
		if err != nil {
			return nil, err
		}
		text, err := FormatRecoveryKey(k)
		return map[string]string{"key": b64.EncodeToString(k), "text": text}, err
	}},
	"recoveryFormat": {1, func(a []string) (any, error) {
		k, err := dec(a[0])
		if err != nil {
			return nil, err
		}
		return FormatRecoveryKey(k)
	}},
	"recoveryParse": {1, func(a []string) (any, error) {
		k, err := ParseRecoveryKey(a[0])
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(k), nil
	}},
	// recoveryWrap(recovery_key, purpose, tenant, user, seed)
	"recoveryWrap": {5, func(a []string) (any, error) {
		k, err := decAll(a[0], a[4])
		if err != nil {
			return nil, err
		}
		out, err := WrapRecovery(k[0], a[1], a[2], a[3], k[1])
		return b64.EncodeToString(out), err
	}},
	// recoveryUnwrap(recovery_key, purpose, tenant, user, wrapped)
	"recoveryUnwrap": {5, func(a []string) (any, error) {
		k, err := decAll(a[0], a[4])
		if err != nil {
			return nil, err
		}
		out, err := UnwrapRecovery(k[0], a[1], a[2], a[3], k[1])
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(out), nil
	}},

	// QR verification. qrNew(pairing_id, fingerprint_hex) makes the one-time secret and the
	// text to show; qrParse reads it back on the new device.
	"qrNew": {2, func(a []string) (any, error) {
		id, err1 := b64url.DecodeString(a[0])
		fp, err2 := hex.DecodeString(a[1])
		if err1 != nil || err2 != nil {
			return nil, ErrQR
		}
		secret, err := NewSecret()
		if err != nil {
			return nil, err
		}
		b, err := QRCode{PairingID: id, Secret: secret, Fingerprint: fp}.Bytes()
		if err != nil {
			return nil, err
		}
		return map[string]string{"secret": b64.EncodeToString(secret), "text": b64url.EncodeToString(b)}, nil
	}},
	"qrParse": {1, func(a []string) (any, error) {
		b, err := b64url.DecodeString(a[0])
		if err != nil {
			return nil, ErrQR
		}
		q, err := ParseQRCode(b)
		if err != nil {
			return nil, err
		}
		return map[string]string{"pairing_id": b64url.EncodeToString(q.PairingID), "secret": b64.EncodeToString(q.Secret), "fingerprint": hex.EncodeToString(q.Fingerprint)}, nil
	}},
	// comparisonCode(secret, pairing_id, ephemeral_public_key)
	"comparisonCode": {3, func(a []string) (any, error) {
		k, err := decAll(a[0], a[2])
		if err != nil {
			return nil, err
		}
		return ComparisonCode(k[0], a[1], k[1])
	}},
	// transferSeal(ephemeral_public_key, secret, pairing_id, verified_device, new_device, master_seed, backup_seed)
	"transferSeal": {7, func(a []string) (any, error) {
		pub, err := xwPub(a[0])
		if err != nil {
			return nil, err
		}
		k, err := decAll(a[1], a[5], a[6])
		if err != nil {
			return nil, err
		}
		if len(k[1]) != MasterSeedBytes || len(k[2]) != xwing.SeedBytes {
			return nil, errArg
		}
		out, err := SealTransfer(pub, k[0], a[2], a[3], a[4], Fields(k[1], k[2]))
		return b64.EncodeToString(out), err
	}},
	// transferOpen(ephemeral_seed, secret, pairing_id, verified_device, new_device, sealed)
	"transferOpen": {6, func(a []string) (any, error) {
		priv, err := xwPriv(a[0])
		if err != nil {
			return nil, err
		}
		k, err := decAll(a[1], a[5])
		if err != nil {
			return nil, err
		}
		keys, err := OpenTransfer(priv, k[0], a[2], a[3], a[4], k[1])
		if err != nil {
			return nil, err
		}
		ms, bs, ok := splitTransfer(keys)
		if !ok {
			return nil, ErrOpen
		}
		return map[string]string{"master_seed": b64.EncodeToString(ms), "backup_seed": b64.EncodeToString(bs)}, nil
	}},
}

func pinsCall(f func(seed []byte, tenantID, userID string, counter int64, b []byte) ([]byte, error)) func(a []string) (any, error) {
	return func(a []string) (any, error) {
		k, err := decAll(a[0], a[4])
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(a[3], 10, 64)
		if err != nil || n < 1 || len(k[0]) != MasterSeedBytes {
			return nil, errArg
		}
		out, err := f(k[0], a[1], a[2], n, k[1])
		if err != nil {
			return nil, err
		}
		return b64.EncodeToString(out), nil
	}
}

// splitTransfer reads Fields(master seed, backup seed) back.
func splitTransfer(b []byte) (masterSeed, backupSeed []byte, ok bool) {
	const m, x = MasterSeedBytes, xwing.SeedBytes
	if len(b) != 8+m+x || binary.BigEndian.Uint32(b) != m || binary.BigEndian.Uint32(b[4+m:]) != x {
		return nil, nil, false
	}
	return b[4 : 4+m], b[8+m:], true
}
