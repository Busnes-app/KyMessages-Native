package xwing_test

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky_server_base/internal/pqc/xwing"
)

// The draft-ietf-hpke-pq vector for KEM 0x647A (copied from ky-primitives recoverykey): this
// seed must give exactly this public key, or the KEM is not X-Wing as published.
func TestSeedDerivesThePublishedPublicKey(t *testing.T) {
	raw, err := os.ReadFile("testdata/xwing-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SkRm, PkRm string }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.SkRm)
	want, _ := hex.DecodeString(v.PkRm)
	k, err := xwing.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Public().Bytes(); !bytes.Equal(got, want) || len(got) != xwing.PublicKeyBytes {
		t.Fatalf("public key differs from the published vector")
	}
	if !bytes.Equal(k.Seed(), seed) {
		t.Fatal("seed does not round-trip")
	}
	// The same key ky-primitives/recoverykey (the suite's capsule KEM) derives.
	rk, err := recoverykey.FromSeed(seed)
	if err != nil || !bytes.Equal(rk.Public().Bytes(), want) {
		t.Fatalf("recoverykey disagrees: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	k, err := xwing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	info, aad, msg := []byte("kymessages.test.v1"), []byte("aad"), []byte("hello")
	sealed, err := xwing.Seal(k.Public(), info, aad, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != xwing.Version || len(sealed) != xwing.Overhead+len(msg) {
		t.Fatalf("wire format: version %d, %d bytes", sealed[0], len(sealed))
	}
	got, err := xwing.Open(k, info, aad, sealed)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open = %q, %v", got, err)
	}
	// Plain RFC 9180 base mode opens the bytes after the version: no custom construction.
	r, err := hpke.NewRecipient(sealed[1:1+xwing.EncBytes], mustHPKE(t, k.Seed()), hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open(aad, sealed[1+xwing.EncBytes:]); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("stdlib HPKE open = %q, %v", got, err)
	}

	other, _ := xwing.Generate()
	for name, c := range map[string]struct {
		k                xwing.PrivateKey
		info, aad, bytes []byte
	}{
		"wrong key":  {other, info, aad, sealed},
		"wrong info": {k, []byte("kymessages.other.v1"), aad, sealed},
		"wrong aad":  {k, info, []byte("other"), sealed},
		"version":    {k, info, aad, append([]byte{2}, sealed[1:]...)},
		"tampered":   {k, info, aad, append(append([]byte(nil), sealed[:len(sealed)-1]...), sealed[len(sealed)-1]^1)},
		"truncated":  {k, info, aad, sealed[:xwing.Overhead-1]},
		"zero key":   {xwing.PrivateKey{}, info, aad, sealed},
	} {
		if _, err := xwing.Open(c.k, c.info, c.aad, c.bytes); !errors.Is(err, xwing.ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mustHPKE(t *testing.T, seed []byte) hpke.PrivateKey {
	t.Helper()
	k, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyLengths(t *testing.T) {
	if _, err := xwing.FromSeed(make([]byte, 31)); !errors.Is(err, xwing.ErrKey) {
		t.Fatal(err)
	}
	if _, err := xwing.ParsePublicKey(make([]byte, xwing.PublicKeyBytes-1)); !errors.Is(err, xwing.ErrKey) {
		t.Fatal(err)
	}
	if _, err := xwing.Seal(xwing.PublicKey{}, nil, nil, nil); !errors.Is(err, xwing.ErrKey) {
		t.Fatal(err)
	}
}
