package blobs_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/blobs"
)

// Independent Node crypto AES-256-GCM vector for the pre-S3 mirror format:
// key bytes 0..31, nonce bytes 0..11, legacy flat-key authenticated identity.
const legacySealFixture = "000102030405060708090a0b0c7b9b7eb696a37ce832b7e7d48e190efaf6e640841a3c1455028bf1c9c8345169d8aa4b8fe6e981cf606a82"

func fixtureKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestSealerReadsLegacyMirrorBytes(t *testing.T) {
	s, err := blobs.NewSealer(fixtureKey())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := hex.DecodeString(legacySealFixture)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open("att_legacy_fixture", sealed)
	if err != nil || string(plain) != "KyMessages legacy attachment" {
		t.Fatalf("legacy v1 bytes: %q %v", plain, err)
	}
}

func TestSealerAuthenticatesContentAndOrgObjectIdentity(t *testing.T) {
	s, err := blobs.NewSealer(fixtureKey())
	if err != nil {
		t.Fatal(err)
	}
	const identity = "orgs/00000000-0000-4000-8000-0000000000a1/att/att_example"
	plain := []byte("object ciphertext from the client")
	sealed, err := s.Seal(identity, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != len(plain)+blobs.SealedOverhead {
		t.Fatal("v1 size changed")
	}
	opened, err := s.Open(identity, sealed)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("round trip: %q %v", opened, err)
	}
	again, err := s.Seal(identity, plain)
	if err != nil || bytes.Equal(again, sealed) {
		t.Fatal("sealing reused a nonce")
	}
	refused := func(name, id string, data []byte) {
		t.Helper()
		got, err := s.Open(id, data)
		if err == nil || len(got) != 0 {
			t.Fatalf("%s released unauthenticated bytes: %q %v", name, got, err)
		}
	}
	refused("wrong org", "orgs/00000000-0000-4000-8000-0000000000b1/att/att_example", sealed)
	refused("wrong object", identity+"_other", sealed)
	corrupt := bytes.Clone(sealed)
	corrupt[len(corrupt)-1] ^= 1
	refused("bad tag", identity, corrupt)
	corrupt = bytes.Clone(sealed)
	corrupt[12] ^= 1
	refused("bad content", identity, corrupt)
	for _, n := range []int{0, 12, blobs.SealedOverhead, len(sealed) - 1} {
		refused("truncated", identity, sealed[:n])
	}
	wrong, err := blobs.NewSealer(bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := wrong.Open(identity, sealed); err == nil || len(got) != 0 {
		t.Fatalf("wrong key: %q %v", got, err)
	}
}

func TestSealerRequiresAES256Key(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := blobs.NewSealer(make([]byte, n)); err == nil {
			t.Fatalf("accepted %d-byte key", n)
		}
	}
}
