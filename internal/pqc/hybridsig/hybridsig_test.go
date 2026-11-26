package hybridsig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/pqc/hybridsig"
)

func TestDigestIsDomainNulMessage(t *testing.T) {
	d, err := hybridsig.Digest("kymessages.test.v1", []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256([]byte("kymessages.test.v1\x00msg")); d != want {
		t.Fatal("digest is not SHA-256(domain || 0x00 || msg)")
	}
	for _, bad := range []string{"", "a\x00b"} {
		if _, err := hybridsig.Digest(bad, nil); !errors.Is(err, hybridsig.ErrDomain) {
			t.Fatalf("domain %q: %v", bad, err)
		}
	}
}

func TestSignVerifyNeedsBothHalves(t *testing.T) {
	k, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public()
	if pub.Check() != nil || len(pub.MLDSA65) != hybridsig.MLDSA65PublicKeyBytes {
		t.Fatal("public key sizes")
	}
	msg := []byte("statement")
	sig, err := k.Sign("kymessages.test.v1", msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify("kymessages.test.v1", msg, sig); err != nil {
		t.Fatal(err)
	}
	// Each half is a standard signature over the digest: ML-DSA-65 with an empty context, pure Ed25519.
	d, _ := hybridsig.Digest("kymessages.test.v1", msg)
	mpk, _ := mldsa.NewPublicKey(mldsa.MLDSA65(), pub.MLDSA65)
	if mldsa.Verify(mpk, d[:], sig.MLDSA65, &mldsa.Options{}) != nil || !ed25519.Verify(pub.Ed25519, d[:], sig.Ed25519) {
		t.Fatal("halves are not standard signatures over the digest")
	}

	other, _ := hybridsig.Generate()
	otherSig, _ := other.Sign("kymessages.test.v1", msg)
	flip := func(b []byte) []byte { c := bytes.Clone(b); c[0] ^= 1; return c }
	for name, c := range map[string]struct {
		domain string
		msg    []byte
		sig    hybridsig.Signature
	}{
		"other domain":                 {"kymessages.other.v1", msg, sig},
		"other message":                {"kymessages.test.v1", []byte("other"), sig},
		"tampered ML-DSA half":         {"kymessages.test.v1", msg, hybridsig.Signature{MLDSA65: flip(sig.MLDSA65), Ed25519: sig.Ed25519}},
		"tampered Ed25519":             {"kymessages.test.v1", msg, hybridsig.Signature{MLDSA65: sig.MLDSA65, Ed25519: flip(sig.Ed25519)}},
		"ML-DSA half from another key": {"kymessages.test.v1", msg, hybridsig.Signature{MLDSA65: otherSig.MLDSA65, Ed25519: sig.Ed25519}},
		"Ed25519 from another key":     {"kymessages.test.v1", msg, hybridsig.Signature{MLDSA65: sig.MLDSA65, Ed25519: otherSig.Ed25519}},
		"missing ML-DSA half":          {"kymessages.test.v1", msg, hybridsig.Signature{Ed25519: sig.Ed25519}},
		"missing Ed25519 half":         {"kymessages.test.v1", msg, hybridsig.Signature{MLDSA65: sig.MLDSA65}},
	} {
		if err := pub.Verify(c.domain, c.msg, c.sig); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

func TestSeedRoundTrip(t *testing.T) {
	k, _ := hybridsig.Generate()
	seed := k.Seed()
	if len(seed) != hybridsig.SeedBytes {
		t.Fatalf("seed is %d bytes", len(seed))
	}
	k2, err := hybridsig.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k2.Public().MLDSA65, k.Public().MLDSA65) || !bytes.Equal(k2.Public().Ed25519, k.Public().Ed25519) {
		t.Fatal("seed does not rebuild the key")
	}
	if _, err := hybridsig.FromSeed(seed[:63]); !errors.Is(err, hybridsig.ErrKey) {
		t.Fatal(err)
	}
}
