package e2eeid_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
)

var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

var b64 = base64.RawStdEncoding

func TestFieldsAreUnambiguous(t *testing.T) {
	a := e2eeid.Fields([]byte("ab"), []byte("c"))
	b := e2eeid.Fields([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("field lists share bytes")
	}
	if want := []byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0, 1, 'c'}; !bytes.Equal(a, want) {
		t.Fatalf("Fields = %v", a)
	}
}

func TestStatementsBindEveryField(t *testing.T) {
	k, _ := hybridsig.Generate()
	pub := k.Public()
	base := e2eeid.DeviceMessage("t1", "u1", "DEVICE01", "curve", "ed")
	sig, _ := k.Sign(e2eeid.DomainDevice, base)
	if pub.Verify(e2eeid.DomainDevice, base, sig) != nil {
		t.Fatal("device statement does not verify")
	}
	for name, m := range map[string][]byte{
		"other org":    e2eeid.DeviceMessage("t2", "u1", "DEVICE01", "curve", "ed"),
		"other user":   e2eeid.DeviceMessage("t1", "u2", "DEVICE01", "curve", "ed"),
		"other device": e2eeid.DeviceMessage("t1", "u1", "DEVICE02", "curve", "ed"),
		"other curve":  e2eeid.DeviceMessage("t1", "u1", "DEVICE01", "curvf", "ed"),
		"other ed":     e2eeid.DeviceMessage("t1", "u1", "DEVICE01", "curve", "ee"),
		"shifted":      e2eeid.DeviceMessage("t1", "u1D", "EVICE01", "curve", "ed"),
	} {
		if pub.Verify(e2eeid.DomainDevice, m, sig) == nil {
			t.Errorf("%s: replayed signature verified", name)
		}
	}
	// A device signature cannot pass as a master self-binding or a backup key statement.
	for _, d := range []string{e2eeid.DomainMaster, e2eeid.DomainBackupKey} {
		if pub.Verify(d, base, sig) == nil {
			t.Errorf("device signature verified under %s", d)
		}
	}
}

func TestFingerprintCoversTheWholeKey(t *testing.T) {
	k, _ := hybridsig.Generate()
	b := k.Public().Bytes()
	fp := e2eeid.Fingerprint(k.Public())
	// The last byte of the ML-DSA half, and the last byte of the Ed25519 half.
	for _, i := range []int{len(b) - 33, len(b) - 1} {
		q, err := hybridsig.ParsePublicKey(flipped(b, i))
		if err != nil {
			continue // not every flip still parses as a key; the next one does
		}
		if e2eeid.Fingerprint(q) == fp {
			t.Fatal("fingerprint ignores part of the key")
		}
	}
}

func flipped(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

func TestRecoveryKeyFormat(t *testing.T) {
	key, _ := e2eeid.NewSecret()
	text, err := e2eeid.FormatRecoveryKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if groups := strings.Fields(text); len(groups) != 14 || len(strings.ReplaceAll(text, " ", "")) != 56 {
		t.Fatalf("format: %q", text)
	}
	for _, typed := range []string{text, strings.ToLower(text), strings.ReplaceAll(text, " ", "-"), strings.ReplaceAll(strings.ReplaceAll(text, "0", "o"), "1", "l")} {
		got, err := e2eeid.ParseRecoveryKey(typed)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("parse %q: %v", typed, err)
		}
	}
	// One mistyped character fails the checksum.
	c := []byte(text)
	if c[0] == 'A' {
		c[0] = 'B'
	} else {
		c[0] = 'A'
	}
	for _, bad := range []string{string(c), text[:len(text)-1], text + "0", "U" + text[1:]} {
		if _, err := e2eeid.ParseRecoveryKey(bad); !errors.Is(err, e2eeid.ErrRecoveryKey) {
			t.Errorf("parse %q: %v", bad, err)
		}
	}
}

func TestRecoveryWrapBindsPurposeOrgAndUser(t *testing.T) {
	rk, _ := e2eeid.NewSecret()
	seed := bytes.Repeat([]byte{7}, e2eeid.MasterSeedBytes)
	w, err := e2eeid.WrapRecovery(rk, "master-key", "t1", "u1", seed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2eeid.UnwrapRecovery(rk, "master-key", "t1", "u1", w); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("unwrap: %v", err)
	}
	other, _ := e2eeid.NewSecret()
	for name, c := range map[string]struct {
		rk                  []byte
		purpose, org, owner string
	}{
		"wrong key":     {other, "master-key", "t1", "u1"},
		"other purpose": {rk, "backup-key", "t1", "u1"},
		"other org":     {rk, "master-key", "t2", "u1"},
		"other user":    {rk, "master-key", "t1", "u2"},
	} {
		if _, err := e2eeid.UnwrapRecovery(c.rk, c.purpose, c.org, c.owner, w); !errors.Is(err, e2eeid.ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e2eeid.WrapRecovery(rk, "session-key", "t1", "u1", seed); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

func TestBackupSealBindsEntryAndMaster(t *testing.T) {
	k, _ := xwing.Generate()
	m, _ := hybridsig.Generate()
	e := e2eeid.BackupEntry{RoomID: "room1", SenderKey: "senderA", SessionID: "sess1", FirstIndex: 7}
	sealed, err := e2eeid.SealBackup(k.Public(), e2eeid.MasterSeed(m), e, []byte("export"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2eeid.OpenBackup(k, e2eeid.MasterSeed(m), e, sealed); err != nil || string(got) != "export" {
		t.Fatalf("open: %v", err)
	}
	// Every named field is bound: a row moved to another room, sender, session or a lower first
	// index (to win the server's keep-the-lowest rule) does not open.
	for name, moved := range map[string]e2eeid.BackupEntry{
		"room":        {RoomID: "room2", SenderKey: "senderA", SessionID: "sess1", FirstIndex: 7},
		"sender key":  {RoomID: "room1", SenderKey: "senderB", SessionID: "sess1", FirstIndex: 7},
		"session":     {RoomID: "room1", SenderKey: "senderA", SessionID: "sess2", FirstIndex: 7},
		"first index": {RoomID: "room1", SenderKey: "senderA", SessionID: "sess1", FirstIndex: 0},
		"shifted":     {RoomID: "room1s", SenderKey: "enderA", SessionID: "sess1", FirstIndex: 7},
	} {
		if _, err := e2eeid.OpenBackup(k, e2eeid.MasterSeed(m), moved, sealed); !errors.Is(err, e2eeid.ErrOpen) {
			t.Errorf("%s: opened", name)
		}
	}
	// The server holds the backup public key and can seal to it, but not with the master seed:
	// a restore refuses what it forges.
	other, _ := hybridsig.Generate()
	forged, _ := e2eeid.SealBackup(k.Public(), e2eeid.MasterSeed(other), e, []byte("forged"))
	if _, err := e2eeid.OpenBackup(k, e2eeid.MasterSeed(m), e, forged); !errors.Is(err, e2eeid.ErrOpen) {
		t.Fatal("a session sealed without the master seed opened")
	}
}

func TestDeviceListIsCanonical(t *testing.T) {
	if _, err := e2eeid.DeviceListMessage("t", "u", 1, 1, []string{"B", "A"}); !errors.Is(err, e2eeid.ErrDeviceList) {
		t.Fatal("unsorted list accepted")
	}
	if _, err := e2eeid.DeviceListMessage("t", "u", 1, 1, []string{"A", "A"}); !errors.Is(err, e2eeid.ErrDeviceList) {
		t.Fatal("duplicate accepted")
	}
	a, _ := e2eeid.DeviceListMessage("t", "u", 1, 2, []string{"A", "B"})
	b, _ := e2eeid.DeviceListMessage("t", "u", 1, 2, []string{"AB"})
	c, _ := e2eeid.DeviceListMessage("t", "u", 1, 3, []string{"A", "B"})
	if bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("lists or epochs share an encoding")
	}
}

func TestTransferNeedsBothLayers(t *testing.T) {
	eph, _ := xwing.Generate()
	secret, _ := e2eeid.NewSecret()
	keys := []byte("keys")
	sealed, err := e2eeid.SealTransfer(eph.Public(), secret, "pair", "OLDDEVICE", "NEWDEVICE", keys)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2eeid.OpenTransfer(eph, secret, "pair", "OLDDEVICE", "NEWDEVICE", sealed); err != nil || !bytes.Equal(got, keys) {
		t.Fatalf("open: %v", err)
	}
	otherEph, _ := xwing.Generate()
	otherSecret, _ := e2eeid.NewSecret()
	// The X-Wing layer alone is not enough (the server could hold that key), nor the QR secret alone.
	if _, err := e2eeid.OpenTransfer(eph, otherSecret, "pair", "OLDDEVICE", "NEWDEVICE", sealed); !errors.Is(err, e2eeid.ErrOpen) {
		t.Fatal("opened without the QR secret")
	}
	if _, err := e2eeid.OpenTransfer(otherEph, secret, "pair", "OLDDEVICE", "NEWDEVICE", sealed); !errors.Is(err, e2eeid.ErrOpen) {
		t.Fatal("opened without the ephemeral key")
	}
	for _, c := range [][3]string{{"pair2", "OLDDEVICE", "NEWDEVICE"}, {"pair", "NEWDEVICE", "OLDDEVICE"}, {"pair", "OLDDEVICE", "THIRDDEV"}} {
		if _, err := e2eeid.OpenTransfer(eph, secret, c[0], c[1], c[2], sealed); !errors.Is(err, e2eeid.ErrOpen) {
			t.Errorf("%v opened", c)
		}
	}
}

func TestPinsNeedTheMasterSeed(t *testing.T) {
	k, _ := hybridsig.Generate()
	sealed, err := e2eeid.SealPins(e2eeid.MasterSeed(k), "t1", "u1", 1, []byte("pins"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2eeid.OpenPins(e2eeid.MasterSeed(k), "t1", "u1", 1, sealed); err != nil || string(got) != "pins" {
		t.Fatalf("open: %v", err)
	}
	other, _ := hybridsig.Generate()
	if _, err := e2eeid.OpenPins(e2eeid.MasterSeed(other), "t1", "u1", 1, sealed); !errors.Is(err, e2eeid.ErrOpen) {
		t.Fatal("opened under another master key")
	}
	if _, err := e2eeid.OpenPins(e2eeid.MasterSeed(k), "t1", "u2", 1, sealed); !errors.Is(err, e2eeid.ErrOpen) {
		t.Fatal("opened for another user")
	}
}

func TestComparisonCodeDependsOnSecretDeviceAndKey(t *testing.T) {
	s1, _ := e2eeid.NewSecret()
	s2, _ := e2eeid.NewSecret()
	c1, _ := e2eeid.ComparisonCode(s1, "pair", "DEV_A", []byte("key-a"))
	c2, _ := e2eeid.ComparisonCode(s2, "pair", "DEV_A", []byte("key-a"))
	c3, _ := e2eeid.ComparisonCode(s1, "pair", "DEV_A", []byte("key-b"))
	c4, _ := e2eeid.ComparisonCode(s1, "pair", "DEV_B", []byte("key-a"))
	if len(c1) != 6 || c1 == c2 && c1 == c3 && c1 == c4 {
		t.Fatalf("codes %s %s %s %s", c1, c2, c3, c4)
	}
	if _, err := e2eeid.ComparisonCode(s1, "pair", "", []byte("key-a")); err == nil {
		t.Fatal("a code without the joining device")
	}
}

// The device list digest is the browser's hash of the same fields.
func TestDeviceListDigest(t *testing.T) {
	got := e2eeid.DeviceListDigest([]string{"a", "bc"})
	want := must(t, "hash", "kymessages.device-list", "a", "bc").(string)
	if got != want || len(got) != 64 {
		t.Fatalf("digest %s, hash %s", got, want)
	}
}

func TestQRCodeRoundTrip(t *testing.T) {
	q := e2eeid.QRCode{PairingID: bytes.Repeat([]byte{1}, 16), Secret: bytes.Repeat([]byte{2}, 32), Fingerprint: bytes.Repeat([]byte{3}, 32)}
	b, err := q.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := e2eeid.ParseQRCode(b)
	if err != nil || !reflect.DeepEqual(got, q) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := e2eeid.ParseQRCode(b[:len(b)-1]); !errors.Is(err, e2eeid.ErrQR) {
		t.Fatal("short QR accepted")
	}
}

// --- Shared vectors: the same file runs through the WebAssembly build in web/src/pqc. ---

type vector struct {
	Name string   `json:"name"`
	Call string   `json:"call"`
	Args []string `json:"args"`
	// Want is the result; Error marks a call that must fail.
	Want  any  `json:"want,omitempty"`
	Error bool `json:"error,omitempty"`
}

const vectorsPath = "testdata/vectors.json"

func TestSharedVectors(t *testing.T) {
	if *update {
		writeVectors(t)
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 20 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		got, err := e2eeid.Call(v.Call, v.Args)
		if v.Error {
			if err == nil {
				t.Errorf("%s: want an error, got %v", v.Name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		// Compare through JSON, as the WebAssembly side does.
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(v.Want)
		if !bytes.Equal(g, w) {
			t.Errorf("%s: got %s, want %s", v.Name, g, w)
		}
	}
}

// seed derives a fixed test seed, so regenerated vectors keep their keys.
func seed(label string, n int) string {
	var out []byte
	for i := 0; len(out) < n; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		h = sha256.Sum256(append([]byte(label), h[:]...))
		out = append(out, h[:]...)
	}
	return b64.EncodeToString(out[:n])
}

func must(t *testing.T, name string, args ...string) any {
	t.Helper()
	v, err := e2eeid.Call(name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func obj(v any) map[string]string { return v.(map[string]string) }

// writeVectors regenerates the vector file. Signatures and seals are randomized, so they are
// made once here and frozen; every vector checks a deterministic step (derivation, encoding,
// verification or opening).
func writeVectors(t *testing.T) {
	const tenant, user, device = "00000000-0000-4000-8000-00000000000a", "usr_alice", "DEVICE_ALICE_1"
	const curve, ed = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU", "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY"
	str := func(v any) string { return v.(string) }
	ms := seed("master", e2eeid.MasterSeedBytes)
	mp := obj(must(t, "masterPublic", ms))
	xs := seed("backup", xwing.SeedBytes)
	xp := must(t, "xwingPublic", xs).(string)
	es := seed("ephemeral", xwing.SeedBytes)
	ep := must(t, "xwingPublic", es).(string)
	rk := seed("recovery", 32)
	rtext := must(t, "recoveryFormat", rk).(string)
	selfSig := str(must(t, "signMaster", ms, tenant, user))
	devSig := str(must(t, "signDevice", ms, tenant, user, device, curve, ed))
	bkSig := str(must(t, "signBackupKey", ms, tenant, user, "1", xp))
	plain := b64.EncodeToString([]byte(`{"session_key":"vector"}`))
	const sender = "c2VuZGVyIGN1cnZlMjU1MTkga2V5IGZvciB2ZWN0b3JzIQ"
	sealedBackup := must(t, "backupSeal", xp, ms, "room-1", sender, "session-1", "3", plain).(string)
	forgedBackup := must(t, "backupSeal", xp, seed("other", e2eeid.MasterSeedBytes), "room-1", sender, "session-1", "3", plain).(string)
	devList := str(must(t, "signDeviceList", ms, tenant, user, "1", "2", `["DEVICE_ALICE_1","DEVICE_ALICE_2"]`))
	digest := e2eeid.DeviceListDigest([]string{"DEVICE_ALICE_1", "DEVICE_ALICE_2"})
	reserve := str(must(t, "signDeviceListReserve", ms, tenant, user, "1", "1", digest))
	batch := `[{"room_id":"room-1","sender_key":"` + sender + `","session_id":"session-1","first_index":3,"sealed":"` + sealedBackup + `"}]`
	batchW := str(must(t, "signBackupWrite", ms, tenant, user, "1", "4", batch))
	wrapM := must(t, "recoveryWrap", rk, "master-key", tenant, user, ms).(string)
	wrapB := must(t, "recoveryWrap", rk, "backup-key", tenant, user, xs).(string)
	pairing := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))
	qr := obj(must(t, "qrNew", pairing, mp["fingerprint"]))
	transfer := must(t, "transferSeal", ep, qr["secret"], pairing, "DEVICE_ALICE_1", "DEVICE_ALICE_2", ms, xs).(string)
	code := must(t, "comparisonCode", qr["secret"], pairing, "DEVICE_ALICE_2", ep).(string)
	pins := b64.EncodeToString([]byte(`{"usr_bob":"fingerprint"}`))
	sealedPins := must(t, "pinsSeal", ms, tenant, user, "3", pins).(string)
	pinsWrite := str(must(t, "signPinsWrite", ms, tenant, user, "1", "3", sealedPins))

	tamperedAt := func(s string, i int) string {
		b, _ := b64.DecodeString(s)
		if i < 0 {
			i += len(b)
		}
		b[i] ^= 1
		return b64.EncodeToString(b)
	}
	tampered := func(s string) string {
		b, _ := b64.DecodeString(s)
		b[len(b)/2] ^= 1
		return b64.EncodeToString(b)
	}
	vs := []vector{
		{Name: "master public key from seed", Call: "masterPublic", Args: []string{ms}, Want: mp},
		{Name: "fingerprint", Call: "fingerprint", Args: []string{mp["public_key"]}, Want: mp["fingerprint"]},
		{Name: "master self-binding verifies", Call: "verifyMaster", Args: []string{mp["public_key"], tenant, user, selfSig}, Want: true},
		{Name: "master self-binding for another user", Call: "verifyMaster", Args: []string{mp["public_key"], tenant, "usr_bob", selfSig}, Want: false},
		{Name: "master self-binding for another org", Call: "verifyMaster", Args: []string{mp["public_key"], "default", user, selfSig}, Want: false},
		{Name: "device cross-signature verifies", Call: "verifyDevice", Args: []string{mp["public_key"], tenant, user, device, curve, ed, devSig}, Want: true},
		{Name: "device cross-signature, tampered ML-DSA half", Call: "verifyDevice", Args: []string{mp["public_key"], tenant, user, device, curve, ed, tamperedAt(devSig, 40)}, Want: false},
		{Name: "device cross-signature, tampered Ed25519 half", Call: "verifyDevice", Args: []string{mp["public_key"], tenant, user, device, curve, ed, tamperedAt(devSig, -1)}, Want: false},
		{Name: "device cross-signature on another device", Call: "verifyDevice", Args: []string{mp["public_key"], tenant, user, "DEVICE_ALICE_2", curve, ed, devSig}, Want: false},
		{Name: "self-binding is not a device signature", Call: "verifyDevice", Args: []string{mp["public_key"], tenant, user, device, curve, ed, selfSig}, Want: false},
		{Name: "backup key signature verifies", Call: "verifyBackupKey", Args: []string{mp["public_key"], tenant, user, "1", xp, bkSig}, Want: true},
		{Name: "backup key signature, other version", Call: "verifyBackupKey", Args: []string{mp["public_key"], tenant, user, "2", xp, bkSig}, Want: false},
		{Name: "X-Wing public key from seed", Call: "xwingPublic", Args: []string{xs}, Want: xp},
		{Name: "backup session opens", Call: "backupOpen", Args: []string{xs, ms, "room-1", sender, "session-1", "3", sealedBackup}, Want: plain},
		{Name: "backup session in another room", Call: "backupOpen", Args: []string{xs, ms, "room-2", sender, "session-1", "3", sealedBackup}, Error: true},
		{Name: "backup session under another sender", Call: "backupOpen", Args: []string{xs, ms, "room-1", "b3RoZXI", "session-1", "3", sealedBackup}, Error: true},
		{Name: "backup session claiming an earlier first index", Call: "backupOpen", Args: []string{xs, ms, "room-1", sender, "session-1", "0", sealedBackup}, Error: true},
		{Name: "backup session, tampered", Call: "backupOpen", Args: []string{xs, ms, "room-1", sender, "session-1", "3", tampered(sealedBackup)}, Error: true},
		{Name: "backup session forged without the master seed", Call: "backupOpen", Args: []string{xs, ms, "room-1", sender, "session-1", "3", forgedBackup}, Error: true},
		{Name: "reservation verifies", Call: "verifyDeviceListReserve", Args: []string{mp["public_key"], tenant, user, "1", "1", digest, reserve}, Want: true},
		{Name: "reservation from another epoch", Call: "verifyDeviceListReserve", Args: []string{mp["public_key"], tenant, user, "1", "2", digest, reserve}, Want: false},
		{Name: "reservation of another list", Call: "verifyDeviceListReserve", Args: []string{mp["public_key"], tenant, user, "1", "1", e2eeid.DeviceListDigest([]string{"DEVICE_EVIL"}), reserve}, Want: false},
		{Name: "a published list is no reservation", Call: "verifyDeviceListReserve", Args: []string{mp["public_key"], tenant, user, "1", "1", digest, devList}, Want: false},
		{Name: "a reservation is no published list", Call: "verifyDeviceList", Args: []string{mp["public_key"], tenant, user, "1", "2", `["DEVICE_ALICE_1","DEVICE_ALICE_2"]`, reserve}, Want: false},
		{Name: "device list verifies", Call: "verifyDeviceList", Args: []string{mp["public_key"], tenant, user, "1", "2", `["DEVICE_ALICE_1","DEVICE_ALICE_2"]`, devList}, Want: true},
		{Name: "device list at another epoch", Call: "verifyDeviceList", Args: []string{mp["public_key"], tenant, user, "1", "3", `["DEVICE_ALICE_1","DEVICE_ALICE_2"]`, devList}, Want: false},
		{Name: "device list with a device added", Call: "verifyDeviceList", Args: []string{mp["public_key"], tenant, user, "1", "2", `["DEVICE_ALICE_1","DEVICE_ALICE_2","DEVICE_EVIL"]`, devList}, Want: false},
		{Name: "pin write verifies", Call: "verifyPinsWrite", Args: []string{mp["public_key"], tenant, user, "1", "3", sealedPins, pinsWrite}, Want: true},
		{Name: "pin write at another counter", Call: "verifyPinsWrite", Args: []string{mp["public_key"], tenant, user, "1", "4", sealedPins, pinsWrite}, Want: false},
		{Name: "pin write over other ciphertext", Call: "verifyPinsWrite", Args: []string{mp["public_key"], tenant, user, "1", "3", tampered(sealedPins), pinsWrite}, Want: false},
		{Name: "backup write verifies", Call: "verifyBackupWrite", Args: []string{mp["public_key"], tenant, user, "1", "4", batch, batchW}, Want: true},
		{Name: "backup write with an entry moved", Call: "verifyBackupWrite", Args: []string{mp["public_key"], tenant, user, "1", "4", strings.Replace(batch, `"first_index":3`, `"first_index":0`, 1), batchW}, Want: false},
		{Name: "backup write for another version", Call: "verifyBackupWrite", Args: []string{mp["public_key"], tenant, user, "2", "4", batch, batchW}, Want: false},
		{Name: "backup write for another generation", Call: "verifyBackupWrite", Args: []string{mp["public_key"], tenant, user, "1", "5", batch, batchW}, Want: false},
		{Name: "hash", Call: "hash", Args: []string{"a", "bc"}, Want: "b534ce16ac9c8b36823f39a395ce8e0e3c7ad9605b82b5444f18cadacd217a5d"},
		{Name: "recovery key format", Call: "recoveryFormat", Args: []string{rk}, Want: rtext},
		{Name: "recovery key parse", Call: "recoveryParse", Args: []string{strings.ToLower(strings.ReplaceAll(rtext, " ", "-"))}, Want: rk},
		{Name: "recovery key with a typo", Call: "recoveryParse", Args: []string{"Z" + rtext[1:]}, Error: true},
		{Name: "recovery unwrap master key", Call: "recoveryUnwrap", Args: []string{rk, "master-key", tenant, user, wrapM}, Want: ms},
		{Name: "recovery unwrap backup key", Call: "recoveryUnwrap", Args: []string{rk, "backup-key", tenant, user, wrapB}, Want: xs},
		{Name: "recovery wrap for another purpose", Call: "recoveryUnwrap", Args: []string{rk, "backup-key", tenant, user, wrapM}, Error: true},
		{Name: "recovery wrap for another user", Call: "recoveryUnwrap", Args: []string{rk, "master-key", tenant, "usr_bob", wrapM}, Error: true},
		{Name: "QR text parses", Call: "qrParse", Args: []string{qr["text"]}, Want: map[string]string{"pairing_id": pairing, "secret": qr["secret"], "fingerprint": mp["fingerprint"]}},
		{Name: "comparison code", Call: "comparisonCode", Args: []string{qr["secret"], pairing, "DEVICE_ALICE_2", ep}, Want: code},
		{Name: "two-layer transfer opens", Call: "transferOpen", Args: []string{es, qr["secret"], pairing, "DEVICE_ALICE_1", "DEVICE_ALICE_2", transfer}, Want: map[string]string{"master_seed": ms, "backup_seed": xs}},
		{Name: "transfer without the QR secret", Call: "transferOpen", Args: []string{es, rk, pairing, "DEVICE_ALICE_1", "DEVICE_ALICE_2", transfer}, Error: true},
		{Name: "pins open", Call: "pinsOpen", Args: []string{ms, tenant, user, "3", sealedPins}, Want: pins},
		{Name: "pins replayed at another counter", Call: "pinsOpen", Args: []string{ms, tenant, user, "4", sealedPins}, Error: true},
		{Name: "pins under another master key", Call: "pinsOpen", Args: []string{seed("other", e2eeid.MasterSeedBytes), tenant, user, "3", sealedPins}, Error: true},
		{Name: "transfer to another device", Call: "transferOpen", Args: []string{es, qr["secret"], pairing, "DEVICE_ALICE_1", "DEVICE_ALICE_3", transfer}, Error: true},
	}
	out, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
