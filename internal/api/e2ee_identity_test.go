package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
	"github.com/Busnes-app/ky_server_base/internal/pqc/hybridsig"
	"github.com/Busnes-app/ky_server_base/internal/pqc/xwing"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

const (
	orgA = "00000000-0000-4000-8000-00000000000a"
	orgB = "00000000-0000-4000-8000-00000000000b"
)

// testIdentity is a client's E3 identity: a hybrid master key and an X-Wing backup key.
type testIdentity struct {
	tenant, user string
	master       *hybridsig.PrivateKey
	backup       xwing.PrivateKey
	recovery     []byte
}

func newIdentity(t *testing.T, tenant, user string) *testIdentity {
	t.Helper()
	m, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := xwing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := e2eeid.NewSecret()
	return &testIdentity{tenant, user, m, b, rk}
}

func (i *testIdentity) sign(t *testing.T, domain string, msg []byte) string {
	t.Helper()
	s, err := i.master.Sign(domain, msg)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(s)
}

// put is the PUT /api/v1/keys/master body for this identity at expected+1.
func (i *testIdentity) put(t *testing.T, expected int64) map[string]any {
	t.Helper()
	pub := i.master.Public()
	bpub := i.backup.Public().Bytes()
	wm, _ := e2eeid.WrapRecovery(i.recovery, "master-key", i.tenant, i.user, e2eeid.MasterSeed(i.master))
	wb, _ := e2eeid.WrapRecovery(i.recovery, "backup-key", i.tenant, i.user, i.backup.Seed())
	return map[string]any{
		"expected_version": expected,
		"master_key":       b64.EncodeToString(pub.Bytes()),
		"self_signature":   i.sign(t, e2eeid.DomainMaster, e2eeid.MasterSelfMessage(i.tenant, i.user, pub)),
		"backup_key": map[string]any{
			"public_key": b64.EncodeToString(bpub),
			"signature":  i.sign(t, e2eeid.DomainBackupKey, e2eeid.BackupKeyMessage(i.tenant, i.user, expected+1, bpub)),
		},
		"recovery": map[string]string{"wrapped_master_key": b64.EncodeToString(wm), "wrapped_backup_key": b64.EncodeToString(wb)},
	}
}

func (i *testIdentity) deviceSig(t *testing.T, d *testDevice, version int64) map[string]any {
	t.Helper()
	return map[string]any{"version": version, "signature": i.sign(t, e2eeid.DomainDevice, e2eeid.DeviceMessage(i.tenant, d.userID, d.id, d.curve, d.ed()))}
}

// staleSession is a valid session of userID signed in 11 minutes ago, past the step-up window.
func staleSession(t *testing.T, st store.Store, userID string) string {
	t.Helper()
	tok := "tok_stale_" + userID + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := st.Sessions().CreateSession(t.Context(), &store.Session{UserID: userID, TokenHash: crypto.SHA256Hex([]byte(tok)),
		CreatedAt: time.Now().Add(-11 * time.Minute), ExpiresAt: time.Now().Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	return tok
}

// backupWrite is a PUT /api/v1/keys/backup body for sessions, signed by the master key for
// backup generation 0.
func (i *testIdentity) backupWrite(t *testing.T, version int64, sessions ...map[string]any) map[string]any {
	t.Helper()
	return i.backupWriteGen(t, version, 0, sessions...)
}

func (i *testIdentity) backupWriteGen(t *testing.T, version, generation int64, sessions ...map[string]any) map[string]any {
	t.Helper()
	entries := make([]e2eeid.BackupWriteEntry, len(sessions))
	for n, e := range sessions {
		fi, _ := e["first_index"].(int64)
		if f, ok := e["first_index"].(int); ok {
			fi = int64(f)
		}
		room, _ := e["room_id"].(string)
		sender, _ := e["sender_key"].(string)
		session, _ := e["session_id"].(string)
		sealed, _ := e["sealed"].(string)
		entries[n] = e2eeid.BackupWriteEntry{RoomID: room, SenderKey: sender, SessionID: session, FirstIndex: fi, Sealed: sealed}
	}
	msg, err := e2eeid.BackupWrite(i.tenant, i.user, version, generation, entries)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"version": version, "generation": generation, "sessions": sessions, "signature": i.sign(t, e2eeid.DomainBackupWrite, msg)}
}

func registerDevice(t *testing.T, srv http.Handler, tok string, d *testDevice) {
	t.Helper()
	if rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", tok, map[string]any{"device_id": d.id, "device_keys": d.keys()}, nil); rec.Code != http.StatusOK {
		t.Fatalf("register %s = %d %s", d.id, rec.Code, rec.Body.String())
	}
}

func decodeBody(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func TestE2EEMasterKeyIsValidatedAndVersioned(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3_alice", "e3alice", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	put := func(body map[string]any) int {
		return doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, body, nil).Code
	}

	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/master", tok, nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"master":null,"tenant_id":"`+orgA+`"}`+"\n" {
		t.Fatalf("before setup = %d %s", rec.Code, rec.Body.String())
	}

	// Garbage is refused before it is stored.
	other := newIdentity(t, orgA, "usr_e3_bob")
	otherOrg := newIdentity(t, orgB, alice.ID)
	// tamper flips byte at (negative: from the end) of the base64 field at path.
	tamper := func(at int, path ...string) map[string]any {
		b := clone(id.put(t, 0))
		m := b
		for _, p := range path[:len(path)-1] {
			m = m[p].(map[string]any)
		}
		raw, _ := b64.DecodeString(m[path[len(path)-1]].(string))
		if at < 0 {
			at += len(raw)
		}
		raw[at] ^= 1
		m[path[len(path)-1]] = b64.EncodeToString(raw)
		return b
	}
	// The signature encoding is the tag, then ML-DSA-65 (3309 B), then Ed25519 (64 B).
	const mldsaByte, edByte = 100, -1
	foreignSelf := clone(id.put(t, 0))
	foreignSelf["self_signature"] = clone(other.put(t, 0))["self_signature"]
	replayedUser := clone(other.put(t, 0)) // bob's identity uploaded as alice's
	replayedOrg := clone(otherOrg.put(t, 0))
	wrongVersion := clone(id.put(t, 1))
	wrongVersion["expected_version"] = 0
	wrongAlg := tamper(0, "master_key") // the algorithm tag
	shortBackup := clone(id.put(t, 0))
	shortBackup["backup_key"].(map[string]any)["public_key"] = b64.EncodeToString(make([]byte, 32))
	for name, body := range map[string]map[string]any{
		"self-signature, ML-DSA half tampered":  tamper(mldsaByte, "self_signature"),
		"self-signature, Ed25519 half tampered": tamper(edByte, "self_signature"),
		"backup key signature tampered":         tamper(edByte, "backup_key", "signature"),
		"backup key swapped":                    tamper(600, "backup_key", "public_key"),
		"self-signature by another key":         foreignSelf,
		"another user's identity":               replayedUser,
		"bound to another org":                  replayedOrg,
		"backup key signed for another version": wrongVersion,
		"classical-only algorithm":              wrongAlg,
		"a classical backup key":                shortBackup,
	} {
		if c := put(body); c != http.StatusBadRequest {
			t.Errorf("%s = %d", name, c)
		}
	}
	// A raw seed in place of a wrap (or any other length or version) is refused.
	for name, fix := range map[string]func(map[string]any){
		"raw master seed": func(b map[string]any) {
			b["recovery"].(map[string]any)["wrapped_master_key"] = b64.EncodeToString(e2eeid.MasterSeed(id.master))
		},
		"raw backup seed": func(b map[string]any) {
			b["recovery"].(map[string]any)["wrapped_backup_key"] = b64.EncodeToString(id.backup.Seed())
		},
		"wrap of wrong size": func(b map[string]any) {
			b["recovery"].(map[string]any)["wrapped_backup_key"] = b64.EncodeToString(make([]byte, 93))
		},
		"wrap of version two": func(b map[string]any) {
			w, _ := b64.DecodeString(b["recovery"].(map[string]any)["wrapped_master_key"].(string))
			w[0] = 2
			b["recovery"].(map[string]any)["wrapped_master_key"] = b64.EncodeToString(w)
		},
	} {
		b := clone(id.put(t, 0))
		fix(b)
		if c := put(b); c != http.StatusBadRequest {
			t.Errorf("%s = %d", name, c)
		}
	}
	// Even the first setup needs a recent sign-in.
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", staleSession(t, st, alice.ID), id.put(t, 0), nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "reauthentication_required") {
		t.Fatalf("first setup from a stale session = %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/master", tok, nil, nil); !strings.Contains(rec.Body.String(), `"master":null`) {
		t.Fatalf("a refused upload was stored: %s", rec.Body.String())
	}

	if c := put(id.put(t, 0)); c != http.StatusOK {
		t.Fatalf("first identity = %d", c)
	}
	if c := put(id.put(t, 0)); c != http.StatusConflict {
		t.Fatalf("a second first-device setup = %d, want 409", c)
	}
	var got struct {
		TenantID string `json:"tenant_id"`
		Master   struct {
			Version   int64  `json:"version"`
			MasterKey string `json:"master_key"`
			BackupKey struct {
				PublicKey string `json:"public_key"`
			} `json:"backup_key"`
			Recovery map[string]string `json:"recovery"`
			Pins     struct {
				Counter int64 `json:"counter"`
			} `json:"pins"`
		} `json:"master"`
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/master", tok, nil, nil)
	decodeBody(t, rec.Body.Bytes(), &got)
	if got.TenantID != orgA || got.Master.Version != 1 || got.Master.MasterKey != b64.EncodeToString(id.master.Public().Bytes()) {
		t.Fatalf("stored identity = %s", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("identity response is cacheable")
	}
	// The recovery wraps come back exactly, and only the recovery key opens them.
	wm, _ := b64.DecodeString(got.Master.Recovery["wrapped_master_key"])
	if seed, err := e2eeid.UnwrapRecovery(id.recovery, "master-key", orgA, alice.ID, wm); err != nil || string(seed) != string(e2eeid.MasterSeed(id.master)) {
		t.Fatalf("recovery wrap does not round-trip: %v", err)
	}

	// A reset needs a recent sign-in: a session from 11 minutes ago is asked to step up.
	reset := newIdentity(t, orgA, alice.ID)
	oldTok := staleSession(t, st, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", oldTok, reset.put(t, 1), nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "reauthentication_required") {
		t.Fatalf("reset from a stale session = %d %s", rec.Code, rec.Body.String())
	}
	// A reset needs the current version and starts version 2.
	if c := put(reset.put(t, 0)); c != http.StatusConflict {
		t.Fatalf("reset without the current version = %d", c)
	}
	if c := put(reset.put(t, 1)); c != http.StatusOK {
		t.Fatalf("reset = %d", c)
	}
	for _, action := range []string{"e2ee.master_key_set", "e2ee.master_key_reset"} {
		if _, err := st.Audit().LatestAuditRecord(t.Context(), action); err != nil {
			t.Errorf("no %s audit row: %v", action, err)
		}
	}
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", "", reset.put(t, 2), nil).Code; c != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", c)
	}
}

func TestE2EEDeviceCrossSignatureAndQuery(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, aliceTok := createOrgUser(t, st, "usr_e3x_alice", "e3xalice", "user", orgA)
	bob, bobTok := createOrgUser(t, st, "usr_e3x_bob", "e3xbob", "user", orgA)
	carol, carolTok := createOrgUser(t, st, "usr_e3x_carol", "e3xcarol", "user", orgB)
	aliceID, bobID, carolID := newIdentity(t, orgA, alice.ID), newIdentity(t, orgA, bob.ID), newIdentity(t, orgB, carol.ID)
	for _, c := range []struct {
		tok string
		id  *testIdentity
	}{{aliceTok, aliceID}, {bobTok, bobID}, {carolTok, carolID}} {
		if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", c.tok, c.id.put(t, 0), nil); rec.Code != http.StatusOK {
			t.Fatalf("identity = %d %s", rec.Code, rec.Body.String())
		}
	}
	a1, a2 := newTestDevice(t, alice.ID, "DEVICE_E3_A1"), newTestDevice(t, alice.ID, "DEVICE_E3_A2")
	b1 := newTestDevice(t, bob.ID, "DEVICE_E3_B1")
	c1 := newTestDevice(t, carol.ID, "DEVICE_E3_C1")
	registerDevice(t, srv, aliceTok, a1)
	registerDevice(t, srv, aliceTok, a2)
	registerDevice(t, srv, bobTok, b1)
	registerDevice(t, srv, carolTok, c1)
	sign := func(tok, device string, body map[string]any) int {
		return doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/"+device+"/signature", tok, body, nil).Code
	}
	for name, c := range map[string]struct {
		tok, device string
		body        map[string]any
		want        int
	}{
		"signature over another device":         {aliceTok, a1.id, aliceID.deviceSig(t, a2, 1), http.StatusBadRequest},
		"signature by another user's master":    {aliceTok, a1.id, bobID.deviceSig(t, a1, 1), http.StatusBadRequest},
		"a stale master version":                {aliceTok, a1.id, aliceID.deviceSig(t, a1, 2), http.StatusConflict},
		"someone else's device":                 {bobTok, a1.id, aliceID.deviceSig(t, a1, 1), http.StatusNotFound},
		"a signature for another org":           {carolTok, c1.id, newIdentity(t, orgA, carol.ID).deviceSig(t, c1, 1), http.StatusBadRequest},
		"a private key field riding along":      {aliceTok, a1.id, map[string]any{"version": 1, "signature": aliceID.deviceSig(t, a1, 1)["signature"], "master_private_key": "x"}, http.StatusBadRequest},
		"a self-binding passed as a device sig": {aliceTok, a1.id, map[string]any{"version": 1, "signature": aliceID.put(t, 0)["self_signature"]}, http.StatusBadRequest},
	} {
		if got := sign(c.tok, c.device, c.body); got != c.want {
			t.Errorf("%s = %d, want %d", name, got, c.want)
		}
	}
	if c := sign(aliceTok, a1.id, aliceID.deviceSig(t, a1, 1)); c != http.StatusNoContent {
		t.Fatalf("cross-sign = %d", c)
	}
	if c := sign(bobTok, b1.id, bobID.deviceSig(t, b1, 1)); c != http.StatusNoContent {
		t.Fatalf("cross-sign bob = %d", c)
	}

	type queried struct {
		TenantID   string `json:"tenant_id"`
		Devices    map[string][]map[string]any
		MasterKeys map[string]struct {
			Version       int64  `json:"version"`
			MasterKey     string `json:"master_key"`
			SelfSignature string `json:"self_signature"`
		} `json:"master_keys"`
	}
	var q queried
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", bobTok, map[string]any{"user_ids": []string{alice.ID, carol.ID}}, nil)
	decodeBody(t, rec.Body.Bytes(), &q)
	if q.TenantID != orgA || len(q.Devices[alice.ID]) != 2 || q.MasterKeys[alice.ID].Version != 1 {
		t.Fatalf("query = %s", rec.Body.String())
	}
	// Another org's user has no devices and no master key, as if unknown.
	if _, ok := q.MasterKeys[carol.ID]; ok || len(q.Devices[carol.ID]) != 0 {
		t.Fatalf("query crossed orgs: %s", rec.Body.String())
	}
	signed := map[string]bool{}
	for _, d := range q.Devices[alice.ID] {
		_, has := d["master_signature"]
		signed[d["device_id"].(string)] = has
	}
	if !signed[a1.id] || signed[a2.id] {
		t.Fatalf("cross-signatures in query: %v", signed)
	}
	// The listed master key and signature verify independently, as a client checks them.
	mk := q.MasterKeys[alice.ID].MasterKey
	raw, _ := b64.DecodeString(mk)
	pub, err := hybridsig.ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := b64.DecodeString(q.MasterKeys[alice.ID].SelfSignature)
	if pub.Verify(e2eeid.DomainMaster, e2eeid.MasterSelfMessage(orgA, alice.ID, pub), ss) != nil {
		t.Fatal("listed self-binding does not verify")
	}

	// A reset of alice's identity withdraws every cross-signature by the old key.
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", aliceTok, newIdentity(t, orgA, alice.ID).put(t, 1), nil); rec.Code != http.StatusOK {
		t.Fatalf("reset = %d", rec.Code)
	}
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", bobTok, map[string]any{"user_ids": []string{alice.ID}}, nil)
	if strings.Contains(rec.Body.String(), "master_signature") {
		t.Fatalf("cross-signature by a replaced master key still listed: %s", rec.Body.String())
	}
	if c := sign(aliceTok, a1.id, aliceID.deviceSig(t, a1, 1)); c != http.StatusConflict {
		t.Fatalf("signature by the replaced master key = %d", c)
	}
}

func TestE2EEKeyBackupRoutes(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3b_alice", "e3balice", "user", orgA)
	_, bobTok := createOrgUser(t, st, "usr_e3b_bob", "e3bbob", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/backup", tok, map[string]any{"version": 1, "sessions": []any{}}, nil).Code; c != http.StatusBadRequest {
		t.Fatalf("empty batch = %d", c)
	}
	senderA := b64.EncodeToString(bytes.Repeat([]byte{0xA}, 32))
	senderB := b64.EncodeToString(bytes.Repeat([]byte{0xB}, 32))
	entryFrom := func(room, sender, session string, idx int64) map[string]any {
		e := e2eeid.BackupEntry{RoomID: room, SenderKey: sender, SessionID: session, FirstIndex: idx}
		sealed, err := e2eeid.SealBackup(id.backup.Public(), e2eeid.MasterSeed(id.master), e, []byte(`{"session":"`+session+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"room_id": room, "sender_key": sender, "session_id": session, "first_index": idx, "sealed": b64.EncodeToString(sealed)}
	}
	entry := func(room, session string, idx int64) map[string]any { return entryFrom(room, senderA, session, idx) }
	putB := func(tok string, version int64, sessions ...map[string]any) int {
		return doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/backup", tok, id.backupWrite(t, version, sessions...), nil).Code
	}
	if c := putB(tok, 1, entry("rm_1", "sessA", 0)); c != http.StatusConflict {
		t.Fatalf("backup before an identity = %d", c)
	}
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if c := putB(tok, 1, entry("rm_1", "sessA", 4), entry("rm_2", "sessB", 0)); c != http.StatusOK {
		t.Fatalf("backup = %d", c)
	}
	if c := putB(tok, 2, entry("rm_1", "sessC", 0)); c != http.StatusConflict {
		t.Fatalf("backup to another version = %d", c)
	}
	bad := entry("rm_1", "sessD", 0)
	bad["session_key"] = "plaintext megolm key"
	short := entry("rm_1", "sessE", 0)
	short["sealed"] = b64.EncodeToString([]byte("too short to be an X-Wing seal"))
	badRoom := entry("rm 1", "sessF", 0)
	noSender := entry("rm_1", "sessG", 0)
	delete(noSender, "sender_key")
	tooBig := entry("rm_1", "sessH", 0)
	tooBig["sealed"] = b64.EncodeToString(make([]byte, e2eeid.MaxSealedSession+1))
	for name, e := range map[string]map[string]any{"a session_key field": bad, "not an X-Wing seal": short, "a bad room ID": badRoom, "no sender key": noSender, "over 4 KiB": tooBig} {
		if c := putB(tok, 1, e); c != http.StatusBadRequest {
			t.Errorf("%s = %d", name, c)
		}
	}
	// A copy reaching further back replaces; the server cannot open either. Another sender
	// with the same session ID is a separate row, so it cannot displace the real sender's.
	better := entry("rm_1", "sessA", 1)
	if c := putB(tok, 1, better); c != http.StatusOK {
		t.Fatal(c)
	}
	if c := putB(tok, 1, entryFrom("rm_1", senderB, "sessA", 0)); c != http.StatusOK {
		t.Fatal(c)
	}
	var page struct {
		Version  int64            `json:"version"`
		Sessions []map[string]any `json:"sessions"`
		More     bool             `json:"more"`
	}
	rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/backup?version=1", tok, nil, nil)
	decodeBody(t, rec.Body.Bytes(), &page)
	if len(page.Sessions) != 3 || page.Sessions[0]["sealed"] != better["sealed"] || page.Sessions[1]["sender_key"] != senderB || page.More {
		t.Fatalf("backup page = %s", rec.Body.String())
	}
	raw, _ := b64.DecodeString(page.Sessions[2]["sealed"].(string))
	if got, err := e2eeid.OpenBackup(id.backup, e2eeid.MasterSeed(id.master), e2eeid.BackupEntry{RoomID: "rm_2", SenderKey: senderA, SessionID: "sessB"}, raw); err != nil || string(got) != `{"session":"sessB"}` {
		t.Fatalf("backed-up session does not open with the backup key: %v", err)
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/backup?version=1&after_room=rm_1&after_sender="+url.QueryEscape(senderB)+"&after_session=sessA", tok, nil, nil)
	decodeBody(t, rec.Body.Bytes(), &page)
	if len(page.Sessions) != 1 || page.Sessions[0]["room_id"] != "rm_2" {
		t.Fatalf("second page = %s", rec.Body.String())
	}
	// Bob has no backup of his own and cannot read alice's.
	if c := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/backup?version=1", bobTok, nil, nil).Code; c != http.StatusConflict {
		t.Fatalf("bob reading a backup = %d", c)
	}
	// Deleting the backup needs a recent sign-in.
	if rec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/backup?version=1", staleSession(t, st, alice.ID), nil, nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "reauthentication_required") {
		t.Fatalf("delete from a stale session = %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/backup?version=1", tok, nil, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"generation":1`) {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/backup?version=1", tok, nil, nil)
	if !strings.Contains(rec.Body.String(), `"sessions":[]`) || !strings.Contains(rec.Body.String(), `"generation":1`) {
		t.Fatalf("after delete = %s", rec.Body.String())
	}
	// A write signed before the deletion, replayed, cannot refill the backup.
	if c := putB(tok, 1, better); c != http.StatusConflict {
		t.Fatalf("replayed write after deletion = %d", c)
	}
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/backup", tok, id.backupWriteGen(t, 1, 1, better), nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"refused":[]`) {
		t.Fatalf("write to the new generation = %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/master", tok, nil, nil); !strings.Contains(rec.Body.String(), `"backup_generation":1`) {
		t.Fatalf("master = %s", rec.Body.String())
	}
}

func TestE2EEPinSet(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3p_alice", "e3palice", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	sealed, _ := e2eeid.SealPins(e2eeid.MasterSeed(id.master), orgA, alice.ID, 1, []byte(`{}`))
	signed := func(signer *testIdentity, counter int64) map[string]any {
		return map[string]any{"version": 1, "expected_counter": counter - 1, "sealed": b64.EncodeToString(sealed),
			"signature": signer.sign(t, e2eeid.DomainPinsWrite, e2eeid.PinsWriteMessage(orgA, alice.ID, 1, counter, sealed))}
	}
	// Only a holder of the master key writes the pin set: no proof, another key, or a proof for
	// another counter is refused before anything is stored.
	unsigned := signed(id, 1)
	delete(unsigned, "signature")
	wrongCounter := signed(id, 2)
	wrongCounter["expected_counter"] = 0
	for name, b := range map[string]map[string]any{"unsigned": unsigned, "another key": signed(newIdentity(t, orgA, alice.ID), 1), "another counter": wrongCounter} {
		if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/pins", tok, b, nil).Code; c != http.StatusBadRequest {
			t.Errorf("%s = %d", name, c)
		}
	}
	body := signed(id, 1)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/pins", tok, body, nil); rec.Code != http.StatusOK || rec.Body.String() != `{"counter":1}`+"\n" {
		t.Fatalf("pins = %d %s", rec.Code, rec.Body.String())
	}
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/pins", tok, body, nil).Code; c != http.StatusConflict {
		t.Fatalf("stale counter = %d", c)
	}
	body["pins"] = "plaintext"
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/pins", tok, body, nil).Code; c != http.StatusBadRequest {
		t.Fatalf("extra field = %d", c)
	}
}

func TestE2EEPairingRelaysTwoLayerTransferOnce(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3q_alice", "e3qalice", "user", orgA)
	_, bobTok := createOrgUser(t, st, "usr_e3q_bob", "e3qbob", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	old, fresh := newTestDevice(t, alice.ID, "DEVICE_E3Q_OLD"), newTestDevice(t, alice.ID, "DEVICE_E3Q_NEW")
	registerDevice(t, srv, tok, old)
	registerDevice(t, srv, tok, fresh)
	start := func(tok, device string) *struct {
		code int
		id   string
		exp  int64
	} {
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/pairings", tok, map[string]string{"device_id": device}, nil)
		if rec.Code == http.StatusCreated && !strings.Contains(rec.Body.String(), `"expires_in_ms":180000`) {
			t.Fatalf("no relative lifetime: %s", rec.Body.String())
		}
		var b struct {
			PairingID string `json:"pairing_id"`
			ExpiresAt int64  `json:"expires_at"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return &struct {
			code int
			id   string
			exp  int64
		}{rec.Code, b.PairingID, b.ExpiresAt}
	}
	if r := start(tok, old.id); r.code != http.StatusForbidden {
		t.Fatalf("an unverified device started a pairing: %d", r.code)
	}
	if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/"+old.id+"/signature", tok, id.deviceSig(t, old, 1), nil).Code; c != http.StatusNoContent {
		t.Fatal(c)
	}
	p := start(tok, old.id)
	if p.code != http.StatusCreated || len(p.id) != 22 {
		t.Fatalf("start = %+v", p)
	}
	if ttl := time.Until(time.UnixMilli(p.exp)); ttl > api.E2EEPairingTTL || ttl < api.E2EEPairingTTL-time.Minute || api.E2EEPairingTTL > 5*time.Minute {
		t.Fatalf("pairing TTL %v", ttl)
	}
	path := "/api/v1/keys/pairings/" + p.id
	// Another user sees nothing, exactly like an unknown pairing.
	if c := doBearerJSON(t, srv, http.MethodGet, path, bobTok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("bob reading alice's pairing = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/pairings/AAAAAAAAAAAAAAAAAAAAAA", tok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("unknown pairing = %d", c)
	}

	// The QR: pairing ID, one-time secret and fingerprint; never a public key.
	pairingRaw, _ := base64.RawURLEncoding.DecodeString(p.id)
	secret, _ := e2eeid.NewSecret()
	fp := e2eeid.Fingerprint(id.master.Public())
	qr, err := e2eeid.QRCode{PairingID: pairingRaw, Secret: secret, Fingerprint: fp[:]}.Bytes()
	if err != nil || len(qr) > 100 {
		t.Fatalf("QR payload: %d bytes, %v", len(qr), err)
	}

	eph, _ := xwing.Generate()
	ephB64 := b64.EncodeToString(eph.Public().Bytes())
	join := func(tok, device, key string) int {
		return doBearerJSON(t, srv, http.MethodPost, path+"/join", tok, map[string]string{"device_id": device, "ephemeral_key": key}, nil).Code
	}
	if c := join(tok, fresh.id, b64.EncodeToString(make([]byte, 32))); c != http.StatusBadRequest {
		t.Fatalf("a classical ephemeral key = %d", c)
	}
	if c := join(bobTok, fresh.id, ephB64); c != http.StatusNotFound {
		t.Fatalf("bob joining = %d", c)
	}
	if c := join(tok, old.id, ephB64); c != http.StatusConflict {
		t.Fatalf("the initiator joining itself = %d", c)
	}
	if c := join(tok, fresh.id, ephB64); c != http.StatusNoContent {
		t.Fatalf("join = %d", c)
	}
	if c := join(tok, fresh.id, ephB64); c != http.StatusConflict {
		t.Fatalf("second join = %d", c)
	}
	rec := doBearerJSON(t, srv, http.MethodGet, path, tok, nil, nil)
	var state map[string]any
	decodeBody(t, rec.Body.Bytes(), &state)
	if state["ephemeral_key"] != ephB64 || state["new_device"] != fresh.id || state["sealed"] != false {
		t.Fatalf("state = %s", rec.Body.String())
	}

	// The verified device seals the master and backup seeds in two layers.
	sealed, err := e2eeid.SealTransfer(eph.Public(), secret, p.id, old.id, fresh.id, e2eeid.Fields(e2eeid.MasterSeed(id.master), id.backup.Seed()))
	if err != nil {
		t.Fatal(err)
	}
	seal := func(device string, private bool) int {
		body := map[string]any{"device_id": device, "sealed": b64.EncodeToString(sealed)}
		if private {
			body["master_private_key"] = b64.EncodeToString(e2eeid.MasterSeed(id.master))
		}
		return doBearerJSON(t, srv, http.MethodPut, path+"/sealed", tok, body, nil).Code
	}
	if c := seal(old.id, true); c != http.StatusBadRequest {
		t.Fatalf("a private key field = %d", c)
	}
	if c := seal(fresh.id, false); c != http.StatusConflict {
		t.Fatalf("the new device sealing = %d", c)
	}
	if c := seal(old.id, false); c != http.StatusNoContent {
		t.Fatalf("seal = %d", c)
	}
	if c := seal(old.id, false); c != http.StatusConflict {
		t.Fatalf("second seal = %d", c)
	}
	if strings.Contains(doBearerJSON(t, srv, http.MethodGet, path, tok, nil, nil).Body.String(), b64.EncodeToString(sealed[:64])) {
		t.Fatal("GET exposes the sealed keys")
	}
	// The verified device's cancel, sent after its seal answer was lost, leaves the keys in place.
	if c := doBearerJSON(t, srv, http.MethodDelete, path+"?unsealed=1", tok, nil, nil).Code; c != http.StatusNoContent {
		t.Fatalf("unsealed-only cancel = %d", c)
	}
	consume := func(device string) *http.Response {
		rec := doBearerJSON(t, srv, http.MethodPost, path+"/consume", tok, map[string]string{"device_id": device}, nil)
		return rec.Result()
	}
	if r := consume(old.id); r.StatusCode != http.StatusConflict {
		t.Fatalf("the initiator consuming = %d", r.StatusCode)
	}
	rec = doBearerJSON(t, srv, http.MethodPost, path+"/consume", tok, map[string]string{"device_id": fresh.id}, nil)
	var got map[string]string
	decodeBody(t, rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["initiator_device"] != old.id {
		t.Fatalf("consume = %d %s", rec.Code, rec.Body.String())
	}
	raw, _ := b64.DecodeString(got["sealed"])
	keys, err := e2eeid.OpenTransfer(eph, secret, p.id, old.id, fresh.id, raw)
	if err != nil || string(keys) != string(e2eeid.Fields(e2eeid.MasterSeed(id.master), id.backup.Seed())) {
		t.Fatalf("transfer does not open on the new device: %v", err)
	}
	// One-time: the pairing is gone.
	if r := consume(fresh.id); r.StatusCode != http.StatusNotFound {
		t.Fatalf("second consume = %d", r.StatusCode)
	}
	if c := doBearerJSON(t, srv, http.MethodGet, path, tok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("pairing readable after consumption = %d", c)
	}

	// Expiry: the maintenance sweep deletes it, and a cancel removes it at once.
	p2 := start(tok, old.id)
	if err := st.E2EE().PrunePairings(t.Context(), time.Now().Add(api.E2EEPairingTTL)); err != nil {
		t.Fatal(err)
	}
	if c := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/pairings/"+p2.id, tok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("expired pairing = %d", c)
	}
	p3 := start(tok, old.id)
	if c := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/pairings/"+p3.id, tok, nil, nil).Code; c != http.StatusNoContent {
		t.Fatalf("cancel = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodGet, "/api/v1/keys/pairings/"+p3.id, tok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("cancelled pairing = %d", c)
	}
}

// Every E3 route refuses a body that names a secret, whatever else it carries.
func TestE2EEIdentityRoutesRefuseSecretFields(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3s_alice", "e3salice", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	secrets := []string{"private_key", "master_private_key", "backup_private_key", "recovery_key", "seed", "session_key", "secret"}
	sender := b64.EncodeToString(make([]byte, 32))
	sealedSession, _ := e2eeid.SealBackup(id.backup.Public(), e2eeid.MasterSeed(id.master), e2eeid.BackupEntry{RoomID: "rm_1", SenderKey: sender, SessionID: "sess"}, []byte("x"))
	routes := []struct {
		method, path string
		body         map[string]any
	}{
		{http.MethodPut, "/api/v1/keys/master", id.put(t, 0)},
		{http.MethodPut, "/api/v1/keys/pins", map[string]any{"version": 1, "expected_counter": 0, "sealed": b64.EncodeToString(make([]byte, 64))}},
		{http.MethodPost, "/api/v1/keys/devices/DEVICE_E3S_1/signature", map[string]any{"version": 1}},
		{http.MethodPut, "/api/v1/keys/backup", map[string]any{"version": 1, "sessions": []any{map[string]any{"room_id": "rm_1", "sender_key": sender, "session_id": "sess", "first_index": 0, "sealed": b64.EncodeToString(sealedSession)}}}},
		{http.MethodPost, "/api/v1/keys/pairings", map[string]any{"device_id": "DEVICE_E3S_1"}},
	}
	for _, r := range routes {
		// Without the extra field each body gets past decoding (to a 404 or 409 here), so the
		// 400 below is the refusal of the field itself.
		if r.path != "/api/v1/keys/master" {
			if c := doBearerJSON(t, srv, r.method, r.path, tok, r.body, nil).Code; c == http.StatusBadRequest {
				t.Fatalf("%s %s baseline = 400", r.method, r.path)
			}
		}
		for _, f := range secrets {
			body := clone(r.body)
			body[f] = b64.EncodeToString(make([]byte, 32))
			if c := doBearerJSON(t, srv, r.method, r.path, tok, body, nil).Code; c != http.StatusBadRequest {
				t.Errorf("%s %s with %q = %d", r.method, r.path, f, c)
			}
		}
	}
	// And none of them stored anything.
	if _, err := st.E2EE().GetMasterKey(t.Context(), alice.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused body was stored: %v", err)
	}
}

func TestE2EEDeviceListIsSignedAndVersioned(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3l_alice", "e3lalice", "user", orgA)
	_, bobTok := createOrgUser(t, st, "usr_e3l_bob", "e3lbob", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	list := func(epoch int64, ids []string, signer *testIdentity) map[string]any {
		msg, err := e2eeid.DeviceListMessage(orgA, alice.ID, 1, epoch, ids)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"version": 1, "expected_epoch": epoch - 1, "epoch": epoch, "device_ids": ids, "signature": signer.sign(t, e2eeid.DomainDeviceList, msg)}
	}
	putL := func(tok string, body map[string]any) int {
		return doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/devices/list", tok, body, nil).Code
	}
	// reservation is a reserve body for ids at expected, signed by signer's master key.
	reservation := func(expected int64, ids []string, signer *testIdentity) map[string]any {
		digest := e2eeid.DeviceListDigest(ids)
		return map[string]any{"version": 1, "expected_epoch": expected, "digest": digest,
			"signature": signer.sign(t, e2eeid.DomainDeviceListReserve, e2eeid.DeviceListReserveMessage(orgA, alice.ID, 1, expected, digest))}
	}
	reserve := func(tok string, expected int64, ids []string) int {
		return doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/list/reserve", tok, reservation(expected, ids, id), nil).Code
	}
	// reserveAndPut is an honest edit: reserve the list's digest, then publish it.
	reserveAndPut := func(body map[string]any) int {
		if c := reserve(tok, body["expected_epoch"].(int64), body["device_ids"].([]string)); c != http.StatusOK {
			return c
		}
		return putL(tok, body)
	}
	unsorted := list(1, []string{"DEVICE_A_00001"}, id)
	unsorted["device_ids"] = []string{"DEVICE_B_00002", "DEVICE_A_00001"}
	for name, c := range map[string]struct {
		tok  string
		body map[string]any
		want int
	}{
		"signed by another key": {tok, list(1, []string{"DEVICE_A_00001"}, newIdentity(t, orgA, alice.ID)), http.StatusBadRequest},
		"a list not sorted":     {tok, unsorted, http.StatusBadRequest},
		"signed for a later epoch": {tok, func() map[string]any {
			b := list(2, []string{"DEVICE_A_00001"}, id)
			b["expected_epoch"] = 0
			b["epoch"] = 1
			return b
		}(), http.StatusBadRequest},
		"another user's list":        {bobTok, list(1, []string{"DEVICE_A_00001"}, id), http.StatusConflict},
		"a private key riding along": {tok, func() map[string]any { b := list(1, []string{"DEVICE_A_00001"}, id); b["seed"] = "x"; return b }(), http.StatusBadRequest},
		"no device_ids":              {tok, func() map[string]any { b := list(1, []string{}, id); delete(b, "device_ids"); return b }(), http.StatusBadRequest},
		"null device_ids":            {tok, func() map[string]any { b := list(1, []string{}, id); b["device_ids"] = nil; return b }(), http.StatusBadRequest},
		"an epoch not past expected": {tok, func() map[string]any { b := list(1, []string{"DEVICE_A_00001"}, id); b["epoch"] = 0; return b }(), http.StatusBadRequest},
	} {
		if got := putL(c.tok, c.body); got != c.want {
			t.Errorf("%s = %d, want %d", name, got, c.want)
		}
	}
	both := []string{"DEVICE_A_00001", "DEVICE_B_00002"}
	if c := putL(tok, list(1, both, id)); c != http.StatusConflict {
		t.Fatalf("a list published without a reservation = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/list/reserve", tok, map[string]any{"version": 1, "expected_epoch": 0, "digest": "ABC"}, nil).Code; c != http.StatusBadRequest {
		t.Fatalf("a malformed digest = %d", c)
	}
	// A session without the master seed cannot hold the list: no signature, another key's, or
	// a published list's signature in its place are all refused, and reserve nothing.
	noSig := reservation(0, both, id)
	delete(noSig, "signature")
	listSig := reservation(0, both, id)
	listSig["signature"] = list(1, both, id)["signature"]
	for name, body := range map[string]map[string]any{
		"no signature":          noSig,
		"signed by another key": reservation(0, both, newIdentity(t, orgA, alice.ID)),
		"a list's signature":    listSig,
	} {
		if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/list/reserve", tok, body, nil).Code; c != http.StatusBadRequest {
			t.Errorf("reservation with %s = %d", name, c)
		}
	}
	// Two devices proposing at once: the second is refused before it signs, and a list it
	// signed anyway is not publishable.
	if c := reserve(tok, 0, both); c != http.StatusOK {
		t.Fatalf("reserve = %d", c)
	}
	held := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/devices/list/reserve", tok, reservation(0, []string{"DEVICE_C_00003"}, id), nil)
	var hint struct {
		RetryInMs int64 `json:"retry_in_ms"`
	}
	decodeBody(t, held.Body.Bytes(), &hint)
	if held.Code != http.StatusConflict || hint.RetryInMs <= 0 || hint.RetryInMs > api.E2EEDeviceListReservation.Milliseconds() {
		t.Fatalf("a competing reservation = %d %s", held.Code, held.Body.String())
	}
	if c := putL(tok, list(1, []string{"DEVICE_C_00003"}, id)); c != http.StatusConflict {
		t.Fatalf("the losing proposal published = %d", c)
	}
	if c := reserve(tok, 0, both); c != http.StatusOK {
		t.Fatalf("an honest retry = %d", c)
	}
	if c := putL(tok, list(1, both, id)); c != http.StatusOK {
		t.Fatalf("list = %d", c)
	}
	if c := reserveAndPut(list(1, []string{"DEVICE_A_00001"}, id)); c != http.StatusConflict {
		t.Fatalf("a stale epoch = %d", c)
	}
	if c := reserveAndPut(list(2, []string{"DEVICE_A_00001"}, id)); c != http.StatusOK {
		t.Fatalf("removing a device = %d", c)
	}
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", bobTok, map[string]any{"user_ids": []string{alice.ID}}, nil)
	if !strings.Contains(rec.Body.String(), `"device_list":{"epoch":2,"device_ids":["DEVICE_A_00001"]`) {
		t.Fatalf("query = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "wrapped_") || strings.Contains(rec.Body.String(), "pins") {
		t.Fatalf("a colleague's query carries the user's wraps or pins: %s", rec.Body.String())
	}
}

func TestE2EEIdentityWritesNeedTheMasterKeyAndCleanJSON(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e3w_alice", "e3walice", "user", orgA)
	id := newIdentity(t, orgA, alice.ID)
	// Two wraps that are the same string must not pass as one check: each is checked for its
	// own length.
	same := clone(id.put(t, 0))
	rc := same["recovery"].(map[string]any)
	rc["wrapped_backup_key"] = rc["wrapped_master_key"]
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, same, nil).Code; c != http.StatusBadRequest {
		t.Fatalf("the master wrap passed as the backup wrap = %d", c)
	}
	// A repeated member name could let a second copy shadow the signed one: refused.
	raw, _ := json.Marshal(id.put(t, 0))
	dup := bytes.Replace(raw, []byte(`{"backup_key"`), []byte(`{"expected_version":7,"backup_key"`), 1)
	if bytes.Equal(dup, raw) {
		t.Fatal("test body did not change")
	}
	req, _ := http.NewRequest(http.MethodPut, "/api/v1/keys/master", bytes.NewReader(dup))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate member name = %d %s", rec.Code, rec.Body.String())
	}
	// Member names match exactly: encoding/json (v1) would read "Expected_Version" as
	// expected_version, a parser matching exactly would not, so the body is refused.
	for name, body := range map[string][]byte{
		"a member name in another case": bytes.Replace(raw, []byte(`"expected_version"`), []byte(`"Expected_Version"`), 1),
		"trailing data":                 append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/keys/master", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil).Code; c != http.StatusOK {
		t.Fatal(c)
	}

	sender := b64.EncodeToString(bytes.Repeat([]byte{7}, 32))
	entry := func(idx int64) map[string]any {
		e := e2eeid.BackupEntry{RoomID: "rm_1", SenderKey: sender, SessionID: "sess", FirstIndex: idx}
		sealed, _ := e2eeid.SealBackup(id.backup.Public(), e2eeid.MasterSeed(id.master), e, []byte("x"))
		return map[string]any{"room_id": "rm_1", "sender_key": sender, "session_id": "sess", "first_index": idx, "sealed": b64.EncodeToString(sealed)}
	}
	put := func(body map[string]any) *httptest.ResponseRecorder {
		return doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/backup", tok, body, nil)
	}
	unsigned := id.backupWrite(t, 1, entry(3))
	delete(unsigned, "signature")
	swapped := id.backupWrite(t, 1, entry(3))
	swapped["sessions"] = []map[string]any{entry(0)} // signed for index 3, sent as 0
	for name, b := range map[string]map[string]any{
		"unsigned":              unsigned,
		"signed by another key": newIdentity(t, orgA, alice.ID).backupWrite(t, 1, entry(3)),
		"signed for another generation": func() map[string]any {
			b := id.backupWriteGen(t, 1, 1, entry(3))
			b["generation"] = 0
			return b
		}(),
		"entries swapped":   swapped,
		"index past uint32": id.backupWrite(t, 1, entry(math.MaxUint32+1)),
	} {
		if rec := put(b); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := put(id.backupWrite(t, 1, entry(math.MaxUint32))); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"stored":1`) {
		t.Fatalf("highest index = %d %s", rec.Code, rec.Body.String())
	}
	if rec := put(id.backupWrite(t, 1, entry(2))); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"full":false`) {
		t.Fatalf("better copy = %d %s", rec.Code, rec.Body.String())
	}
}
