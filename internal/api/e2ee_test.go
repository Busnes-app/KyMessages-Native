package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/api"
)

var b64 = base64.RawStdEncoding

// testDevice is a client device: an Ed25519 signing key and a Curve25519 public key.
type testDevice struct {
	userID, id, curve string
	priv              ed25519.PrivateKey
}

func newTestDevice(t *testing.T, userID, id string) *testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	curve := make([]byte, 32)
	_, _ = rand.Read(curve)
	return &testDevice{userID: userID, id: id, curve: b64.EncodeToString(curve), priv: priv}
}

func (d *testDevice) ed() string { return b64.EncodeToString(d.priv.Public().(ed25519.PublicKey)) }

func (d *testDevice) sign(msg string) string {
	return b64.EncodeToString(ed25519.Sign(d.priv, []byte(msg)))
}

func (d *testDevice) keys() map[string]string {
	return map[string]string{"curve25519": d.curve, "ed25519": d.ed(), "signature": d.sign(api.E2EEDeviceSigned(d.userID, d.id, d.curve, d.ed()))}
}

func (d *testDevice) otk(id string) map[string]string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	key := b64.EncodeToString(k)
	return map[string]string{"key_id": id, "key": key, "signature": d.sign(api.E2EEOneTimeKeySigned(d.userID, d.id, id, key))}
}

func TestE2EEKeyUpload(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e2_alice", "e2alice", "user", "00000000-0000-4000-8000-00000000000a")
	dev := newTestDevice(t, alice.ID, "DEVICE_ALICE_1")
	upload := func(body map[string]any) int {
		return doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", tok, body, nil).Code
	}

	bad := dev.keys()
	bad["signature"] = dev.sign("something else")
	if c := upload(map[string]any{"device_id": dev.id, "device_keys": bad}); c != http.StatusBadRequest {
		t.Fatalf("bad self-signature = %d", c)
	}
	// Signed for another user: a device cannot be registered under someone else's name.
	other := newTestDevice(t, "usr_someone_else", dev.id)
	if c := upload(map[string]any{"device_id": dev.id, "device_keys": other.keys()}); c != http.StatusBadRequest {
		t.Fatalf("keys signed for another user = %d", c)
	}
	// Any field beyond the public keys is refused, so a private key cannot ride along.
	if c := upload(map[string]any{"device_id": dev.id, "device_keys": dev.keys(), "private_key": "secret"}); c != http.StatusBadRequest {
		t.Fatalf("upload with a private key field = %d", c)
	}
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", tok, map[string]any{
		"device_id": dev.id, "device_keys": dev.keys(),
		"one_time_keys": []map[string]string{dev.otk("AAAAAQ"), dev.otk("AAAAAg")},
		"fallback_key":  dev.otk("AAAAFB"),
	}, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"has_fallback_key":true,"one_time_key_count":2}`+"\n" {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body.String())
	}
	if c := upload(map[string]any{"device_id": dev.id, "device_keys": dev.keys()}); c != http.StatusOK {
		t.Fatalf("identical re-upload = %d", c)
	}
	swapped := newTestDevice(t, alice.ID, dev.id)
	if c := upload(map[string]any{"device_id": dev.id, "device_keys": swapped.keys()}); c != http.StatusConflict {
		t.Fatalf("new identity keys on an existing device = %d", c)
	}
	// One-time keys must be signed by this device.
	if c := upload(map[string]any{"device_id": dev.id, "one_time_keys": []map[string]string{swapped.otk("AAAAAw")}}); c != http.StatusBadRequest {
		t.Fatalf("one-time key signed by another device = %d", c)
	}
	many := make([]map[string]string, 101)
	for i := range many {
		many[i] = dev.otk(fmt.Sprintf("K%05d", i))
	}
	if c := upload(map[string]any{"device_id": dev.id, "one_time_keys": many}); c != http.StatusBadRequest {
		t.Fatalf("101 one-time keys = %d", c)
	}
	if c := upload(map[string]any{"device_id": "short"}); c != http.StatusBadRequest {
		t.Fatalf("invalid device ID = %d", c)
	}
	if c := upload(map[string]any{"device_id": "DEVICE_NOT_REGISTERED"}); c != http.StatusNotFound {
		t.Fatalf("keys for an unregistered device = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", "", map[string]any{"device_id": dev.id}, nil).Code; c != http.StatusUnauthorized {
		t.Fatalf("anonymous upload = %d", c)
	}

	// A retried upload whose response was lost is accepted: stored key IDs do not count twice.
	capped := newTestDevice(t, alice.ID, "DEVICE_ALICE_CAP")
	sixty := make([]map[string]string, 60)
	for i := range sixty {
		sixty[i] = capped.otk(fmt.Sprintf("C%05d", i))
	}
	for i := range 2 {
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", tok, map[string]any{"device_id": capped.id, "device_keys": capped.keys(), "one_time_keys": sixty}, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != `{"has_fallback_key":false,"one_time_key_count":60}`+"\n" {
			t.Fatalf("upload %d of the same 60 keys = %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	// 41 new keys would make 101: refused, and none of them is stored.
	more := make([]map[string]string, 41)
	for i := range more {
		more[i] = capped.otk(fmt.Sprintf("N%05d", i))
	}
	if c := upload(map[string]any{"device_id": capped.id, "one_time_keys": more}); c != http.StatusBadRequest {
		t.Fatalf("upload past the cap = %d", c)
	}
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", tok, map[string]any{"device_id": capped.id, "one_time_keys": more[:40]}, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"has_fallback_key":false,"one_time_key_count":100}`+"\n" {
		t.Fatalf("upload up to the cap = %d %s (a refused upload must store nothing)", rec.Code, rec.Body.String())
	}
}

func TestE2EEQueryClaimAndMailStayInTheOrg(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, aliceTok := createOrgUser(t, st, "usr_e2q_alice", "e2qalice", "user", "00000000-0000-4000-8000-00000000000a")
	bob, bobTok := createOrgUser(t, st, "usr_e2q_bob", "e2qbob", "user", "00000000-0000-4000-8000-00000000000a")
	carol, carolTok := createOrgUser(t, st, "usr_e2q_carol", "e2qcarol", "user", "00000000-0000-4000-8000-00000000000b")
	devs := map[string]*testDevice{}
	for _, u := range []struct{ id, tok string }{{alice.ID, aliceTok}, {bob.ID, bobTok}, {carol.ID, carolTok}} {
		d := newTestDevice(t, u.id, "DEV_"+u.id)
		devs[u.id] = d
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/upload", u.tok, map[string]any{
			"device_id": d.id, "device_keys": d.keys(), "one_time_keys": []map[string]string{d.otk("AAAAAQ")}, "fallback_key": d.otk("AAAAFB"),
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload %s = %d %s", u.id, rec.Code, rec.Body.String())
		}
	}

	// Query: Bob's device is listed; Carol (another org) has none, like a user without keys.
	rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", aliceTok, map[string]any{"user_ids": []string{bob.ID, carol.ID, "usr_nobody"}}, nil)
	var q struct {
		Devices map[string][]struct {
			DeviceID, Curve25519, Ed25519, Signature string
		}
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &q) != nil {
		t.Fatalf("query = %d %s", rec.Code, rec.Body.String())
	}
	if len(q.Devices[bob.ID]) != 1 || q.Devices[bob.ID][0].Ed25519 != devs[bob.ID].ed() || len(q.Devices[carol.ID]) != 0 || len(q.Devices["usr_nobody"]) != 0 {
		t.Fatalf("query devices = %+v", q.Devices)
	}

	// Claim: Bob's one-time key, then his fallback key; Carol's device is not claimable.
	claim := func() []map[string]any {
		rec := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/claim", aliceTok, map[string]any{"devices": []map[string]string{
			{"user_id": bob.ID, "device_id": devs[bob.ID].id}, {"user_id": carol.ID, "device_id": devs[carol.ID].id},
		}}, nil)
		var out struct{ Keys []map[string]any }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("claim = %d %s", rec.Code, rec.Body.String())
		}
		return out.Keys
	}
	first, second := claim(), claim()
	if len(first) != 1 || first[0]["key_id"] != "AAAAAQ" || first[0]["fallback"] != false {
		t.Fatalf("first claim = %v", first)
	}
	if len(second) != 1 || second[0]["key_id"] != "AAAAFB" || second[0]["fallback"] != true {
		t.Fatalf("second claim = %v (want the fallback key)", second)
	}

	// Mail: Alice reaches Bob's device; Carol's device (another org) is refused. Only a device on
	// its user's signed list sends mail.
	aliceID := newIdentity(t, orgA, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", aliceTok, aliceID.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatalf("identity = %d %s", rec.Code, rec.Body.String())
	}
	aliceID.listDevices(t, srv, aliceTok, 1, devs[alice.ID].id)
	send := func(toUser, toDevice string) int {
		return doBearerJSON(t, srv, http.MethodPut, "/api/v1/to-device", aliceTok, map[string]any{"device_id": devs[alice.ID].id, "messages": []map[string]string{
			{"user_id": toUser, "device_id": toDevice, "type": "olm.v1", "content": "ciphertext-for-" + toUser},
		}}, nil).Code
	}
	if c := send(bob.ID, devs[bob.ID].id); c != http.StatusOK {
		t.Fatalf("send to bob = %d", c)
	}
	if c := send(carol.ID, devs[carol.ID].id); c != http.StatusNotFound {
		t.Fatalf("send across orgs = %d", c)
	}
	// A sender must use their own device.
	if c := doBearerJSON(t, srv, http.MethodPut, "/api/v1/to-device", aliceTok, map[string]any{"device_id": devs[bob.ID].id, "messages": []map[string]string{
		{"user_id": bob.ID, "device_id": devs[bob.ID].id, "type": "olm.v1", "content": "x"},
	}}, nil).Code; c != http.StatusNotFound {
		t.Fatalf("send as another user's device = %d", c)
	}
	// Only the owner reads a device's mail.
	if c := doBearerJSON(t, srv, http.MethodGet, "/api/v1/to-device?device_id="+devs[bob.ID].id, aliceTok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("alice reading bob's mail = %d", c)
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/to-device?device_id="+devs[bob.ID].id, bobTok, nil, nil)
	var mail struct {
		Messages []struct {
			ID                           int64
			SenderUserID, SenderDeviceID string `json:"-"`
			Content                      string
		}
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &mail) != nil || len(mail.Messages) != 1 || mail.Messages[0].Content != "ciphertext-for-"+bob.ID {
		t.Fatalf("bob's mail = %d %s", rec.Code, rec.Body.String())
	}
	// after pages past mail the client keeps unacknowledged; a bad after is refused.
	path := "/api/v1/to-device?device_id=" + devs[bob.ID].id + "&after="
	if rec := doBearerJSON(t, srv, http.MethodGet, path+strconv.FormatInt(mail.Messages[0].ID, 10), bobTok, nil, nil); rec.Body.String() != `{"messages":[]}`+"\n" {
		t.Fatalf("after its ID = %s", rec.Body.String())
	}
	for _, bad := range []string{"-1", "x"} {
		if c := doBearerJSON(t, srv, http.MethodGet, path+bad, bobTok, nil, nil).Code; c != http.StatusBadRequest {
			t.Fatalf("after=%s = %d", bad, c)
		}
	}
	if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/to-device/ack", bobTok, map[string]any{"device_id": devs[bob.ID].id, "ids": []int64{mail.Messages[0].ID}}, nil).Code; c != http.StatusNoContent {
		t.Fatalf("ack = %d", c)
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/to-device?device_id="+devs[bob.ID].id, bobTok, nil, nil)
	if rec.Body.String() != `{"messages":[]}`+"\n" {
		t.Fatalf("after ack = %s", rec.Body.String())
	}

	// Mail carries the sender device's keys, so it stays verifiable after that device signs out.
	if c := send(bob.ID, devs[bob.ID].id); c != http.StatusOK {
		t.Fatalf("second send to bob = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/devices/"+devs[alice.ID].id, aliceTok, nil, nil).Code; c != http.StatusNoContent {
		t.Fatalf("alice signing her device out = %d", c)
	}
	rec = doBearerJSON(t, srv, http.MethodGet, "/api/v1/to-device?device_id="+devs[bob.ID].id, bobTok, nil, nil)
	var queued struct {
		Messages []struct {
			SenderKeys map[string]string `json:"sender_keys"`
		}
	}
	want := devs[alice.ID].keys()
	want["device_id"] = devs[alice.ID].id
	if json.Unmarshal(rec.Body.Bytes(), &queued) != nil || len(queued.Messages) != 1 || !maps.Equal(queued.Messages[0].SenderKeys, want) {
		t.Fatalf("mail from a signed-out device = %s, want sender_keys %v", rec.Body.String(), want)
	}

	// Removing a device removes it from queries.
	if c := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/devices/"+devs[bob.ID].id, aliceTok, nil, nil).Code; c != http.StatusNotFound {
		t.Fatalf("alice removing bob's device = %d", c)
	}
	if c := doBearerJSON(t, srv, http.MethodDelete, "/api/v1/keys/devices/"+devs[bob.ID].id, bobTok, nil, nil).Code; c != http.StatusNoContent {
		t.Fatalf("bob removing his device = %d", c)
	}
	rec = doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", aliceTok, map[string]any{"user_ids": []string{bob.ID}}, nil)
	if rec.Body.String() != `{"devices":{"`+bob.ID+`":[]},"master_keys":{},"tenant_id":"00000000-0000-4000-8000-00000000000a"}`+"\n" {
		t.Fatalf("query after removal = %s", rec.Body.String())
	}
}

// Key and mailbox traffic has its own budget: it must not spend the chat-write budget (240 a
// minute) that message sends use.
func TestE2EEUsesItsOwnRateLimit(t *testing.T) {
	srv, st, _ := newMultiTenantTestServer(t)
	alice, tok := createOrgUser(t, st, "usr_e2rl_alice", "e2rlalice", "user", "00000000-0000-4000-8000-00000000000a")
	for i := range 241 {
		if c := doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", tok, map[string]any{"user_ids": []string{alice.ID}}, nil).Code; c != http.StatusOK {
			t.Fatalf("query %d = %d", i+1, c)
		}
	}
}
