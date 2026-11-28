package api_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/crypto"

	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// botList is a PUT /api/v1/keys/bots/{id}/devices body: devs signed by signer's master key at
// version 1, as owner's list for bot.
func botList(t *testing.T, signer *testIdentity, owner, bot string, expected, epoch int64, devs ...*testDevice) map[string]any {
	t.Helper()
	list := make([]e2eeid.BotDevice, len(devs))
	out := make([]map[string]string, len(devs))
	for i, d := range devs {
		list[i] = e2eeid.BotDevice{DeviceID: d.id, Curve25519: d.curve, Ed25519: d.ed()}
		out[i] = map[string]string{"device_id": d.id, "curve25519": d.curve, "ed25519": d.ed()}
	}
	// A list with no encoding (unsorted) is still sent, over a signature of nothing it could mean.
	msg, err := e2eeid.BotDevicesMessage(signer.tenant, owner, 1, bot, epoch, list)
	if err != nil {
		msg = []byte("no list")
	}
	return map[string]any{"version": 1, "expected_epoch": expected, "epoch": epoch, "devices": out, "signature": signer.sign(t, e2eeid.DomainBotDevices, msg)}
}

// freshSession is a session of u signed in now, inside the step-up window.
func freshSession(t *testing.T, st store.Store, u *store.User) string {
	t.Helper()
	tok := "tok_fresh_" + u.ID + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := st.Sessions().CreateSession(t.Context(), &store.Session{UserID: u.ID, TokenHash: crypto.SHA256Hex([]byte(tok)),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	return tok
}

type botQuery struct {
	Devices    map[string][]map[string]any `json:"devices"`
	MasterKeys map[string]map[string]any   `json:"master_keys"`
	BotDevices map[string]struct {
		OwnerID string              `json:"owner_id"`
		Epoch   int64               `json:"epoch"`
		Devices []map[string]string `json:"devices"`
	} `json:"bot_devices"`
}

// E4: only the bot's owner, with their current master key, vouches for the bot's devices, and
// only for devices the bot uploaded with exactly those keys. A key query hands colleagues the
// list and the owner's master key to check it; revoking the bot removes its devices.
func TestE2EEBotDevicesAreVouchedByTheirOwner(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	alice, _ := createChatTestUser(t, st, "u_e4_alice", "e4alice", "user")
	bob, _ := createChatTestUser(t, st, "u_e4_bob", "e4bob", "user")
	aliceTok, bobTok := freshSession(t, st, alice), freshSession(t, st, bob)
	admin := loginAs(t, srv, st, "root", "admin")
	created := decode[agentTokenBody](t, adminDo(t, srv, admin, "POST", "/api/admin/agents", map[string]string{"name": "agent-e4-helper", "owner": alice.ID}))
	botID, botTok := created.Agent.UserID, created.Token
	aliceID, bobID := newIdentity(t, store.DefaultTenantID, alice.ID), newIdentity(t, store.DefaultTenantID, bob.ID)
	for tok, id := range map[string]*testIdentity{aliceTok: aliceID, bobTok: bobID} {
		if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", tok, id.put(t, 0), nil); rec.Code != http.StatusOK {
			t.Fatalf("identity = %d %s", rec.Code, rec.Body.String())
		}
	}
	d1, d2 := newTestDevice(t, botID, "BOTDEVICE1"), newTestDevice(t, botID, "BOTDEVICE2")
	registerDevice(t, srv, botTok, d1)
	registerDevice(t, srv, botTok, d2)
	var own struct {
		Bots []struct {
			UserID string `json:"user_id"`
		} `json:"bots"`
	}
	decodeBody(t, doBearerJSON(t, srv, http.MethodGet, "/api/v1/bots", aliceTok, nil, nil).Body.Bytes(), &own)
	if len(own.Bots) != 1 || own.Bots[0].UserID != botID {
		t.Fatalf("owner's bots = %+v", own)
	}
	decodeBody(t, doBearerJSON(t, srv, http.MethodGet, "/api/v1/bots", bobTok, nil, nil).Body.Bytes(), &own)
	if len(own.Bots) != 0 {
		t.Fatalf("bob sees bots he does not own: %+v", own)
	}
	unknown := newTestDevice(t, botID, "BOTDEVICE9")
	swapped := *d1
	swapped.priv = newTestDevice(t, botID, "x").priv
	path := "/api/v1/keys/bots/" + botID + "/devices"

	for name, c := range map[string]struct {
		tok  string
		body map[string]any
		want int
	}{
		"signed by another user's master key": {aliceTok, botList(t, bobID, alice.ID, botID, 0, 1, d1), http.StatusBadRequest},
		"signed for another bot":              {aliceTok, botList(t, aliceID, alice.ID, "bot_other", 0, 1, d1), http.StatusBadRequest},
		"a device the bot never uploaded":     {aliceTok, botList(t, aliceID, alice.ID, botID, 0, 1, unknown), http.StatusBadRequest},
		"a device with other keys":            {aliceTok, botList(t, aliceID, alice.ID, botID, 0, 1, &swapped), http.StatusBadRequest},
		"someone who does not own the bot":    {bobTok, botList(t, bobID, bob.ID, botID, 0, 1, d1), http.StatusNotFound},
		"the bot itself":                      {botTok, botList(t, aliceID, alice.ID, botID, 0, 1, d1), http.StatusNotFound},
		"an epoch that does not rise":         {aliceTok, botList(t, aliceID, alice.ID, botID, 0, 0, d1), http.StatusBadRequest},
		"unsorted devices":                    {aliceTok, botList(t, aliceID, alice.ID, botID, 0, 1, d2, d1), http.StatusBadRequest},
	} {
		if rec := doBearerJSON(t, srv, http.MethodPut, path, c.tok, c.body, nil); rec.Code != c.want {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body.String(), c.want)
		}
	}
	query := func() botQuery {
		var q botQuery
		decodeBody(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", bobTok, map[string]any{"user_ids": []string{botID}}, nil).Body.Bytes(), &q)
		return q
	}
	if q := query(); len(q.BotDevices) != 0 {
		t.Fatalf("a refused list was stored: %+v", q.BotDevices)
	}

	if rec := doBearerJSON(t, srv, http.MethodPut, path, aliceTok, botList(t, aliceID, alice.ID, botID, 0, 1, d1, d2), nil); rec.Code != http.StatusOK {
		t.Fatalf("owner's list = %d %s", rec.Code, rec.Body.String())
	}
	q := query()
	if l := q.BotDevices[botID]; l.OwnerID != alice.ID || l.Epoch != 1 || len(l.Devices) != 2 || l.Devices[0]["device_id"] != d1.id {
		t.Fatalf("bot list = %+v", q.BotDevices)
	}
	if q.MasterKeys[alice.ID]["master_key"] == nil {
		t.Fatalf("the owner's master key does not come with the list: %+v", q.MasterKeys)
	}
	// A stale epoch loses the compare-and-swap; the owner removes a device at the next epoch.
	if rec := doBearerJSON(t, srv, http.MethodPut, path, aliceTok, botList(t, aliceID, alice.ID, botID, 0, 2, d1), nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale epoch = %d, want 409", rec.Code)
	}
	if rec := doBearerJSON(t, srv, http.MethodPut, path, aliceTok, botList(t, aliceID, alice.ID, botID, 1, 2, d1), nil); rec.Code != http.StatusOK {
		t.Fatalf("removal = %d %s", rec.Code, rec.Body.String())
	}
	if l := query().BotDevices[botID]; l.Epoch != 2 || len(l.Devices) != 1 {
		t.Fatalf("after removal = %+v", l)
	}

	// Revoking the bot removes its devices, so nobody lists them for keys again.
	if rec := adminDo(t, srv, admin, "POST", "/api/admin/agents/"+created.Agent.ID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	if q := query(); len(q.Devices[botID]) != 0 {
		t.Fatalf("revoked bot still has devices: %+v", q.Devices[botID])
	}
	// A revoked bot's owner can vouch for nothing more.
	if rec := doBearerJSON(t, srv, http.MethodPut, path, aliceTok, botList(t, aliceID, alice.ID, botID, 2, 3), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("list for a revoked bot = %d, want 404", rec.Code)
	}
}

// A list signed by a master key the owner has since replaced vouches for nothing.
func TestE2EEBotDevicesLapseWithTheOwnersIdentity(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	alice, _ := createChatTestUser(t, st, "u_e4r_alice", "e4ralice", "user")
	aliceTok := freshSession(t, st, alice)
	const botID = "bot_e4r_helper"
	botTok := createChatTestBot(t, st, botID, "agent-e4r", alice.ID)
	aliceID := newIdentity(t, store.DefaultTenantID, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", aliceTok, aliceID.put(t, 0), nil); rec.Code != http.StatusOK {
		t.Fatalf("identity = %d", rec.Code)
	}
	d1 := newTestDevice(t, botID, "BOTDEVICE1")
	registerDevice(t, srv, botTok, d1)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/bots/"+botID+"/devices", aliceTok, botList(t, aliceID, alice.ID, botID, 0, 1, d1), nil); rec.Code != http.StatusOK {
		t.Fatalf("owner's list = %d %s", rec.Code, rec.Body.String())
	}
	reset := newIdentity(t, store.DefaultTenantID, alice.ID)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/master", aliceTok, reset.put(t, 1), nil); rec.Code != http.StatusOK {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body.String())
	}
	var q botQuery
	decodeBody(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", aliceTok, map[string]any{"user_ids": []string{botID}}, nil).Body.Bytes(), &q)
	if len(q.BotDevices) != 0 {
		t.Fatalf("a list signed by the replaced key is still served: %+v", q.BotDevices)
	}
	// The owner's new identity vouches again from epoch 1, as their client sees no list.
	body := botList(t, reset, alice.ID, botID, 0, 1, d1)
	body["version"] = 2
	msg, _ := e2eeid.BotDevicesMessage(store.DefaultTenantID, alice.ID, 2, botID, 1, []e2eeid.BotDevice{{DeviceID: d1.id, Curve25519: d1.curve, Ed25519: d1.ed()}})
	body["signature"] = reset.sign(t, e2eeid.DomainBotDevices, msg)
	if rec := doBearerJSON(t, srv, http.MethodPut, "/api/v1/keys/bots/"+botID+"/devices", aliceTok, body, nil); rec.Code != http.StatusOK {
		t.Fatalf("vouching after a reset = %d %s", rec.Code, rec.Body.String())
	}
	decodeBody(t, doBearerJSON(t, srv, http.MethodPost, "/api/v1/keys/query", aliceTok, map[string]any{"user_ids": []string{botID}}, nil).Body.Bytes(), &q)
	if l := q.BotDevices[botID]; l.Epoch != 1 || len(l.Devices) != 1 {
		t.Fatalf("after re-vouching = %+v", q.BotDevices)
	}
}
