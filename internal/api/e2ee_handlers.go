package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// End-to-end encryption key server (docs/superpowers/specs/2026-11-22-e2ee-design.md §9). The
// server stores public keys and relays Olm ciphertext; it never sees a private key or plaintext.
// It checks signatures only to refuse garbage early: clients verify everything themselves.
const (
	e2eeMaxKeysPerUpload = 100
	e2eeMaxStoredKeys    = 100
	e2eeMaxBatch         = 100
	e2eeMaxContent       = 64 << 10
	e2eeMailboxPage      = 100
	// E2EEMailboxTTL is how long undelivered to-device mail is kept.
	E2EEMailboxTTL = 30 * 24 * time.Hour
)

// e2eeLimit is its own budget: key queries, claims and mailbox fetches and acks follow every
// room join and WebSocket wake, and must not spend the user's chat-write budget.
var e2eeLimit = chatLimit{"e2ee:", 600}

var (
	e2eeDeviceID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	e2eeKeyID    = regexp.MustCompile(`^[A-Za-z0-9+/_-]{1,64}$`)
	e2eeMsgType  = regexp.MustCompile(`^[a-z0-9._]{1,64}$`)
)

// E2EEDeviceSigned and E2EEOneTimeKeySigned are the exact strings a device signs with its
// Ed25519 key; clients build and verify the same strings.
func E2EEDeviceSigned(userID, deviceID, curve, ed string) string {
	return "kymessages.device.v1\n" + userID + "\n" + deviceID + "\n" + curve + "\n" + ed
}

func E2EEOneTimeKeySigned(userID, deviceID, keyID, key string) string {
	return "kymessages.otk.v1\n" + userID + "\n" + deviceID + "\n" + keyID + "\n" + key
}

// e2eeKey decodes an unpadded base64 32-byte public key, as vodozemac writes them.
func e2eeKey(s string) ([]byte, bool) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	return b, err == nil && len(b) == 32
}

func e2eeSigned(edKey, message, signature string) bool {
	pub, ok := e2eeKey(edKey)
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	return ok && err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, []byte(message), sig)
}

// e2eeCaller is the authenticated user and their tenant, or false after writing the refusal.
func (s *Server) e2eeCaller(w http.ResponseWriter, r *http.Request) (*store.User, string, bool) {
	user, _, ok := s.currentUser(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return nil, "", false
	}
	tenantID, ok := s.requireUserTenant(w, r, user)
	if !ok {
		return nil, "", false
	}
	return user, tenantID, s.allowChatAction(w, user.ID, e2eeLimit)
}

// ownDevice loads the caller's device, writing 404 when it is not theirs.
func (s *Server) ownDevice(w http.ResponseWriter, r *http.Request, user *store.User, deviceID string) (*store.E2EEDevice, bool) {
	d, err := s.store.E2EE().GetDevice(r.Context(), user.ID, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Unknown device")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load device")
		return nil, false
	}
	return d, true
}

type e2eeKeyJSON struct {
	KeyID     string `json:"key_id"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

// POST /api/v1/keys/upload registers the caller's device (its identity keys never change) and
// adds signed one-time keys and a fallback key.
func (s *Server) handleE2EEUpload(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceID   string `json:"device_id"`
		DeviceKeys *struct {
			Curve25519 string `json:"curve25519"`
			Ed25519    string `json:"ed25519"`
			Signature  string `json:"signature"`
		} `json:"device_keys"`
		OneTimeKeys []e2eeKeyJSON `json:"one_time_keys"`
		FallbackKey *e2eeKeyJSON  `json:"fallback_key"`
	}
	// Strict: an upload carrying any other field (a private key by mistake) is refused.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || !e2eeDeviceID.MatchString(req.DeviceID) || len(req.OneTimeKeys) > e2eeMaxKeysPerUpload {
		s.writeError(w, http.StatusBadRequest, "Invalid key upload")
		return
	}
	ctx := r.Context()
	var dev *store.E2EEDevice
	if k := req.DeviceKeys; k != nil {
		_, curveOK := e2eeKey(k.Curve25519)
		if !curveOK || !e2eeSigned(k.Ed25519, E2EEDeviceSigned(user.ID, req.DeviceID, k.Curve25519, k.Ed25519), k.Signature) {
			s.writeError(w, http.StatusBadRequest, "Device keys are not validly self-signed")
			return
		}
		dev = &store.E2EEDevice{TenantID: tenantID, UserID: user.ID, DeviceID: req.DeviceID, Curve25519: k.Curve25519, Ed25519: k.Ed25519, Signature: k.Signature}
		switch err := s.store.E2EE().UpsertDevice(ctx, dev); {
		case errors.Is(err, store.ErrE2EEKeyMismatch):
			s.writeError(w, http.StatusConflict, "This device ID already has other keys")
			return
		case err != nil:
			s.writeError(w, http.StatusInternalServerError, "Failed to register device")
			return
		}
	} else if dev, ok = s.ownDevice(w, r, user, req.DeviceID); !ok {
		return
	}
	if dev.TenantID != tenantID {
		s.writeError(w, http.StatusNotFound, "Unknown device")
		return
	}
	keys := make([]store.E2EEOneTimeKey, 0, len(req.OneTimeKeys)+1)
	add := func(k e2eeKeyJSON, fallback bool) bool {
		_, okKey := e2eeKey(k.Key)
		if !e2eeKeyID.MatchString(k.KeyID) || !okKey || !e2eeSigned(dev.Ed25519, E2EEOneTimeKeySigned(user.ID, dev.DeviceID, k.KeyID, k.Key), k.Signature) {
			return false
		}
		keys = append(keys, store.E2EEOneTimeKey{KeyID: k.KeyID, Key: k.Key, Signature: k.Signature, Fallback: fallback})
		return true
	}
	for _, k := range req.OneTimeKeys {
		if !add(k, false) {
			s.writeError(w, http.StatusBadRequest, "One-time keys must be validly signed by the device")
			return
		}
	}
	if req.FallbackKey != nil && !add(*req.FallbackKey, true) {
		s.writeError(w, http.StatusBadRequest, "The fallback key must be validly signed by the device")
		return
	}
	err := s.store.E2EE().AddOneTimeKeys(ctx, user.ID, dev.DeviceID, keys, e2eeMaxStoredKeys)
	if errors.Is(err, store.ErrE2EETooManyKeys) {
		s.writeError(w, http.StatusBadRequest, "Too many one-time keys stored for this device")
		return
	}
	var count int
	var fallback bool
	if err == nil {
		count, err = s.store.E2EE().CountOneTimeKeys(ctx, user.ID, dev.DeviceID)
	}
	if err == nil {
		fallback, err = s.store.E2EE().HasFallbackKey(ctx, user.ID, dev.DeviceID)
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to store keys")
		return
	}
	// A device with no live fallback key (none yet, or retired by a restore) must upload a new one.
	s.writeJSON(w, http.StatusOK, map[string]any{"one_time_key_count": count, "has_fallback_key": fallback})
}

type e2eeDeviceJSON struct {
	DeviceID   string `json:"device_id"`
	Curve25519 string `json:"curve25519"`
	Ed25519    string `json:"ed25519"`
	Signature  string `json:"signature"`
	// The current master key's cross-signature; absent until the device is verified.
	MasterSignature string `json:"master_signature,omitempty"`
}

// POST /api/v1/keys/query lists the devices and master keys of users in the caller's
// organization, which it names as tenant_id (the org every signed statement binds). Anyone
// else has no devices and no master key, exactly like a user who has never set up encryption.
func (s *Server) handleE2EEQuery(w http.ResponseWriter, r *http.Request) {
	_, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.UserIDs) == 0 || len(req.UserIDs) > e2eeMaxBatch {
		s.writeError(w, http.StatusBadRequest, "Name 1 to 100 users")
		return
	}
	devs, err := s.store.E2EE().ListDevices(r.Context(), tenantID, req.UserIDs)
	var masters []store.E2EEMasterKey
	if err == nil {
		masters, err = s.store.E2EE().ListMasterKeys(r.Context(), tenantID, req.UserIDs)
	}
	var bots map[string]e2eeBotDevicesJSON
	var owners []store.E2EEMasterKey
	if err == nil {
		bots, owners, err = s.botLists(r, tenantID, req.UserIDs)
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load devices")
		return
	}
	// A bot's owner's master key comes with its list, so a client can check the owner's signature.
	masters = append(masters, owners...)
	version := map[string]int64{}
	masterOut := map[string]e2eeMasterJSON{}
	for i := range masters {
		masterOut[masters[i].UserID] = masterJSON(&masters[i])
		version[masters[i].UserID] = masters[i].Version
	}
	out := make(map[string][]e2eeDeviceJSON, len(req.UserIDs))
	for _, id := range req.UserIDs {
		out[id] = []e2eeDeviceJSON{}
	}
	for _, d := range devs {
		j := e2eeDeviceJSON{DeviceID: d.DeviceID, Curve25519: d.Curve25519, Ed25519: d.Ed25519, Signature: d.Signature}
		// Only a signature by the current master key counts; a reset leaves none.
		if v, ok := version[d.UserID]; ok && d.MasterVersion == v {
			j.MasterSignature = d.MasterSignature
		}
		out[d.UserID] = append(out[d.UserID], j)
	}
	resp := map[string]any{"tenant_id": tenantID, "devices": out, "master_keys": masterOut}
	if len(bots) > 0 {
		resp["bot_devices"] = bots
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/keys/claim takes one one-time key per named device, to start Olm sessions.
func (s *Server) handleE2EEClaim(w http.ResponseWriter, r *http.Request) {
	_, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Devices []struct {
			UserID   string `json:"user_id"`
			DeviceID string `json:"device_id"`
		} `json:"devices"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Devices) == 0 || len(req.Devices) > e2eeMaxBatch {
		s.writeError(w, http.StatusBadRequest, "Name 1 to 100 devices")
		return
	}
	type claimed struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
		e2eeKeyJSON
		Fallback bool `json:"fallback"`
	}
	out := []claimed{}
	for _, want := range req.Devices {
		d, err := s.store.E2EE().GetDevice(r.Context(), want.UserID, want.DeviceID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && d.TenantID != tenantID) {
			continue // another org's device reads as no device
		}
		var k *store.E2EEOneTimeKey
		if err == nil {
			k, err = s.store.E2EE().ClaimOneTimeKey(r.Context(), want.UserID, want.DeviceID)
		}
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to claim keys")
			return
		}
		out = append(out, claimed{want.UserID, want.DeviceID, e2eeKeyJSON{k.KeyID, k.Key, k.Signature}, k.Fallback})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// PUT /api/v1/to-device relays opaque messages (Olm ciphertext) from the caller's device to
// devices in the caller's organization, and wakes their WebSockets.
func (s *Server) handleE2EESendToDevice(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		Messages []struct {
			UserID   string `json:"user_id"`
			DeviceID string `json:"device_id"`
			Type     string `json:"type"`
			Content  string `json:"content"`
		} `json:"messages"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Messages) == 0 || len(req.Messages) > e2eeMaxBatch {
		s.writeError(w, http.StatusBadRequest, "Send 1 to 100 messages")
		return
	}
	sender, ok := s.ownDevice(w, r, user, req.DeviceID)
	if !ok {
		return
	}
	// New mail only from a device on its user's current signed list (spec §8): mail it sent while
	// listed stays deliverable, but a removed device cannot send more.
	if listed, err := s.deviceListed(r, tenantID, user.ID, sender); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the device list")
		return
	} else if !listed {
		s.writeError(w, http.StatusForbidden, "This device is not on its signed device list")
		return
	}
	msgs := make([]store.E2EEToDevice, 0, len(req.Messages))
	recipients := map[string]struct{}{}
	for _, m := range req.Messages {
		if !e2eeMsgType.MatchString(m.Type) || m.Content == "" || len(m.Content) > e2eeMaxContent {
			s.writeError(w, http.StatusBadRequest, "Invalid message")
			return
		}
		d, err := s.store.E2EE().GetDevice(r.Context(), m.UserID, m.DeviceID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && d.TenantID != tenantID) {
			s.writeError(w, http.StatusNotFound, "Unknown recipient device")
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to load device")
			return
		}
		msgs = append(msgs, store.E2EEToDevice{TenantID: tenantID, RecipientUserID: m.UserID, RecipientDeviceID: m.DeviceID,
			SenderUserID: user.ID, SenderDeviceID: sender.DeviceID,
			SenderCurve25519: sender.Curve25519, SenderEd25519: sender.Ed25519, SenderSignature: sender.Signature, SenderMasterSignature: sender.MasterSignature,
			Type: m.Type, Content: m.Content})
		recipients[m.UserID] = struct{}{}
	}
	if err := s.store.E2EE().SendToDevice(r.Context(), msgs); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to send")
		return
	}
	for id := range recipients {
		_ = s.chatHub.PublishUser(r.Context(), id, chat.Event{Type: chat.EventToDevice, UserID: id})
	}
	s.writeJSON(w, http.StatusOK, map[string]int{"sent": len(msgs)})
}

// deviceListed says whether d is on userID's current signed list: a person's device list, or
// for a bot the list its owner signed, with the same keys.
func (s *Server) deviceListed(r *http.Request, tenantID, userID string, d *store.E2EEDevice) (bool, error) {
	if strings.HasPrefix(userID, "bot_") {
		bots, _, err := s.botLists(r, tenantID, []string{userID})
		return err == nil && slices.Contains(bots[userID].Devices, e2eeid.BotDevice{DeviceID: d.DeviceID, Curve25519: d.Curve25519, Ed25519: d.Ed25519}), err
	}
	ms, err := s.store.E2EE().ListMasterKeys(r.Context(), tenantID, []string{userID})
	if err != nil || len(ms) != 1 {
		return false, err
	}
	var ids []string
	return json.Unmarshal([]byte(ms[0].DeviceList), &ids) == nil && slices.Contains(ids, d.DeviceID), nil
}

// GET /api/v1/to-device?device_id=[&after=] reads the caller's oldest unacknowledged device
// mail, above ID after if given (a client paging past mail it keeps for later).
func (s *Server) handleE2EEToDevice(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	dev, ok := s.ownDevice(w, r, user, r.URL.Query().Get("device_id"))
	if !ok {
		return
	}
	var after int64
	if v := r.URL.Query().Get("after"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			after = n
		} else {
			s.writeError(w, http.StatusBadRequest, "Invalid after")
			return
		}
	}
	msgs, err := s.store.E2EE().ToDevice(r.Context(), user.ID, dev.DeviceID, after, e2eeMailboxPage)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to read mail")
		return
	}
	type mail struct {
		ID             int64  `json:"id"`
		SenderUserID   string `json:"sender_user_id"`
		SenderDeviceID string `json:"sender_device_id"`
		// The sender device's self-signed keys (and master cross-signature) at send time, so
		// mail from a device signed out since stays verifiable.
		SenderKeys e2eeDeviceJSON `json:"sender_keys"`
		Type       string         `json:"type"`
		Content    string         `json:"content"`
		SentAt     int64          `json:"sent_at"`
	}
	out := make([]mail, len(msgs))
	for i, m := range msgs {
		out[i] = mail{m.ID, m.SenderUserID, m.SenderDeviceID, e2eeDeviceJSON{DeviceID: m.SenderDeviceID, Curve25519: m.SenderCurve25519, Ed25519: m.SenderEd25519, Signature: m.SenderSignature, MasterSignature: m.SenderMasterSignature}, m.Type, m.Content, m.CreatedAt.UnixMilli()}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

// POST /api/v1/to-device/ack deletes the device mail the caller processed, by ID.
func (s *Server) handleE2EEAck(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceID string  `json:"device_id"`
		IDs      []int64 `json:"ids"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.IDs) == 0 || len(req.IDs) > e2eeMailboxPage {
		s.writeError(w, http.StatusBadRequest, "Invalid acknowledgement")
		return
	}
	dev, ok := s.ownDevice(w, r, user, req.DeviceID)
	if !ok {
		return
	}
	if err := s.store.E2EE().AckToDevice(r.Context(), user.ID, dev.DeviceID, req.IDs); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to acknowledge")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /api/v1/keys/devices/{id} removes one of the caller's devices with its keys and mail.
func (s *Server) handleE2EEDeleteDevice(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	err := s.store.E2EE().DeleteDevice(r.Context(), user.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Unknown device")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to remove device")
		return
	}
	s.audit(r.Context(), user.ID, r, "e2ee.device_removed", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}
