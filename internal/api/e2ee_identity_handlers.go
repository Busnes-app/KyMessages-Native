package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
	"github.com/Busnes-app/ky_server_base/internal/pqc/hybridsig"
	"github.com/Busnes-app/ky_server_base/internal/pqc/xwing"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// E3 identity and recovery (docs/superpowers/specs/2026-11-22-e2ee-design.md §3, §9): each
// user's hybrid master key, its device cross-signatures, the X-Wing key backup and QR pairing.
// The server checks every signature to refuse garbage early; clients verify again. It stores
// only public keys, signatures and ciphertext it cannot open.
const (
	// E2EEBackupMaxSessions and E2EEBackupMaxBytes cap one user's key backup. The whole
	// database is one capsule member, which ky-primitives caps at 64 MiB, so each user may take
	// 2 MiB of sealed text (about 1,000 sessions).
	E2EEBackupMaxSessions = 2000
	E2EEBackupMaxBytes    = 2 << 20
	e2eeBackupPage        = 200
	e2eeBackupBatch       = 100
	// A recovery wrap is version 1 ‖ nonce (12) ‖ AES-256-GCM of the seed (+16): 93 bytes for
	// the 64-byte master seed and 61 for the 32-byte backup seed. Anything else (a raw seed
	// uploaded by mistake) is refused.
	e2eeMasterWrapBytes = 1 + 12 + e2eeid.MasterSeedBytes + 16
	e2eeBackupWrapBytes = 1 + 12 + xwing.SeedBytes + 16
	e2eeMaxDeviceList   = 100
	// E2EEPairingTTL is how long a QR pairing stays open.
	E2EEPairingTTL   = 3 * time.Minute
	e2eeIdentityBody = 64 << 10
	e2eeMaxPins      = 512 << 10
	e2eeMaxTransfer  = 4 << 10
)

var (
	e2eeRoomID    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	e2eePairingID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// Master keys and their signatures travel as unpadded base64 of hybridsig's tagged encodings
// ("mldsa65+ed25519" 0x00 ‖ ML-DSA-65 half ‖ Ed25519 half), which name the algorithm.
func parseMasterKey(v string) (*hybridsig.PublicKey, bool) {
	b, err := base64.RawStdEncoding.DecodeString(v)
	if err != nil {
		return nil, false
	}
	p, err := hybridsig.ParsePublicKey(b)
	return p, err == nil
}

// verifyHybrid reports whether sig verifies under pub for domain and msg.
func verifyHybrid(pub *hybridsig.PublicKey, domain string, msg []byte, sig string) bool {
	b, err := base64.RawStdEncoding.DecodeString(sig)
	return err == nil && len(b) == hybridsig.SignatureBytes && pub.Verify(domain, msg, b) == nil
}

// e2eeFresh writes the console's step-up refusal unless the caller's session is younger than
// stepUpWindow. Identity setup, reset and backup deletion all change what the user's other
// devices and colleagues trust or can recover, so a stolen older session cannot do them.
func (s *Server) e2eeFresh(w http.ResponseWriter, r *http.Request, user *store.User) bool {
	if _, sess, _ := s.currentUser(r); sess != nil && time.Since(sess.CreatedAt) <= stepUpWindow {
		return true
	}
	s.writeStepUp(w, user)
	return false
}

// decodeIdentity is decodeStrict with a larger cap: master keys and their signatures are
// several kilobytes, and a pin set or backup batch more.
func decodeIdentity(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && dec.Decode(&struct{}{}) == io.EOF
}

func decodedLen(s string) (int, bool) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	return len(b), err == nil
}

// Request bodies. Every one is decoded strictly, and none has a field for a private key, a
// recovery key or a session key (TestE2EEIdentityBodiesCarryNoSecrets).
type (
	e2eeMasterPut struct {
		ExpectedVersion int64  `json:"expected_version"`
		MasterKey       string `json:"master_key"`
		SelfSignature   string `json:"self_signature"`
		BackupKey       struct {
			PublicKey string `json:"public_key"`
			Signature string `json:"signature"`
		} `json:"backup_key"`
		Recovery struct {
			WrappedMasterKey string `json:"wrapped_master_key"`
			WrappedBackupKey string `json:"wrapped_backup_key"`
		} `json:"recovery"`
	}
	e2eePinsPut struct {
		Version         int64  `json:"version"`
		ExpectedCounter int64  `json:"expected_counter"`
		Sealed          string `json:"sealed"`
	}
	e2eeDeviceSignature struct {
		Version   int64  `json:"version"`
		Signature string `json:"signature"`
	}
	e2eeBackupEntry struct {
		RoomID     string `json:"room_id"`
		SenderKey  string `json:"sender_key"`
		SessionID  string `json:"session_id"`
		FirstIndex int64  `json:"first_index"`
		Sealed     string `json:"sealed"`
	}
	e2eeDeviceListPut struct {
		Version       int64    `json:"version"`
		ExpectedEpoch int64    `json:"expected_epoch"`
		DeviceIDs     []string `json:"device_ids"`
		Signature     string   `json:"signature"`
	}
	e2eeBackupPut struct {
		Version  int64             `json:"version"`
		Sessions []e2eeBackupEntry `json:"sessions"`
	}
	e2eePairingStart struct {
		DeviceID string `json:"device_id"`
	}
	e2eePairingJoin struct {
		DeviceID     string `json:"device_id"`
		EphemeralKey string `json:"ephemeral_key"`
	}
	e2eePairingSeal struct {
		DeviceID string `json:"device_id"`
		Sealed   string `json:"sealed"`
	}
)

type e2eeDeviceListJSON struct {
	Epoch     int64    `json:"epoch"`
	DeviceIDs []string `json:"device_ids"`
	Signature string   `json:"signature"`
}

type e2eeMasterJSON struct {
	Version       int64  `json:"version"`
	MasterKey     string `json:"master_key"`
	SelfSignature string `json:"self_signature"`
	// The master-signed list of the user's devices; absent until the first device signs one.
	DeviceList *e2eeDeviceListJSON `json:"device_list,omitempty"`
}

func masterJSON(m *store.E2EEMasterKey) e2eeMasterJSON {
	out := e2eeMasterJSON{Version: m.Version, MasterKey: m.MasterKey, SelfSignature: m.SelfSignature}
	var ids []string
	if m.DeviceListEpoch > 0 && json.Unmarshal([]byte(m.DeviceList), &ids) == nil {
		out.DeviceList = &e2eeDeviceListJSON{m.DeviceListEpoch, ids, m.DeviceListSignature}
	}
	return out
}

// GET /api/v1/keys/master answers the caller's own identity, with the recovery-key wraps a
// new device needs and the sealed pin set, or master null before the first device sets one.
func (s *Server) handleE2EEGetMaster(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	m, err := s.store.E2EE().GetMasterKey(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.TenantID != tenantID) {
		s.writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "master": nil})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the encryption identity")
		return
	}
	mj := masterJSON(m)
	s.writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "master": map[string]any{
		"version": m.Version, "master_key": m.MasterKey, "self_signature": m.SelfSignature, "device_list": mj.DeviceList,
		"backup_key": map[string]any{"public_key": m.BackupKey, "signature": m.BackupSignature},
		"recovery":   map[string]string{"wrapped_master_key": m.RecoveryMaster, "wrapped_backup_key": m.RecoveryBackup},
		"pins":       map[string]any{"counter": m.PinsCounter, "sealed": m.Pins},
	}})
}

// PUT /api/v1/keys/master sets the caller's identity (expected_version 0) or replaces it
// (expected_version the current one, from a sign-in in the last 10 minutes), which also drops
// the old key backup, pin set and device cross-signatures. Colleagues then see the change.
func (s *Server) handleE2EEPutMaster(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeMasterPut
	if !decodeIdentity(w, r, e2eeIdentityBody, &req) || req.ExpectedVersion < 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid encryption identity")
		return
	}
	if !s.e2eeFresh(w, r, user) {
		return
	}
	version := req.ExpectedVersion + 1
	pub, ok := parseMasterKey(req.MasterKey)
	backupPub, err := base64.RawStdEncoding.DecodeString(req.BackupKey.PublicKey)
	if !ok || err != nil || xwingKey(backupPub) != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid encryption identity")
		return
	}
	if !verifyHybrid(pub, e2eeid.DomainMaster, e2eeid.MasterSelfMessage(tenantID, user.ID, pub), req.SelfSignature) ||
		!verifyHybrid(pub, e2eeid.DomainBackupKey, e2eeid.BackupKeyMessage(tenantID, user.ID, version, backupPub), req.BackupKey.Signature) {
		s.writeError(w, http.StatusBadRequest, "The encryption identity is not validly signed")
		return
	}
	for wrap, want := range map[string]int{req.Recovery.WrappedMasterKey: e2eeMasterWrapBytes, req.Recovery.WrappedBackupKey: e2eeBackupWrapBytes} {
		b, err := base64.RawStdEncoding.DecodeString(wrap)
		if err != nil || len(b) != want || b[0] != 1 {
			s.writeError(w, http.StatusBadRequest, "Invalid recovery wraps")
			return
		}
	}
	m := &store.E2EEMasterKey{TenantID: tenantID, UserID: user.ID, MasterKey: req.MasterKey, SelfSignature: req.SelfSignature,
		BackupKey: req.BackupKey.PublicKey, BackupSignature: req.BackupKey.Signature,
		RecoveryMaster: req.Recovery.WrappedMasterKey, RecoveryBackup: req.Recovery.WrappedBackupKey}
	switch err := s.store.E2EE().PutMasterKey(r.Context(), m, req.ExpectedVersion); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The encryption identity changed; reload it")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the encryption identity")
		return
	}
	action := "e2ee.master_key_set"
	if req.ExpectedVersion > 0 {
		action = "e2ee.master_key_reset"
	}
	s.audit(r.Context(), user.ID, r, action, user.ID, "version="+strconv.FormatInt(m.Version, 10))
	s.writeJSON(w, http.StatusOK, map[string]int64{"version": m.Version})
}

func xwingKey(b []byte) error {
	_, err := xwing.ParsePublicKey(b)
	return err
}

// PUT /api/v1/keys/pins replaces the caller's sealed pin set, compare-and-swap on its counter.
func (s *Server) handleE2EEPutPins(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eePinsPut
	if !decodeIdentity(w, r, e2eeMaxPins*2, &req) || req.Version < 1 || req.ExpectedCounter < 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid pin set")
		return
	}
	if n, ok := decodedLen(req.Sealed); !ok || n < 29 || n > e2eeMaxPins {
		s.writeError(w, http.StatusBadRequest, "Invalid pin set")
		return
	}
	switch err := s.store.E2EE().PutPins(r.Context(), tenantID, user.ID, req.Version, req.ExpectedCounter, req.Sealed); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The pin set changed; reload it")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the pin set")
	default:
		s.writeJSON(w, http.StatusOK, map[string]int64{"counter": req.ExpectedCounter + 1})
	}
}

// POST /api/v1/keys/devices/{id}/signature stores the master key's signature over one of the
// caller's devices, after checking it against the current master key.
func (s *Server) handleE2EESignDevice(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeDeviceSignature
	if !decodeIdentity(w, r, e2eeIdentityBody, &req) {
		s.writeError(w, http.StatusBadRequest, "Invalid device signature")
		return
	}
	dev, ok := s.ownDevice(w, r, user, r.PathValue("id"))
	if !ok {
		return
	}
	m, err := s.store.E2EE().GetMasterKey(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (m.TenantID != tenantID || dev.TenantID != tenantID || m.Version != req.Version)) {
		s.writeError(w, http.StatusConflict, "The encryption identity changed; reload it")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the encryption identity")
		return
	}
	pub, ok := parseMasterKey(m.MasterKey)
	if !ok || !verifyHybrid(pub, e2eeid.DomainDevice, e2eeid.DeviceMessage(tenantID, user.ID, dev.DeviceID, dev.Curve25519, dev.Ed25519), req.Signature) {
		s.writeError(w, http.StatusBadRequest, "The device signature does not verify")
		return
	}
	switch err := s.store.E2EE().SignDevice(r.Context(), user.ID, dev.DeviceID, req.Version, req.Signature); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The encryption identity changed; reload it")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the device signature")
		return
	}
	s.audit(r.Context(), user.ID, r, "e2ee.device_verified", dev.DeviceID, "")
	w.WriteHeader(http.StatusNoContent)
}

// PUT /api/v1/keys/devices/list stores the master-signed list of the caller's devices,
// compare-and-swap on its epoch. Clients trust only listed devices and remember the newest
// epoch, so a device removed from the list cannot be brought back by the server.
func (s *Server) handleE2EEPutDeviceList(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeDeviceListPut
	if !decodeIdentity(w, r, e2eeIdentityBody, &req) || req.Version < 1 || req.ExpectedEpoch < 0 || len(req.DeviceIDs) > e2eeMaxDeviceList {
		s.writeError(w, http.StatusBadRequest, "Invalid device list")
		return
	}
	for _, id := range req.DeviceIDs {
		if !e2eeDeviceID.MatchString(id) {
			s.writeError(w, http.StatusBadRequest, "Invalid device list")
			return
		}
	}
	msg, err := e2eeid.DeviceListMessage(tenantID, user.ID, req.Version, req.ExpectedEpoch+1, req.DeviceIDs)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid device list")
		return
	}
	m, err := s.store.E2EE().GetMasterKey(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (m.TenantID != tenantID || m.Version != req.Version)) {
		s.writeError(w, http.StatusConflict, "The encryption identity changed; reload it")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the encryption identity")
		return
	}
	pub, ok := parseMasterKey(m.MasterKey)
	if !ok || !verifyHybrid(pub, e2eeid.DomainDeviceList, msg, req.Signature) {
		s.writeError(w, http.StatusBadRequest, "The device list is not validly signed")
		return
	}
	list, _ := json.Marshal(req.DeviceIDs)
	switch err := s.store.E2EE().PutDeviceList(r.Context(), tenantID, user.ID, req.Version, req.ExpectedEpoch, string(list), req.Signature); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The device list changed; reload it")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the device list")
	default:
		s.writeJSON(w, http.StatusOK, map[string]int64{"epoch": req.ExpectedEpoch + 1})
	}
}

// e2eeBackupVersion reads the caller's current identity version, writing 409 when version
// is not it.
func (s *Server) e2eeBackupVersion(w http.ResponseWriter, r *http.Request, userID, tenantID string, version int64) bool {
	m, err := s.store.E2EE().GetMasterKey(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (m.TenantID != tenantID || m.Version != version)) {
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
		return false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the key backup")
		return false
	}
	return true
}

// GET /api/v1/keys/backup?version=&after_room=&after_session= pages the caller's sealed sessions.
func (s *Server) handleE2EEGetBackup(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	version, err := strconv.ParseInt(q.Get("version"), 10, 64)
	if err != nil || version < 1 || len(q.Get("after_room")) > 128 || len(q.Get("after_sender")) > 64 || len(q.Get("after_session")) > 128 {
		s.writeError(w, http.StatusBadRequest, "Invalid key backup query")
		return
	}
	if !s.e2eeBackupVersion(w, r, user.ID, tenantID, version) {
		return
	}
	after := store.E2EEBackupCursor{RoomID: q.Get("after_room"), SenderKey: q.Get("after_sender"), SessionID: q.Get("after_session")}
	rows, err := s.store.E2EE().ListBackupSessions(r.Context(), user.ID, version, after, e2eeBackupPage)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the key backup")
		return
	}
	out := make([]e2eeBackupEntry, len(rows))
	for i, b := range rows {
		out[i] = e2eeBackupEntry{b.RoomID, b.SenderKey, b.SessionID, b.FirstIndex, b.Sealed}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"version": version, "sessions": out, "more": len(rows) == e2eeBackupPage})
}

// PUT /api/v1/keys/backup adds sealed sessions; a session already backed up is replaced only
// by a copy reaching further back.
func (s *Server) handleE2EEPutBackup(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeBackupPut
	if !decodeIdentity(w, r, 1<<20, &req) || req.Version < 1 || len(req.Sessions) == 0 || len(req.Sessions) > e2eeBackupBatch {
		s.writeError(w, http.StatusBadRequest, "Send 1 to 100 backed-up sessions")
		return
	}
	rows := make([]store.E2EEBackupSession, len(req.Sessions))
	for i, b := range req.Sessions {
		n, ok := decodedLen(b.Sealed)
		_, senderOK := e2eeKey(b.SenderKey)
		if !e2eeRoomID.MatchString(b.RoomID) || !senderOK || !e2eeSessionID.MatchString(b.SessionID) || b.FirstIndex < 0 || b.FirstIndex > 1<<32 || !ok || n < xwing.Overhead || n > e2eeid.MaxSealedSession {
			s.writeError(w, http.StatusBadRequest, "Invalid backed-up session")
			return
		}
		rows[i] = store.E2EEBackupSession{RoomID: b.RoomID, SenderKey: b.SenderKey, SessionID: b.SessionID, FirstIndex: b.FirstIndex, Sealed: b.Sealed}
	}
	if !s.e2eeBackupVersion(w, r, user.ID, tenantID, req.Version) {
		return
	}
	switch err := s.store.E2EE().PutBackupSessions(r.Context(), user.ID, req.Version, rows, E2EEBackupMaxSessions, E2EEBackupMaxBytes); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
	case errors.Is(err, store.ErrE2EEBackupFull):
		s.writeError(w, http.StatusInsufficientStorage, "The key backup is full")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the key backup")
	default:
		s.writeJSON(w, http.StatusOK, map[string]int{"stored": len(rows)})
	}
}

// DELETE /api/v1/keys/backup?version= empties the caller's key backup.
func (s *Server) handleE2EEDeleteBackup(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if err != nil || version < 1 {
		s.writeError(w, http.StatusBadRequest, "Invalid key backup version")
		return
	}
	if !s.e2eeFresh(w, r, user) {
		return
	}
	if !s.e2eeBackupVersion(w, r, user.ID, tenantID, version) {
		return
	}
	switch err := s.store.E2EE().DeleteBackup(r.Context(), user.ID, version); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete the key backup")
	default:
		s.audit(r.Context(), user.ID, r, "e2ee.backup_deleted", user.ID, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- QR pairing: a relay between two devices of one user, one-time and short-lived. ---

// POST /api/v1/keys/pairings opens a pairing from a verified device (one whose cross-signature
// is by the current master key). It cancels the caller's other pairings.
func (s *Server) handleE2EEPairingStart(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eePairingStart
	if !decodeIdentity(w, r, 4<<10, &req) {
		s.writeError(w, http.StatusBadRequest, "Invalid pairing")
		return
	}
	dev, ok := s.ownDevice(w, r, user, req.DeviceID)
	if !ok {
		return
	}
	m, err := s.store.E2EE().GetMasterKey(r.Context(), user.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the encryption identity")
		return
	}
	if err != nil || dev.TenantID != tenantID || m.TenantID != tenantID || dev.MasterSignature == "" || dev.MasterVersion != m.Version {
		s.writeError(w, http.StatusForbidden, "Only a verified device can verify another")
		return
	}
	raw := make([]byte, e2eeid.PairingIDBytes)
	if _, err := rand.Read(raw); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to start pairing")
		return
	}
	p := &store.E2EEPairing{ID: base64.RawURLEncoding.EncodeToString(raw), TenantID: tenantID, UserID: user.ID,
		InitiatorDevice: dev.DeviceID, MasterVersion: m.Version, ExpiresAt: time.Now().Add(E2EEPairingTTL)}
	switch err := s.store.E2EE().CreatePairing(r.Context(), p); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusForbidden, "Only a verified device can verify another")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to start pairing")
		return
	}
	// A relative lifetime as well: the browser's clock may disagree with the server's.
	s.writeJSON(w, http.StatusCreated, map[string]any{"pairing_id": p.ID, "expires_at": p.ExpiresAt.UnixMilli(), "expires_in_ms": E2EEPairingTTL.Milliseconds()})
}

// e2eePairing loads the caller's unexpired pairing named in the path, writing 404 otherwise:
// another user's or org's pairing reads exactly like an unknown one.
func (s *Server) e2eePairing(w http.ResponseWriter, r *http.Request) (*store.User, string, *store.E2EEPairing, bool) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return nil, "", nil, false
	}
	id := r.PathValue("id")
	if !e2eePairingID.MatchString(id) {
		s.writeError(w, http.StatusNotFound, "Unknown pairing")
		return nil, "", nil, false
	}
	p, err := s.store.E2EE().GetPairing(r.Context(), tenantID, user.ID, id, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Unknown pairing")
		return nil, "", nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load pairing")
		return nil, "", nil, false
	}
	return user, tenantID, p, true
}

// GET /api/v1/keys/pairings/{id} answers the pairing's state, never the sealed keys.
func (s *Server) handleE2EEPairingGet(w http.ResponseWriter, r *http.Request) {
	_, _, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"pairing_id": p.ID, "initiator_device": p.InitiatorDevice, "new_device": p.NewDevice,
		"ephemeral_key": p.EphemeralKey, "sealed": p.Sealed != "", "expires_at": p.ExpiresAt.UnixMilli(), "expires_in_ms": max(time.Until(p.ExpiresAt).Milliseconds(), 0)})
}

// POST /api/v1/keys/pairings/{id}/join posts the new device's ephemeral X-Wing key, once.
func (s *Server) handleE2EEPairingJoin(w http.ResponseWriter, r *http.Request) {
	user, tenantID, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	var req e2eePairingJoin
	if !decodeIdentity(w, r, 4<<10, &req) {
		s.writeError(w, http.StatusBadRequest, "Invalid pairing")
		return
	}
	eph, err := base64.RawStdEncoding.DecodeString(req.EphemeralKey)
	if err != nil || xwingKey(eph) != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid ephemeral key")
		return
	}
	dev, ok := s.ownDevice(w, r, user, req.DeviceID)
	if !ok {
		return
	}
	if dev.TenantID != tenantID {
		s.writeError(w, http.StatusNotFound, "Unknown device")
		return
	}
	switch err := s.store.E2EE().JoinPairing(r.Context(), tenantID, user.ID, p.ID, dev.DeviceID, req.EphemeralKey, time.Now()); {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusConflict, "This pairing was already used")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to join pairing")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PUT /api/v1/keys/pairings/{id}/sealed stores the initiator's two-layer sealed keys, once.
func (s *Server) handleE2EEPairingSeal(w http.ResponseWriter, r *http.Request) {
	user, tenantID, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	var req e2eePairingSeal
	if !decodeIdentity(w, r, 16<<10, &req) {
		s.writeError(w, http.StatusBadRequest, "Invalid pairing")
		return
	}
	if n, ok := decodedLen(req.Sealed); !ok || n < xwing.Overhead || n > e2eeMaxTransfer {
		s.writeError(w, http.StatusBadRequest, "Invalid sealed keys")
		return
	}
	switch err := s.store.E2EE().SealPairing(r.Context(), tenantID, user.ID, p.ID, req.DeviceID, req.Sealed, time.Now()); {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusConflict, "This pairing is not waiting for keys from this device")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the keys")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/keys/pairings/{id}/consume hands the sealed keys to the new device and deletes
// the pairing in the same statement, so they are handed out exactly once.
func (s *Server) handleE2EEPairingConsume(w http.ResponseWriter, r *http.Request) {
	user, tenantID, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	var req e2eePairingStart
	if !decodeIdentity(w, r, 4<<10, &req) {
		s.writeError(w, http.StatusBadRequest, "Invalid pairing")
		return
	}
	got, err := s.store.E2EE().ConsumePairing(r.Context(), tenantID, user.ID, p.ID, req.DeviceID, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusConflict, "No keys are waiting for this device")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to read pairing")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]string{"initiator_device": got.InitiatorDevice, "sealed": got.Sealed})
}

// DELETE /api/v1/keys/pairings/{id} cancels a pairing from either device.
func (s *Server) handleE2EEPairingDelete(w http.ResponseWriter, r *http.Request) {
	user, tenantID, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	if err := s.store.E2EE().DeletePairing(r.Context(), tenantID, user.ID, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, "Failed to cancel pairing")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
