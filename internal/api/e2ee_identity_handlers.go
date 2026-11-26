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
	// E2EEBackupMaxSessions caps one user's key backup (about 2 KB a session).
	E2EEBackupMaxSessions = 20000
	e2eeBackupPage        = 200
	e2eeBackupBatch       = 100
	// E2EEPairingTTL is how long a QR pairing stays open.
	E2EEPairingTTL   = 3 * time.Minute
	e2eeIdentityBody = 64 << 10
	e2eeMaxWrap      = 512
	e2eeMaxPins      = 512 << 10
	e2eeMaxTransfer  = 4 << 10
)

var (
	e2eeRoomID    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	e2eePairingID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// hybridJSON is a hybridsig key or signature on the wire.
type hybridJSON struct {
	Alg     string `json:"alg"`
	MLDSA65 string `json:"mldsa65"`
	Ed25519 string `json:"ed25519"`
}

func (h hybridJSON) halves() ([]byte, []byte, bool) {
	m, err1 := base64.RawStdEncoding.DecodeString(h.MLDSA65)
	e, err2 := base64.RawStdEncoding.DecodeString(h.Ed25519)
	return m, e, h.Alg == hybridsig.Alg && err1 == nil && err2 == nil
}

func (h hybridJSON) publicKey() (hybridsig.PublicKey, bool) {
	m, e, ok := h.halves()
	p := hybridsig.PublicKey{MLDSA65: m, Ed25519: e}
	return p, ok && p.Check() == nil
}

func (h hybridJSON) signature() (hybridsig.Signature, bool) {
	m, e, ok := h.halves()
	return hybridsig.Signature{MLDSA65: m, Ed25519: e}, ok
}

func (h hybridJSON) encode() string {
	b, _ := json.Marshal(h)
	return string(b)
}

func parseHybrid(s string) (hybridJSON, bool) {
	var h hybridJSON
	return h, json.Unmarshal([]byte(s), &h) == nil
}

// verifyHybrid reports whether sig verifies under pub for domain and msg.
func verifyHybrid(pub hybridsig.PublicKey, domain string, msg []byte, sig hybridJSON) bool {
	sg, ok := sig.signature()
	return ok && pub.Verify(domain, msg, sg) == nil
}

func storedMasterPublic(m *store.E2EEMasterKey) (hybridsig.PublicKey, bool) {
	h, ok := parseHybrid(m.MasterKey)
	if !ok {
		return hybridsig.PublicKey{}, false
	}
	return h.publicKey()
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
		ExpectedVersion int64      `json:"expected_version"`
		MasterKey       hybridJSON `json:"master_key"`
		SelfSignature   hybridJSON `json:"self_signature"`
		BackupKey       struct {
			PublicKey string     `json:"public_key"`
			Signature hybridJSON `json:"signature"`
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
		Version   int64      `json:"version"`
		Signature hybridJSON `json:"signature"`
	}
	e2eeBackupEntry struct {
		RoomID     string `json:"room_id"`
		SessionID  string `json:"session_id"`
		FirstIndex int64  `json:"first_index"`
		Sealed     string `json:"sealed"`
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

type e2eeMasterJSON struct {
	Version       int64      `json:"version"`
	MasterKey     hybridJSON `json:"master_key"`
	SelfSignature hybridJSON `json:"self_signature"`
}

func masterJSON(m *store.E2EEMasterKey) (e2eeMasterJSON, bool) {
	k, ok1 := parseHybrid(m.MasterKey)
	sg, ok2 := parseHybrid(m.SelfSignature)
	return e2eeMasterJSON{m.Version, k, sg}, ok1 && ok2
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
	mj, ok1 := masterJSON(m)
	bs, ok2 := parseHybrid(m.BackupSignature)
	if !ok1 || !ok2 {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the encryption identity")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "master": map[string]any{
		"version": mj.Version, "master_key": mj.MasterKey, "self_signature": mj.SelfSignature,
		"backup_key": map[string]any{"public_key": m.BackupKey, "signature": bs},
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
	// A reset replaces what every colleague pinned and what the user's other devices hold, so
	// it needs a recent sign-in, as console changes do; a stolen older session cannot do it.
	if _, sess, _ := s.currentUser(r); req.ExpectedVersion > 0 && (sess == nil || time.Since(sess.CreatedAt) > stepUpWindow) {
		s.writeStepUp(w, user)
		return
	}
	version := req.ExpectedVersion + 1
	pub, ok := req.MasterKey.publicKey()
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
	for _, wrap := range []string{req.Recovery.WrappedMasterKey, req.Recovery.WrappedBackupKey} {
		if n, ok := decodedLen(wrap); !ok || n < 29 || n > e2eeMaxWrap {
			s.writeError(w, http.StatusBadRequest, "Invalid recovery wraps")
			return
		}
	}
	m := &store.E2EEMasterKey{TenantID: tenantID, UserID: user.ID, MasterKey: req.MasterKey.encode(), SelfSignature: req.SelfSignature.encode(),
		BackupKey: req.BackupKey.PublicKey, BackupSignature: req.BackupKey.Signature.encode(),
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
	user, _, ok := s.e2eeCaller(w, r)
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
	switch err := s.store.E2EE().PutPins(r.Context(), user.ID, req.Version, req.ExpectedCounter, req.Sealed); {
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
	pub, ok := storedMasterPublic(m)
	if !ok || !verifyHybrid(pub, e2eeid.DomainDevice, e2eeid.DeviceMessage(tenantID, user.ID, dev.DeviceID, dev.Curve25519, dev.Ed25519), req.Signature) {
		s.writeError(w, http.StatusBadRequest, "The device signature does not verify")
		return
	}
	switch err := s.store.E2EE().SignDevice(r.Context(), user.ID, dev.DeviceID, req.Version, req.Signature.encode()); {
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
	if err != nil || version < 1 || len(q.Get("after_room")) > 128 || len(q.Get("after_session")) > 128 {
		s.writeError(w, http.StatusBadRequest, "Invalid key backup query")
		return
	}
	if !s.e2eeBackupVersion(w, r, user.ID, tenantID, version) {
		return
	}
	rows, err := s.store.E2EE().ListBackupSessions(r.Context(), user.ID, version, q.Get("after_room"), q.Get("after_session"), e2eeBackupPage)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the key backup")
		return
	}
	out := make([]e2eeBackupEntry, len(rows))
	for i, b := range rows {
		out[i] = e2eeBackupEntry{b.RoomID, b.SessionID, b.FirstIndex, b.Sealed}
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
		if !e2eeRoomID.MatchString(b.RoomID) || !e2eeSessionID.MatchString(b.SessionID) || b.FirstIndex < 0 || b.FirstIndex > 1<<32 || !ok || n < xwing.Overhead || n > e2eeid.MaxSealedSession {
			s.writeError(w, http.StatusBadRequest, "Invalid backed-up session")
			return
		}
		rows[i] = store.E2EEBackupSession{RoomID: b.RoomID, SessionID: b.SessionID, FirstIndex: b.FirstIndex, Sealed: b.Sealed}
	}
	if !s.e2eeBackupVersion(w, r, user.ID, tenantID, req.Version) {
		return
	}
	switch err := s.store.E2EE().PutBackupSessions(r.Context(), user.ID, req.Version, rows, E2EEBackupMaxSessions); {
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
		InitiatorDevice: dev.DeviceID, ExpiresAt: time.Now().Add(E2EEPairingTTL)}
	if err := s.store.E2EE().CreatePairing(r.Context(), p); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to start pairing")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"pairing_id": p.ID, "expires_at": p.ExpiresAt.UnixMilli()})
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
		"ephemeral_key": p.EphemeralKey, "sealed": p.Sealed != "", "expires_at": p.ExpiresAt.UnixMilli()})
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
	if dev.TenantID != tenantID || s.store.E2EE().JoinPairing(r.Context(), tenantID, user.ID, p.ID, dev.DeviceID, req.EphemeralKey, time.Now()) != nil {
		s.writeError(w, http.StatusConflict, "This pairing was already used")
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
	if s.store.E2EE().SealPairing(r.Context(), tenantID, user.ID, p.ID, req.DeviceID, req.Sealed, time.Now()) != nil {
		s.writeError(w, http.StatusConflict, "This pairing is not waiting for keys from this device")
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
