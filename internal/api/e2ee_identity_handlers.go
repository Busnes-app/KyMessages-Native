package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"math"
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
	E2EEPairingTTL = 3 * time.Minute
	// E2EEDeviceListReservation is how long a device holds the next device list epoch between
	// reserving it and publishing the list it signed.
	E2EEDeviceListReservation = 30 * time.Second
	e2eeIdentityBody          = 64 << 10
	e2eeMaxPins               = 512 << 10
	e2eeMaxTransfer           = 4 << 10
)

var (
	e2eeRoomID    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	e2eePairingID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	e2eeDigest    = regexp.MustCompile(`^[0-9a-f]{64}$`)
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

// decodeIdentity decodes one JSON value with encoding/json/v2 under a size cap: member names
// match case-sensitively, and a repeated or unknown name, invalid UTF-8 or trailing data fails.
// So no signed field can be shadowed by a second spelling that another parser would read.
func decodeIdentity(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	return err == nil && jsonv2.Unmarshal(b, v, jsonv2.RejectUnknownMembers(true)) == nil
}

// errProof is a write whose master-key signature does not verify.
var errProof = errors.New("e2ee: the write is not signed by the current master key")

// proofOf verifies sig over msg under the master key the store hands it, inside the write's
// transaction.
func proofOf(domain string, msg []byte, sig string) store.Proof {
	return func(masterKey string) error {
		pub, ok := parseMasterKey(masterKey)
		if !ok || !verifyHybrid(pub, domain, msg, sig) {
			return errProof
		}
		return nil
	}
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
		// The master key's kymessages.pins-write.v1 signature over this write.
		Signature string `json:"signature"`
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
		Version       int64 `json:"version"`
		ExpectedEpoch int64 `json:"expected_epoch"`
		// The epoch the reservation granted, which the signature names.
		Epoch     int64    `json:"epoch"`
		DeviceIDs []string `json:"device_ids"`
		Signature string   `json:"signature"`
	}
	e2eeDeviceListReserve struct {
		Version       int64 `json:"version"`
		ExpectedEpoch int64 `json:"expected_epoch"`
		// e2eeid.DeviceListDigest of the proposed list.
		Digest string `json:"digest"`
	}
	e2eeBackupPut struct {
		Version    int64             `json:"version"`
		Generation int64             `json:"generation"`
		Sessions   []e2eeBackupEntry `json:"sessions"`
		// The master key's kymessages.backup-write.v1 signature over the batch.
		Signature string `json:"signature"`
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
		// An empty list is an array, never null.
		out.DeviceList = &e2eeDeviceListJSON{m.DeviceListEpoch, append([]string{}, ids...), m.DeviceListSignature}
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
		"backup_key":        map[string]any{"public_key": m.BackupKey, "signature": m.BackupSignature},
		"backup_generation": m.BackupGeneration,
		"recovery":          map[string]string{"wrapped_master_key": m.RecoveryMaster, "wrapped_backup_key": m.RecoveryBackup},
		"pins":              map[string]any{"counter": m.PinsCounter, "sealed": m.Pins},
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
	// Each wrap on its own: two equal strings must not stand in for both checks.
	if !wrapOK(req.Recovery.WrappedMasterKey, e2eeMasterWrapBytes) || !wrapOK(req.Recovery.WrappedBackupKey, e2eeBackupWrapBytes) {
		s.writeError(w, http.StatusBadRequest, "Invalid recovery wraps")
		return
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

// wrapOK reports whether wrap is version 1 and exactly n bytes.
func wrapOK(wrap string, n int) bool {
	b, err := base64.RawStdEncoding.DecodeString(wrap)
	return err == nil && len(b) == n && b[0] == 1
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
	sealed, err := base64.RawStdEncoding.DecodeString(req.Sealed)
	if err != nil || len(sealed) < 29 || len(sealed) > e2eeMaxPins {
		s.writeError(w, http.StatusBadRequest, "Invalid pin set")
		return
	}
	proof := proofOf(e2eeid.DomainPinsWrite, e2eeid.PinsWriteMessage(tenantID, user.ID, req.Version, req.ExpectedCounter+1, sealed), req.Signature)
	switch err := s.store.E2EE().PutPins(r.Context(), tenantID, user.ID, req.Version, req.ExpectedCounter, req.Sealed, proof); {
	case errors.Is(err, errProof):
		s.writeError(w, http.StatusBadRequest, "The pin set is not signed by the current master key")
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
	deviceID := r.PathValue("id")
	// Verified against the master key and device row read in the write's own transaction, so
	// a reset committing meanwhile cannot let a signature by the old key land.
	proof := func(masterKey string, d *store.E2EEDevice) error {
		return proofOf(e2eeid.DomainDevice, e2eeid.DeviceMessage(tenantID, user.ID, d.DeviceID, d.Curve25519, d.Ed25519), req.Signature)(masterKey)
	}
	switch err := s.store.E2EE().SignDevice(r.Context(), tenantID, user.ID, deviceID, req.Version, req.Signature, proof); {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Unknown device")
		return
	case errors.Is(err, errProof):
		s.writeError(w, http.StatusBadRequest, "The device signature does not verify")
		return
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The encryption identity changed; reload it")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the device signature")
		return
	}
	s.audit(r.Context(), user.ID, r, "e2ee.device_verified", deviceID, "")
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/keys/devices/list/reserve reserves the next device list epoch for one proposed
// list, named by its digest, for E2EEDeviceListReservation, and answers {epoch, expires_in_ms}:
// the epoch the list is signed for. A device signs a list only after reserving it, so of two
// devices editing the list at once only one ever signs; the other gets 409, with retry_in_ms
// while a live reservation holds the list, and reads the winner. Reserving the same digest again
// renews it at the same epoch (an honest retry); a different digest replacing a lapsed
// reservation gets a higher epoch, so the two are never signed for one epoch.
func (s *Server) handleE2EEReserveDeviceList(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeDeviceListReserve
	if !decodeIdentity(w, r, 4<<10, &req) || req.Version < 1 || req.ExpectedEpoch < 0 || !e2eeDigest.MatchString(req.Digest) {
		s.writeError(w, http.StatusBadRequest, "Invalid device list reservation")
		return
	}
	now := time.Now()
	switch res, err := s.store.E2EE().ReserveDeviceList(r.Context(), tenantID, user.ID, req.Version, req.ExpectedEpoch, req.Digest, now, E2EEDeviceListReservation); {
	case errors.Is(err, store.ErrE2EEVersion):
		out := map[string]any{"error": "The device list changed or is being changed; reload it"}
		if !res.Until.IsZero() {
			out["retry_in_ms"] = min(max(res.Until.Sub(now).Milliseconds(), 0), E2EEDeviceListReservation.Milliseconds())
		}
		s.writeJSON(w, http.StatusConflict, out)
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to reserve the device list")
	default:
		// Counted from before the write, so the browser never thinks it holds longer than it does.
		s.writeJSON(w, http.StatusOK, map[string]any{"epoch": res.Epoch, "expires_in_ms": max(res.Until.Sub(now).Milliseconds()-1000, 0)})
	}
}

// PUT /api/v1/keys/devices/list stores the master-signed list of the caller's devices,
// compare-and-swap on its epoch and only under a live reservation of its digest. Clients trust
// only listed devices and remember the newest epoch, so a device removed from the list cannot
// be brought back by the server.
func (s *Server) handleE2EEPutDeviceList(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeDeviceListPut
	// device_ids must be present: a missing or null list is no list, not an empty one.
	if !decodeIdentity(w, r, e2eeIdentityBody, &req) || req.Version < 1 || req.ExpectedEpoch < 0 || req.Epoch <= req.ExpectedEpoch || req.DeviceIDs == nil || len(req.DeviceIDs) > e2eeMaxDeviceList {
		s.writeError(w, http.StatusBadRequest, "Invalid device list")
		return
	}
	for _, id := range req.DeviceIDs {
		if !e2eeDeviceID.MatchString(id) {
			s.writeError(w, http.StatusBadRequest, "Invalid device list")
			return
		}
	}
	msg, err := e2eeid.DeviceListMessage(tenantID, user.ID, req.Version, req.Epoch, req.DeviceIDs)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid device list")
		return
	}
	list, _ := json.Marshal(req.DeviceIDs)
	digest := e2eeid.DeviceListDigest(req.DeviceIDs)
	switch err := s.store.E2EE().PutDeviceList(r.Context(), tenantID, user.ID, req.Version, req.ExpectedEpoch, req.Epoch, string(list), digest, req.Signature, time.Now(), proofOf(e2eeid.DomainDeviceList, msg, req.Signature)); {
	case errors.Is(err, errProof):
		s.writeError(w, http.StatusBadRequest, "The device list is not validly signed")
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The device list changed; reload it")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the device list")
	default:
		s.writeJSON(w, http.StatusOK, map[string]int64{"epoch": req.Epoch})
	}
}

// e2eeBackupVersion reads the caller's current identity version, writing 409 when version
// is not it.
func (s *Server) e2eeBackupVersion(w http.ResponseWriter, r *http.Request, userID, tenantID string, version int64) (*store.E2EEMasterKey, bool) {
	m, err := s.store.E2EE().GetMasterKey(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (m.TenantID != tenantID || m.Version != version)) {
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the key backup")
		return nil, false
	}
	return m, true
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
	m, ok := s.e2eeBackupVersion(w, r, user.ID, tenantID, version)
	if !ok {
		return
	}
	after := store.E2EEBackupCursor{RoomID: q.Get("after_room"), SenderKey: q.Get("after_sender"), SessionID: q.Get("after_session")}
	rows, err := s.store.E2EE().ListBackupSessions(r.Context(), tenantID, user.ID, version, after, e2eeBackupPage)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the key backup")
		return
	}
	out := make([]e2eeBackupEntry, len(rows))
	for i, b := range rows {
		out[i] = e2eeBackupEntry{b.RoomID, b.SenderKey, b.SessionID, b.FirstIndex, b.Sealed}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{"version": version, "generation": m.BackupGeneration, "sessions": out, "more": len(rows) == e2eeBackupPage})
}

// PUT /api/v1/keys/backup adds sealed sessions; a session already backed up is replaced only
// by a copy reaching further back.
func (s *Server) handleE2EEPutBackup(w http.ResponseWriter, r *http.Request) {
	user, tenantID, ok := s.e2eeCaller(w, r)
	if !ok {
		return
	}
	var req e2eeBackupPut
	if !decodeIdentity(w, r, 1<<20, &req) || req.Version < 1 || req.Generation < 0 || len(req.Sessions) == 0 || len(req.Sessions) > e2eeBackupBatch {
		s.writeError(w, http.StatusBadRequest, "Send 1 to 100 backed-up sessions")
		return
	}
	rows := make([]store.E2EEBackupSession, len(req.Sessions))
	signed := make([]e2eeid.BackupWriteEntry, len(req.Sessions))
	for i, b := range req.Sessions {
		n, ok := decodedLen(b.Sealed)
		_, senderOK := e2eeKey(b.SenderKey)
		// A Megolm ratchet index is a uint32.
		if !e2eeRoomID.MatchString(b.RoomID) || !senderOK || !e2eeSessionID.MatchString(b.SessionID) || b.FirstIndex < 0 || b.FirstIndex > math.MaxUint32 || !ok || n < xwing.Overhead || n > e2eeid.MaxSealedSession {
			s.writeError(w, http.StatusBadRequest, "Invalid backed-up session")
			return
		}
		rows[i] = store.E2EEBackupSession{RoomID: b.RoomID, SenderKey: b.SenderKey, SessionID: b.SessionID, FirstIndex: b.FirstIndex, Sealed: b.Sealed}
		signed[i] = e2eeid.BackupWriteEntry(b)
	}
	msg, err := e2eeid.BackupWrite(tenantID, user.ID, req.Version, req.Generation, signed)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid backed-up session")
		return
	}
	// Only a device holding the master key writes the backup: the batch is signed, and checked
	// against the master key of the version it names inside the write's transaction. The
	// generation fences it from a deletion signed later.
	res, err := s.store.E2EE().PutBackupSessions(r.Context(), tenantID, user.ID, req.Version, req.Generation, rows, E2EEBackupMaxSessions, E2EEBackupMaxBytes, proofOf(e2eeid.DomainBackupWrite, msg, req.Signature))
	switch {
	case errors.Is(err, errProof):
		s.writeError(w, http.StatusBadRequest, "The backup write is not signed by the current master key")
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to store the key backup")
	default:
		// refused: the indexes of entries that did not fit the caps; the rest landed.
		refused := res.Refused
		if refused == nil {
			refused = []int{}
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"stored": res.Stored, "kept": res.Kept, "full": len(refused) > 0, "refused": refused})
	}
}

// DELETE /api/v1/keys/backup?version= empties the caller's key backup and starts a new
// generation, which it answers.
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
	if _, ok := s.e2eeBackupVersion(w, r, user.ID, tenantID, version); !ok {
		return
	}
	switch gen, err := s.store.E2EE().DeleteBackup(r.Context(), tenantID, user.ID, version); {
	case errors.Is(err, store.ErrE2EEVersion):
		s.writeError(w, http.StatusConflict, "The key backup version is not current")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete the key backup")
	default:
		s.audit(r.Context(), user.ID, r, "e2ee.backup_deleted", user.ID, "")
		s.writeJSON(w, http.StatusOK, map[string]int64{"generation": gen})
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

// DELETE /api/v1/keys/pairings/{id} cancels a pairing from either device. With ?unsealed=1 (the
// verified device's cancel) it cancels only while no keys were sealed to it: a seal whose answer
// was lost must not be undone under the new device that is fetching it.
func (s *Server) handleE2EEPairingDelete(w http.ResponseWriter, r *http.Request) {
	user, tenantID, p, ok := s.e2eePairing(w, r)
	if !ok {
		return
	}
	del := s.store.E2EE().DeletePairing
	if r.URL.Query().Get("unsealed") == "1" {
		del = s.store.E2EE().DeletePairingUnsealed
	}
	if err := del(r.Context(), tenantID, user.ID, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, "Failed to cancel pairing")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
