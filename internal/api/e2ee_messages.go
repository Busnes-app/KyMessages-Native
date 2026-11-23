package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Encrypted rooms (docs/superpowers/specs/2026-11-22-e2ee-design.md §4, §10 E2). Members post
// only e2ee_room_v1 envelopes; plain_v1 stays open to kybot_ tokens until bot devices land (E4).
// The server checks an envelope's shape to refuse plaintext sent by mistake. It never reads the
// ciphertext, which only room members' devices can open.

// maxEnvelopeLen bounds an e2ee_room_v1 body: a 16 KiB message grows by about a third in
// base64, plus the Megolm header, MAC and signature and the envelope's own fields.
const maxEnvelopeLen = 48 << 10

// CodeE2EERequired is the error code for a plain_v1 message from anything but a bot token.
const CodeE2EERequired = "e2ee_required"

var e2eeSessionID = regexp.MustCompile(`^[A-Za-z0-9+/]{1,128}$`)

// validRoomEnvelope reports whether body is exactly the e2ee_room_v1 envelope:
// {"alg":"megolm.v1","sender_key","device_id","session_id","ciphertext"}.
func validRoomEnvelope(body string) bool {
	var env struct {
		Alg        string `json:"alg"`
		SenderKey  string `json:"sender_key"`
		DeviceID   string `json:"device_id"`
		SessionID  string `json:"session_id"`
		Ciphertext string `json:"ciphertext"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&env) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return false
	}
	_, keyOK := e2eeKey(env.SenderKey)
	ct, err := base64.RawStdEncoding.DecodeString(env.Ciphertext)
	return env.Alg == "megolm.v1" && keyOK && e2eeDeviceID.MatchString(env.DeviceID) &&
		e2eeSessionID.MatchString(env.SessionID) && err == nil && len(ct) > 0
}

// isBotToken reports whether the request authenticated with a kybot_ bearer token.
func isBotToken(user *store.User, sess *store.Session) bool {
	return user.Role == "bot" && sess != nil && strings.HasPrefix(sess.TokenHash, auth.AgentSessionPrefix)
}

var errEncoding = errors.New("encoding refused")

// messageEncoding resolves the encoding of a posted or edited body, writing the refusal and
// returning errEncoding when it is not allowed. An omitted encoding means plain_v1, as before.
func (s *Server) messageEncoding(w http.ResponseWriter, user *store.User, sess *store.Session, requested, body string) (string, error) {
	switch strings.TrimSpace(requested) {
	case "", store.MessageEncodingPlainV1:
		if !isBotToken(user, sess) {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Rooms are end-to-end encrypted: send an e2ee_room_v1 envelope",
				"code":  CodeE2EERequired,
			})
			return "", errEncoding
		}
		if len(body) > maxMessageBodyLen {
			s.writeError(w, http.StatusBadRequest, "Message body must be 1 to 16384 bytes")
			return "", errEncoding
		}
		return store.MessageEncodingPlainV1, nil
	case store.MessageEncodingE2EERoomV1:
		if len(body) > maxEnvelopeLen || !validRoomEnvelope(body) {
			s.writeError(w, http.StatusBadRequest, "Invalid e2ee_room_v1 envelope")
			return "", errEncoding
		}
		return store.MessageEncodingE2EERoomV1, nil
	default:
		s.writeError(w, http.StatusBadRequest, "Unsupported message encoding")
		return "", errEncoding
	}
}
