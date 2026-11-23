package api_test

import (
	"encoding/base64"
	"encoding/json"
)

// testEnvelope wraps text in an e2ee_room_v1 envelope of the right shape. The server never
// opens the ciphertext, so tests stand in the text's bytes for real Megolm output.
func testEnvelope(text string) string {
	b, _ := json.Marshal(map[string]string{
		"alg":        "megolm.v1",
		"sender_key": base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		"device_id":  "TESTDEVICE01",
		"session_id": base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		"ciphertext": base64.RawStdEncoding.EncodeToString([]byte("megolm:" + text)),
	})
	return string(b)
}

// sealed is a message request body a member's client sends: text as an envelope, plus fields.
func sealed(text string, fields map[string]any) map[string]any {
	out := map[string]any{"body": testEnvelope(text), "encoding": "e2ee_room_v1"}
	for k, v := range fields {
		out[k] = v
	}
	return out
}
