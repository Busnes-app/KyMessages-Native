package sso

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Quota keys belong to this app. Unsupported or malformed limits never silently become
// unlimited; that org stays unavailable until KyIdentity supplies a valid newer snapshot.
func parseTenantQuotas(raw json.RawMessage) (store.TenantQuotas, error) {
	var wire struct {
		MaxUploadBytes      json.RawMessage `json:"max_upload_bytes"`
		MaxPendingUserBytes json.RawMessage `json:"max_pending_user_bytes"`
	}
	var q store.TenantQuotas
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return q, errors.New("quotas must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return q, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return q, errors.New("extra quota value")
	}
	if wire.MaxUploadBytes != nil {
		var value int64
		if err := json.Unmarshal(wire.MaxUploadBytes, &value); err != nil || value < 1024 || value > 100<<20 {
			return q, errors.New("invalid max_upload_bytes")
		}
		q.MaxUploadBytes = value
	}
	if wire.MaxPendingUserBytes != nil {
		var value int64
		if err := json.Unmarshal(wire.MaxPendingUserBytes, &value); err != nil || value < 1024 || value > 1<<53 {
			return q, errors.New("invalid max_pending_user_bytes")
		}
		q.MaxPendingUserBytes = value
	}
	return q, nil
}
