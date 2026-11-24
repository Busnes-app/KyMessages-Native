package chat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	callNotifyPartBytes    = 2048
	maxCallNotifyBytes     = 128 << 10
	maxPendingCallNotifies = 128
	callNotifyTTL          = 10 * time.Second
)

type callNotifyPart struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Index  int    `json:"index"`
	Total  int    `json:"total"`
	Data   []byte `json:"data"`
}

type callNotifyEnvelope struct {
	Part *callNotifyPart `json:"call_fragment"`
}

func callNotifyType(typ string) bool {
	return typ == EventCallSignal || typ == EventCallMigrate || typ == EventCallState
}

// Call control has no refetch endpoint: unlike message notifications, it must travel whole.
// Chunk only these events; existing message/refetch behavior stays unchanged.
func encodeBusNotifications(ev Event) ([]string, error) {
	if !callNotifyType(ev.Type) {
		payload, err := encodeNotifyPayload(ev)
		return []string{payload}, err
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if len(raw) <= MaxNotifyBytes {
		return []string{string(raw)}, nil
	}
	if len(raw) > maxCallNotifyBytes {
		return nil, errors.New("call event exceeds notification limit")
	}
	digest := sha256.Sum256(raw)
	id := uuid.NewString()
	total := (len(raw) + callNotifyPartBytes - 1) / callNotifyPartBytes
	parts := make([]string, 0, total)
	for i := 0; i < total; i++ {
		end := min((i+1)*callNotifyPartBytes, len(raw))
		payload, err := json.Marshal(callNotifyEnvelope{Part: &callNotifyPart{ID: id, Digest: hex.EncodeToString(digest[:]), Index: i, Total: total, Data: raw[i*callNotifyPartBytes : end]}})
		if err != nil {
			return nil, err
		}
		parts = append(parts, string(payload))
	}
	return parts, nil
}

type pendingCallNotify struct {
	digest   string
	parts    [][]byte
	received int
	expires  time.Time
}

type callNotifyDecoder struct{ pending map[string]*pendingCallNotify }

// decode retains at most 128 incomplete events (16 MiB of content), for ten seconds. A
// reconnect starts a fresh decoder. Missing, malformed or corrupt parts never reach clients.
func (d *callNotifyDecoder) decode(payload string, now time.Time) (*Event, error) {
	if len(payload) > MaxNotifyBytes {
		return nil, errors.New("notification exceeds size limit")
	}
	for id, p := range d.pending {
		if !now.Before(p.expires) {
			delete(d.pending, id)
		}
	}
	var envelope callNotifyEnvelope
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		return nil, err
	}
	p := envelope.Part
	if p == nil {
		var ev Event
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			return nil, err
		}
		return &ev, nil
	}
	if len(p.ID) != 36 || len(p.Digest) != 64 || p.Total < 2 || p.Total > maxCallNotifyBytes/callNotifyPartBytes || p.Index < 0 || p.Index >= p.Total || len(p.Data) == 0 || len(p.Data) > callNotifyPartBytes {
		return nil, errors.New("invalid call notification part")
	}
	if d.pending == nil {
		d.pending = make(map[string]*pendingCallNotify)
	}
	entry := d.pending[p.ID]
	if entry == nil {
		if len(d.pending) >= maxPendingCallNotifies {
			var oldest string
			for id, e := range d.pending {
				if oldest == "" || e.expires.Before(d.pending[oldest].expires) {
					oldest = id
				}
			}
			delete(d.pending, oldest)
		}
		entry = &pendingCallNotify{digest: p.Digest, parts: make([][]byte, p.Total), expires: now.Add(callNotifyTTL)}
		d.pending[p.ID] = entry
	}
	if len(entry.parts) != p.Total || entry.digest != p.Digest {
		delete(d.pending, p.ID)
		return nil, errors.New("conflicting call notification part")
	}
	if entry.parts[p.Index] != nil {
		return nil, nil
	}
	entry.parts[p.Index] = p.Data
	entry.received++
	if entry.received != p.Total {
		return nil, nil
	}
	delete(d.pending, p.ID)
	var raw []byte
	for _, part := range entry.parts {
		raw = append(raw, part...)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != entry.digest {
		return nil, errors.New("corrupt call notification")
	}
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, err
	}
	if !callNotifyType(ev.Type) {
		return nil, errors.New("invalid fragmented event type")
	}
	return &ev, nil
}
