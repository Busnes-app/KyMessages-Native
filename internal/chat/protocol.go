package chat

import "encoding/json"

// Wire event types shared across the event bus and WebSocket clients.
const (
	EventHello         = "hello"
	EventPong          = "pong"
	EventMessageNew    = "message.new"
	EventMessageEdit   = "message.edit"
	EventMessageDelete = "message.delete"
	EventReactionSet   = "reaction.set"
	EventRoomMember    = "room.member"
	EventRoomUpdated   = "room.updated"
	EventRoomClosed    = "room.closed"
	EventTyping        = "typing"
	EventReadSync      = "read.sync"
	EventAuthRevoked   = "auth.revoked"
)

// Client-to-server frame types.
const (
	ClientFramePing   = "ping"
	ClientFrameTyping = "typing"
)

// Event is the single envelope used on both the internal event bus (in-memory or
// PostgreSQL LISTEN/NOTIFY) and server-to-client WebSocket frames.
type Event struct {
	Type   string          `json:"t"`
	RoomID string          `json:"room,omitempty"`
	Seq    int64           `json:"seq,omitempty"`
	UserID string          `json:"user_id,omitempty"`
	Data   json.RawMessage `json:"d,omitempty"`
}

// ClientFrame is a client-to-server WebSocket control frame.
type ClientFrame struct {
	Type   string `json:"t"`
	RoomID string `json:"room,omitempty"`
	Active bool   `json:"active,omitempty"`
}

// RoomMemberDelta is the payload for EventRoomMember so every pod updates its live
// room subscription index without requiring clients to reconnect.
type RoomMemberDelta struct {
	Action string `json:"action"` // "added" or "removed"
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// TypingPayload is the ephemeral payload for EventTyping (never persisted to SQL).
type TypingPayload struct {
	UserID string `json:"user_id"`
	Active bool   `json:"active"`
}

// ReadSyncPayload synchronizes read cursors across a user's open tabs/devices.
type ReadSyncPayload struct {
	RoomID      string `json:"room_id"`
	LastReadSeq int64  `json:"last_read_seq"`
}

// MustMarshalData encodes v as json.RawMessage for an Event payload.
func MustMarshalData(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
