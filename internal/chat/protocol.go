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
	// EventToDevice tells a user's sockets that end-to-end encryption mail is waiting.
	EventToDevice = "to_device"
	// EventTenantRevoked travels only on the bus: every pod drops that tenant's guests.
	EventTenantRevoked = "tenant.revoked"

	// Phase 3: Hybrid P2P + LiveKit SFU calling & external guest waiting room events.
	EventCallState     = "call.state"
	EventCallSignal    = "call.signal"
	EventCallMigrate   = "call.migrate"
	EventLobbyKnock    = "lobby.knock"
	EventLobbyDecision = "lobby.decision"
)

// Client-to-server frame types.
const (
	ClientFramePing          = "ping"
	ClientFrameTyping        = "typing"
	ClientFrameCallSignal    = "call.signal"
	ClientFrameCallMedia     = "call.media"
	ClientFrameCallMigrated  = "call.migrated"
	ClientFrameCallICEFailed = "call.ice_failed"
)

// Event is the single envelope used on both the internal event bus (in-memory or
// PostgreSQL LISTEN/NOTIFY) and server-to-client WebSocket frames. UserID is the recipient:
// Dispatch sends an event that has it to that user only, so a room event leaves it empty and
// puts any actor ID in Data.
type Event struct {
	Type   string          `json:"t"`
	RoomID string          `json:"room,omitempty"`
	Seq    int64           `json:"seq,omitempty"`
	UserID string          `json:"user_id,omitempty"`
	Data   json.RawMessage `json:"d,omitempty"`
}

// ClientFrame is a client-to-server WebSocket control frame.
type ClientFrame struct {
	Type        string          `json:"t"`
	RoomID      string          `json:"room,omitempty"`
	Active      bool            `json:"active,omitempty"`
	CallID      string          `json:"call_id,omitempty"`
	PeerID      string          `json:"peer_id,omitempty"`
	FromPeerID  string          `json:"from_peer_id,omitempty"`
	ToPeerID    string          `json:"to_peer_id,omitempty"`
	Kind        string          `json:"kind,omitempty"`
	Epoch       int             `json:"epoch,omitempty"`
	Audio       *bool           `json:"audio,omitempty"`
	Video       *bool           `json:"video,omitempty"`
	ScreenShare *bool           `json:"screen_share,omitempty"`
	ProtectIP   *bool           `json:"protect_ip,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// RoomMemberDelta is the payload for EventRoomMember so every pod updates its live
// room subscription index without requiring clients to reconnect.
type RoomMemberDelta struct {
	Action string `json:"action"` // "added", "removed" or "role"
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

// CallPeerState describes one live participant inside an active call.
type CallPeerState struct {
	PeerID      string          `json:"peer_id"`
	UserID      string          `json:"user_id"`
	DisplayName string          `json:"display_name"`
	IsGuest     bool            `json:"is_guest"`
	Audio       bool            `json:"audio"`
	Video       bool            `json:"video"`
	ScreenShare bool            `json:"screen_share"`
	ProtectIP   bool            `json:"protect_ip,omitempty"`
	ECDHPubJWK  json.RawMessage `json:"ecdh_pub_jwk,omitempty"`
	JoinedAt    int64           `json:"joined_at"`
}

// CallStatePayload is broadcast to the room whenever call membership, media flags,
// mode, or epoch changes (and when a call ends, with Active=false and empty Peers).
type CallStatePayload struct {
	CallID       string          `json:"call_id"`
	RoomID       string          `json:"room_id"`
	Active       bool            `json:"active"`
	Mode         string          `json:"mode"`
	Epoch        int             `json:"epoch"`
	SFUSticky    bool            `json:"sfu_sticky"`
	SFUAvailable bool            `json:"sfu_available"`
	LiveKitURL   string          `json:"livekit_url,omitempty"`
	Peers        []CallPeerState `json:"peers"`
}

// CallSignalPayload relays one P2P WebRTC SDP/ICE/E2EE key signal between two peers in a call.
type CallSignalPayload struct {
	CallID     string          `json:"call_id"`
	RoomID     string          `json:"room_id"`
	FromPeerID string          `json:"from_peer_id"`
	ToPeerID   string          `json:"to_peer_id"`
	Kind       string          `json:"kind"` // "offer", "answer", "ice", "e2ee_key"
	Data       json.RawMessage `json:"data"`
}

// CallMigratePayload instructs a single participant to execute a make-before-break
// handover between p2p_mesh and sfu_livekit. Each peer receives its own scoped LiveKit JWT.
type CallMigratePayload struct {
	CallID       string          `json:"call_id"`
	RoomID       string          `json:"room_id"`
	Epoch        int             `json:"epoch"`
	TargetMode   string          `json:"target_mode"` // "p2p_mesh" or "sfu_livekit"
	Reason       string          `json:"reason"`
	LiveKitURL   string          `json:"livekit_url,omitempty"`
	LiveKitToken string          `json:"livekit_token,omitempty"`
	Peers        []CallPeerState `json:"peers"`
}

// LobbyKnockPayload notifies internal meeting members that an external guest is waiting.
type LobbyKnockPayload struct {
	MeetingID   string `json:"meeting_id"`
	RoomID      string `json:"room_id"`
	GuestID     string `json:"guest_id"`
	DisplayName string `json:"display_name"`
	KnockedAt   int64  `json:"knocked_at"`
	Status      string `json:"status"` // "waiting", "admitted", "denied", "left"
}

// LobbyDecisionPayload informs a waiting guest whether they were admitted or denied.
type LobbyDecisionPayload struct {
	MeetingID    string `json:"meeting_id"`
	RoomID       string `json:"room_id"`
	GuestID      string `json:"guest_id"`
	Decision     string `json:"decision"` // "admitted", "denied", "expired"
	DecidedBy    string `json:"decided_by,omitempty"`
	LiveKitURL   string `json:"livekit_url,omitempty"`
	LiveKitToken string `json:"livekit_token,omitempty"`
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
