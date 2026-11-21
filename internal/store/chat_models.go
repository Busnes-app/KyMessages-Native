package store

// DefaultTenantID is used by single-tenant self-hosted deployments and default hosted contexts.
const DefaultTenantID = "default"

// Room kinds.
const (
	RoomKindDM      = "dm"
	RoomKindChannel = "channel"
	RoomKindMeeting = "meeting"
)

// Room member roles.
const (
	RoomRoleOwner  = "owner"
	RoomRoleAdmin  = "admin"
	RoomRoleMember = "member"
	RoomRoleBot    = "bot"
)

// Message payload encodings.
const (
	MessageEncodingPlainV1    = "plain_v1"
	MessageEncodingE2EERoomV1 = "e2ee_room_v1"
	MessageEncodingSystemV1   = "system_v1"
)

// Tenant P2P media policies.
const (
	P2PPolicyHybrid  = "hybrid"
	P2PPolicySFUOnly = "sfu_only"
)

// Webhook directions.
const (
	WebhookDirectionIncoming = "incoming"
	WebhookDirectionOutgoing = "outgoing"
)

// Tenant represents an isolated organization or personal space on a hosted or self-hosted instance.
type Tenant struct {
	ID            string `json:"id"`
	Slug          string `json:"slug"`
	DisplayName   string `json:"display_name"`
	Plan          string `json:"plan"`
	P2PPolicy     string `json:"p2p_policy"`
	P2PMaxVideo   int    `json:"p2p_max_video"`
	P2PMaxAudio   int    `json:"p2p_max_audio"`
	GuestForceSFU bool   `json:"guest_force_sfu"`
	CreatedAt     int64  `json:"created_at"` // Unix milliseconds
}

// Room represents a DM, team channel, or KyCalendar meeting room.
type Room struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Kind      string `json:"kind"`
	DMPairKey string `json:"-"`
	Name      string `json:"name"`
	Topic     string `json:"topic"`
	IsPrivate bool   `json:"is_private"`
	LastSeq   int64  `json:"last_seq"`
	ClosedAt  *int64 `json:"closed_at,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"` // Unix milliseconds
}

// RoomSummary extends Room with the requesting user's membership state and unread count.
type RoomSummary struct {
	Room
	Role        string `json:"role"`
	LastReadSeq int64  `json:"last_read_seq"`
	UnreadCount int64  `json:"unread_count"`
	NotifyMode  string `json:"notify_mode"`
}

// RoomMember represents a user or agent's membership in a room.
type RoomMember struct {
	TenantID    string `json:"tenant_id"`
	RoomID      string `json:"room_id"`
	UserID      string `json:"user_id"`
	Role        string `json:"role"`
	LastReadSeq int64  `json:"last_read_seq"`
	NotifyMode  string `json:"notify_mode"`
	JoinedAt    int64  `json:"joined_at"` // Unix milliseconds
}

// Message is one ordered message inside a room.
type Message struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	RoomID         string            `json:"room_id"`
	Seq            int64             `json:"seq"`
	SenderID       string            `json:"sender_id"`
	SenderName     string            `json:"sender_name,omitempty"`
	ReplyToID      string            `json:"reply_to_id,omitempty"`
	Encoding       string            `json:"encoding"`
	Body           string            `json:"body"`
	EditedAt       *int64            `json:"edited_at,omitempty"`
	DeletedAt      *int64            `json:"deleted_at,omitempty"`
	IdempotencyKey string            `json:"-"`
	CreatedAt      int64             `json:"created_at"` // Unix milliseconds
	Reactions      []ReactionSummary `json:"reactions,omitempty"`
}

// ReactionSummary aggregates reactions by emoji for a single message.
type ReactionSummary struct {
	Emoji   string   `json:"emoji"`
	UserIDs []string `json:"user_ids"`
	Count   int      `json:"count"`
}

// MessagePageQuery configures cursor-based pagination or catch-up for room messages.
type MessagePageQuery struct {
	TenantID  string
	RoomID    string
	BeforeSeq int64 // If > 0, return messages with seq < BeforeSeq (history scrollback; uses read replica)
	AfterSeq  int64 // If > 0, return messages with seq > AfterSeq (live catch-up; uses primary)
	Limit     int   // Clamped to [1, 100], default 50
}

// CreateMessageParams carries validated inputs for atomic message creation.
type CreateMessageParams struct {
	ID              string
	TenantID        string
	RoomID          string
	SenderID        string
	SenderName      string
	ReplyToID       string
	Encoding        string
	Body            string
	IdempotencyKey  string
	SkipMemberCheck bool // True only for verified room webhooks or system events
}

// RoomWebhook represents an incoming or outgoing webhook bound to one room.
type RoomWebhook struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	RoomID    string `json:"room_id"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
	TokenHash string `json:"-"`
	TargetURL string `json:"target_url,omitempty"`
	CreatedBy string `json:"created_by"`
	RevokedAt *int64 `json:"revoked_at,omitempty"`
	CreatedAt int64  `json:"created_at"` // Unix milliseconds
}

// Call transport modes.
const (
	CallModeP2PMesh    = "p2p_mesh"
	CallModeSFULiveKit = "sfu_livekit"
)

// CallSession tracks an active or completed voice/video call in a room.
type CallSession struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	RoomID      string `json:"room_id"`
	Mode        string `json:"mode"`
	Epoch       int    `json:"epoch"`
	SFUSticky   bool   `json:"sfu_sticky"`
	LiveKitRoom string `json:"livekit_room,omitempty"`
	StartedBy   string `json:"started_by"`
	StartedAt   int64  `json:"started_at"`
	EndedAt     *int64 `json:"ended_at,omitempty"`
}

// Meeting represents a KyCalendar-backed or standalone native meeting room.
type Meeting struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	RoomID       string `json:"room_id"`
	OrganizerSub string `json:"organizer_sub"`
	Title        string `json:"title"`
	ClosedAt     *int64 `json:"closed_at,omitempty"`
	UpdatedAt    int64  `json:"updated_at"`
}

// MeetingWindow is one active time window [StartsAt, EndsAt] in Unix milliseconds.
type MeetingWindow struct {
	MeetingID string `json:"meeting_id"`
	StartsAt  int64  `json:"starts_at"`
	EndsAt    int64  `json:"ends_at"`
}

// MeetingGuest binds one hashed external guest invite token to a meeting.
type MeetingGuest struct {
	ID        string `json:"id"`
	MeetingID string `json:"meeting_id"`
	GuestKey  string `json:"guest_key"`
	TokenHash string `json:"-"`
	RevokedAt *int64 `json:"revoked_at,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// UpsertMeetingParams defines the desired reconciled state of a meeting.
type UpsertMeetingParams struct {
	ID             string
	TenantID       string
	RoomID         string // Used only if creating a new meeting room
	OrganizerID    string // Local user ID for room ownership
	OrganizerSub   string
	Title          string
	MemberUserIDs  []string // Internal local user IDs that should be members
	Windows        []MeetingWindow
	NewGuestTokens map[string]MeetingGuest // key -> guest record to insert if key is not already active
	KeepGuestKeys  map[string]struct{}     // active keys to retain; others are revoked
}

// UpsertMeetingResult reports what changed during meeting reconciliation.
type UpsertMeetingResult struct {
	Meeting          *Meeting
	Room             *Room
	Created          bool
	AddedMemberIDs   []string
	RemovedMemberIDs []string
	IssuedGuestKeys  []string // guest keys newly created or re-issued
	RevokedGuestKeys []string
}
