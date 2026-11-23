package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Busnes-app/ky-primitives/applysetup"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrSharingOff    = errors.New("status sharing is off")
	ErrAlreadyExists = errors.New("record already exists")
	// ErrUsernameTaken: another account holds the username (exact case, as the column is unique).
	ErrUsernameTaken                  = fmt.Errorf("username is taken: %w", ErrAlreadyExists)
	ErrSessionExpired                 = errors.New("session expired")
	ErrPairingExpired                 = errors.New("pairing session expired")
	ErrRoomClosed                     = errors.New("room is closed")
	ErrReplyNotFound                  = errors.New("reply target is not a message in this room")
	ErrAttachmentInvalid              = errors.New("attachment not found, not owned by sender, or already attached")
	ErrAttachmentTenantQuotaExceeded  = errors.New("workspace attachment storage quota exceeded")
	ErrAttachmentPendingQuotaExceeded = errors.New("pending attachment quota exceeded")
	ErrForbidden                      = errors.New("forbidden")
)

// Store defines the unified storage contract implemented across SQLite, PostgreSQL, and MySQL.
type Store interface {
	ApplyInstaller(context.Context, applysetup.Common, bool) (applysetup.Report, error)
	InstallerIdentity(context.Context, string, string) (bool, bool, error)
	InstallerUserAllowed(context.Context, *User) (bool, error)
	ApplyInstallerDirectory(context.Context, string, string, string, string, string, bool, bool) (string, error)

	Users() UserStore
	Sessions() SessionStore
	Devices() DeviceStore
	Groups() GroupStore
	Audit() AuditStore
	Settings() SettingsStore
	Agents() AgentStore
	Chat() ChatStore
	SuiteReplay() SuiteReplayStore
	Presence() PresenceStore

	// Notify emits a PostgreSQL NOTIFY on channel with payload (no-op on SQLite).
	Notify(ctx context.Context, channel, payload string) error

	InvalidateRestoredGrants(context.Context) error
	Driver() string
	Ping(ctx context.Context) error
	Close() error
}

// PresenceStore holds each user's suite status inputs, keyed by (tenant, user).
type PresenceStore interface {
	// Presence reads the rows of userIDs in tenantID; a user without one is absent from the map.
	Presence(ctx context.Context, tenantID string, userIDs []string) (map[string]Presence, error)
	// SetSharing turns sharing on or off; off clears every other input in the same write.
	SetSharing(ctx context.Context, tenantID, userID string, on bool) error
	// SetManual sets a manual status, or clears it with state "". ErrSharingOff while off.
	SetManual(ctx context.Context, tenantID, userID, state string, until time.Time) error
	// SetCalendar and SetOutOfOffice store a push unless its revision is older than the stored
	// one (PresenceStale) or sharing is off (PresenceSharingOff). A zero OOO period is off.
	SetCalendar(ctx context.Context, tenantID, userID string, revision int64, busy []BusyWindow) (PresenceOutcome, error)
	SetOutOfOffice(ctx context.Context, tenantID, userID string, revision int64, start, end time.Time) (PresenceOutcome, error)
}

// Presence is one user's stored status inputs. Zero times are unset.
type Presence struct {
	ShareOff            bool
	ManualState         string // available, busy, away or ""
	ManualUntil         time.Time
	OOOStart, OOOEnd    time.Time
	CalendarAt          time.Time // when the last calendar push was stored
	Busy                []BusyWindow
	CalendarRev, OOORev int64
}

// BusyWindow is one calendar busy block, [Start, End).
type BusyWindow struct {
	Start, End time.Time
}

// PresenceOutcome is what a calendar or out-of-office push did.
type PresenceOutcome string

const (
	PresenceApplied    PresenceOutcome = "applied"
	PresenceStale      PresenceOutcome = "stale"
	PresenceSharingOff PresenceOutcome = "sharing_off"
)

// SuiteReplayStore tracks verified suite syncauth event IDs in the primary database so
// replays are rejected across restarts and across replicas.
type SuiteReplayStore interface {
	// Record records eventID as seen if it has not been recorded yet. It returns fresh=true
	// when eventID was inserted for the first time and fresh=false when it already existed.
	Record(ctx context.Context, eventID string, nowUnix, expiresAtUnix int64) (fresh bool, err error)
	// Forget removes eventID so a failed transient request (5xx) can be retried.
	Forget(ctx context.Context, eventID string) error
	// Prune removes expired replay rows whose expires_at <= beforeUnix.
	Prune(ctx context.Context, beforeUnix int64) error
}

// DirectoryEvent identifies one signed directory delivery: the sender's event ID and the
// per-user revision it carries.
type DirectoryEvent struct {
	ID       string
	Revision int64
}

// TenancyModeSettingKey persists the database's tenancy mode ("single" or "multi") so an
// instance cannot silently flip modes across restarts. TenancyStaffOrgSettingKey locks
// KY_STAFF_ORG_ID once initialized in multi-tenant mode.
const (
	TenancyModeSettingKey     = "tenancy.mode"
	TenancyStaffOrgSettingKey = "tenancy.staff_org_id"
)

// UserFilter selects users by one exact attribute; the zero value matches everyone.
// Provider and OrgID, when set, also limit the result to that sso_provider / org_id.
type UserFilter struct {
	Field    UserField
	Value    string
	Provider string
	OrgID    string
}

type UserField int

const (
	UserFieldNone     UserField = iota
	UserFieldUsername           // case-insensitive
	UserFieldEmail              // case-insensitive
	UserFieldSubject            // exact sso_subject (SCIM externalId)
)

// UserStore defines repository operations for accounts.
type UserStore interface {
	CreateUser(ctx context.Context, u *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetLocalUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserBySSO(ctx context.Context, provider, subject string) (*User, error)
	UpdateUser(ctx context.Context, u *User) error
	// UpdateProfile writes username, email, display name, role and status only.
	UpdateProfile(ctx context.Context, u *User) error
	// Directory updates are ordered per SSO provider and subject by a record that outlives
	// the user. Each event ID is used once, whether or not it applied; an event applies only
	// when its revision is newer than the last applied one or is -1 (the sender's
	// post-restore resend), atomically with its write, and reports whether it applied.
	ApplyDirectoryProfile(ctx context.Context, u *User, ev DirectoryEvent) (bool, error)
	CreateDirectoryUser(ctx context.Context, u *User, ev DirectoryEvent) (bool, error)
	DeleteDirectoryUser(ctx context.Context, u *User, ev DirectoryEvent) (bool, error)
	// DirectoryStatuses maps each subject of provider to its user's status, or to "deleted"
	// when the directory deleted it (an order row with no user). Of several rows for one
	// subject, a non-active status wins.
	DirectoryStatuses(ctx context.Context, provider string) (map[string]string, error)
	ResetAdminPassword(ctx context.Context, userID, newHash string) error
	CompletePasswordChange(ctx context.Context, userID, oldHash, newHash, ip string) error
	UpdateRecoveryCodes(ctx context.Context, userID, oldHashes, newHashes string) error
	// SpendTOTPCounter records counter as used. It returns ErrAlreadyExists when counter is
	// not greater than the stored one, which is how a replayed code inside the skew window fails.
	SpendTOTPCounter(ctx context.Context, userID string, counter int64) error
	// TOTP enrolment for local accounts: a pending secret, then enable (revoking every
	// session, MFA challenge and pairing) or disable. Each is ErrNotFound when the account
	// is not in the expected state.
	SetPendingTOTP(ctx context.Context, userID, secretEnc string) error
	EnableTOTP(ctx context.Context, userID, secretEnc, recoveryHashes string) error
	DisableTOTP(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, offset, limit int, filter UserFilter) ([]*User, int, error)
	CountUsers(ctx context.Context) (int, error)
}

// SessionStore defines repository operations for active login sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, s *Session, expectedPasswordHash string) error
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpiredSessions(ctx context.Context) error
	CreateMFAChallenge(ctx context.Context, challenge *MFAChallenge, expectedPasswordHash string) error
	ConsumeMFAChallenge(ctx context.Context, tokenHash string) (userID, passwordHash string, err error)
}

// DeviceStore handles 90s ephemeral QR pairing sessions and paired push clients.
type DeviceStore interface {
	CreatePairing(ctx context.Context, p *DevicePairing, expectedPasswordHash string) error
	GetPairingBySecret(ctx context.Context, secret string) (*DevicePairing, error)
	ConsumePairing(ctx context.Context, secret, deviceName, platform, pushToken string) error
	CleanExpiredPairings(ctx context.Context) error
}

// GroupStore defines repository operations for SCIM and RBAC groups.
type GroupStore interface {
	CreateGroup(ctx context.Context, g *Group) error
	GetGroupByID(ctx context.Context, id string) (*Group, error)
	GetGroupByName(ctx context.Context, name string) (*Group, error)
	UpdateGroup(ctx context.Context, g *Group) error
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context, offset, limit int) ([]*Group, int, error)
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
	GetUserGroups(ctx context.Context, userID string) ([]*Group, error)
}

// AuditStore logs security events.
type AuditStore interface {
	LogAudit(ctx context.Context, r *AuditRecord) error
	// ListAuditRecords pages rows newest first by insertion order. With prefixes, only rows
	// whose action starts with one of them; the count is of those rows.
	ListAuditRecords(ctx context.Context, offset, limit int, prefixes ...string) ([]*AuditRecord, int, error)
	LatestAuditRecord(ctx context.Context, action string) (*AuditRecord, error)
}

// SettingsStore handles persistent key-value configuration.
type SettingsStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, val string) error
	DeleteSetting(ctx context.Context, key string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)
}

// AgentStore is the registry of native chat bot/agent accounts.
type AgentStore interface {
	// CreateAgent returns ErrAlreadyExists when the username or backing user_id is taken.
	CreateAgent(ctx context.Context, a *Agent) error
	GetAgent(ctx context.Context, id string) (*Agent, error)
	// GetAgentByTokenHash returns the active agent matching the SHA-256 token hash, or ErrNotFound.
	GetAgentByTokenHash(ctx context.Context, tokenHash string) (*Agent, error)
	// ListAgents returns every agent, oldest first.
	ListAgents(ctx context.Context) ([]*Agent, error)
	// ListAgentsByOwner returns agents owned by ownerUserID.
	ListAgentsByOwner(ctx context.Context, ownerUserID string) ([]*Agent, error)
	// SetAgentToken records the agent's current token hash and state: a non-empty hash with
	// AgentTokenActive, or "" with AgentTokenRevoked or AgentTokenExpired. It returns ErrNotFound
	// unless the agent still holds fromTokenHash, so a concurrent change is never overwritten.
	SetAgentToken(ctx context.Context, id, fromTokenHash, newTokenHash, state string) error
	// TouchAgentLastUsed records the most recent authenticated API/WS use of the agent.
	TouchAgentLastUsed(ctx context.Context, id string, at time.Time) error
	DeleteAgent(ctx context.Context, id string) error
}

// ChatStore handles multi-tenant native KyMessages tenants, rooms, messages, reactions, and webhooks.
type ChatStore interface {
	// Tenants
	CreateTenant(ctx context.Context, t *Tenant) error
	EnsureTenant(ctx context.Context, tenantID string) (*Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	SetTenantStatus(ctx context.Context, tenantID, status string) error
	ApplyTenantLifecycle(ctx context.Context, tenantID, status string, revision int64) (bool, error)
	HoldsSingleTenantData(ctx context.Context) (bool, error)
	// OrgIDs lists every org ID the database binds: account org_ids and non-default tenants.
	OrgIDs(ctx context.Context) ([]string, error)
	UpdateTenantMediaPolicy(ctx context.Context, tenantID, policy string, maxVideo, maxAudio int, guestForceSFU bool) (*Tenant, error)

	// Rooms & Membership
	CreateRoom(ctx context.Context, r *Room, initialMemberIDs []string) error
	GetOrCreateDM(ctx context.Context, tenantID, userA, userB string) (*Room, bool, error)
	GetRoom(ctx context.Context, tenantID, roomID string) (*Room, error)
	ListUserRooms(ctx context.Context, tenantID, userID string) ([]*RoomSummary, error)
	ListUserRoomIDs(ctx context.Context, tenantID, userID string) ([]string, error)
	UpdateRoom(ctx context.Context, tenantID, roomID, name, topic string) (*Room, error)
	CloseRoom(ctx context.Context, tenantID, roomID string) (*Room, error)

	AddRoomMember(ctx context.Context, m *RoomMember) error
	// RemoveRoomMember returns the member it promoted to owner when the room would
	// otherwise be left without a moderator; "" when none was needed or possible.
	RemoveRoomMember(ctx context.Context, tenantID, roomID, userID string) (string, error)
	GetRoomMember(ctx context.Context, tenantID, roomID, userID string) (*RoomMember, error)
	ListRoomMembers(ctx context.Context, tenantID, roomID string) ([]*RoomMember, error)
	UpdateReadCursor(ctx context.Context, tenantID, roomID, userID string, seq int64) (int64, error)
	UpdateRoomNotifyMode(ctx context.Context, tenantID, roomID, userID, mode string) error

	// Web Push Subscriptions
	UpsertPushSubscription(ctx context.Context, sessionHash string, sub *PushSubscription, maxPerUser int) (*PushSubscription, error)
	ListPushSubscriptions(ctx context.Context, tenantID, userID string) ([]*PushSubscription, error)
	ListPushRecipients(ctx context.Context, tenantID, roomID string, userIDs []string) ([]*PushSubscription, error)
	DeletePushSubscriptionByEndpoint(ctx context.Context, tenantID, userID, endpoint string) error
	DeletePushSubscriptionByID(ctx context.Context, tenantID, userID, id string) error
	DeletePushSubscriptionInternal(ctx context.Context, id string) error
	TouchPushSubscription(ctx context.Context, id string, usedAt int64) error

	// Messages & Reactions
	CreateMessage(ctx context.Context, p CreateMessageParams) (*Message, bool, error)
	GetMessage(ctx context.Context, tenantID, roomID, messageID string) (*Message, error)
	ListMessages(ctx context.Context, q MessagePageQuery) ([]*Message, bool, error)
	EditMessage(ctx context.Context, tenantID, roomID, messageID, actorID, newBody string) (*Message, error)
	DeleteMessage(ctx context.Context, tenantID, roomID, messageID, actorID string, allowModerator bool) (*Message, error)
	SearchMessages(ctx context.Context, tenantID, userID, roomID, query string, limit int) ([]*Message, error)

	AddReaction(ctx context.Context, tenantID, roomID, messageID, userID, emoji string) error
	RemoveReaction(ctx context.Context, tenantID, roomID, messageID, userID, emoji string) error

	// Attachments
	CreateAttachment(ctx context.Context, a *Attachment) error
	ReserveAttachmentQuota(ctx context.Context, tenantID, uploaderID string, requestedBytes int64, limits AttachmentQuotaLimits, ttl time.Duration) (*AttachmentQuotaReservation, error)
	ReleaseAttachmentQuota(ctx context.Context, tenantID, reservationID string) error
	CommitAttachmentWithQuota(ctx context.Context, reservationID string, a *Attachment, limits AttachmentQuotaLimits) error
	GetAttachment(ctx context.Context, tenantID, attachmentID string) (*Attachment, error)
	ListMessageAttachments(ctx context.Context, tenantID, roomID, messageID string) ([]Attachment, error)
	ListStagedAttachments(ctx context.Context, tenantID, roomID, uploaderID string) ([]Attachment, error)
	DeleteAttachment(ctx context.Context, tenantID, attachmentID string) error
	DeleteStagedAttachment(ctx context.Context, tenantID, attachmentID, uploaderID string) (string, error)
	SumAttachmentBytesByTenant(ctx context.Context, tenantID string) (int64, error)
	SumPendingAttachmentBytesByUploader(ctx context.Context, tenantID, uploaderID string) (int64, error)
	PurgeOrphanAttachments(ctx context.Context, olderThanMilli int64, limit int) ([]string, error)

	// Webhooks
	CreateRoomWebhook(ctx context.Context, w *RoomWebhook) error
	GetRoomWebhook(ctx context.Context, webhookID string) (*RoomWebhook, error)
	ListRoomWebhooks(ctx context.Context, tenantID, roomID string) ([]*RoomWebhook, error)
	RevokeRoomWebhook(ctx context.Context, tenantID, roomID, webhookID string) error

	// Call Sessions
	CreateCallSession(ctx context.Context, cs *CallSession) error
	GetActiveCallSession(ctx context.Context, tenantID, roomID string) (*CallSession, error)
	UpdateCallSession(ctx context.Context, cs *CallSession) error
	EndCallSession(ctx context.Context, tenantID, callID string, endedAt int64) error

	// Native Meetings & External Guest Links
	UpsertMeeting(ctx context.Context, p UpsertMeetingParams) (*UpsertMeetingResult, error)
	GetMeeting(ctx context.Context, tenantID, meetingID string) (*Meeting, []MeetingWindow, []MeetingGuest, error)
	GetMeetingByRoomID(ctx context.Context, tenantID, roomID string) (*Meeting, []MeetingWindow, error)
	CreateMeetingGuest(ctx context.Context, g *MeetingGuest) error
	GetMeetingGuestByTokenHash(ctx context.Context, tokenHash string) (*MeetingGuest, *Meeting, []MeetingWindow, error)
	CloseMeeting(ctx context.Context, tenantID, meetingID string) (*Meeting, error)
}
