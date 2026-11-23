package chat

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

const (
	// DefaultGuestLeaveGrace is how long a disconnected admitted guest has before
	// leaving means waiting in the lobby again (per meeting rooms spec).
	DefaultGuestLeaveGrace = 20 * time.Second
	// WindowEarlyGrace lets guests enter the lobby slightly before a scheduled start.
	WindowEarlyGrace = 15 * time.Minute
	// WindowLateGrace prevents abrupt cutoffs right on the top of the hour.
	WindowLateGrace = 15 * time.Minute
)

var (
	ErrGuestNotFound      = errors.New("guest session not found")
	ErrGuestNotAdmitted   = errors.New("guest has not been admitted")
	ErrMeetingClosed      = errors.New("meeting is closed")
	ErrMeetingNotInWindow = errors.New("meeting is outside its scheduled window")
	ErrGuestTokenRevoked  = errors.New("guest invite link has been revoked")
)

// GuestSession tracks one external meeting guest's lobby/room admission state.
type GuestSession struct {
	SessionSecret string `json:"-"`
	GuestID       string `json:"guest_id"`
	MeetingID     string `json:"meeting_id"`
	TenantID      string `json:"tenant_id"`
	RoomID        string `json:"room_id"`
	GuestKey      string `json:"guest_key"`
	DisplayName   string `json:"display_name"`
	Status        string `json:"status"` // "waiting", "admitted", "denied"
	KnockedAt     int64  `json:"knocked_at"`
	DecidedBy     string `json:"decided_by,omitempty"`
	leaveTimer    *time.Timer
}

// LobbyManager manages external meeting guest waiting rooms, admission, and confined sessions.
type LobbyManager struct {
	hub        *Hub
	calls      *CallManager
	leaveGrace time.Duration
	now        func() time.Time

	mu           sync.Mutex
	bySecret     map[string]*GuestSession            // sessionSecret -> session
	byGuestID    map[string]*GuestSession            // guestID -> session
	byRoom       map[string]map[string]*GuestSession // roomID -> guestID -> session
	byMeetingKey map[string]string                   // meetingID+"|"+guestKey -> guestID (1 live session per token)
}

// NewLobbyManager constructs a LobbyManager wired to Hub and CallManager.
func NewLobbyManager(hub *Hub, calls *CallManager) *LobbyManager {
	return &LobbyManager{
		hub:          hub,
		calls:        calls,
		leaveGrace:   DefaultGuestLeaveGrace,
		now:          time.Now,
		bySecret:     make(map[string]*GuestSession),
		byGuestID:    make(map[string]*GuestSession),
		byRoom:       make(map[string]map[string]*GuestSession),
		byMeetingKey: make(map[string]string),
	}
}

// SetLeaveGrace overrides the 20s leave-means-wait-again grace period (useful for tests).
func (l *LobbyManager) SetLeaveGrace(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaveGrace = d
}

// HashMeetingToken computes the SHA-256 hex digest stored in meeting_guests.token_hash.
func HashMeetingToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateOpaqueToken generates a 32-byte URL-safe random token for guest links or guest sessions.
func GenerateOpaqueToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// IsWithinMeetingWindows reports whether now falls within any scheduled window (with grace),
// or returns true when a meeting has no scheduled windows (ad-hoc meeting).
func IsWithinMeetingWindows(now time.Time, windows []store.MeetingWindow) bool {
	if len(windows) == 0 {
		return true
	}
	ms := now.UTC().UnixMilli()
	early := WindowEarlyGrace.Milliseconds()
	late := WindowLateGrace.Milliseconds()
	for _, w := range windows {
		if ms >= w.StartsAt-early && ms <= w.EndsAt+late {
			return true
		}
	}
	return false
}

// Knock registers a guest in the meeting's waiting room and notifies internal members.
// Enforces 1 live session per guest invite token: knocking again replaces any older session.
func (l *LobbyManager) Knock(ctx context.Context, guest *store.MeetingGuest, meeting *store.Meeting, windows []store.MeetingWindow, displayName string) (*GuestSession, error) {
	if meeting.ClosedAt != nil {
		return nil, ErrMeetingClosed
	}
	if guest.RevokedAt != nil {
		return nil, ErrGuestTokenRevoked
	}
	if !IsWithinMeetingWindows(l.now(), windows) {
		return nil, ErrMeetingNotInWindow
	}

	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = "Guest"
	}
	if len(displayName) > 64 {
		displayName = displayName[:64]
	}

	secret, err := GenerateOpaqueToken()
	if err != nil {
		return nil, err
	}
	guestID := "guest_" + uuid.Must(uuid.NewV7()).String()
	nowMs := l.now().UTC().UnixMilli()
	mk := meeting.ID + "|" + guest.GuestKey

	var evictedGuestID string
	var evictedRoomID string

	l.mu.Lock()
	if oldID, exists := l.byMeetingKey[mk]; exists {
		if old := l.byGuestID[oldID]; old != nil {
			evictedGuestID = old.GuestID
			evictedRoomID = old.RoomID
			l.deleteSessionLocked(old)
		}
	}

	sess := &GuestSession{
		SessionSecret: secret,
		GuestID:       guestID,
		MeetingID:     meeting.ID,
		TenantID:      meeting.TenantID,
		RoomID:        meeting.RoomID,
		GuestKey:      guest.GuestKey,
		DisplayName:   displayName,
		Status:        "waiting",
		KnockedAt:     nowMs,
	}
	l.bySecret[secret] = sess
	l.byGuestID[guestID] = sess
	if l.byRoom[meeting.RoomID] == nil {
		l.byRoom[meeting.RoomID] = make(map[string]*GuestSession)
	}
	l.byRoom[meeting.RoomID][guestID] = sess
	l.byMeetingKey[mk] = guestID
	sessCopy := *sess
	l.mu.Unlock()

	if evictedGuestID != "" {
		l.evictLiveGuest(ctx, evictedRoomID, evictedGuestID)
	}

	if l.hub != nil {
		_ = l.hub.PublishRoom(ctx, meeting.RoomID, Event{
			Type:   EventLobbyKnock,
			RoomID: meeting.RoomID,
			Data: MustMarshalData(LobbyKnockPayload{
				MeetingID:   meeting.ID,
				RoomID:      meeting.RoomID,
				GuestID:     guestID,
				DisplayName: displayName,
				KnockedAt:   nowMs,
				Status:      "waiting",
			}),
		})
	}
	return &sessCopy, nil
}

// GetBySecret resolves an active guest session from its bearer/cookie secret.
func (l *LobbyManager) GetBySecret(secret string) (*GuestSession, bool) {
	if secret == "" {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.bySecret[secret]
	if s == nil {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// ListWaiting returns all currently waiting (and admitted) guests for roomID.
func (l *LobbyManager) ListWaiting(roomID string) []LobbyKnockPayload {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.byRoom[roomID]
	out := make([]LobbyKnockPayload, 0, len(m))
	for _, s := range m {
		if s.Status == "waiting" || s.Status == "admitted" {
			out = append(out, LobbyKnockPayload{
				MeetingID:   s.MeetingID,
				RoomID:      s.RoomID,
				GuestID:     s.GuestID,
				DisplayName: s.DisplayName,
				KnockedAt:   s.KnockedAt,
				Status:      s.Status,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].KnockedAt < out[j].KnockedAt
	})
	return out
}

// Decide admits or denies a waiting guest in roomID.
func (l *LobbyManager) Decide(ctx context.Context, roomID, guestID, actorID string, admit bool) (*GuestSession, error) {
	l.mu.Lock()
	s := l.byGuestID[guestID]
	if s == nil || s.RoomID != roomID {
		l.mu.Unlock()
		return nil, ErrGuestNotFound
	}
	decision := "denied"
	if admit {
		decision = "admitted"
		s.Status = "admitted"
		s.DecidedBy = actorID
	} else {
		s.Status = "denied"
		s.DecidedBy = actorID
		l.deleteSessionLocked(s)
	}
	cp := *s
	l.mu.Unlock()

	if l.hub != nil {
		if admit {
			// Confined guest socket now receives events for this single meeting room only.
			l.hub.SubscribeUserToRoom(guestID, roomID)
		}
		// Notify room members so the lobby badge updates across all host tabs.
		_ = l.hub.PublishRoom(ctx, roomID, Event{
			Type:   EventLobbyKnock,
			RoomID: roomID,
			Data: MustMarshalData(LobbyKnockPayload{
				MeetingID:   cp.MeetingID,
				RoomID:      roomID,
				GuestID:     guestID,
				DisplayName: cp.DisplayName,
				KnockedAt:   cp.KnockedAt,
				Status:      decision,
			}),
		})
		// Deliver decision directly to the waiting guest.
		ev := Event{
			Type:   EventLobbyDecision,
			RoomID: roomID,
			UserID: guestID,
			Data: MustMarshalData(LobbyDecisionPayload{
				MeetingID: cp.MeetingID,
				RoomID:    roomID,
				GuestID:   guestID,
				Decision:  decision,
				DecidedBy: actorID,
			}),
		}
		if !l.hub.SendToUserLocal(guestID, ev) {
			_ = l.hub.PublishUser(ctx, guestID, ev)
		}
		if !admit {
			_ = l.hub.RevokeUser(ctx, guestID)
		}
	}
	return &cp, nil
}

// MarkConnected cancels any pending 20s leave timer if the guest reconnected in time.
func (l *LobbyManager) MarkConnected(guestID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.byGuestID[guestID]; s != nil && s.leaveTimer != nil {
		s.leaveTimer.Stop()
		s.leaveTimer = nil
	}
}

// HandleDisconnect starts the 20s leave-means-wait-again grace timer when a guest disconnects.
func (l *LobbyManager) HandleDisconnect(guestID string, remainingConns int) {
	if remainingConns > 0 {
		return
	}
	l.mu.Lock()
	s := l.byGuestID[guestID]
	if s == nil {
		l.mu.Unlock()
		return
	}
	if s.leaveTimer != nil {
		s.leaveTimer.Stop()
	}
	grace := l.leaveGrace
	roomID := s.RoomID
	meetingID := s.MeetingID
	displayName := s.DisplayName
	knockedAt := s.KnockedAt
	s.leaveTimer = time.AfterFunc(grace, func() {
		l.expireGuest(guestID, roomID, meetingID, displayName, knockedAt)
	})
	l.mu.Unlock()
}

func (l *LobbyManager) expireGuest(guestID, roomID, meetingID, displayName string, knockedAt int64) {
	l.mu.Lock()
	s := l.byGuestID[guestID]
	if s == nil {
		l.mu.Unlock()
		return
	}
	l.deleteSessionLocked(s)
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.evictLiveGuest(ctx, roomID, guestID)
	if l.hub != nil {
		_ = l.hub.PublishRoom(ctx, roomID, Event{
			Type:   EventLobbyKnock,
			RoomID: roomID,
			Data: MustMarshalData(LobbyKnockPayload{
				MeetingID:   meetingID,
				RoomID:      roomID,
				GuestID:     guestID,
				DisplayName: displayName,
				KnockedAt:   knockedAt,
				Status:      "left",
			}),
		})
	}
}

// RevokeMeeting evicts every guest currently waiting in or admitted to roomID.
func (l *LobbyManager) RevokeMeeting(ctx context.Context, roomID string) {
	l.mu.Lock()
	m := l.byRoom[roomID]
	var guestIDs []string
	for gid, s := range m {
		guestIDs = append(guestIDs, gid)
		l.deleteSessionLocked(s)
	}
	l.mu.Unlock()

	for _, gid := range guestIDs {
		l.evictLiveGuest(ctx, roomID, gid)
	}
}

// GuestCheck returns the hub's guest check: a guest needs its lobby session on this pod and an
// active org (isActive, read from the primary), so a missed tenant.revoked notification still
// closes it on the next ping. A lookup error keeps it open: an outage must not eject everyone.
func (l *LobbyManager) GuestCheck(isActive func(ctx context.Context, tenantID string) (bool, error)) func(guestID string) bool {
	return func(guestID string) bool {
		l.mu.Lock()
		s := l.byGuestID[guestID]
		l.mu.Unlock()
		if s == nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		active, err := isActive(ctx, s.TenantID)
		return err != nil || active
	}
}

// RevokeTenant evicts every guest of tenantID this pod holds, waiting or admitted, and takes
// them out of their calls.
func (l *LobbyManager) RevokeTenant(ctx context.Context, tenantID string) {
	type gone struct{ roomID, guestID string }
	var evict []gone
	l.mu.Lock()
	for _, s := range l.byGuestID {
		if s.TenantID == tenantID {
			evict = append(evict, gone{s.RoomID, s.GuestID})
			l.deleteSessionLocked(s)
		}
	}
	l.mu.Unlock()
	for _, g := range evict {
		l.evictLiveGuest(ctx, g.roomID, g.guestID)
	}
}

// RevokeGuestKey evicts the live session for one revoked guest_key in meetingID.
func (l *LobbyManager) RevokeGuestKey(ctx context.Context, meetingID, guestKey string) {
	mk := meetingID + "|" + guestKey
	l.mu.Lock()
	gid := l.byMeetingKey[mk]
	if gid == "" {
		l.mu.Unlock()
		return
	}
	s := l.byGuestID[gid]
	var roomID string
	if s != nil {
		roomID = s.RoomID
		l.deleteSessionLocked(s)
	}
	l.mu.Unlock()

	if gid != "" {
		l.evictLiveGuest(ctx, roomID, gid)
	}
}

func (l *LobbyManager) evictLiveGuest(ctx context.Context, roomID, guestID string) {
	if l.calls != nil && roomID != "" {
		l.calls.Leave(ctx, roomID, guestID)
	}
	if l.hub != nil {
		if roomID != "" {
			l.hub.UnsubscribeUserFromRoom(guestID, roomID)
		}
		_ = l.hub.RevokeUser(ctx, guestID)
	}
}

func (l *LobbyManager) deleteSessionLocked(s *GuestSession) {
	if s.leaveTimer != nil {
		s.leaveTimer.Stop()
		s.leaveTimer = nil
	}
	delete(l.bySecret, s.SessionSecret)
	delete(l.byGuestID, s.GuestID)
	if rm := l.byRoom[s.RoomID]; rm != nil {
		delete(rm, s.GuestID)
		if len(rm) == 0 {
			delete(l.byRoom, s.RoomID)
		}
	}
	mk := s.MeetingID + "|" + s.GuestKey
	if l.byMeetingKey[mk] == s.GuestID {
		delete(l.byMeetingKey, mk)
	}
}
