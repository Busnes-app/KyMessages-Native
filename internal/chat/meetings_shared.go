package chat

import (
	"context"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Multi mode keeps every lobby session in the shared database, so a guest is known on every
// replica: a knock on one, an admission on another and the next request on a third all agree.
// Only leave timers stay in process, on the replica holding the guest's socket.

// guestSessionTTL matches the guest cookie's lifetime.
const guestSessionTTL = 4 * time.Hour

// sharedLobbyTimeout bounds one lobby database call made without a request context.
const sharedLobbyTimeout = 5 * time.Second

// UseShared switches the lobby to the shared session store (multi mode). Call it before serving.
func (l *LobbyManager) UseShared(db *store.GuestSessionStore) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.db = db
	l.timers = make(map[string]*time.Timer)
}

func fromShared(g store.GuestSession) *GuestSession {
	return &GuestSession{GuestID: g.GuestID, MeetingID: g.MeetingID, TenantID: g.TenantID, RoomID: g.RoomID,
		GuestKey: g.GuestKey, DisplayName: g.DisplayName, Status: g.Status, KnockedAt: g.KnockedAt, DecidedBy: g.DecidedBy}
}

func (l *LobbyManager) knockShared(ctx context.Context, meeting *store.Meeting, guestKey, displayName, secret, guestID string, nowMs int64) (*GuestSession, error) {
	replaced, err := l.db.Create(ctx, secret, store.GuestSession{
		GuestID: guestID, TenantID: meeting.TenantID, MeetingID: meeting.ID, RoomID: meeting.RoomID, GuestKey: guestKey,
		DisplayName: displayName, Status: "waiting", KnockedAt: nowMs, SeenAt: nowMs, ExpiresAt: nowMs + guestSessionTTL.Milliseconds(),
	})
	if err != nil {
		return nil, err
	}
	for _, old := range replaced {
		l.stopTimer(old.GuestID)
		l.evictLiveGuest(ctx, old.RoomID, old.GuestID)
	}
	sess := fromShared(store.GuestSession{GuestID: guestID, TenantID: meeting.TenantID, MeetingID: meeting.ID, RoomID: meeting.RoomID,
		GuestKey: guestKey, DisplayName: displayName, Status: "waiting", KnockedAt: nowMs})
	sess.SessionSecret = secret
	return sess, nil
}

func (l *LobbyManager) bySecretShared(secret string) (*GuestSession, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	g, err := l.db.BySecret(ctx, secret, l.now().UnixMilli())
	if err != nil {
		return nil, false
	}
	return fromShared(*g), true
}

func (l *LobbyManager) listShared(roomID string) []LobbyKnockPayload {
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	rows, _ := l.db.InRoom(ctx, roomID, l.now().UnixMilli())
	out := make([]LobbyKnockPayload, 0, len(rows))
	for _, s := range rows {
		out = append(out, LobbyKnockPayload{MeetingID: s.MeetingID, RoomID: s.RoomID, GuestID: s.GuestID,
			DisplayName: s.DisplayName, KnockedAt: s.KnockedAt, Status: s.Status})
	}
	return out
}

func (l *LobbyManager) decideShared(ctx context.Context, roomID, guestID, actorID string, admit bool) (*GuestSession, error) {
	var g *store.GuestSession
	if admit {
		row, err := l.db.Admit(ctx, roomID, guestID, actorID, l.now().UnixMilli())
		if err == store.ErrNotFound {
			return nil, ErrGuestNotFound
		}
		if err != nil {
			return nil, err
		}
		g = row
	} else {
		rows, err := l.db.Delete(ctx, roomID, guestID)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, ErrGuestNotFound
		}
		g = &rows[0]
		g.Status, g.DecidedBy = "denied", actorID
		l.stopTimer(guestID)
	}
	cp := fromShared(*g)
	decision := cp.Status
	if l.hub != nil {
		_ = l.hub.PublishRoom(ctx, roomID, Event{Type: EventLobbyKnock, RoomID: roomID, Data: MustMarshalData(LobbyKnockPayload{
			MeetingID: cp.MeetingID, RoomID: roomID, GuestID: guestID, DisplayName: cp.DisplayName, KnockedAt: cp.KnockedAt, Status: decision,
		})})
		// The guest's socket may be on any replica; the hub there subscribes it to the room
		// when it delivers an admission (Hub.Dispatch).
		_ = l.hub.PublishUser(ctx, guestID, Event{Type: EventLobbyDecision, RoomID: roomID, UserID: guestID, Data: MustMarshalData(LobbyDecisionPayload{
			MeetingID: cp.MeetingID, RoomID: roomID, GuestID: guestID, Decision: decision, DecidedBy: actorID,
		})})
		if !admit {
			_ = l.hub.RevokeUser(ctx, guestID)
		}
	}
	return cp, nil
}

func (l *LobbyManager) markConnectedShared(guestID string) {
	l.stopTimer(guestID)
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	_ = l.db.Touch(ctx, guestID, l.now().UnixMilli())
}

func (l *LobbyManager) disconnectShared(guestID string) {
	leftAt := l.now().UnixMilli()
	l.mu.Lock()
	if t := l.timers[guestID]; t != nil {
		t.Stop()
	}
	l.timers[guestID] = time.AfterFunc(l.leaveGrace, func() {
		l.mu.Lock()
		delete(l.timers, guestID)
		l.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
		defer cancel()
		// A socket that reconnected anywhere since leftAt touched the row, so it survives.
		rows, err := l.db.DeleteIfUnseen(ctx, guestID, leftAt)
		if err != nil {
			return
		}
		for _, s := range rows {
			l.evictLiveGuest(ctx, s.RoomID, s.GuestID)
			if l.hub != nil {
				_ = l.hub.PublishRoom(ctx, s.RoomID, Event{Type: EventLobbyKnock, RoomID: s.RoomID, Data: MustMarshalData(LobbyKnockPayload{
					MeetingID: s.MeetingID, RoomID: s.RoomID, GuestID: s.GuestID, DisplayName: s.DisplayName, KnockedAt: s.KnockedAt, Status: "left",
				})})
			}
		}
	})
	l.mu.Unlock()
}

func (l *LobbyManager) stopTimer(guestID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t := l.timers[guestID]; t != nil {
		t.Stop()
		delete(l.timers, guestID)
	}
}

func (l *LobbyManager) evictShared(ctx context.Context, rows []store.GuestSession) {
	for _, s := range rows {
		l.stopTimer(s.GuestID)
		l.evictLiveGuest(ctx, s.RoomID, s.GuestID)
	}
}

func (l *LobbyManager) guestValidShared(isActive func(ctx context.Context, tenantID string) (bool, error), guestID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	g, err := l.db.ByID(ctx, guestID, l.now().UnixMilli())
	if err == store.ErrNotFound {
		return false
	}
	if err != nil {
		return true // an outage must not eject everyone, as for members
	}
	active, err := isActive(ctx, g.TenantID)
	return err != nil || active
}
