package chat

import (
	"context"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Multi mode keeps every lobby session in the shared database, so a guest is known on every
// replica: a knock on one, an admission on another and the next request on a third all agree.
// Leave timers stay in process, on the replica whose socket closed. Each replica refreshes the
// seen_at of the guests it holds sockets for every quarter of the leave grace, and every
// authenticated guest request refreshes it too. Timers and reads share one rule: a session
// ends once nobody refreshed it for the presence window (1.25 × the grace), so a guest still
// connected elsewhere, or still polling, keeps it.

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
	l.live = make(map[string]struct{})
}

func fromShared(g store.GuestSession) *GuestSession {
	return &GuestSession{GuestID: g.GuestID, MeetingID: g.MeetingID, TenantID: g.TenantID, RoomID: g.RoomID,
		GuestKey: g.GuestKey, DisplayName: g.DisplayName, Status: g.Status, KnockedAt: g.KnockedAt, DecidedBy: g.DecidedBy}
}

func (l *LobbyManager) knockShared(ctx context.Context, meeting *store.Meeting, guestKey, inviteHash, displayName, secret, guestID string, nowMs int64) (*GuestSession, error) {
	replaced, err := l.db.Create(ctx, secret, store.GuestSession{
		GuestID: guestID, TenantID: meeting.TenantID, MeetingID: meeting.ID, RoomID: meeting.RoomID, GuestKey: guestKey, InviteHash: inviteHash,
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
	g, err := l.db.BySecret(ctx, secret, l.now().UnixMilli(), l.presence())
	if err != nil {
		return nil, false
	}
	return fromShared(*g), true
}

func (l *LobbyManager) listShared(roomID string) []LobbyKnockPayload {
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	rows, _ := l.db.InRoom(ctx, roomID, l.now().UnixMilli(), l.presence())
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
		row, err := l.db.Admit(ctx, roomID, guestID, actorID, l.now().UnixMilli(), l.presence())
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
	l.mu.Lock()
	l.live[guestID] = struct{}{}
	start := !l.beating
	l.beating = true
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
	defer cancel()
	_ = l.db.Touch(ctx, guestID)
	if start {
		go l.heartbeat()
	}
}

// heartbeat refreshes this replica's connected guests until it holds none.
func (l *LobbyManager) heartbeat() {
	for {
		l.mu.Lock()
		every := l.leaveGrace / 4
		l.mu.Unlock()
		time.Sleep(every)
		l.mu.Lock()
		ids := make([]string, 0, len(l.live))
		for id := range l.live {
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			l.beating = false
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
		_ = l.db.Touch(ctx, ids...)
		cancel()
	}
}

func (l *LobbyManager) disconnectShared(guestID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.live, guestID)
	if t := l.timers[guestID]; t != nil {
		t.Stop()
	}
	l.armDepartureLocked(guestID)
}

// A poll can keep a disconnected guest alive past the first timer. Rearm until the database
// actually removes the session, so eventual departure still emits its event and removes media.
func (l *LobbyManager) armDepartureLocked(guestID string) {
	live := l.leaveGrace + l.leaveGrace/4
	var timer *time.Timer
	timer = l.afterFunc(live, func() {
		l.mu.Lock()
		if l.timers[guestID] != timer {
			l.mu.Unlock()
			return
		}
		delete(l.timers, guestID)
		_, connected := l.live[guestID]
		l.mu.Unlock()
		if connected {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), sharedLobbyTimeout)
		defer cancel()
		rows, err := l.db.DeleteIfUnseen(ctx, guestID, live)
		if err != nil || len(rows) == 0 {
			// A missing row already departed elsewhere. An error or a refreshed row needs a retry.
			exists, lookupErr := l.db.Exists(ctx, guestID)
			if lookupErr == nil && !exists {
				return
			}
			l.mu.Lock()
			if _, connected := l.live[guestID]; !connected && l.timers[guestID] == nil {
				l.armDepartureLocked(guestID)
			}
			l.mu.Unlock()
			return
		}
		for _, s := range rows {
			l.evictLiveGuest(ctx, s.RoomID, s.GuestID)
			if l.hub != nil {
				_ = l.hub.PublishRoom(ctx, s.RoomID, Event{Type: EventLobbyKnock, RoomID: s.RoomID, Data: MustMarshalData(LobbyKnockPayload{MeetingID: s.MeetingID, RoomID: s.RoomID, GuestID: s.GuestID, DisplayName: s.DisplayName, KnockedAt: s.KnockedAt, Status: "left"})})
			}
		}
	})
	l.timers[guestID] = timer
}

// presence is how long a session stays usable after the last refresh by any replica: the
// leave grace, plus one heartbeat interval of slack.
func (l *LobbyManager) presence() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.leaveGrace + l.leaveGrace/4
}

func (l *LobbyManager) stopTimer(guestID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.live, guestID)
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
	// This check runs for a socket open on this replica, which is presence: refresh first, so a
	// database outage longer than the window does not end a connected guest's session once the
	// database is back. (If the refresh fails, the lookup fails too and the socket stays open.)
	l.mu.Lock()
	_, local := l.live[guestID]
	l.mu.Unlock()
	if local {
		_ = l.db.Touch(ctx, guestID)
	}
	g, err := l.db.ByID(ctx, guestID, l.now().UnixMilli(), l.presence())
	if err == store.ErrNotFound {
		return false
	}
	if err != nil {
		return true // an outage must not eject everyone, as for members
	}
	active, err := isActive(ctx, g.TenantID)
	return err != nil || active
}
