package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/crypto"
)

// GuestSession is one meeting guest's lobby session as every replica sees it (multi mode).
// The secret the guest presents is stored only as its SHA-256.
type GuestSession struct {
	GuestID     string
	TenantID    string
	MeetingID   string
	RoomID      string
	GuestKey    string
	DisplayName string
	Status      string // "waiting" or "admitted"
	KnockedAt   int64
	DecidedBy   string
	SeenAt      int64
	ExpiresAt   int64
}

// GuestSessionStore holds lobby sessions in the shared database.
type GuestSessionStore struct{ s *SQLStore }

// GuestSessions returns the shared lobby session store.
func (s *SQLStore) GuestSessions() *GuestSessionStore { return &GuestSessionStore{s: s} }

const guestSessionCols = `guest_id, tenant_id, meeting_id, room_id, guest_key, display_name, status, knocked_at, decided_by, seen_at, expires_at`

func scanGuestSession(row interface{ Scan(...any) error }) (*GuestSession, error) {
	var g GuestSession
	err := row.Scan(&g.GuestID, &g.TenantID, &g.MeetingID, &g.RoomID, &g.GuestKey, &g.DisplayName, &g.Status, &g.KnockedAt, &g.DecidedBy, &g.SeenAt, &g.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

func (g *GuestSessionStore) list(ctx context.Context, q string, args ...any) ([]GuestSession, error) {
	rows, err := g.s.db.QueryContext(ctx, g.s.rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestSession
	for rows.Next() {
		s, err := scanGuestSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// Create stores sess under secret, replacing the live session of the same invite (tenant,
// meeting, guest key), whose rows it returns so the caller can evict them.
func (g *GuestSessionStore) Create(ctx context.Context, secret string, sess GuestSession) ([]GuestSession, error) {
	var lastErr error
	// Two replicas knocking with one invite at once: the loser meets the unique key and retries,
	// replacing the winner's session.
	for range 3 {
		replaced, err := g.create(ctx, secret, sess)
		if err == nil {
			return replaced, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (g *GuestSessionStore) create(ctx context.Context, secret string, sess GuestSession) ([]GuestSession, error) {
	tx, err := g.s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, g.s.rebind(`DELETE FROM meeting_guest_sessions WHERE tenant_id = ? AND meeting_id = ? AND guest_key = ? RETURNING `+guestSessionCols),
		sess.TenantID, sess.MeetingID, sess.GuestKey)
	if err != nil {
		return nil, err
	}
	var replaced []GuestSession
	for rows.Next() {
		r, err := scanGuestSession(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		replaced = append(replaced, *r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO meeting_guest_sessions (secret_hash, `+guestSessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, `+g.s.dbNowMillis()+`, ?)`),
		crypto.SHA256Hex([]byte(secret)), sess.GuestID, sess.TenantID, sess.MeetingID, sess.RoomID, sess.GuestKey, sess.DisplayName,
		sess.Status, sess.KnockedAt, sess.DecidedBy, sess.ExpiresAt); err != nil {
		return nil, fmt.Errorf("guest session insert: %w", err)
	}
	return replaced, tx.Commit()
}

// BySecret atomically checks and refreshes the live session a guest's secret names.
// It shares the row lock with DeleteIfUnseen: a poll cannot succeed without extending presence.
// present is the presence rule every read and admission applies: a session counts only while
// some replica refreshed seen_at (database clock) within live. Departure is therefore enforced
// by the database, not by whichever replica's leave timer happens to run.
func (g *GuestSessionStore) present() string {
	return ` AND seen_at > ` + g.s.dbNowMillis() + ` - ?`
}

func (g *GuestSessionStore) BySecret(ctx context.Context, secret string, nowMs int64, live time.Duration) (*GuestSession, error) {
	return scanGuestSession(g.s.db.QueryRowContext(ctx, g.s.rebind(`UPDATE meeting_guest_sessions SET seen_at = `+g.s.dbNowMillis()+` WHERE secret_hash = ? AND expires_at > ?`+g.present()+` RETURNING `+guestSessionCols),
		crypto.SHA256Hex([]byte(secret)), nowMs, live.Milliseconds()))
}

// ByID resolves an unexpired session by guest ID.
func (g *GuestSessionStore) ByID(ctx context.Context, guestID string, nowMs int64, live time.Duration) (*GuestSession, error) {
	return scanGuestSession(g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT `+guestSessionCols+` FROM meeting_guest_sessions WHERE guest_id = ? AND expires_at > ?`+g.present()),
		guestID, nowMs, live.Milliseconds()))
}

// InRoom lists the unexpired sessions of roomID.
func (g *GuestSessionStore) InRoom(ctx context.Context, roomID string, nowMs int64, live time.Duration) ([]GuestSession, error) {
	return g.list(ctx, `SELECT `+guestSessionCols+` FROM meeting_guest_sessions WHERE room_id = ? AND expires_at > ?`+g.present()+` ORDER BY knocked_at ASC`, roomID, nowMs, live.Milliseconds())
}

// Admit marks guestID in roomID admitted by actorID.
func (g *GuestSessionStore) Admit(ctx context.Context, roomID, guestID, actorID string, nowMs int64, live time.Duration) (*GuestSession, error) {
	return scanGuestSession(g.s.db.QueryRowContext(ctx, g.s.rebind(`UPDATE meeting_guest_sessions SET status = 'admitted', decided_by = ?
WHERE guest_id = ? AND room_id = ? AND expires_at > ?`+g.present()+` RETURNING `+guestSessionCols), actorID, guestID, roomID, nowMs, live.Milliseconds()))
}

// Touch records, on the database clock, that each guest has a live socket on the caller's
// replica, so no replica's leave timer ends its session.
func (g *GuestSessionStore) Touch(ctx context.Context, guestIDs ...string) error {
	if len(guestIDs) == 0 {
		return nil
	}
	args := make([]any, len(guestIDs))
	for i, id := range guestIDs {
		args[i] = id
	}
	_, err := g.s.db.ExecContext(ctx, g.s.rebind(`UPDATE meeting_guest_sessions SET seen_at = `+g.s.dbNowMillis()+
		` WHERE guest_id IN (?`+strings.Repeat(", ?", len(guestIDs)-1)+`)`), args...)
	return err
}

// Exists checks cleanup ownership without treating elapsed presence as completed departure.
func (g *GuestSessionStore) Exists(ctx context.Context, guestID string) (bool, error) {
	var one int
	err := g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT 1 FROM meeting_guest_sessions WHERE guest_id = ?`), guestID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Delete removes guestID's session (in roomID when roomID is set) and returns it.
func (g *GuestSessionStore) Delete(ctx context.Context, roomID, guestID string) ([]GuestSession, error) {
	if roomID == "" {
		return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE guest_id = ? RETURNING `+guestSessionCols, guestID)
	}
	return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE guest_id = ? AND room_id = ? RETURNING `+guestSessionCols, guestID, roomID)
}

// DeleteIfUnseen removes guestID's session only if no replica touched it for idle.
func (g *GuestSessionStore) DeleteIfUnseen(ctx context.Context, guestID string, idle time.Duration) ([]GuestSession, error) {
	return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE guest_id = ? AND seen_at <= `+g.s.dbNowMillis()+` - ? RETURNING `+guestSessionCols, guestID, idle.Milliseconds())
}

// DeleteRoom removes every session in roomID.
func (g *GuestSessionStore) DeleteRoom(ctx context.Context, roomID string) ([]GuestSession, error) {
	return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE room_id = ? RETURNING `+guestSessionCols, roomID)
}

// DeleteTenant removes every session of tenantID.
func (g *GuestSessionStore) DeleteTenant(ctx context.Context, tenantID string) ([]GuestSession, error) {
	return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE tenant_id = ? RETURNING `+guestSessionCols, tenantID)
}

// DeleteKey removes the session of one invite.
func (g *GuestSessionStore) DeleteKey(ctx context.Context, tenantID, meetingID, guestKey string) ([]GuestSession, error) {
	return g.list(ctx, `DELETE FROM meeting_guest_sessions WHERE tenant_id = ? AND meeting_id = ? AND guest_key = ? RETURNING `+guestSessionCols, tenantID, meetingID, guestKey)
}
