package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type presenceStore struct {
	store *SQLStore
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnixOrZero(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func joinBusy(b []BusyWindow) string {
	lines := make([]string, len(b))
	for i, w := range b {
		lines[i] = fmt.Sprintf("%d-%d", w.Start.Unix(), w.End.Unix())
	}
	return strings.Join(lines, "\n")
}

func splitBusy(s string) []BusyWindow {
	var out []BusyWindow
	for line := range strings.SplitSeq(s, "\n") {
		var a, b int64
		if _, err := fmt.Sscanf(line, "%d-%d", &a, &b); err == nil {
			out = append(out, BusyWindow{fromUnixOrZero(a), fromUnixOrZero(b)})
		}
	}
	return out
}

func (s *presenceStore) Presence(ctx context.Context, tenantID string, userIDs []string) (map[string]Presence, error) {
	out := map[string]Presence{}
	if len(userIDs) == 0 {
		return out, nil
	}
	q := `SELECT user_id, share_off, manual_state, manual_until, ooo_revision, ooo_start, ooo_end, cal_revision, cal_at, busy FROM presence WHERE tenant_id = ? AND user_id IN (?` + strings.Repeat(", ?", len(userIDs)-1) + `)`
	args := make([]any, 0, len(userIDs)+1)
	args = append(args, tenantID)
	for _, id := range userIDs {
		args = append(args, id)
	}
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, busy string
		var p Presence
		var off int
		var mu, ooS, ooE, ca int64
		if err := rows.Scan(&id, &off, &p.ManualState, &mu, &p.OOORev, &ooS, &ooE, &p.CalendarRev, &ca, &busy); err != nil {
			return nil, err
		}
		p.ShareOff = off != 0
		p.ManualUntil, p.OOOStart, p.OOOEnd, p.CalendarAt = fromUnixOrZero(mu), fromUnixOrZero(ooS), fromUnixOrZero(ooE), fromUnixOrZero(ca)
		p.Busy = splitBusy(busy)
		out[id] = p
	}
	return out, rows.Err()
}

// ensure makes the user's row, sharing on, if it has none.
func (s *presenceStore) ensure(ctx context.Context, tenantID, userID string) error {
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`INSERT INTO presence (tenant_id, user_id) VALUES (?, ?) ON CONFLICT (tenant_id, user_id) DO NOTHING`), tenantID, userID)
	return err
}

func (s *presenceStore) SetSharing(ctx context.Context, tenantID, userID string, on bool) error {
	if err := s.ensure(ctx, tenantID, userID); err != nil {
		return err
	}
	if on {
		_, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE presence SET share_off = 0 WHERE tenant_id = ? AND user_id = ?`), tenantID, userID)
		return err
	}
	// Revisions stay, so a push older than the one cleared stays stale after sharing is back.
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE presence SET share_off = 1, manual_state = '', manual_until = 0, ooo_start = 0, ooo_end = 0, cal_at = 0, busy = '' WHERE tenant_id = ? AND user_id = ?`), tenantID, userID)
	return err
}

func (s *presenceStore) SetManual(ctx context.Context, tenantID, userID, state string, until time.Time) error {
	if err := s.ensure(ctx, tenantID, userID); err != nil {
		return err
	}
	if state == "" {
		until = time.Time{}
	}
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE presence SET manual_state = ?, manual_until = ? WHERE tenant_id = ? AND user_id = ? AND share_off = 0`), state, unixOrZero(until), tenantID, userID)
	if err = oneRow(res, err); errors.Is(err, ErrNotFound) {
		return ErrSharingOff
	}
	return err
}

// push applies set (columns after the revision column) when sharing is on and revision is not
// older than the stored one, else says why not.
func (s *presenceStore) push(ctx context.Context, tenantID, userID, revCol string, revision int64, set string, args ...any) (PresenceOutcome, error) {
	if err := s.ensure(ctx, tenantID, userID); err != nil {
		return "", err
	}
	args = append([]any{revision}, args...)
	args = append(args, tenantID, userID, revision)
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE presence SET `+revCol+` = ?, `+set+` WHERE tenant_id = ? AND user_id = ? AND share_off = 0 AND `+revCol+` <= ?`), args...)
	switch err = oneRow(res, err); {
	case err == nil:
		return PresenceApplied, nil
	case !errors.Is(err, ErrNotFound):
		return "", err
	}
	var off int
	err = s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT share_off FROM presence WHERE tenant_id = ? AND user_id = ?`), tenantID, userID).Scan(&off)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", ErrNotFound
	case err != nil:
		return "", err
	case off != 0:
		return PresenceSharingOff, nil
	}
	return PresenceStale, nil
}

func (s *presenceStore) SetCalendar(ctx context.Context, tenantID, userID string, revision int64, busy []BusyWindow) (PresenceOutcome, error) {
	return s.push(ctx, tenantID, userID, "cal_revision", revision, `cal_at = ?, busy = ?`, time.Now().Unix(), joinBusy(busy))
}

func (s *presenceStore) SetOutOfOffice(ctx context.Context, tenantID, userID string, revision int64, start, end time.Time) (PresenceOutcome, error) {
	return s.push(ctx, tenantID, userID, "ooo_revision", revision, `ooo_start = ?, ooo_end = ?`, unixOrZero(start), unixOrZero(end))
}
