package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/crypto"
)

// Shared limits are multi mode's replacement for per-process counters: every replica counts in
// one row. Keys are stored as SHA-256, so client addresses never sit in the table.

// BumpAttempt counts one attempt against key in a fixed window that starts at its first attempt,
// and returns the count so far in the current window. Windows use the database clock.
func (s *SQLStore) BumpAttempt(ctx context.Context, key string, window time.Duration) (int64, error) {
	now := s.dbNowMillis()
	var count int64
	err := s.db.QueryRowContext(ctx, s.rebind(`INSERT INTO attempt_counters (key_hash, count, reset_at) VALUES (?, 1, `+now+` + ?)
ON CONFLICT (key_hash) DO UPDATE SET
	count = CASE WHEN attempt_counters.reset_at < `+now+` THEN 1 ELSE attempt_counters.count + 1 END,
	reset_at = CASE WHEN attempt_counters.reset_at < `+now+` THEN excluded.reset_at ELSE attempt_counters.reset_at END
RETURNING count`), crypto.SHA256Hex([]byte(key)), window.Milliseconds()).Scan(&count)
	return count, err
}

// AttemptState reads key's count and the time left in its window; an expired or absent
// window is (0, 0).
func (s *SQLStore) AttemptState(ctx context.Context, key string) (int64, time.Duration, error) {
	var count, left int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT count, reset_at - `+s.dbNowMillis()+` FROM attempt_counters WHERE key_hash = ?`),
		crypto.SHA256Hex([]byte(key))).Scan(&count, &left)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && left < 0) {
		return 0, 0, nil
	}
	return count, time.Duration(left) * time.Millisecond, err
}

// SpendPoW records a solved challenge's signature until expiresAtUnix; false means it was
// already spent, on any replica.
func (s *SQLStore) SpendPoW(ctx context.Context, signature string, expiresAtUnix int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO pow_spent (sig_hash, expires_at) VALUES (?, ?) ON CONFLICT (sig_hash) DO NOTHING`),
		crypto.SHA256Hex([]byte(signature)), expiresAtUnix)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PruneShared deletes expired attempt windows, spent challenges and guest sessions.
func (s *SQLStore) PruneShared(ctx context.Context) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM attempt_counters WHERE reset_at < `+s.dbNowMillis()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM pow_spent WHERE expires_at < ?`), now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM meeting_guest_sessions WHERE expires_at < ?`), now.UnixMilli())
	return err
}
