package store

import (
	"context"
	"errors"
)

type suiteReplayStore struct {
	store *SQLStore
}

// Record inserts eventID into suite_replay_events atomically if not already present.
// Returns fresh=true when newly inserted, fresh=false on duplicate.
func (s *suiteReplayStore) Record(ctx context.Context, eventID string, nowUnix, expiresAtUnix int64) (bool, error) {
	if eventID == "" {
		return false, errors.New("suite replay event_id is required")
	}
	res, err := s.store.db.ExecContext(
		ctx,
		s.store.rebind(`INSERT INTO suite_replay_events (event_id, seen_at, expires_at) VALUES (?, ?, ?) ON CONFLICT (event_id) DO NOTHING`),
		eventID, nowUnix, expiresAtUnix,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Forget removes an event ID from the replay ledger (used only if a transient 5xx failure
// prevented handling so the peer can retry safely).
func (s *suiteReplayStore) Forget(ctx context.Context, eventID string) error {
	if eventID == "" {
		return nil
	}
	_, err := s.store.db.ExecContext(
		ctx,
		s.store.rebind(`DELETE FROM suite_replay_events WHERE event_id = ?`),
		eventID,
	)
	return err
}

// Prune deletes expired suite replay event entries whose expires_at <= beforeUnix.
func (s *suiteReplayStore) Prune(ctx context.Context, beforeUnix int64) error {
	_, err := s.store.db.ExecContext(
		ctx,
		s.store.rebind(`DELETE FROM suite_replay_events WHERE expires_at <= ?`),
		beforeUnix,
	)
	return err
}
