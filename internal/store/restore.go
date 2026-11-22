package store

import (
	"context"
	"time"
)

// InvalidateRestoredGrants is an offline restore operation, before accepting any
// traffic. It clears ephemeral sessions/challenges/pairings, closes any active calls
// from snapshot time, and revokes active bot tokens (since a snapshot cannot prove
// which tokens were revoked after backup).
func (s *SQLStore) InvalidateRestoredGrants(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, query := range []string{
		`DELETE FROM sessions`,
		`DELETE FROM mfa_challenges`,
		`DELETE FROM device_pairings`,
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE call_sessions SET ended_at = ? WHERE ended_at IS NULL`), now.UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE agents SET token_hash = '', token_state = ? WHERE token_state = ?`), AgentTokenRevoked, AgentTokenActive); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO audit_records (action, details, created_at) VALUES (?, ?, ?)`),
		"restore.grants_invalidated", "Sessions, challenges, pairings, active calls, and bot tokens invalidated. Users sign in again and rotate bot tokens.", now); err != nil {
		return err
	}
	return tx.Commit()
}
