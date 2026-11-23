package store

import (
	"context"
	"time"
)

// InvalidateRestoredGrants is an offline restore operation, before accepting any
// traffic. It clears ephemeral sessions/challenges/pairings and push subscriptions (a
// snapshot cannot prove which were revoked after backup), closes any active calls
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
		`DELETE FROM push_subscriptions`,
		`DELETE FROM attachment_upload_reservations`,
		// A one-time key claimed after the backup would be handed out again, but its device already
		// spent the private half; restored mail was already read. Devices re-upload one-time keys
		// when their count runs low. Fallback keys are never consumed, so they stay.
		`DELETE FROM e2ee_one_time_keys WHERE fallback = 0`,
		`DELETE FROM e2ee_to_device`,
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
		"restore.grants_invalidated", "Sessions, challenges, pairings, push subscriptions, active calls, bot tokens, one-time encryption keys and undelivered encryption mail invalidated. Users sign in again and rotate bot tokens.", now); err != nil {
		return err
	}
	return tx.Commit()
}
