package store

import (
	"context"
	"time"
)

// InvalidateRestoredGrants is an offline restore operation, before accepting any
// traffic. It clears ephemeral sessions/challenges/pairings and push subscriptions (a
// snapshot cannot prove which were revoked after backup) and meeting guest sessions (a
// restored admission would let a removed guest back in), closes any active calls
// from snapshot time, revokes active bot tokens (since a snapshot cannot prove
// which tokens were revoked after backup), and resets multi-tenant KyIdentity sync
// freshness/cursors, active customer tenant admission, and cached storage pool grants
// (preserving tenancy.mode, tenancy.staff_org_id, permanent erased_subjects tombstones,
// the single-tenant default org, the staff org, and pool_seq/pool_required_seq fences).
func (s *SQLStore) InvalidateRestoredGrants(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// These tables contain only multi-mode state. Retain old media targets before restored
	// call records are ended, so a fresh owner cannot inherit an old admission or bearer.
	if _, err := tx.ExecContext(ctx, `INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT DISTINCT c.tenant_id,c.livekit_room,'','' FROM call_sessions c
 WHERE c.livekit_room IS NOT NULL AND c.livekit_room<>'' AND EXISTS(SELECT 1 FROM call_room_owners o WHERE o.room_id=c.room_id AND o.tenant_id=c.tenant_id)
 ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM call_seats`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE call_room_owners SET expires_at=0,generation=generation+1`); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM sessions`,
		`DELETE FROM mfa_challenges`,
		`DELETE FROM device_pairings`,
		`DELETE FROM push_subscriptions`,
		`DELETE FROM attachment_upload_reservations`,
		// A one-time key claimed after the backup would be handed out again, but its device already
		// spent the private half, and a fallback key may have been rotated away since; restored mail
		// was already read. Every key becomes a retired tombstone, so a retried upload cannot
		// revive it either. Devices upload new keys when the upload response shows none.
		`UPDATE e2ee_one_time_keys SET claimed = 1`,
		`DELETE FROM e2ee_to_device`,
		`DELETE FROM meeting_guest_sessions`,
		// Clear KyIdentity sync freshness and incremental cursors (never tenancy.mode,
		// tenancy.staff_org_id, or erased_subjects) so startup refuses a pre-restore <24h
		// timestamp offline and replays orgs/erasures from zero once KyIdentity answers.
		`DELETE FROM server_settings WHERE key IN (
			'tenancy.kyidentity_synced_at',
			'tenancy.full_sync_at',
			'tenancy.orgs_revision',
			'tenancy.erased_revision'
		)`,
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	// Mark active customer orgs unverified (suspended) until a fresh KyIdentity sync admits
	// them again; keep the single-tenant default org, the staff org, and terminal deleted
	// tombstones intact.
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE tenants SET status = ?
		WHERE status = ? AND id <> ?
		AND NOT EXISTS (SELECT 1 FROM server_settings WHERE key = ? AND value = tenants.id)`),
		TenantStatusSuspended, TenantStatusActive, DefaultTenantID, TenancyStaffOrgSettingKey); err != nil {
		return err
	}
	// Clear cached storage pool grants so pre-restore ceilings/expiry cannot be spent before
	// a fresh KyIdentity report, while preserving pool_seq and pool_required_seq fences.
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE tenants
		SET pool_ceiling_bytes = NULL, pool_expires_at = NULL, pool_reported_bytes = NULL
		WHERE id <> ?`), DefaultTenantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE call_sessions SET ended_at = ? WHERE ended_at IS NULL`), now.UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE agents SET token_hash = '', token_state = ? WHERE token_state = ?`), AgentTokenRevoked, AgentTokenActive); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO audit_records (action, details, created_at) VALUES (?, ?, ?)`),
		"restore.grants_invalidated", "Sessions, challenges, pairings, push subscriptions, active calls, bot tokens, one-time encryption keys, undelivered encryption mail, tenancy sync state and cached storage pool grants invalidated. Users sign in again and rotate bot tokens.", now); err != nil {
		return err
	}
	return tx.Commit()
}
