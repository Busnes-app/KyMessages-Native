package store

import (
	"context"
	"time"
)

// RememberErasedSubject fences future provisioning even when this install never held the
// account. It preserves all current account IDs and deactivates them before cleanup begins.
func (c *chatStore) RememberErasedSubject(ctx context.Context, subject, orgID string) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if c.store.driver == "postgres" {
		// The user INSERT trigger takes this same identity lock before creating an account.
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('kymessages:erased-subject:' || current_schema()), hashtext($1))`, subject); err != nil {
			return err
		}
	} else {
		// Acquire SQLite's writer before checking binding; deferred read-to-write upgrades lose.
		if _, err = tx.ExecContext(ctx, `UPDATE sso_generation SET generation=generation WHERE id=1`); err != nil {
			return err
		}
	}
	var mismatches int
	if err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT COUNT(*) FROM (
 SELECT org_id FROM users WHERE sso_provider='kyidentity' AND sso_subject=?
 UNION ALL SELECT org_id FROM user_subjects WHERE provider='kyidentity' AND subject=?
 UNION ALL SELECT org_id FROM erased_subjects WHERE subject=?
 ) bindings WHERE org_id <> ?`), subject, subject, subject, orgID).Scan(&mismatches); err != nil {
		return err
	}
	if mismatches != 0 {
		return ErrErasureOrgMismatch
	}
	if _, err = tx.ExecContext(ctx, c.store.rebind(`INSERT INTO erased_subjects(subject,org_id,erased_at) VALUES(?,?,?) ON CONFLICT(subject) DO NOTHING`), subject, orgID, time.Now().UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, c.store.rebind(`INSERT INTO user_subjects(provider,subject,user_id,org_id)
 SELECT sso_provider,sso_subject,id,org_id FROM users WHERE sso_provider='kyidentity' AND sso_subject=? AND org_id=? ON CONFLICT DO NOTHING`), subject, orgID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, c.store.rebind(`UPDATE users SET status='deleted',updated_at=? WHERE sso_provider='kyidentity' AND sso_subject=? AND org_id=?`), time.Now().UTC(), subject, orgID); err != nil {
		return err
	}
	return tx.Commit()
}
