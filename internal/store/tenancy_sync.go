package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Tenancy sync and purge (multi mode). KyIdentity's org list is the authority; this database
// only remembers what it last applied. An org a complete full read did not list is held
// offline (suspended, missing_since set, its lifecycle revision untouched) and never purged.
// Only an explicit deletion purges.

// ActiveTenantIDs lists the active orgs (not the default tenant).
func (c *chatStore) ActiveTenantIDs(ctx context.Context) ([]string, error) {
	return c.ids(ctx, `SELECT id FROM tenants WHERE status = 'active' AND id <> ? ORDER BY id`, DefaultTenantID)
}

// DeletedUnpurgedTenants lists deleted orgs whose data has not been purged yet.
func (c *chatStore) DeletedUnpurgedTenants(ctx context.Context) ([]string, error) {
	return c.ids(ctx, `SELECT id FROM tenants WHERE status = 'deleted' AND purged_at IS NULL AND id <> ? ORDER BY id`, DefaultTenantID)
}

func (c *chatStore) ids(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MarkTenantMissing holds an active org offline as if suspended. It reports whether it changed.
func (c *chatStore) MarkTenantMissing(ctx context.Context, tenantID string, nowMs int64) (bool, error) {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET status = 'suspended', missing_since = ? WHERE id = ? AND status = 'active'`), nowMs, tenantID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO tenant_pending_revocations (tenant_id) VALUES (?) ON CONFLICT (tenant_id) DO NOTHING`), tenantID); err != nil {
			return false, err
		}
	}
	return n == 1, tx.Commit()
}

// ClearTenantMissing serves a missing org again once KyIdentity lists it as active at revision,
// unless a newer lifecycle event applied since (which also clears the flag, see
// ApplyTenantLifecycle): a stale listing never undoes a newer suspension.
func (c *chatStore) ClearTenantMissing(ctx context.Context, tenantID string, revision int64) (bool, error) {
	return c.changed(ctx, `UPDATE tenants SET status = 'active', missing_since = NULL WHERE id = ? AND missing_since IS NOT NULL AND status = 'suspended' AND lifecycle_revision <= ? AND NOT EXISTS (SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id = tenants.id)`, tenantID, revision)
}

// TenantMissing reports whether tenantID carries the missing flag.
func (c *chatStore) TenantMissing(ctx context.Context, tenantID string) (bool, error) {
	var since sql.NullInt64
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`SELECT missing_since FROM tenants WHERE id = ?`), tenantID).Scan(&since)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return since.Valid, err
}

func (c *chatStore) changed(ctx context.Context, q string, args ...any) (bool, error) {
	res, err := c.store.db.ExecContext(ctx, c.store.rebind(q), args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PurgeAttachmentBatch returns up to limit of a deleted org's attachment blobs. The caller
// deletes the blobs, then DeleteAttachmentRows, so an interrupted purge still has a row for
// every blob left.
func (c *chatStore) PurgeAttachmentBatch(ctx context.Context, tenantID string, limit int) ([]BlobRef, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT a.id, a.tenant_id, a.blob_key FROM attachments a
JOIN tenants t ON t.id = a.tenant_id AND t.status = 'deleted' WHERE a.tenant_id = ? ORDER BY a.id LIMIT ?`), tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlobRef
	for rows.Next() {
		var r BlobRef
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Key); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteAttachmentRows deletes a deleted org's attachment rows by ID.
func (c *chatStore) DeleteAttachmentRows(ctx context.Context, tenantID string, refs []BlobRef) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range refs {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM attachments WHERE id = ? AND tenant_id = ? AND tenant_id IN (SELECT id FROM tenants WHERE status = 'deleted')`), r.ID, tenantID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PurgeTenantRows deletes the rest of a deleted org's data, child tables first, once its
// attachments are gone. The tenants row stays as a tombstone, so a late event cannot bring the
// org back. It does nothing for an org that is not deleted or already purged.
func (c *chatStore) PurgeTenantRows(ctx context.Context, tenantID string) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// The upload commit's lock: a commit in flight finishes first, and later ones see the org
	// deleted and commit nothing.
	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var one int
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT 1 FROM tenants WHERE id = ? AND status = 'deleted' AND purged_at IS NULL`), tenantID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if err := c.requireNoRetainedVersionsTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.tenant_id=?`, tenantID); err != nil {
		return err
	}
	// Retain every SFU room before its call/room rows disappear. Cleanup must finish before
	// MarkTenantPurged may hide this org from later attempts.
	if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT DISTINCT tenant_id,livekit_room,'','' FROM call_sessions WHERE tenant_id=? AND livekit_room IS NOT NULL AND livekit_room<>'' ON CONFLICT DO NOTHING`), tenantID); err != nil {
		return err
	}
	members := `SELECT id FROM users WHERE org_id = ?`
	for _, s := range []struct {
		q    string
		args []any
	}{
		{`DELETE FROM attachments WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM message_reactions WHERE message_id IN (SELECT id FROM messages WHERE tenant_id = ?)`, []any{tenantID}},
		{`DELETE FROM messages WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM meeting_guest_sessions WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM meeting_guests WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM meeting_windows WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM meetings WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM call_sessions WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM room_members WHERE tenant_id = ?`, []any{tenantID}},
		// Room webhooks (where the table exists) cascade from rooms.
		{`DELETE FROM rooms WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM push_subscriptions WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM attachment_upload_reservations WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM presence WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM device_pairings WHERE user_id IN (` + members + `)`, []any{tenantID}},
		{`DELETE FROM users WHERE id IN (SELECT user_id FROM agents WHERE owner_user_id IN (` + members + `))`, []any{tenantID}},
		{`DELETE FROM agents WHERE owner_user_id IN (` + members + `)`, []any{tenantID}},
		// Sessions, MFA challenges, presence and push subscriptions cascade from users.
		{`DELETE FROM users WHERE org_id = ?`, []any{tenantID}},
		{`DELETE FROM user_subjects WHERE org_id = ?`, []any{tenantID}},
		{`DELETE FROM pending_blob_deletes WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM user_erasure_actors WHERE tenant_id = ?`, []any{tenantID}},
		{`DELETE FROM user_erasure_state WHERE tenant_id = ?`, []any{tenantID}},
	} {
		if _, err := tx.ExecContext(ctx, c.store.rebind(s.q), s.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkTenantPurged records that a deleted org's rows and blobs are gone (the purge's last step,
// after its blob prefix is deleted, so a failure before it reruns the whole purge).
func (c *chatStore) MarkTenantPurged(ctx context.Context, tenantID string) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := c.requireNoRetainedVersionsTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT COUNT(*) FROM pending_call_evictions WHERE tenant_id=?`), tenantID).Scan(&pending); err != nil {
		return err
	}
	if pending != 0 {
		return ErrCallCleanupPending
	}
	res, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET purged_at = ? WHERE id = ? AND status = 'deleted' AND purged_at IS NULL`), time.Now().UnixMilli(), tenantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO audit_records (action, resource, details, created_at) VALUES ('tenancy.org_purged', ?, '', ?)`), "tenant:"+tenantID, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PendingTenantRevocations survives missing detection, lifecycle changes and process restarts.
func (c *chatStore) PendingTenantRevocations(ctx context.Context) ([]string, error) {
	return c.ids(ctx, `SELECT tenant_id FROM tenant_pending_revocations ORDER BY tenant_id`)
}
func (c *chatStore) CompleteTenantRevocation(ctx context.Context, id string) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`DELETE FROM tenant_pending_revocations WHERE tenant_id = ?`), id)
	return err
}
