package store

import (
	"context"
	"database/sql"
	"time"
)

// Erasure (KyIdentity user.erased, multi mode): delete one person's data. Their messages in
// rooms others still use become tombstones (no body, no name, no attachments; the row keeps
// the thread's order). A DM whose other member is gone too is deleted whole. Blobs go first
// (ErasureBlobs), then the rows (EraseUser), so an interrupted run leaves rows naming every
// blob still there, and a rerun finishes. Both are idempotent.

// goneDMs selects the erased user's DM rooms whose every other member is gone (no live row).
const goneDMs = `SELECT r.id FROM rooms r JOIN room_members m ON m.room_id = r.id AND m.user_id = ?
WHERE r.tenant_id = ? AND r.kind = 'dm' AND NOT EXISTS (
	SELECT 1 FROM room_members o JOIN users u ON u.id = o.user_id
	WHERE o.room_id = r.id AND o.user_id <> ? AND u.status <> 'deleted')`

// ErasureBlobs lists every blob an erasure of userID removes.
func (c *chatStore) ErasureBlobs(ctx context.Context, tenantID, userID string) ([]BlobRef, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT a.id, a.tenant_id, a.blob_key FROM attachments a
WHERE a.tenant_id = ? AND (a.uploader_id = ?
	OR a.message_id IN (SELECT id FROM messages WHERE tenant_id = ? AND sender_id = ?)
	OR a.room_id IN (`+goneDMs+`))`), tenantID, userID, tenantID, userID, userID, tenantID, userID)
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

// EraseUser deletes userID's rows in tenantID and records the erasure under the opaque ID only.
// It reports whether the user existed.
func (c *chatStore) EraseUser(ctx context.Context, tenantID, userID string) (bool, error) {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var one int
	err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT 1 FROM users WHERE id = ? AND org_id = ?`), userID, tenantID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now().UnixMilli()
	steps := []struct {
		q    string
		args []any
	}{
		// DMs nobody else uses: everything in them goes.
		{`DELETE FROM attachments WHERE room_id IN (` + goneDMs + `)`, []any{userID, tenantID, userID}},
		{`DELETE FROM message_reactions WHERE message_id IN (SELECT id FROM messages WHERE room_id IN (` + goneDMs + `))`, []any{userID, tenantID, userID}},
		{`DELETE FROM messages WHERE room_id IN (` + goneDMs + `)`, []any{userID, tenantID, userID}},
		{`DELETE FROM rooms WHERE id IN (` + goneDMs + `)`, []any{userID, tenantID, userID}},
		// Elsewhere: tombstones, and nothing of theirs attached or reacted.
		{`DELETE FROM attachments WHERE tenant_id = ? AND (uploader_id = ? OR message_id IN (SELECT id FROM messages WHERE tenant_id = ? AND sender_id = ?))`, []any{tenantID, userID, tenantID, userID}},
		{`UPDATE messages SET body = '', sender_name = '', deleted_at = COALESCE(deleted_at, ?) WHERE tenant_id = ? AND sender_id = ?`, []any{now, tenantID, userID}},
		{`DELETE FROM message_reactions WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM room_members WHERE tenant_id = ? AND user_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND uploader_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM device_pairings WHERE user_id = ?`, []any{userID}},
		// Their bots, and the bots' accounts.
		{`DELETE FROM users WHERE id IN (SELECT user_id FROM agents WHERE owner_user_id = ?)`, []any{userID}},
		{`DELETE FROM agents WHERE owner_user_id = ?`, []any{userID}},
		// The account; sessions, MFA challenges, presence and push subscriptions cascade.
		{`DELETE FROM users WHERE id = ?`, []any{userID}},
		{`INSERT INTO audit_records (action, resource, details, created_at) VALUES ('sso.user_erased', ?, '', ?)`, []any{"user:" + userID, time.Now().UTC()}},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, c.store.rebind(s.q), s.args...); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}
