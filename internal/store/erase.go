package store

import (
	"context"
	"errors"
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

// ErasureTargets lists every account a KyIdentity subject had whose row is gone (user_subjects).
func (c *chatStore) ErasureTargets(ctx context.Context, provider, subject string) ([]*User, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT user_id, org_id FROM user_subjects WHERE provider = ? AND subject = ? ORDER BY user_id`), provider, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{SSOProvider: provider, SSOSubject: subject}
		if err := rows.Scan(&u.ID, &u.OrgID); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeactivateForErasure is erasure's first step: the account stops serving before anything is
// disconnected or deleted, so nothing admitted meanwhile can recreate access.
func (c *chatStore) DeactivateForErasure(ctx context.Context, userID string) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE users SET status = 'deleted', updated_at = ? WHERE id = ?`), time.Now().UTC(), userID)
	return err
}

// EraseUser deletes the user's rows in tenantID, keeps the subject mapping so a repeat finds
// them again, records the erasure under the opaque ID only, and returns the blobs of the
// attachment rows it deleted (an upload that committed after ErasureBlobs), for the caller to
// delete too. It is idempotent and needs no account row.
func (c *chatStore) EraseUser(ctx context.Context, tenantID string, user *User) ([]BlobRef, error) {
	userID := user.ID
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := rememberSubject(ctx, c.store, tx, &User{ID: userID, OrgID: tenantID, SSOProvider: user.SSOProvider, SSOSubject: user.SSOSubject}); err != nil {
		return nil, err
	}
	var late []BlobRef
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM attachments WHERE room_id IN (` + goneDMs + `) RETURNING id, tenant_id, blob_key`, []any{userID, tenantID, userID}},
		{`DELETE FROM attachments WHERE tenant_id = ? AND (uploader_id = ? OR message_id IN (SELECT id FROM messages WHERE tenant_id = ? AND sender_id = ?)) RETURNING id, tenant_id, blob_key`, []any{tenantID, userID, tenantID, userID}},
	} {
		rows, err := tx.QueryContext(ctx, c.store.rebind(q.sql), q.args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r BlobRef
			if err := rows.Scan(&r.ID, &r.TenantID, &r.Key); err != nil {
				rows.Close()
				return nil, err
			}
			late = append(late, r)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, err
		}
	}
	// Blobs of rows deleted here are queued in the same transaction, so a failed delete after
	// commit is retried (PendingBlobDeletes) instead of lost with its row.
	for _, r := range late {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_blob_deletes (tenant_id, blob_key) VALUES (?, ?) ON CONFLICT (tenant_id, blob_key) DO NOTHING`), r.TenantID, r.Key); err != nil {
			return nil, err
		}
	}
	now := time.Now().UnixMilli()
	steps := []struct {
		q    string
		args []any
	}{
		// DMs nobody else uses: everything left in them goes.
		{`DELETE FROM message_reactions WHERE message_id IN (SELECT id FROM messages WHERE room_id IN (` + goneDMs + `))`, []any{userID, tenantID, userID}},
		{`DELETE FROM messages WHERE room_id IN (` + goneDMs + `)`, []any{userID, tenantID, userID}},
		{`DELETE FROM rooms WHERE id IN (` + goneDMs + `)`, []any{userID, tenantID, userID}},
		// Elsewhere: tombstones, and nothing of theirs reacted.
		{`UPDATE messages SET body = '', sender_name = '', deleted_at = COALESCE(deleted_at, ?) WHERE tenant_id = ? AND sender_id = ?`, []any{now, tenantID, userID}},
		{`DELETE FROM message_reactions WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM room_members WHERE tenant_id = ? AND user_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND uploader_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM device_pairings WHERE user_id = ?`, []any{userID}},
		// Their bots, and the bots' accounts.
		{`DELETE FROM users WHERE id IN (SELECT user_id FROM agents WHERE owner_user_id = ?)`, []any{userID}},
		{`DELETE FROM agents WHERE owner_user_id = ?`, []any{userID}},
		// The account; sessions, MFA challenges, presence and push subscriptions cascade.
		{`DELETE FROM users WHERE id = ? AND org_id = ?`, []any{userID, tenantID}},
		{`INSERT INTO audit_records (action, resource, details, created_at) VALUES ('sso.user_erased', ?, '', ?)`, []any{"user:" + userID, time.Now().UTC()}},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, c.store.rebind(s.q), s.args...); err != nil {
			return nil, err
		}
	}
	return late, tx.Commit()
}

// PendingBlobDeletes lists up to limit queued blob deletes.
func (c *chatStore) PendingBlobDeletes(ctx context.Context, limit int) ([]BlobRef, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT tenant_id, blob_key FROM pending_blob_deletes ORDER BY tenant_id, blob_key LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlobRef
	for rows.Next() {
		var r BlobRef
		if err := rows.Scan(&r.TenantID, &r.Key); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClearPendingBlobDeletes drops queued deletes whose blobs are gone.
func (c *chatStore) ClearPendingBlobDeletes(ctx context.Context, refs []BlobRef) error {
	for _, r := range refs {
		if _, err := c.store.db.ExecContext(ctx, c.store.rebind(`DELETE FROM pending_blob_deletes WHERE tenant_id = ? AND blob_key = ?`), r.TenantID, r.Key); err != nil {
			return err
		}
	}
	return nil
}
