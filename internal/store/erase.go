package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// Erasure (KyIdentity user.erased, multi mode): delete one person's data. Their messages in
// rooms others still use become tombstones (no body, no name, no attachments; the row keeps
// the thread's order). Owned rooms and DMs with no other member are deleted whole. Blobs go first
// (ErasureBlobs), then the rows (EraseUser), so an interrupted run leaves rows naming every
// blob still there, and a rerun finishes. Both are idempotent.

// goneErasureRooms selects DMs and owned rooms with no remaining member. Disabled members
// still own their content; only a missing or erased account stops counting as a member.
const goneErasureRooms = `SELECT r.id FROM rooms r CROSS JOIN (SELECT ? AS user_id) actor
WHERE r.tenant_id = ? AND (
 r.created_by = actor.user_id OR EXISTS (SELECT 1 FROM room_members m
 WHERE m.tenant_id = r.tenant_id AND m.room_id = r.id AND m.user_id = actor.user_id
 AND (r.kind = 'dm' OR m.role = 'owner')))
AND NOT EXISTS (SELECT 1 FROM room_members o JOIN users u ON u.id = o.user_id
 WHERE o.tenant_id = r.tenant_id AND o.room_id = r.id AND o.user_id <> actor.user_id AND o.user_id NOT IN (SELECT user_id FROM user_erasure_actors
 WHERE tenant_id = r.tenant_id AND owner_user_id = ?) AND u.status <> 'deleted')`

// ErasureBlobs lists every blob an erasure of userID removes.
func (c *chatStore) ErasureBlobs(ctx context.Context, tenantID, userID string) ([]BlobRef, error) {
	actors, err := c.erasureActors(ctx, c.store.db, tenantID, userID)
	if err != nil {
		return nil, err
	}
	var out []BlobRef
	for _, actor := range actors {
		refs, err := c.erasureActorBlobs(ctx, tenantID, actor, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

func (c *chatStore) erasureActorBlobs(ctx context.Context, tenantID, actorID, ownerID string) ([]BlobRef, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT a.id, a.tenant_id, a.blob_key FROM attachments a
 WHERE a.tenant_id = ? AND (a.uploader_id = ? OR a.message_id IN (SELECT id FROM messages WHERE tenant_id = ? AND sender_id = ?) OR a.room_id IN (`+goneErasureRooms+`))
 UNION SELECT '',tenant_id,blob_key FROM pending_blob_deletes WHERE tenant_id = ? AND user_id = ?
 UNION SELECT '',tenant_id,blob_key FROM retained_attachment_versions WHERE tenant_id = ? AND uploader_id = ?`), tenantID, actorID, tenantID, actorID, actorID, tenantID, ownerID, tenantID, ownerID, tenantID, actorID)
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
func (c *chatStore) DeactivateForErasure(ctx context.Context, tenantID, userID string) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := c.rememberErasureActors(ctx, tx, tenantID, userID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, c.store.rebind(`UPDATE users SET status = 'deleted', updated_at = ? WHERE id IN (SELECT user_id FROM user_erasure_actors WHERE owner_user_id = ? AND tenant_id = ?) AND (org_id = ? OR (sso_provider = 'bot' AND org_id = ''))`), time.Now().UTC(), userID, tenantID, tenantID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (c *chatStore) rememberErasureActors(ctx context.Context, tx *sql.Tx, tenantID, ownerID string) error {
	if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO user_erasure_actors (owner_user_id,tenant_id,user_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`), ownerID, tenantID, ownerID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO user_erasure_actors (owner_user_id,tenant_id,user_id)
 SELECT ?, ?, a.user_id FROM agents a JOIN users u ON u.id = a.user_id WHERE a.owner_user_id = ? AND (u.org_id = ? OR (u.sso_provider = 'bot' AND u.org_id = '')) ON CONFLICT DO NOTHING`), ownerID, tenantID, ownerID, tenantID)
	return err
}

func (c *chatStore) erasureActors(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, tenantID, ownerID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, c.store.rebind(`SELECT user_id FROM user_erasure_actors WHERE owner_user_id = ? AND tenant_id = ? UNION SELECT ? ORDER BY user_id`), ownerID, tenantID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// EraseUser deletes the user's rows in tenantID, keeps the subject mapping so a repeat finds
// them again, starts durable completion tracking, and returns the blobs of the
// attachment rows it deleted (an upload that committed after ErasureBlobs), for the caller to
// delete too. It is idempotent and needs no account row.
func (c *chatStore) EraseUser(ctx context.Context, tenantID string, user *User) ([]BlobRef, error) {
	userID := user.ID
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	if err := rememberSubject(ctx, c.store, tx, &User{ID: userID, OrgID: tenantID, SSOProvider: user.SSOProvider, SSOSubject: user.SSOSubject}); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO user_erasure_state (user_id, tenant_id) VALUES (?, ?) ON CONFLICT (user_id) DO NOTHING`), userID, tenantID); err != nil {
		return nil, err
	}
	if err := c.rememberErasureActors(ctx, tx, tenantID, userID); err != nil {
		return nil, err
	}
	if err := c.handoverErasureRooms(ctx, tx, tenantID, userID); err != nil {
		return nil, err
	}
	actors, err := c.erasureActors(ctx, tx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	var late []BlobRef
	for _, actorID := range actors {
		refs, err := c.eraseActorTx(ctx, tx, tenantID, actorID, userID)
		if err != nil {
			return nil, err
		}
		late = append(late, refs...)
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM agents WHERE owner_user_id = ? AND user_id IN (SELECT user_id FROM user_erasure_actors WHERE owner_user_id = ? AND tenant_id = ?)`), userID, userID, tenantID); err != nil {
		return nil, err
	}
	return late, tx.Commit()
}

func (c *chatStore) eraseActorTx(ctx context.Context, tx *sql.Tx, tenantID, userID, ownerID string) ([]BlobRef, error) {
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.tenant_id=? AND call_seats.user_id=?`, tenantID, userID); err != nil {
		return nil, err
	}
	var late []BlobRef
	// Retained files survive the ordinary delete and have no live attachment row.
	// Keep them retryable even if an earlier discovery ran before that deletion.
	rows, err := tx.QueryContext(ctx, c.store.rebind(`SELECT tenant_id,blob_key FROM retained_attachment_versions WHERE tenant_id=? AND uploader_id=?`), tenantID, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ref BlobRef
		if err := rows.Scan(&ref.TenantID, &ref.Key); err != nil {
			rows.Close()
			return nil, err
		}
		late = append(late, ref)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM attachments WHERE room_id IN (` + goneErasureRooms + `) RETURNING id, tenant_id, blob_key`, []any{userID, tenantID, ownerID}},
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
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_blob_deletes (tenant_id, blob_key, user_id) VALUES (?, ?, ?) ON CONFLICT (tenant_id, blob_key) DO NOTHING`), r.TenantID, r.Key, ownerID); err != nil {
			return nil, err
		}
	}
	now := time.Now().UnixMilli()
	steps := []struct {
		q    string
		args []any
	}{
		// DMs and owned rooms nobody else uses: everything left in them goes.
		{`DELETE FROM message_reactions WHERE message_id IN (SELECT id FROM messages WHERE room_id IN (` + goneErasureRooms + `))`, []any{userID, tenantID, ownerID}},
		{`DELETE FROM messages WHERE room_id IN (` + goneErasureRooms + `)`, []any{userID, tenantID, ownerID}},
		{`DELETE FROM rooms WHERE id IN (` + goneErasureRooms + `)`, []any{userID, tenantID, ownerID}},
		// Elsewhere: tombstones, and nothing of theirs reacted.
		{`UPDATE messages SET body = '', original_body = '', sender_name = '', deleted_at = COALESCE(deleted_at, ?) WHERE tenant_id = ? AND sender_id = ?`, []any{now, tenantID, userID}},
		{`DELETE FROM message_reactions WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM room_members WHERE tenant_id = ? AND user_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND uploader_id = ?`, []any{tenantID, userID}},
		{`DELETE FROM device_pairings WHERE user_id = ?`, []any{userID}},
		// The account; sessions, MFA challenges, presence and push subscriptions cascade.
		{`DELETE FROM users WHERE id = ? AND (org_id = ? OR (sso_provider = 'bot' AND org_id = ''))`, []any{userID, tenantID}},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, c.store.rebind(s.q), s.args...); err != nil {
			return nil, err
		}
	}
	return late, nil
}

// blobDeleteClaimed marks a queued delete of no person's (an upload intent, a staged removal) that
// a sweep has leased: a late commit of that upload then refuses, so no row names an erased blob.
const blobDeleteClaimed = "~sweep"

// QueueUploadIntent records, before an upload writes its blob, that the blob must be erased
// unless the upload commits: CommitAttachmentWithQuota removes the intent in its transaction, and
// a sweep erases what is left once notBefore (past the upload's deadline) passes.
func (c *chatStore) QueueUploadIntent(ctx context.Context, tenantID, key string, notBefore int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_blob_deletes (tenant_id, blob_key, user_id, not_before) VALUES (?, ?, '', ?)`), normalizeTenant(tenantID), key, notBefore)
	return err
}

// DuePendingBlobDeletes returns up to limit queued deletes that are due, a random sample. Deletes
// of no person's are leased first (for lease), so a late commit refuses them and a sweep that dies
// before it erases leaves them due again once the lease ends.
func (c *chatStore) DuePendingBlobDeletes(ctx context.Context, limit int, at time.Time, lease time.Duration) ([]BlobRef, error) {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	now := at.UnixMilli()
	rows, err := tx.QueryContext(ctx, c.store.rebind(`SELECT tenant_id, blob_key, user_id FROM pending_blob_deletes WHERE not_before <= ? ORDER BY random() LIMIT ?`), now, limit)
	if err != nil {
		return nil, err
	}
	type due struct {
		BlobRef
		user string
	}
	var found []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.TenantID, &d.Key, &d.user); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, d)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	out := make([]BlobRef, 0, len(found))
	for _, d := range found {
		if d.user != "" && d.user != blobDeleteClaimed {
			out = append(out, d.BlobRef) // an erasure's: no upload can commit it
			continue
		}
		res, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE pending_blob_deletes SET user_id = ?, not_before = ? WHERE tenant_id = ? AND blob_key = ? AND user_id IN ('', ?) AND not_before <= ?`),
			blobDeleteClaimed, now+lease.Milliseconds(), d.TenantID, d.Key, blobDeleteClaimed, now)
		if err != nil {
			return nil, err
		}
		if n, err := res.RowsAffected(); err == nil && n == 1 {
			out = append(out, d.BlobRef)
		}
	}
	return out, tx.Commit()
}

// PendingBlobDeletes lists up to limit queued blob deletes, a random sample of them.
func (c *chatStore) PendingBlobDeletes(ctx context.Context, limit int) ([]BlobRef, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT tenant_id, blob_key FROM pending_blob_deletes ORDER BY random() LIMIT ?`), limit)
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

// ClearPendingBlobDeletes drops erased blobs (every version gone: Backend.Erase) and their
// retained charges, and records each completed erasure once.
// The completion transition and audit share the cleanup transaction, on every replica.
func (c *chatStore) ClearPendingBlobDeletes(ctx context.Context, refs []BlobRef) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Cleanup and retention share quota ownership. Lock each org in stable order
	// so a multi-org sweep cannot race a newly retained charge or another sweep.
	orgs := make(map[string]bool)
	for _, r := range refs {
		orgs[r.TenantID] = true
	}
	ordered := make([]string, 0, len(orgs))
	for org := range orgs {
		ordered = append(ordered, org)
	}
	sort.Strings(ordered)
	for _, org := range ordered {
		if err := c.lockAttachmentQuotaTx(ctx, tx, org); err != nil {
			return err
		}
	}
	for _, r := range refs {
		// The caller erased every version of r, so its retained charge goes too.
		if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM retained_attachment_versions WHERE tenant_id = ? AND blob_key = ?`), r.TenantID, r.Key); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM pending_blob_deletes WHERE tenant_id = ? AND blob_key = ?`), r.TenantID, r.Key); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, c.store.rebind(`UPDATE user_erasure_state SET completed_at = ? WHERE completed_at IS NULL AND NOT EXISTS (SELECT 1 FROM pending_blob_deletes p WHERE p.tenant_id = user_erasure_state.tenant_id AND p.user_id = user_erasure_state.user_id)
 AND NOT EXISTS (SELECT 1 FROM pending_call_evictions p WHERE p.tenant_id=user_erasure_state.tenant_id AND (p.user_id=user_erasure_state.user_id OR p.user_id IN(SELECT a.user_id FROM user_erasure_actors a WHERE a.tenant_id=p.tenant_id AND a.owner_user_id=user_erasure_state.user_id))) AND NOT EXISTS (SELECT 1 FROM retained_attachment_versions v WHERE v.tenant_id=user_erasure_state.tenant_id AND (v.uploader_id=user_erasure_state.user_id OR v.uploader_id IN (SELECT a.user_id FROM user_erasure_actors a WHERE a.tenant_id=v.tenant_id AND a.owner_user_id=user_erasure_state.user_id))) RETURNING user_id`), time.Now().UnixMilli())
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO audit_records (action, resource, details, created_at) VALUES ('sso.user_erased', ?, '', ?)`), "user:"+id, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
