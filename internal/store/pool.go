package store

import (
	"context"
	"database/sql"
	"errors"
)

// The org storage pool (multi mode). KyIdentity holds each org's pool across every app; this
// app reports the bytes it stores per org and receives a grant: a ceiling it may fill until the
// grant expires. Writes that add bytes check it under the tenant's quota lock; writes that free
// bytes never do.

// poolCeilingTx returns tenantID's unexpired ceiling, or ErrPoolUnavailable.
func (c *chatStore) poolCeilingTx(ctx context.Context, tx *sql.Tx, tenantID string, nowMs int64) (int64, error) {
	var ceiling, expires sql.NullInt64
	err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT pool_ceiling_bytes, pool_expires_at FROM tenants WHERE id = ?`), tenantID).Scan(&ceiling, &expires)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!ceiling.Valid || !expires.Valid || expires.Int64 <= nowMs) {
		return 0, ErrPoolUnavailable
	}
	return ceiling.Int64, err
}

// PoolUsage is one org's storage figure for a pool report.
type PoolUsage struct {
	TenantID      string
	UsedBytes     int64  // posted and staged attachments plus live upload reservations
	ReportedBytes *int64 // last reported usage
	CeilingBytes  *int64
	ExpiresAt     *int64 // Unix ms
}

// PoolUsages lists every active org with its usage, or only tenantID when it is set.
func (c *chatStore) PoolUsages(ctx context.Context, nowMs int64, tenantID string) ([]PoolUsage, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`
SELECT t.id,
	COALESCE((SELECT SUM(a.size_bytes) FROM attachments a WHERE a.tenant_id = t.id), 0) +
	COALESCE((SELECT SUM(r.reserved_bytes) FROM attachment_upload_reservations r WHERE r.tenant_id = t.id AND r.expires_at > ?), 0),
	t.pool_reported_bytes, t.pool_ceiling_bytes, t.pool_expires_at
FROM tenants t WHERE t.status = 'active' AND (? = '' OR t.id = ?) ORDER BY t.id`), nowMs, tenantID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PoolUsage
	for rows.Next() {
		var u PoolUsage
		var rep, ceil, exp sql.NullInt64
		if err := rows.Scan(&u.TenantID, &u.UsedBytes, &rep, &ceil, &exp); err != nil {
			return nil, err
		}
		u.ReportedBytes, u.CeilingBytes, u.ExpiresAt = nullPtr(rep), nullPtr(ceil), nullPtr(exp)
		out = append(out, u)
	}
	return out, rows.Err()
}

func nullPtr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

// NextPoolSeq takes tenantID's next report sequence from the shared database, so it rises
// across replicas and lease handovers whatever their clocks say.
func (c *chatStore) NextPoolSeq(ctx context.Context, tenantID string) (int64, error) {
	var seq int64
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`UPDATE tenants SET pool_seq = pool_seq + 1 WHERE id = ? RETURNING pool_seq`), tenantID).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return seq, err
}

// SetPoolGrant stores KyIdentity's grant for the report with seq, unless a later report was
// numbered since (its answer, not this one, is current).
func (c *chatStore) SetPoolGrant(ctx context.Context, tenantID string, seq, reportedBytes, ceilingBytes, expiresAtMs int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET pool_reported_bytes = ?, pool_ceiling_bytes = ?, pool_expires_at = ?
WHERE id = ? AND pool_seq = ?`), reportedBytes, ceilingBytes, expiresAtMs, tenantID, seq)
	return err
}

// RaisePoolSeq moves tenantID's sequence up to seq (KyIdentity holds a higher one, as after a
// database restore), so the next report applies.
func (c *chatStore) RaisePoolSeq(ctx context.Context, tenantID string, seq int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET pool_seq = ? WHERE id = ? AND pool_seq < ?`), seq, tenantID, seq)
	return err
}
