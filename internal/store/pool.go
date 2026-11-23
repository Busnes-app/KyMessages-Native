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

// NextPoolReport takes tenantID's next report sequence from the shared database (so it rises
// across replicas and lease handovers, whatever their clocks say) and the usage that report
// carries, in one transaction. The sequence update holds the tenant row until commit, so a
// later sequence always reads a later snapshot: KyIdentity, which keeps the highest sequence,
// never keeps an older total.
func (c *chatStore) NextPoolReport(ctx context.Context, tenantID string) (seq, used int64, err error) {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var required int64
	err = tx.QueryRowContext(ctx, c.store.rebind(`UPDATE tenants SET pool_seq = CASE WHEN pool_required_seq = 0 THEN pool_seq + 1 ELSE pool_seq END WHERE id = ? RETURNING pool_seq, pool_required_seq`), tenantID).Scan(&seq, &required)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err == nil && required != 0 {
		return 0, 0, ErrPoolUnavailable
	}
	if err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT
	COALESCE((SELECT SUM(size_bytes) FROM attachments WHERE tenant_id = ?), 0) +
	COALESCE((SELECT SUM(reserved_bytes) FROM attachment_upload_reservations WHERE tenant_id = ? AND expires_at > ?), 0)`),
		tenantID, tenantID, nowMilli()).Scan(&used); err != nil {
		return 0, 0, err
	}
	return seq, used, tx.Commit()
}

// SetPoolGrant stores KyIdentity's grant for the report with seq, unless a later report was
// numbered since (its answer, not this one, is current).
func (c *chatStore) SetPoolGrant(ctx context.Context, tenantID string, seq, reportedBytes, ceilingBytes, expiresAtMs int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET pool_reported_bytes = ?, pool_ceiling_bytes = ?, pool_expires_at = ?
WHERE id = ? AND pool_seq = ? AND pool_required_seq = 0`), reportedBytes, ceilingBytes, expiresAtMs, tenantID, seq)
	return err
}

// RecordStalePoolReport fences growth after sequence rewind without following the newer writer.
func (c *chatStore) RecordStalePoolReport(ctx context.Context, tenantID string, sentSeq, heldSeq int64) error {
	if heldSeq < sentSeq {
		return ErrInvalidInput
	}
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET pool_required_seq = ?, pool_ceiling_bytes = NULL, pool_expires_at = NULL WHERE id = ? AND pool_seq = ?`), heldSeq, tenantID, sentSeq)
	return err
}

// RaisePoolSeq is an explicit offline operator reconciliation, never an automatic reporter action.
func (c *chatStore) RaisePoolSeq(ctx context.Context, tenantID string, seq int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET pool_seq = CASE WHEN pool_seq < ? THEN ? ELSE pool_seq END, pool_required_seq = 0 WHERE id = ? AND pool_required_seq <= ?`), seq, seq, tenantID, seq)
	return err
}
