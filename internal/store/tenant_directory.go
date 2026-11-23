package store

import (
	"context"
	"database/sql"
	"errors"
)

// TenantQuotas are per-app safety limits. Zero means use the install limit; the shared
// KyIdentity storage pool remains independent of these limits.
type TenantQuotas struct {
	MaxUploadBytes      int64
	MaxPendingUserBytes int64
}

// TenantDirectoryEntry is a narrowed, verified KyIdentity org snapshot, never an ID-token claim.
type TenantDirectoryEntry struct {
	TenantID string
	Revision int64
	Status   string
	Enabled  bool
	Valid    bool
	Quotas   TenantQuotas
}

// ApplyTenantDirectory commits enablement, safety limits and lifecycle together. The tenant
// row also fences grant issuance; the quota lock serializes an in-flight upload commit.
func (c *chatStore) ApplyTenantDirectory(ctx context.Context, e TenantDirectoryEntry) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := c.lockAttachmentQuotaTx(ctx, tx, e.TenantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET id = id WHERE id = ?`), e.TenantID); err != nil {
		return err
	}
	var status string
	var revision int64
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT status, lifecycle_revision FROM tenants WHERE id = ?`), e.TenantID).Scan(&status, &revision); err != nil {
		return err
	}
	if status == TenantStatusDeleted {
		return tx.Commit()
	}
	// Explicit deletion remains terminal even when delivered out of revision order.
	if e.Status != TenantStatusDeleted && e.Revision < revision {
		return tx.Commit()
	}
	var old TenantDirectoryEntry
	err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT revision, status, enabled, valid, max_upload_bytes, max_pending_user_bytes FROM tenant_directory WHERE tenant_id = ?`), e.TenantID).Scan(&old.Revision, &old.Status, &old.Enabled, &old.Valid, &old.Quotas.MaxUploadBytes, &old.Quotas.MaxPendingUserBytes)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && e.Status != TenantStatusDeleted {
		if e.Revision < old.Revision {
			return tx.Commit()
		}
		if e.Revision == old.Revision && (e.Status != old.Status || e.Enabled != old.Enabled || e.Valid != old.Valid || e.Quotas != old.Quotas) {
			return ErrInvalidInput
		}
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO tenant_directory (tenant_id, revision, status, enabled, valid, max_upload_bytes, max_pending_user_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT (tenant_id) DO UPDATE SET revision = excluded.revision, status = excluded.status, enabled = excluded.enabled, valid = excluded.valid, max_upload_bytes = excluded.max_upload_bytes, max_pending_user_bytes = excluded.max_pending_user_bytes`), e.TenantID, max(revision, e.Revision), e.Status, boolToInt(e.Enabled), boolToInt(e.Valid), e.Quotas.MaxUploadBytes, e.Quotas.MaxPendingUserBytes); err != nil {
		return err
	}
	effective := e.Status
	if !e.Enabled || !e.Valid {
		effective = TenantStatusSuspended
	}
	if e.Status == TenantStatusDeleted {
		effective = TenantStatusDeleted
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE tenants SET status = ?, lifecycle_revision = ?, missing_since = NULL WHERE id = ?`), effective, max(revision, e.Revision), e.TenantID); err != nil {
		return err
	}
	if effective != TenantStatusActive {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO tenant_pending_revocations (tenant_id) VALUES (?) ON CONFLICT (tenant_id) DO NOTHING`), e.TenantID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Directory readiness is consulted on the primary alongside lifecycle status, including by
// grant issuance. An org created from a token or a user webhook has no ready snapshot.
const directoryReadySQL = `EXISTS (SELECT 1 FROM tenant_directory d WHERE d.tenant_id = tenants.id AND d.status = 'active' AND d.enabled = 1 AND d.valid = 1 AND d.revision >= tenants.lifecycle_revision)`

func (c *chatStore) directoryQuotaTx(ctx context.Context, tx *sql.Tx, tenantID string, limits AttachmentQuotaLimits) (AttachmentQuotaLimits, error) {
	var q TenantQuotas
	err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT d.max_upload_bytes, d.max_pending_user_bytes FROM tenant_directory d JOIN tenants t ON t.id = d.tenant_id WHERE t.id = ? AND t.status = 'active' AND d.status = 'active' AND d.enabled = 1 AND d.valid = 1 AND d.revision >= t.lifecycle_revision AND NOT EXISTS (SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id = t.id)`), tenantID).Scan(&q.MaxUploadBytes, &q.MaxPendingUserBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return limits, ErrForbidden
	}
	if err != nil {
		return limits, err
	}
	if q.MaxUploadBytes > 0 && (limits.MaxUploadBytes == 0 || q.MaxUploadBytes < limits.MaxUploadBytes) {
		limits.MaxUploadBytes = q.MaxUploadBytes
	}
	if q.MaxPendingUserBytes > 0 && (limits.MaxPendingUserBytes == 0 || q.MaxPendingUserBytes < limits.MaxPendingUserBytes) {
		limits.MaxPendingUserBytes = q.MaxPendingUserBytes
	}
	return limits, nil
}
