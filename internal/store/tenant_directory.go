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
	// HomeRegion is the org's cell (KyIdentity home_region), fixed at provisioning.
	HomeRegion string
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
	err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT revision, status, enabled, valid, max_upload_bytes, max_pending_user_bytes, home_region FROM tenant_directory WHERE tenant_id = ?`), e.TenantID).Scan(&old.Revision, &old.Status, &old.Enabled, &old.Valid, &old.Quotas.MaxUploadBytes, &old.Quotas.MaxPendingUserBytes, &old.HomeRegion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && e.Status != TenantStatusDeleted {
		if e.Revision < old.Revision {
			return tx.Commit()
		}
		// home_region never changes (KyIdentity H2); a snapshot from before migration 67 has
		// none yet, and the next listing fills it in, even at the same revision.
		if old.HomeRegion != "" && e.HomeRegion != old.HomeRegion {
			return ErrInvalidInput
		}
		if e.Revision == old.Revision && (e.Status != old.Status || e.Enabled != old.Enabled || e.Valid != old.Valid || e.Quotas != old.Quotas) {
			return ErrInvalidInput
		}
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO tenant_directory (tenant_id, revision, status, enabled, valid, max_upload_bytes, max_pending_user_bytes, home_region) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT (tenant_id) DO UPDATE SET revision = excluded.revision, status = excluded.status, enabled = excluded.enabled, valid = excluded.valid, max_upload_bytes = excluded.max_upload_bytes, max_pending_user_bytes = excluded.max_pending_user_bytes, home_region = excluded.home_region`), e.TenantID, max(revision, e.Revision), e.Status, boolToInt(e.Enabled), boolToInt(e.Valid), e.Quotas.MaxUploadBytes, e.Quotas.MaxPendingUserBytes, e.HomeRegion); err != nil {
		return err
	}
	var served bool
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT EXISTS (SELECT 1 FROM tenant_directory d WHERE d.tenant_id = ? AND `+cellServedSQL+`)`), e.TenantID).Scan(&served); err != nil {
		return err
	}
	effective := e.Status
	if !e.Enabled || !e.Valid || !served {
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

// cellServedSQL holds when snapshot d's home region is a cell this deployment serves (C5),
// or d is the staff org, which every cell serves under its own fixed region. served_cells is
// empty only where no cells are configured (single mode, tests).
const cellServedSQL = `(d.home_region IN (SELECT cell FROM served_cells) OR NOT EXISTS (SELECT 1 FROM served_cells) OR d.tenant_id IN (SELECT value FROM server_settings WHERE key = '` + TenancyStaffOrgSettingKey + `'))`

// Directory readiness is consulted on the primary alongside lifecycle status, including by
// grant issuance. An org created from a token or a user webhook has no ready snapshot, and an
// org of another cell is never ready here.
func directoryReady(tenants string) string {
	return `EXISTS (SELECT 1 FROM tenant_directory d WHERE d.tenant_id = ` + tenants + `.id AND d.status = 'active' AND d.enabled = 1 AND d.valid = 1 AND d.revision >= ` + tenants + `.lifecycle_revision AND ` + cellServedSQL + `)`
}

var directoryReadySQL = directoryReady("tenants")

func (c *chatStore) directoryQuotaTx(ctx context.Context, tx *sql.Tx, tenantID string, limits AttachmentQuotaLimits) (AttachmentQuotaLimits, error) {
	var q TenantQuotas
	err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT d.max_upload_bytes, d.max_pending_user_bytes FROM tenant_directory d JOIN tenants t ON t.id = d.tenant_id WHERE t.id = ? AND t.status = 'active' AND d.status = 'active' AND d.enabled = 1 AND d.valid = 1 AND d.revision >= t.lifecycle_revision AND `+cellServedSQL+` AND NOT EXISTS (SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id = t.id)`), tenantID).Scan(&q.MaxUploadBytes, &q.MaxPendingUserBytes)
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

// SetServedCells replaces the cells this deployment serves (KY_CELLS), at every multi-mode
// start, before any request is served. Orgs of other cells stop being ready at once.
func (c *chatStore) SetServedCells(ctx context.Context, cells []string) error {
	if len(cells) == 0 {
		return ErrInvalidInput
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM served_cells`); err != nil {
		return err
	}
	for _, cell := range cells {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO served_cells (cell) VALUES (?)`), cell); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TenantHomeRegion is the org's cell from its directory snapshot; ErrNotFound before one.
func (c *chatStore) TenantHomeRegion(ctx context.Context, tenantID string) (string, error) {
	var cell string
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`SELECT home_region FROM tenant_directory WHERE tenant_id = ?`), tenantID).Scan(&cell)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && cell == "") {
		return "", ErrNotFound
	}
	return cell, err
}
