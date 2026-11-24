package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
)

var ErrObjectCleanupPending = errors.New("attachment object cleanup pending")

// RetainedAttachmentVersion is durable provenance for an ordinary deletion,
// independent of the live attachment/user rows. This is internal workflow data,
// not a member-facing DTO or authorization grant.
type RetainedAttachmentVersion struct {
	TenantID, AttachmentID, BlobKey, VersionID    string
	UploaderID, UploaderProvider, UploaderSubject string
	SizeBytes                                     int64
	SHA256Hex                                     string
	RetainedAt                                    int64
}

// DeleteAttachmentRetainingVersion atomically replaces the live quota charge
// with a retained one. A future S3 coordinator must supply the exact DATA version
// receipt after fencing its remote delete; a delete-marker ID is not that receipt.
// No current HTTP route calls this method. It never permanently deletes data.
func (c *chatStore) DeleteAttachmentRetainingVersion(ctx context.Context, tenantID, attachmentID, versionID string) error {
	if !config.IsCanonicalUUID(tenantID) || attachmentID == "" || versionID == "" || versionID == "null" {
		return ErrInvalidInput
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return err
	}
	// Replays after live-row deletion retain the original receipt. A new
	// receipt needs live provenance; this method never guesses it after deletion.
	var exists int
	err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT 1 FROM retained_attachment_versions WHERE tenant_id=? AND attachment_id=? AND version_id=?`), tenantID, attachmentID, versionID).Scan(&exists)
	if err == nil {
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	q := `SELECT a.blob_key,a.uploader_id,u.sso_provider,u.sso_subject,a.size_bytes,a.sha256_hex
 FROM attachments a JOIN users u ON u.id=a.uploader_id
 WHERE a.tenant_id=? AND a.id=? AND (u.org_id=? OR (u.org_id='' AND u.sso_provider='bot'))`
	if c.store.driver == "postgres" {
		q += ` FOR UPDATE OF a,u`
	}
	var v RetainedAttachmentVersion
	err = tx.QueryRowContext(ctx, c.store.rebind(q), tenantID, attachmentID, tenantID).Scan(&v.BlobKey, &v.UploaderID, &v.UploaderProvider, &v.UploaderSubject, &v.SizeBytes, &v.SHA256Hex)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, c.store.rebind(`INSERT INTO retained_attachment_versions
 (tenant_id,attachment_id,blob_key,version_id,uploader_id,uploader_provider,uploader_subject,size_bytes,sha256_hex,retained_at)
 VALUES (?,?,?,?,?,?,?,?,?,?)`), tenantID, attachmentID, v.BlobKey, versionID, v.UploaderID, v.UploaderProvider, v.UploaderSubject, v.SizeBytes, v.SHA256Hex, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, c.store.rebind(`DELETE FROM attachments WHERE tenant_id=? AND id=?`), tenantID, attachmentID); err != nil {
		return err
	}
	return tx.Commit()
}

// RetainedAttachmentVersions is an org-scoped workflow inventory. The API must
// separately bind any future member action to its verified uploader and fresh
// KyIdentity authentication; listing here does not confer deletion authority.
func (c *chatStore) RetainedAttachmentVersions(ctx context.Context, tenantID, uploaderID string) ([]RetainedAttachmentVersion, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT tenant_id,attachment_id,blob_key,version_id,uploader_id,uploader_provider,uploader_subject,size_bytes,sha256_hex,retained_at
 FROM retained_attachment_versions WHERE tenant_id=? AND uploader_id=? ORDER BY attachment_id`), tenantID, uploaderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetainedAttachmentVersion
	for rows.Next() {
		var v RetainedAttachmentVersion
		if err := rows.Scan(&v.TenantID, &v.AttachmentID, &v.BlobKey, &v.VersionID, &v.UploaderID, &v.UploaderProvider, &v.UploaderSubject, &v.SizeBytes, &v.SHA256Hex, &v.RetainedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (c *chatStore) requireNoRetainedVersionsTx(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var count int
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT COUNT(*) FROM retained_attachment_versions WHERE tenant_id=?`), tenantID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrObjectCleanupPending
	}
	return nil
}
