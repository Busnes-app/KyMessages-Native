package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
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

// retainVersionsTx records the object-store version of each attachment row matched by
// where (over attachments a) before the caller deletes the rows, so the bucket's retained
// copy stays charged to the org and findable by erasure (§9.4). Disk rows have no version
// and retain nothing. Uploader provenance is a snapshot: it outlives the account row.
func (c *chatStore) retainVersionsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) error {
	_, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO retained_attachment_versions
 (tenant_id,attachment_id,blob_key,version_id,uploader_id,uploader_provider,uploader_subject,size_bytes,sha256_hex,retained_at)
 SELECT a.tenant_id,a.id,a.blob_key,a.version_id,a.uploader_id,COALESCE(u.sso_provider,''),COALESCE(u.sso_subject,''),a.size_bytes,a.sha256_hex,?
 FROM attachments a LEFT JOIN users u ON u.id=a.uploader_id
 WHERE a.version_id<>'' AND `+where+` ON CONFLICT DO NOTHING`), append([]any{time.Now().UnixMilli()}, args...)...)
	return err
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
