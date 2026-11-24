package migrations

// Provenance and quota survive ordinary attachment/account deletion. There is
// deliberately no cascade to a live content/account row: remote cleanup must
// succeed before its independent retained-version inventory may be removed.
const retainedAttachmentVersionsSchema = `
CREATE TABLE retained_attachment_versions (
    tenant_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    blob_key TEXT NOT NULL,
    version_id TEXT NOT NULL CHECK (version_id <> '' AND version_id <> 'null'),
    uploader_id TEXT NOT NULL,
    uploader_provider TEXT NOT NULL,
    uploader_subject TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256_hex TEXT NOT NULL,
    retained_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, blob_key, version_id)
);
CREATE INDEX retained_attachment_versions_attachment ON retained_attachment_versions(tenant_id, attachment_id, version_id);
CREATE INDEX retained_attachment_versions_uploader ON retained_attachment_versions(tenant_id, uploader_id);
`
