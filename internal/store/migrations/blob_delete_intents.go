package migrations

// blobDeleteIntentsSchema lets the durable blob-delete queue hold an upload's intent: queued
// before its blob is written, due only after the upload's deadline, and removed by its commit.
const blobDeleteIntentsSchema = `
ALTER TABLE pending_blob_deletes ADD COLUMN not_before BIGINT NOT NULL DEFAULT 0;
`
