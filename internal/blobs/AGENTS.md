# Blobs

## Purpose
Stores chat attachment bytes on local disk, outside the web root, for `internal/api`'s attachment routes.

## Ownership
Owns the on-disk blob directory (`KY_ATTACHMENTS_DIR`), blob key validation and the upload MIME decision. Quotas and staged/posted state live in `internal/store`; the encrypted backup mirror lives in `internal/backup`.

## Local Contracts
- `NewStore` creates the directory (0700) and proves it writable. `api.NewServer` records a failure (`BlobsError`; attachment routes answer 503 and bootstrap reports `available: false`), and `cmd/server` then fails startup.
- Keys are flat identifiers (`ValidKey`: no slashes or dots). Every access goes through `os.OpenRoot` on the store directory.
- `Backend` is what the API uses: `Put`, `Open` (an `io.ReadSeekCloser`, so downloads keep ranges), `Delete`, `DeletePrefix` and `SweepStaleTemps`, each naming the blob's org. `*Store` is the disk backend. `NewStore` (single mode) keeps every blob flat and ignores the org; `DeletePrefix` refuses there. `NewOrgStore` (multi mode) keeps each blob at `orgs/<tenant_id>/att/<key>` (org names `^[a-z0-9-]{1,64}$`), so `DeletePrefix` removes one org, orphans included.
- Org-layout reads and deletes fall back to the flat path until `RelocationDone`; `Relocate` moves one flat blob (an atomic rename on one volume, idempotent). The API's relocation runs inside the leased attachment sweep and records `blobs.layout = org` when it finishes.
- `EnsureStoreID` makes a multi-mode replica prove its directory is the shared volume: it creates `.store-id` once (written whole, then hard-linked into place) and compares it with the database's `blobs.store_id` (`SetSettingOnce`, the first replica's). A mismatch fails startup (`BlobsError`).
- `Put` enforces `1 <= size <= maxBytes`, computes SHA-256, writes to an `.upload-*` temp file and renames it into place (0600). `SweepStaleTemps` removes crashed temp files.
- The MIME type is sniffed, never taken from the client. PNG, JPEG, GIF and WebP must also decode as images; anything else, including HTML, SVG and XML, is `application/octet-stream`. `SafeServeMIME` is the download allowlist; `IsInlineSafeImage` (raster only, never SVG) is the only inline disposition.

## Verification
- `go test ./internal/blobs/ ./internal/api/ -run Attachment`

## Child DOX Index
None.
