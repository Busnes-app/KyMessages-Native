# Blobs

## Purpose
Stores chat attachment bytes on local disk, outside the web root, for `internal/api`'s attachment routes.

## Ownership
Owns the on-disk blob directory (`KY_ATTACHMENTS_DIR`), blob key validation and the upload MIME decision. Quotas and staged/posted state live in `internal/store`; the encrypted backup mirror lives in `internal/backup`.

## Local Contracts
- `NewStore` creates the directory (0700) and proves it writable. `api.NewServer` records a failure (`BlobsError`; attachment routes answer 503 and bootstrap reports `available: false`), and `cmd/server` then fails startup.
- Keys are flat identifiers (`ValidKey`: no slashes or dots). Every access goes through `os.OpenRoot` on the store directory.
- `Put` enforces `1 <= size <= maxBytes`, computes SHA-256, writes to an `.upload-*` temp file and renames it into place (0600). `SweepStaleTemps` removes crashed temp files.
- The MIME type is sniffed, never taken from the client. PNG, JPEG, GIF and WebP must also decode as images; anything else, including HTML, SVG and XML, is `application/octet-stream`. `SafeServeMIME` is the download allowlist; `IsInlineSafeImage` (raster only, never SVG) is the only inline disposition.

## Verification
- `go test ./internal/blobs/ ./internal/api/ -run Attachment`

## Child DOX Index
None.
