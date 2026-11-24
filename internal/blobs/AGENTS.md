# Blobs

## Purpose
Owns attachment storage outside the web root: the active disk backend, shared ciphertext codec and gated object-storage adapters.

## Ownership
Owns the shared attachment ciphertext codec, the on-disk blob directory (`KY_ATTACHMENTS_DIR`), blob key validation and the upload MIME decision. Quotas and staged/posted state live in `internal/store`; the encrypted backup mirror lives in `internal/backup`.

## Local Contracts
- Private `sealedObjects` consumes the shared `ky-primitives/s3` client for bounded conditional ciphertext writes and exact-version verified reads. Each write stages in its own directory, preserves MIME/hash rules and authenticates the complete org/object key. Reads verify size, GCM and expected digest before exposing a private seekable file; close removes it. Missing version/ETag is uncertain receipt data, never a failed-write proof. This is not an active `Backend`: durable admission/operation/version fencing, accounting, replica erasure, cache ownership and runtime wiring remain required before hosted use.
- `Sealer` owns the existing mirror v1 encoding: 12-byte nonce, AES-256-GCM ciphertext/tag, authenticated with `kymessages-attachments/v1` plus NUL and the exact caller identity. The mirror uses its flat blob key; org-scoped object callers must bind the full org/object key. Only an authenticated complete blob may become readable. This codec does not select an object backend or enable hosted startup.
- `NewStore` creates the directory (0700) and proves it writable. `api.NewServer` records a failure (`BlobsError`; attachment routes answer 503 and bootstrap reports `available: false`), and `cmd/server` then fails startup.
- Keys are flat identifiers (`ValidKey`: no slashes or dots). Every access goes through `os.OpenRoot` on the store directory.
- `Backend` is what the API uses: `Put`, `Open` (an `io.ReadSeekCloser`, so downloads keep ranges), `Delete`, `DeletePrefix` and `SweepStaleTemps`, each naming the blob's org. `*Store` is the disk backend. `NewStore` (single mode) keeps every blob flat and ignores the org; `DeletePrefix` refuses there. `NewOrgStore` (multi mode) keeps each blob at `orgs/<tenant_id>/att/<key>` (org names `^[a-z0-9-]{1,64}$`), so `DeletePrefix` removes one org, orphans included.
- Org-layout reads and deletes always fall back to the flat path (a miss costs one extra open), to read legacy experimental files during internal migration tests; mixed-version multi-mode disk deployments are unsupported. `FlatKeys` lists the flat blobs (the directory's top level), and `Relocate` moves one (an atomic rename on one volume, idempotent; a source gone meanwhile is no error). The API relocates on every leased attachment sweep, by each flat key's attachment row; a file without a row is left alone.
- `EnsureStoreID` checks the org-layout disk fixture used by internal multi-mode tests: it creates `.store-id` once (written whole, then hard-linked into place) and compares it with the database's `blobs.store_id` (`SetSettingOnce`, the first replica's). A mismatch fails startup (`BlobsError`).
- `Put` enforces `1 <= size <= maxBytes`, computes SHA-256, writes to an `.upload-*` temp file and renames it into place (0600). `SweepStaleTemps` removes crashed temp files.
- The MIME type is sniffed, never taken from the client. PNG, JPEG, GIF and WebP must also decode as images; anything else, including HTML, SVG and XML, is `application/octet-stream`. `SafeServeMIME` is the download allowlist; `IsInlineSafeImage` (raster only, never SVG) is the only inline disposition.

## Verification
- `go test ./internal/blobs/ ./internal/api/ -run Attachment`

## Child DOX Index
None.
