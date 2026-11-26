# Push

## Purpose
Sends Web Push notifications (RFC 8030/8291/8292) for new messages and incoming calls, without a third-party SDK.

## Ownership
Owns VAPID key handling (`vapid.go`), payload encryption (`crypto.go`, aes128gcm), endpoint validation and the bounded delivery pool (`sender.go`). Subscriptions are stored by `internal/store` (`push_subscriptions`); who gets a push is decided in `internal/api/push_handlers.go`.

## Local Contracts
- `LoadOrCreateVAPIDKey` reads `<KY_DATA_DIR>/vapid.key` or creates it once: a synced temp file hard-linked into place, so a crash or a concurrent first start never leaves a partial key. `KY_VAPID_PRIVATE_KEY` overrides the file. The key is in the backup capsule, so restored subscriptions keep working (restore still deletes them; browsers register again).
- `ValidateEndpoint` takes HTTPS on port 443 only and refuses loopback, private, link-local and other non-public addresses, at validation and again at dial time; redirects are never followed.
- `Dispatcher` runs 4 workers over a 256-job queue. `Enqueue` never blocks and returns false when full (callers log drops). `Close` stops intake, lets queued jobs deliver for up to `sendTimeout` (10s), then cancels. A 404/410 calls `onGone`, which deletes the subscription.
- Payloads carry the room, sender and a short preview; encrypted messages are never previewed. Calls use urgency `high` and a 60s TTL.

## Verification
- `go test ./internal/push/ ./internal/api/ -run 'Push|VAPID|Dispatcher|Mention|Logout|PQTLS'`

## Child DOX Index
None.
