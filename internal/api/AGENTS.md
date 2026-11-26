# API

## Purpose
Exposes HTTP REST routes, authentication endpoints, Single Sign-On callbacks, SCIM endpoints, backup restore drill handlers, and static React PWA hosting.

## Ownership
Owns HTTP routing, request parsing, session cookie validation, CORS headers, and error response formatting.

## Local Contracts
- Member-initiated permanent retained-version deletion requires the exact original uploader and fresh verified KyIdentity authentication. Attachment-delete/room/staff authority alone is insufficient; local login, a newly minted session or derived pairing cannot prove fresh KyIdentity sign-in. Keep this action inactive until its authorization and negative regressions exist. Signed erasure/org-purge workflows retain their required all-version/all-copy cleanup.
- Guest info, knock and authenticated guest routes handle a storage/lookup error before reading returned rows; generic failures return bounded JSON errors without a panic or database details.
- Shared guest admission follows the current invitation token hash on primary reads, independently of post-commit revocation events. Re-inviting the same guest key requires a fresh knock/admission; an old cookie or call socket cannot inherit it. Scheduled windows also fence media grants/reconciliation. This changes no single-mode guest route or host/moderator permission model.
- Hosted member calls use `/api/v1/rooms/{id}/calls/{state,join,leave,escalate,ws}`. Admitted guests use `/api/v1/rooms/{id}/calls/guest/{token}/{join,leave,ws}` with exact token/session/meeting/room binding; token-only guest call writes cannot bypass affinity. The edge must hash the same room ID for every HTTP/WS call route. Ordinary member/guest chat and lobby sockets stay separate. A multi-mode join supplies `call_ws_path`; guest info supplies `call_room_id`, omitted in single mode. HTTP departure reports pending SFU cleanup as 503; revoked in-flight joins return 401 without a grant. Hosted meeting closure atomically fences ownership, ends the call, retains SFU retirement, and deletes guest admissions before post-commit socket revocations; a failed SFU delete returns retryable 503 and cannot be acknowledged as complete. Closed room state reads return no call. See `room_call_routing_test.go` and the gated networking guide.
- Multi-mode erasure, tenant revocation and org purge drain durable SFU room retirement before acknowledging completion. An SFU failure after row deletion remains retryable and cannot produce a completion audit/terminal purge mark. The shared call-cleanup reconciliation tick is elected with `call_cleanup`; a failed room cannot starve unrelated cleanup batches. `call_cleanup_test.go` exercises a receiving replica without the departed owner's memory, failure/retry and exact-once completion.

- `NewServer` enables bounded call-notification chunking only for the multi-mode PostgreSQL bus; single-mode bus wire behavior stays unchanged. Room ownership is claimed only after exact principal/org/room authorization; wrong owners return retryable 503 `call_owner_unavailable`, with no replica address.

- After multi-mode erasure, a surviving shared-room successor immediately has owner permissions; cleanup failure/retry and duplicate deliveries retain that choice and other members' content. Only owned rooms with no remaining member disappear. `erasure_handover_test.go` exercises real signed deliveries, encrypted member messages, attachments and successor API access.

- An erased KyIdentity subject cannot be auto-provisioned by a later multi-mode sign-in; the database fence returns a generic 403 with no session. Erasure of an unknown subject creates the same permanent fence. Wrong-org erasure leaves the account and its grants unchanged.

- Multi-mode sign-in reads an existing authoritative org snapshot; tokens never admit/create a tenant. User routes, guest/call admission and grant issuance refuse an org without an active, enabled, valid directory snapshot. Uploads enforce per-org upload and staged-user limits; text/read/delete behavior does not depend on these byte limits. Admission tests explicitly seed directory snapshots for already-authorized org fixtures.

- `POST /api/sso/kyidentity/logout` is public and CSRF-exempt: its credential is the verified
  logout_token form field (64 KiB maximum, exactly one). Refused tokens/replays return 400;
  unavailable storage returns 503. Accepted logout publishes session-specific WS revocations
  across pods. Verified logouts for an unprovisioned subject retain an identity fence for
  the first callback; they do not create an account. Register this URI on the KyIdentity OAuth client.
- The SSO callback reads the database revocation generation before exchange and carries the
  verified IdP issuer/sid/iat into session issuance. Both device pairing steps inherit that binding.
- Installer directory events narrow canonical org_id in multi mode before calling the store;
  its transaction compares the subject/account binding before revision or authority changes.

- `GET /api/admin/network-check` (`requireAdmin`, `no-store`) reports how the request arrived: `peer_ip`, `client_ip`, `forwarded_trusted`, `forwarded_proto`, `app_url_https`, `host_matches`, `trusted_proxies_narrow` (true only when every `KY_TRUSTED_PROXIES` prefix is a single address, /32 or /128; false when empty). Admin-only because it describes the deployment's wiring. `forwarded_proto` is reported only when the direct peer is in `KY_TRUSTED_PROXIES`; otherwise forwarded headers are ignored and it is empty.
- POST `/api/auth/change-password` accepts a restricted local session, current password and a different policy-valid new password. Browser CSRF and per-IP/account limits apply. Success revokes all sessions and requires sign-in again; flagged sessions get `password_change_required` on protected routes and public-only settings.
- All JSON API endpoints return structured errors `{"error": "message"}` upon failure.
- `/api/auth/me` returns `Cache-Control: no-store` for both signed-in and anonymous
  responses so browser device setup never uses cached account status.
- Non-API routes fall back to serving `web.Handler()` for client-side SPA routing. Unmatched `/api/` paths answer a JSON 404 (`Unknown API endpoint`), never the SPA's 200, so a webhook sender on a retired or mistyped route retries instead of being falsely acknowledged (`TestUnknownAPIPathIsNotAcknowledged`). A wrong method on an `/api/` route also gets this 404 rather than 405.
- New routes are unauthenticated only by deliberate choice; privileged ones are registered wrapped in `s.requireAdmin` in `routes()`, so the trust level of every route is readable in one place.
- Deposit, export and drill return 413 for oversized snapshots through `writeTooLarge`, which
  names a `*backup.SizeError`'s size and member. Each sets its own write deadline
  (`depositWriteBudget`, `exportWriteBudget`, `drillWriteBudget`, each counting
  `backup.DumpTimeout`): the listener's 15s `WriteTimeout` is for JSON replies. All three
  routes are `tracked`; export audits after the download, with `outcome` `delivered` or
  `interrupted`, on a detached context.
- Backup capsule/status versions use `config.AppVersion`, shared with the CLI.
- Backup status includes the latest recorded `admin.backup_run` as `last_run`:
  outcome, trigger, recorded timestamp and capsule ID only. Classify the known audit
  prefix; legacy formats are unknown and partial destination/receipt failures are
  warnings. Keep raw audit/error details out of this DTO. A failed audit lookup is
  a visible `last_run_error`, not an invented success or empty history. This result
  is separate from the last successful remote receipt.
- Backup handlers seal the server capsule; `last_run` reads the `admin.backup_run` audit action. Status also carries `capsule_size`. A `*backup.SizeError` is a 413 naming size and member.
- Backup routes and theme writes are admin-only: capsules and settings carry site data and secrets. Export, pair-remote, deposit, unpair, pin-key and schedule use `requireFreshAdmin`: step-up is a sign-in from the last 10 minutes (`stepUpWindow`), which repeats the password, plus TOTP once the local admin has enabled it, or the suite login for SSO admins; older sessions get 403 `reauthentication_required` with one generic message ("Confirm it's you: ..."), shared by every step-up route. `Session.CreatedAt` is the credential time: a session minted by `pair/verify` inherits the initiating session's time via `IssueDerivedSession`, so pairing cannot refresh an old session. SSO sessions carry the ID token's signed `auth_time` (zero when missing, which never passes); a KyIdentity admin's refusal includes `reauth_url` `/api/sso/kyidentity/login?fresh=1`, which forces `prompt=login` and `max_age=0`. Drill and status stay `requireAdmin`. The pin is write-once, so a stolen session pinning its own key first would own every later capsule. Routes are registered with method patterns, and because the `/api/` catch-all answers any method, tests pin that a wrong method never reaches a backup handler rather than expecting 405.

| Method | Path | Handler | Response |
|---|---|---|---|
| POST | `/api/backup/drill` | `handleBackupDrill` | `recoveryclient.DrillResult`; 409 while `backup.Lock` is held |
| POST | `/api/backup/export-capsule` | `handleExportCapsule` | `.kycap` attachment; POST so the CSRF check covers it; 409 while `backup.Lock` is held |
| POST | `/api/backup/pair-remote` | `handlePairRemoteRecovery` | `{recovery_key_id, threshold, total_shares}` |
| POST | `/api/backup/deposit` | `handleRunBackup` | `recoveryclient.Result` (+`receipt_unrecorded`) |
| DELETE | `/api/backup/pairing` | `handleUnpair` | `{paired:false}`; URL and token rows only, key pin stays |
| POST | `/api/backup/pin-key` | `handlePinKey` | write-once; 409 on a different key |
| PUT | `/api/backup/schedule` | `handleSetSchedule` | `{interval_sec}` read back from the store |
| GET | `/api/backup/status` | `handleBackupStatus` | pairing, key, local copies, schedule, members, `database_driver`; never the token. `recovery_key_error` also names an unreadable pin and a `recovery.pub` left without its settings record. `scheduler_error` (string, absent when fine) is set when `backup.RunConfig` fails, which stops `cmd/server`'s scheduler for the process's life; the web renders it |

- `POST /api/backup/deposit` is one `recoveryclient.Run`: seal once, deliver to the local directory and to KyRecovery when paired. 412 no key, key pin missing, no destination, no database snapshot, or a private destination with `KY_BACKUP_ALLOW_PRIVATE_RECOVERY` off; 409 key mismatch or a run in flight (`backup.Lock` held by this or another process: scheduler, CLI deposit, export or drill; audited like any failure); 413 over the capsule caps; 502 when KyRecovery refused (`recoveryclient.ErrRemote`, naming a local copy that was written, so the `ErrPrivateDestination` arm must stay above it: the lib wraps both on the dial path); 500 for a failure before a byte left; 200 with `receipt_unrecorded` when the store holds the capsule but the receipt was not written. It runs on a context detached from the request with a 20-minute write deadline; the acting admin is resolved before the upload and the audit row is written on that same detached context.
- The write-once or irreversible backup handlers (`handlePairRemoteRecovery`, `handlePinKey`, `runBackup` behind both deposit routes, `handleUnpair`) run on `context.WithoutCancel(r.Context())` so a dropped connection cannot leave a pin, a pairing, a deposit or an unpair half-written with no audit row; `handleSetSchedule` stays on the request context. Every failure branch after input parsing is audited. Their routes are registered as `s.tracked(s.requireFreshAdmin(s.handleX))`, so the `detached` counter is incremented the moment `ServeHTTP` dispatches -- before `requireAdmin`'s session lookup, which is itself a store round-trip that `ReadTimeout` (15s) lets outlast `shutdownTimeout` (5s). Registering inside the handler was too late: `Shutdown` returns after its timeout with requests still active, and one still in the auth lookup would leave `WaitDetached()` reading zero and the store closing under a request about to pin a key. The header-read window before `ServeHTTP` is entered cannot be covered by any counter, because no handler goroutine exists yet; `Shutdown`'s own drain is what covers it. The counter is a mutex and a `sync.Cond`, not a `sync.WaitGroup`, which panics when an `Add` from zero races an in-progress `Wait` -- two admin requests at SIGTERM do exactly that. `WaitDetached()` is what `cmd/server` blocks on before closing the store, because `http.Server.Shutdown` returns without knowing these goroutines exist.
- Audit actions: `backup.paired`, `backup.pair_failed`, `admin.backup_run` (details start with `outcome="success|failure"`), `admin.backup_unpair`, `admin.backup_key_pin`, `admin.backup_schedule`, `admin.backup_export` (a downloaded capsule, resource the capsule ID), and from `cmd/server` `admin.backup_scheduler` (`outcome="failure"`, once when the scheduler stops at start). `AuditDetails` flattens the lib's details map into the bounded audit field with locally derived fields first and remote error text last; values are quoted and `=` is escaped before the final `AuditSafe` cut. `cmd/server` uses it for the scheduler and CLI rows. Details carry key or capsule IDs, digests and paths, never the token.
- Rate-limit keys for `login:`, `mfa:`, `pair:` and `password-change:` come from `auth.ClientIP` via `allowClientAttempt`, never from `RemoteAddr` or a raw header, so a limit is neither shared by everyone behind a proxy nor bypassable by forging `X-Forwarded-For`. IPv6 clients are keyed per /64. That map is capped and randomly evicts. In `KY_TENANCY_MODE=multi` both limiters count in the shared `attempt_counters` table instead (`attemptLimiter.shared`; keys stored as SHA-256, windows on the database clock), so every replica spends one budget; a database error refuses (`TestReplicasShareTheSignInBudget`). Multi mode also spends proof-of-work in `pow_spent` and keeps meeting guest sessions in `meeting_guest_sessions` (`chat.LobbyManager.UseShared`), so a guest knocks, is admitted and is recognised on any replica (`TestReplicasShareGuestSessions`). Single mode keeps all three in memory.
- Multi mode refuses a KyIdentity sign-in whose ID token carries `export_only: true` (the org is
  `deletion_scheduled`) with the suspended-org answer (403 "Organization is suspended or
  inactive"), provisions nothing, and audits `sso.export_only_refused` naming only the org
  (`TestExportOnlyTokenIsRefusedInMultiMode`). `eraseUser` serves `user.erased`: the account stops
  serving with its owned bots (their IDs are persisted before ownership records go) and loses its grants first, then it is disconnected, then blobs, then
  `store.EraseUser` (and the blobs it returns), then a last disconnect
  (`TestUserErasedDeletesThePersonsData`, `TestUserErasedRevokesAccessFirst`,
  `TestUserErasedAfterUserDeleted`). Multi-mode uploads commit only for an active uploader, and a
  multi-mode call join re-checks the account after its peer registers, leaving the call and
  answering 401 when it no longer serves (`TestCallJoinOverlappingErasureIsRefused`). The
  attachment sweep drains `pending_blob_deletes`, each entry on its own in a random sample, so one failing blob holds back nothing (`TestErasureQueuesStragglerBlobs`, `TestQueuedBlobDeletesAreIndependent`). In multi
  mode every replica drops a whole-user `auth.revoked` user's call seats (`Hub.SetUserRevokeHandler`),
  and call reconciliation removes member peers whose account no longer serves
  (`CallManager.SetUserCheck`, `TestUserRevocationDropsRemoteCallSeats`).
- `PurgeDeletedOrgs` is the leased `org_purge` job: per deleted org, attachment blobs then rows in
  batches of 200, re-checking the lease before each batch, then `store.PurgeTenantRows`, then
  `DeletePrefix` (which takes any blob an in-flight upload wrote), then `MarkTenantPurged`
  (`TestTenancySyncDeletedOrgIsPurged`). `SyncTenancy` is the leased
  `tenancy_sync` job (incremental, full once a day); `StartupTenancySync` runs before serving.
- The org storage pool (`pool.go`, multi mode, customer orgs only; the staff org and org-less
  operators are exempt). Uploads check KyIdentity's grant (`AttachmentQuotaLimits.Pool`), and
  `KY_ATTACHMENTS_MAX_TOTAL_BYTES` does not apply (startup warns when it is set). An upload with
  no usable grant reports its org once (`POST /api/suite/storage`, Basic suite client
  credentials, HTTPS issuer, no redirects; at most 6 such calls per org per minute) and looks
  again. The synchronous refresh and periodic reporter share bounded per-org database
  leases through the entire sequence/snapshot, remote exchange and grant application, so
  concurrent cold uploads cannot discard their only grant. Only synchronous single-org refresh waits for contention; periodic batches skip busy orgs and retry them next tick while renewing other orgs and continuing later batches. Different orgs remain independent;
  expiration, wrong-sequence replies and stale-restore fences still fail closed. Refusals: `413 {"code":"org_storage_full"}`, `503 {"code":"pool_unavailable"}`, never
  naming another app. Deletes, reads, text and calls never check the pool. `RefreshPool` is the
  leased `pool_report` job (every minute): absolute totals for each org whose usage changed, has
  used half its grant, or whose grant is missing or under 10 minutes from expiry.
- KyCalendar meetings (contract B, KyCalendar `docs/SUITE-INTEGRATIONS.md`): `PUT`/`DELETE /api/meetings/{id}` go through `verifySuite` on the `kycalendar` pair with event types `kycalendar.meeting.put`/`.close`, then strict `decodeSuiteBody`. The body's `id` must equal the path's (the path is unsigned), else 400 `bad_body`. The PUT organizer is `sub` + `issuer` resolved by `suiteUser` (404 `no_user` otherwise; it is always a member); `member_subs` resolve the same way under that issuer and org, and misses come back in `skipped_subs` (`meeting_contract_test.go`, which signs KyCalendar's own request bytes).
- Guest checks compare the session's tenant, meeting and guest key with the link's. Each org has its own meeting ID space (`meetings` keyed by `(tenant_id, id)`), so a `PUT /api/meetings/{id}` for an ID another org holds creates the caller's own meeting (`TestTwoOrgsShareAMeetingIDButNothingElse`).
- Per-account windows (`mfa-user:`, `password-change-user:`, `pair-init:`) use `allowAccountAttempt` with existing user IDs only, in a separate uncapped map that anonymous traffic cannot evict. Password login counts failures only, per 15 minutes: 10 per account and client (`login-fail:<user>:<client>`, in the capped client map) and 100 per account from anywhere (`login-fail-user:`, account map). Both are checked before the password is verified, so a locked-out caller learns nothing from a right password, and an attacker's guesses never lock the owner out from another address (`TestLoginLockoutIsPerClientAndCountsOnlyFailures`). Login resolves only local accounts and runs a dummy hash for unknown names.
- TOTP for the signed-in local admin (`totp_handlers.go`, all `requireFreshAdmin`, `no-store`): `POST /api/auth/totp/begin` stores a new AES-GCM-encrypted secret, not yet enabled (sign-in ignores it), and answers `{secret, otpauth_uri}`; 409 when already on. `POST /api/auth/totp/confirm` `{"code"}` spends one code from that secret, enables it with 10 fresh recovery codes (compare-and-swap on the secret), revokes every session, MFA challenge and pairing of the account, reissues the caller's session with its original credential time and answers `{totp_enabled, recovery_codes}`, the only time the codes are shown. `POST /api/auth/totp/disable` `{"code"}` takes a current code or an unused recovery code. Code attempts share the `mfa-user:` window; suite accounts get 409 (their second factor is KyIdentity's). Audited `auth.totp_enabled` / `auth.totp_disabled`. With TOTP on, password login only ever yields an MFA transaction, so step-up (a sign-in from the last 10 minutes) repeats password plus TOTP (`TestTOTPEnrolment`).
- KyIdentity sign-in routes (`/api/sso/kyidentity/login`, `/callback`) answer 404 while `KY_SSO_ENABLED=false`. The callback deletes its PKCE and nonce cookies, refuses accounts whose status is not `active` (403, audited `sso.login_refused`) and audits a session it issues as `sso.login`. Upstream error text (discovery, code exchange) is logged, never sent: the browser gets 502 "Suite sign-in is unavailable" or 401 "Suite sign-in failed; try again". There is no SAML or generic OIDC route.
- Auth cookie names come from `auth.CookieName`: `__Host-` prefixed (session, CSRF, `ky_pkce_<state>`, `ky_nonce_<state>`; all `Path=/`) when cookies are Secure and `KY_COOKIE_DOMAIN` is unset; the unprefixed names are then ignored (`TestSecureCookiesUseHostPrefix`).
- Login, MFA and `pair/verify` mint sessions without a CSRF token, so `ServeHTTP` requires `Content-Type: application/json` on them (415 otherwise): a cross-site form cannot send it without a preflight that foreign origins fail. PoW solutions are single-use.
- `pair/verify` accepts only the QR `secret`, bounds device fields, returns one error for every miss and audits `device.paired`.
- `POST /api/devices/pair/poll` (unauthenticated; CSRF applies when a session cookie is sent) takes the same secret as a strict JSON body `{"secret"}` (`decodeStrict`, 4 KiB) and answers only status, expiry and device name. The secret redeems a session, so it never travels in a URL: `GET` answers 405 with `Allow: POST` (an exception to the 404-for-wrong-method rule, so old clients fail loudly) and a query-string secret is ignored (`pair_poll_test.go`).
- `GET /api/admin/scim/users` (`scim_admin.go`, `requireAdmin`, `no-store`) answers `{enabled, token_set, users:[{id, username, display_name, email, status}]}`: the `sso_provider = 'scim'` rows read from the store (the console holds no SCIM bearer token), and whether `KY_SCIM_TOKEN` is set. The token is never in the reply (`scim_admin_test.go`).
- CORS permits only the exact configured `KY_APP_URL` origin and credentialed browser writes require matching CSRF cookie/header tokens.
- API request bodies are capped at 1 MiB and all responses receive baseline CSP, anti-framing, MIME-sniffing, and referrer-policy headers. HSTS (`includeSubDomains`, with secure cookies) is sent only when `r.Host` matches the `KY_APP_URL` host (`hostMatches`) so other hosts served alongside the app do not receive an unintended HSTS pin (`TestHSTSOnlyOnTheAppHost`).
- KyIdentity accounts are matched by subject only, never by username. The directory webhook answers 409 for `sso.ErrSyncUsernameConflict` (never 500, which KyIdentity fences). The sign-in callback auto-provisions only on `store.ErrNotFound`; a username another account holds is a JSON 409 naming it, audited `sso.login_conflict` (resource the username, details `subject="..."`), with no session and no change to that account (`TestSSOSignInRefusesUsernameHeldByLocalAccount`).
- Messages (`chat_handlers.go`, `e2ee_messages.go`): `POST /api/v1/rooms/{id}/messages` and `PATCH .../messages/{mid}` take `{body, encoding}`. A member's session (cookie or bearer) must send `e2ee_room_v1`; `plain_v1`, named or by default, is 400 `{"error","code":"e2ee_required"}`. Only a `kybot_` token (`isBotToken`: role `bot` and an `agent:` session) may send `plain_v1`, at most 16 KiB, until E4. An envelope must be exactly `{"alg":"megolm.v1","sender_key","device_id","session_id","ciphertext"}` (32-byte key, device-ID pattern, unpadded base64), at most 48 KiB; the server never opens the ciphertext. An edit stores the new encoding (`ChatStore.EditMessage`). Tests post envelopes with `testEnvelope`/`sealed` (`e2ee_envelope_helper_test.go`). The CSP's `script-src` is `'self' 'wasm-unsafe-eval'` and nothing else (`TestCSPLetsTheBrowserCompileWebAssemblyOnly`).
- Web Push (`push_handlers.go`, session-authenticated, `no-store`): `GET /api/v1/push/subscriptions` lists the caller's subscriptions and the VAPID public key; `POST` registers one (bots 403; endpoint and keys validated; changing owners requires the same subscription keys, otherwise a generic 400 `Invalid push subscription`; the store locks the active user then the caller's session (the logout order), so a revoked session gets 401; at most 20 per user, the least recently registered evicted); `DELETE` removes one by endpoint. `PUT /api/v1/rooms/{id}/notifications` sets the member's `notify_mode` (`all`, `mentions`, `mute`). `POST /api/auth/logout` takes an optional `{"push_endpoint"}` and deletes that subscription with the session. A message notification's text is always "New message" (`pushMessageBody`): never content, and `mentions` mode matches `@handles` only in bot plaintext. Message and call fan-out runs in `pushAsync`, off the request path and counted in `detached`; `WaitDetached` then closes the dispatcher, which can add up to 10s to shutdown.
- `Server.OnDirectoryChange(fn)` registers a callback run after each acknowledged KyIdentity directory webhook (never after a refused one); it must not block, as the sender is waiting.
- `GET /api/settings` tiers its payload: public fields for the login screen, `db_driver`/`scim_enabled` for any session, and `extra_settings` for admins only; KyRecovery tokens are omitted in both sealed and legacy plaintext forms, dropped by the `kyrecovery_token` key prefix rather than by literal key name. `extra_settings` never carries the keys in `notExtra` (`brand_logo`, served at `/app-icon.png`; `kyidentity_webhook_last`) or `installer.*` keys. `app_name` is the effective name (`brand_name`, else `KY_APP_NAME`; the default on a store error).
- Console routes (`health_handlers.go`, `audit_handlers.go`, `branding_handlers.go`, `agent_handlers.go`) are admin-only and `no-store`; the fresh ones are `requireFreshAdmin`, `tracked` and run on a detached context. `/api/admin/health` probes `kymessages`, `database`, and (when `KY_LIVEKIT_*` is configured) `livekit` in parallel. Audit `kind` is `auth|backup|branding|agents|scim`; a present but empty or unknown value is 400. `limit` is 1-100, `offset` non-negative. Audit kinds map to action prefixes: `auth` = `auth.`, `device.`, `sso.`; `backup` = `backup.`, `admin.backup_`, `restore.`; `branding` = `admin.brand_`; `agents` = `agent.`; `scim` = `scim.`. Rows with no user show actor `system`; `scim.*` rows show `scim` (their user ID is the provisioned user). Actor and target are clipped to 200 bytes of valid UTF-8 (`clip200`), outcome to 1024, details to 4096 and IP to 64 (`clipTo`). The audit view's outcome comes from `detailOutcome`, which trusts an outcome only when the whole details string is `key="quoted"` tokens separated by single spaces; older unquoted rows show none.

| Method | Path | Handler | Guard | Response |
|---|---|---|---|---|
| GET | `/api/admin/health` | `handleHealth` | admin | per-component status, version, error |
| GET | `/api/admin/audit?kind&offset&limit` | `handleAudit` | admin | `{records, total, offset, limit}`, newest first |
| GET | `/api/admin/branding` | `handleBranding` | admin | `{name, stored_name, default_name, logo}` |
| PUT | `/api/admin/branding/name` | `handleBrandName` | fresh | the branding view |
| PUT | `/api/admin/branding/logo` | `handleBrandLogo` | fresh | the branding view |
| DELETE | `/api/admin/branding/logo` | `handleBrandLogoReset` | fresh | the branding view |

- Branding (`branding_handlers.go`): `GET /api/admin/branding` (admin, `no-store`) answers `{name, stored_name, default_name, logo:{custom, sha256, size}}`. `PUT /api/admin/branding/name` (`{"name"}`, strict; blank resets to `KY_APP_NAME`; 400 when `branding.ValidateName` refuses), `PUT /api/admin/branding/logo` (raw body: 415 unless `image/png`, 413 over 1 MiB through the handler's own `MaxBytesReader`, 400 when `branding.NormalizePNG` refuses) and `DELETE /api/admin/branding/logo` are `requireFreshAdmin`, `tracked`, run on a detached 10 s context and answer the same view. Settings: `brand_name`, and `brand_logo` (base64 of the normalised PNG); both travel in the capsule. The effective name is display only: capsules, pairing, local copies and backup status keep `KY_APP_NAME` (`TestBrandNameNeverRenamesTheService`). Audit `admin.brand_name` (`outcome old new`, names clipped to 40 bytes) and `admin.brand_logo` (`outcome sha256 size`, or `outcome="reset"`), success and failure after authentication and input parsing; refusals are `refused: <reason>`, never the bytes. A malformed name body is not audited.
- Agents (`agent_handlers.go`): native chat bot/agent accounts in `store.Agents()`, scoped to the caller's tenant in multi-tenant mode. Create takes `{name, owner}` strictly: `name` matches `^agent-[a-z0-9-]{1,32}$`; `owner` is the ID of an active non-bot user in the same org. Tokens have the `kybot_` prefix; only the SHA-256 hash is stored. Create and rotate are the only replies with a plaintext token (`no-store`, with `agentskill.Config` blocks per runtime for `KY_APP_URL` and the owner's username); it is never stored, logged or audited. All changes are `tracked`, run detached (`agentTimeout`) and audit `agent.create|rotate|revoke|delete`. `ExpireIdleAgents` (hourly from `cmd/server`) revokes active tokens unused for 90 days (`agentIdle`) or whose owner is no longer active, auditing `agent.expire`.

| Method | Path | Handler | Guard | Response |
|---|---|---|---|---|
| GET | `/api/admin/agents` | `handleAgents` | admin | `{agents:[{id, user_id, username, display_name, owner:{id, username, display_name, status}, token_state, last_used_at, created_at}], owners:[...], idle_days}` |
| GET | `/api/admin/agents/skill` | `handleAgentSkill` | admin | the skill folder as `application/zip` |
| POST | `/api/admin/agents` | `handleAgentCreate` | fresh | `{agent, token, configs:{openclaw, hermes}}` |
| POST | `/api/admin/agents/{id}/rotate` | `handleAgentRotate` | fresh | as create |
| POST | `/api/admin/agents/{id}/revoke` | `handleAgentRevoke` | admin | `{outcome:"revoked"}` |
| DELETE | `/api/admin/agents/{id}` | `handleAgentDelete` | fresh | `{outcome:"deleted"}` |

- `GET /app-icon.png` (public) serves the stored logo as `image/png` with `Cache-Control: no-cache` and an `ETag` of the quoted SHA-256 (304 on `If-None-Match`, via `http.ServeContent`), else the embedded stamp, also `no-cache`, so a new logo or a reset shows on the next load.
- Private installer IPC validates the live snapshot and reports pending graceful activation;
  it is separate from public HTTP. Its transport answers any refusal with a generic 409, so
  `ApplyInstaller` logs the reason as `[INSTALLER] setup refused: ...`
  (`TestInstallerRefusalReasonIsLogged`); bundles carry file references, so no reason holds a secret. `GET /api/installer/network` deliberately exposes only
  `clientIp`, `proxyHeadersTrusted`, `scheme`, with `no-store`, using native peer trust.
- `POST /api/installer/directory` and the managed suite sync alias verify the protected
  HMAC credential before owned, revision-fenced authority updates.
- Installer ownership settings (`installer.*`) are omitted from `extra_settings`.
- `POST /api/v1/messages/state {ids}` (1–50) answers which messages the caller can still read (a member of the room, in their org), with `deleted` and `edited_at` and never the text; on-device search checks its hits with it. It reads the primary.
- End-to-end encryption key server (`e2ee_handlers.go`): `POST /api/v1/keys/upload` (strict body:
  self-signed device keys plus signed one-time and fallback keys; `409` when a device ID's keys
  change; answers `one_time_key_count` and `has_fallback_key`, false when none was uploaded yet or
  a restore retired it), `/keys/query`, `/keys/claim`, `DELETE /api/v1/keys/devices/{id}`, `PUT /api/v1/to-device`,
  `GET /api/v1/to-device?device_id=` (each mail carries `sender_keys`, the sender device's self-signed keys stored at send time, so mail from a device deleted since stays verifiable) and `POST /api/v1/to-device/ack {device_id, ids}`. Every
  route stays inside the caller's org; another org's device reads as no device. A sent message
  publishes a `to_device` WebSocket event to the recipient. These routes spend their own `e2ee:`
  budget (600 a minute), not chat writes.

- E3 identity routes (`e2ee_identity_handlers.go`, spec §9.1): `GET/PUT /api/v1/keys/master`,
  `PUT /api/v1/keys/pins`, `POST /api/v1/keys/devices/{id}/signature`, `GET/PUT/DELETE
  /api/v1/keys/backup` and `/api/v1/keys/pairings[/{id}[/join|/sealed|/consume]]`. Bodies are
  decoded strictly (`decodeIdentity`) and carry no secret field; every hybrid signature is
  verified for the caller's org and user before it is stored; versions are compare-and-swap
  (`409`); a reset (`expected_version` > 0) needs a session younger than `stepUpWindow`; `/keys/query` adds `tenant_id`, `master_keys` and current-version
  `master_signature`s. Pairings are one per user, 3 minutes (`E2EEPairingTTL`), started only by a
  cross-signed device, joined and sealed once, consumed once; another user's or org's reads as
  unknown. Same `e2ee:` budget.
- In multi mode, whole-user bus revocations remove call seats on every replica even without a chat socket; session-only revocations leave calls alone. Guest invite replacement, denial and revocation use the same bus path.

## Verification
- `go test -v ./internal/api/...` (`authz_test.go` pins the per-role exposure of every privileged route; `backup_test.go` the backup routes, on SQLite only because a run snapshots the database)
- `console_test.go` covers the console routes, the shared `staleAdmin` step-up helper and the audit outcome parser
- `scripts/smoke-test.sh` asserts the same boundaries against a running binary

## Child DOX Index
None.
