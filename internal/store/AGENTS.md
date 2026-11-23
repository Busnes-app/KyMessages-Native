# Storage Layer

## Purpose
Provides the unified Database Abstraction Layer (DAL) supporting pluggable backends (SQLite zero-CGO default and PostgreSQL enterprise) with automated dialect-aware migrations.

## Ownership
Owns data models, store interfaces (`UserStore`, `SessionStore`, `DeviceStore`, `GroupStore`, `AuditStore`, `SettingsStore`, `AgentStore`), dialect translations, and schema migrations.

## Local Contracts
- Web Push endpoint ownership changes require both stored subscription keys to match (decoded base64url); comparison and transfer commit in one transaction, with a PostgreSQL row lock. A mismatch returns `ErrInvalidInput` without changing the subscription. Same-owner registration may refresh keys.
- Migration 51 adds IdP issuer/sid/issuance/generation to sessions and device pairings, permanent
  `sso_logout_events` replay IDs and `sso_revocations` fences. Preserve existing sessions,
  pairings and push subscriptions on upgrade; the new binding columns default to unbound.
  Changing this upgrade policy requires owner approval. Push registrations retain the verified
  originating session's sid; a sid logout removes matching bound registrations atomically.
- `SSOGeneration` reads the primary before code exchange. `ApplySSOLogout` persists fences
  by verified issuer/subject/org even before local provisioning. It and grant issuance lock a
  shared `sso_identities` row before the user row. Existing accounts must match subject/org
  before the issuer/jti, fence and matching grant revocation commit together. Subject fences
  (`sso_subject_revocations`) survive account creation/deletion; credential reset fences remain
  keyed by local user ID. A sid targets that IdP session plus every unbound
  session of the verified subject/org; another subject or org is unaffected. Unbound pairings
  remain until subject logout/MFA reset, but cannot mint a session past a sid fence.
  A subject logout revokes every grant and push subscription. Issuance holds the same user row through its
  fence check. The shared generation orders in-flight callbacks independently of pod clocks.
- `ResetDirectoryMFA` spends each unseen reset independently of profile revision ordering,
  with a new credential snapshot, subject fence and grant/push deletion. `directory_mfa_resets`
  deduplicates reset revisions per directory restore generation (reset -1 uses the event ID).
  An accepted profile/deletion resend at revision -1 advances that generation atomically;
  global event IDs remain spent across generations. Delayed resets for a deletion tombstone
  are recorded and acknowledged without recreating the user. Managed MFA resets share the
  ledger and do not rewrite a profile or advance its revision. `ApplyInstallerDirectory` requires the narrowed org_id and
  compares it even on a duplicate before changing authority or accepting the event.

- `AuditStore.ListAuditRecords(offset, limit, prefixes...)` pages newest first by `id`; prefixes match the
  literal action start (`substr`, not LIKE) and the count covers only matching rows.
- `AuditStore.LatestAuditRecord(action)` reads the latest inserted row for one
  exact action, returning `ErrNotFound` when absent. Migration 13 indexes `(action,
  id)`; insertion order handles timestamp ties/backwards clocks without scanning
  unrelated activity. Backup status reads this append-only source, not a second
  shared last-result setting.
- `CompletePasswordChange` atomically compares the old password, updates a flagged local account, clears the flag, deletes sessions/MFA challenges/device pairings and records `auth.password_changed`. Session/MFA/pairing issuance locks the same user row against the verified hash and, for an org-bound account, the `tenants` row while it is active, so a suspension either refuses the grant or sweeps it; MFA challenges persist the creation-time password hash, and consumption returns that snapshot to reject stale completions. Migration 4 discards preexisting challenges because their credential snapshot is unknown.
- `ResetAdminPassword` reactivates a local administrator with the replacement flag set and shares the atomic grant purge and audit path with `CompletePasswordChange`; it also works for disabled accounts.
- `InvalidateRestoredGrants` runs only on an offline restored database: atomically
  delete sessions, MFA challenges, device pairings, push subscriptions and meeting guest
  sessions (a restored admission would readmit a removed guest), revoke active agent
  tokens, and audit `restore.grants_invalidated`. Users sign in again.
- Migrations 5–12 and 17–19 built the retired messaging stack; migration 21 drops its tables
  (children first), `messaging.*` audit rows and the three `messages_*` backup settings, and
  is idempotent. Migrations are append-only: keep their SQL.
- SQLite file-URI directory setup decodes the URI path; never create a literal
  `file:` directory. This permits read/write-only restoration of paths with reserved
  characters without accidentally opening a different database.
- `UpdateProfile` writes only username, email, display name, role and status. SCIM and the KyIdentity webhook use it so a stale read cannot revert a concurrent password change or recovery-code redemption. `ListUsers` filters by one exact `UserFilter` field, and by `sso_provider` when `UserFilter.Provider` is set.
- `DeleteUserSessions` deletes the user's sessions, MFA challenges and device pairings in one transaction (`deleteGrants`, shared with the password paths): a pending challenge or pairing would otherwise mint a session after a SCIM or directory revocation.
- TOTP enrolment: `SetPendingTOTP` writes the encrypted secret only on a local account with TOTP off; `EnableTOTP` turns it on only if the stored secret is still the one confirmed, stores the recovery-code digests and deletes every grant in the same transaction; `DisableTOTP` clears secret and codes. Each is `ErrNotFound` from any other state. No migration: the columns exist since v1.
- `CreateUser`, `CreateDirectoryUser` and `ApplyDirectoryProfile` check the username against every other row first (inside the directory transaction) and return `ErrUsernameTaken` (wraps `ErrAlreadyExists`) on both engines; a refused directory write rolls back with its event ID. A write that loses a race to a concurrent insert meets the UNIQUE constraint instead; `uniqueError` maps that engine error (SQLite `users.username`, Postgres `users_username_key`) to `ErrUsernameTaken` too, any other unique violation to `ErrAlreadyExists` (`unique_internal_test.go`).
- `GetLocalUserByUsername` returns only `sso_provider = 'local'` rows, preferring an exact-case match. Usernames are unique only case-sensitively, so password login and `init-admin` must never resolve an SSO row.
- Migrations 15 and 16 add `directory_sync_state` (provider, subject, last applied directory revision). It is deliberately not a users column: it outlives deletion as a tombstone. Migration 16 discarded earlier timestamp-based rows and added `directory_sync_events`, the permanent set of delivered directory event IDs per provider (applied or superseded). It grows by one row per directory change, which is small for the target team size. `ApplyDirectoryProfile`, `CreateDirectoryUser` and `DeleteDirectoryUser` advance it with a conditional upsert and write the user in the same transaction.
- `DirectoryStatuses(provider)` maps each subject to its user status, or `deleted` for a tombstone row with no user. Subjects are not unique: of several rows, a non-active status wins (fail closed). Owned dedicated administrators project as inactive without changing their console role or independent local operators.
- Migration 20 renames the stored suite provider `kysignon` to `kyidentity` in `users.sso_provider`, `directory_sync_state` and `directory_sync_events`; its SQL is idempotent.
- Migration 14 rebuilds `device_pairings` without the six-digit code column; pending pairings (90 s) are dropped on upgrade.
- Migration 24 replaces the legacy `agents` table with the native chat bot/agent registry (`AgentStore`): `user_id`, unique `username`, `owner_user_id`, SHA-256 `token_hash`, and `token_state` (`active` with a non-empty hash; `revoked` or `expired` with an empty hash, enforced on every write). It never stores a plaintext token. `SetAgentToken` and `DeleteAgent` answer `ErrNotFound` for no row.
- Migration 31 adds the end-to-end encryption key server (`E2EEStore`): `e2ee_devices`
  (identity keys never change; a different upload is `ErrE2EEKeyMismatch`), `e2ee_one_time_keys`
  keyed by `(user_id, device_id, fallback, key_id)` because vodozemac numbers one-time and
  fallback keys with separate counters, and the `e2ee_to_device` mailbox. `ClaimOneTimeKey`
  marks one key per call `claimed` (a tombstone, so a retried upload cannot republish it; the
  rows go with the device), never the same key twice (`FOR UPDATE SKIP LOCKED` on PostgreSQL);
  while keys remain but are all locked by other claims it retries with a short backoff (2 s
  budget), and only with none left does it return the live fallback key, without deleting it. A new fallback key retires the old one as a tombstone, so a stale retry cannot restore a retired fallback. `AddOneTimeKeys` enforces its cap
  after the insert inside the transaction, so a retried upload never trips it; on PostgreSQL it
  first locks the device row (`FOR UPDATE`) so concurrent uploads cannot both pass the cap. Mail has no
  cursor: `ToDevice` returns the oldest unacknowledged rows and `AckToDevice` deletes exactly the
  IDs named, because PostgreSQL IDs commit out of order. Only public keys and ciphertext are stored.
- `store.Open(ctx, cfg)` initializes and auto-migrates the configured database backend. On
  PostgreSQL `migrations.Run` holds `pg_advisory_lock(hashtext('kymessages:migrate'))` on one
  connection for the whole run and reads `schema_migrations` under it, so replicas starting
  together apply each migration once (`TestConcurrentRunsAllSucceed`). SQLite takes no lock.
- E2EE owns migrations 53–54 after merged webhook removal 52; tenancy starts at 55.
  Migration 55 adds `job_leases (name, holder, expires_at)`. `AcquireLease(name, holder, ttl)`
  is one conditional upsert that wins only when the lease is free, expired or already the
  holder's; it reads the database clock (Unix ms), never a replica's (`TestJobLeaseHandover`).
- Migration 56 rekeys `meetings` by `(tenant_id, id)`; `meeting_windows` and `meeting_guests`
  gain `tenant_id` and reference `meetings (tenant_id, id)`. It rebuilds and renames the three
  tables, one SQL for both engines (`TestMeetingsPerTenantKeyKeepsData`). Every meeting query
  matches `tenant_id`, and `UpsertMeeting` takes `pg_advisory_xact_lock` on the pair first.
- Migrations 42-43 add multi mode's shared state: `attempt_counters` (`BumpAttempt`,
  `AttemptState`), `pow_spent` (`SpendPoW`) and `meeting_guest_sessions`
  (`GuestSessions()`: keyed by the secret's SHA-256, one live session per tenant, meeting and
  guest key, 4 h expiry). `seen_at` is on the database clock: each replica `Touch`es the guests
  it holds sockets for every quarter of the leave grace, and a leave timer (`DeleteIfUnseen`) ends a
  session only when nobody touched it for the same window reads use, 1.25 × the grace
  (`TestSharedLobbyOverlappingSocketsAcrossReplicas`, `TestSharedLobbyPollingAfterDisconnect`).
  Departure does not depend on that timer: `BySecret`, `ByID`, `InRoom` and `Admit` accept a
  session only if `seen_at` is within `live` (the lobby passes 1.25 × the leave grace), so a
  replica that exits or a failed delete cannot keep an admission usable. Every authenticated
  guest request atomically validates and refreshes the session with `BySecret`, so a waiting guest who only polls stays listed
  (`TestSharedLobbyAdmissionLapsesWithoutAnyReplica`). The socket check for a guest connected to this replica refreshes the session before reading it, so a database outage longer than the window does not drop a connected guest (`TestSharedLobbyConnectedGuestSurvivesAnOutage`). `PruneShared` deletes rows nobody touched
  for 10 minutes. `PruneShared` deletes
  expired rows; the leased maintenance loop runs it in multi mode only.
  `migrations.Run` refuses with `ErrNewerSchema` a database whose `schema_migrations` holds a
  version above this build's newest (image rollback, or a capsule from a newer build), before
  running anything. It takes only `sqlite` or `postgres`/`postgresql` and picks its placeholder
  from that.
- `GetAllSettings` returns any row scan error rather than omitting the row. `SetSettingOnce` stores a value only when the key is unset and returns the stored one, so the first replica wins (`blobs.store_id`).
- Migration 59 adds the org storage pool to `tenants`: `pool_seq` (each report's sequence,
  `NextPoolReport`, which takes it and the usage snapshot in one transaction, so it rises across replicas and a later sequence never carries an older total), and KyIdentity's latest grant
  (`pool_ceiling_bytes`, `pool_expires_at` in Unix ms, `pool_reported_bytes`). `SetPoolGrant`
  applies only to the latest numbered report; a stale response records `pool_required_seq`, invalidates growth grants and pauses reports for that org. Only explicit offline operator reconciliation (`RaisePoolSeq`) releases it; the reporter never follows a newer writer automatically.
  With `AttachmentQuotaLimits.Pool`, `ReserveAttachmentQuota` and `CommitAttachmentWithQuota`
  check the org's usage plus the new bytes against the unexpired ceiling under the tenant lock:
  `ErrPoolFull`, or `ErrPoolUnavailable` with no grant or an expired one. Single mode never sets
  `Pool` and never reads the columns.
- `ErasureBlobs` and `EraseUser` (`erase.go`, multi mode `user.erased`) delete one person's data:
  account (sessions, MFA, presence and push cascade), pairings, reservations, reactions,
  memberships, owned bots and their accounts, staged and posted attachments, and every DM whose
  other members are all gone; their messages elsewhere become tombstones (`body`, `sender_name`
  emptied, `deleted_at` set, row kept). The caller first runs `DeactivateForErasure` (status
  `deleted`) and drops every grant, deletes the blobs `ErasureBlobs` lists, then `EraseUser`
  removes the rows and returns the blobs of attachment rows it deleted (an upload that committed
  meanwhile) for the caller to delete. Both are idempotent and need no account row. The audit row
  `sso.user_erased` names only `user:<id>`.
- Migration 60 adds `user_subjects (provider, subject, user_id, org_id)`: `DeleteDirectoryUser`
  and `EraseUser` record an org-bound account's mapping before its row goes, so an erasure after
  `user.deleted`, or a repeat, still finds the person's data (`ErasureTarget`). Single-mode
  accounts (no org) are never recorded.
- `AttachmentQuotaLimits.ActiveUploader` (multi mode) makes `CommitAttachmentWithQuota` refuse
  (`ErrForbidden`) an uploader whose account no longer serves.
- `PurgeOrphanAttachments` returns `BlobRef`s (tenant and key), and `AttachmentTenant` returns a blob key's org, because the multi-mode blob layout needs each blob's org.
- SQLite runs in WAL mode with foreign keys enabled.
- PostgreSQL queries are rebound dynamically from standard positional parameters.
- MFA challenges and device pairings are consumed with database state transitions that permit exactly one successful use.
- Recovery-code hash updates use optimistic concurrency so simultaneous redemption cannot reuse a code.

- Installer config, owned identities, authority changes, durable revision/digest fences and
  native SQL audit commit together. Common setup retains the full immutable envelope;
  checks and reruns do not write or reactivate revoked accounts.
- Directory offboarding and `user.mfa_reset` replace a managed row's `password_hash` (it holds
  no password) with a random value in the revoking transaction, so session, MFA-challenge and
  pairing creation fenced on an earlier snapshot fail. `CreatePairing` takes that snapshot too.
- Native user/settings writers cannot change installer-owned authority. Managed browser
  sessions require the exact retained issuer/subject/user/role binding. Directory deletion
  retains the row as `deleted`; it cannot be reactivated.

## Verification
- `go test -v ./internal/store/...`
- `migrations/migrations_test.go` builds a v16 database through the test-only
  `RunThrough` seam (`export_test.go`) and checks migrations 17, 19, 20 and 21 on both engines,
  and the newer-schema refusal through `Run` and `store.Open`.

## Child DOX Index
None.

- Shared leave timers rearm while a disconnected guest keeps polling. The eventual database delete emits one departure and evicts the call seat; deterministic scheduler callbacks cover polling beyond the first timer and later inactivity.
