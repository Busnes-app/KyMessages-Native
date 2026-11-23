# Storage Layer

## Purpose
Provides the unified Database Abstraction Layer (DAL) supporting pluggable backends (SQLite zero-CGO default and PostgreSQL enterprise) with automated dialect-aware migrations.

## Ownership
Owns data models, store interfaces (`UserStore`, `SessionStore`, `DeviceStore`, `GroupStore`, `AuditStore`, `SettingsStore`, `AgentStore`), dialect translations, and schema migrations.

## Local Contracts
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
  delete sessions, MFA challenges, device pairings and push subscriptions, revoke active agent
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
  deletes one key per call, never the same key twice (`FOR UPDATE SKIP LOCKED` on PostgreSQL);
  while keys remain but are all locked by other claims it retries with a short backoff (2 s
  budget), and only with none left does it return the fallback key, without deleting it. `AddOneTimeKeys` enforces its cap
  after the insert inside the transaction, so a retried upload never trips it; on PostgreSQL it
  first locks the device row (`FOR UPDATE`) so concurrent uploads cannot both pass the cap. Mail has no
  cursor: `ToDevice` returns the oldest unacknowledged rows and `AckToDevice` deletes exactly the
  IDs named, because PostgreSQL IDs commit out of order. Only public keys and ciphertext are stored.
- `store.Open(ctx, cfg)` initializes and auto-migrates the configured database backend.
  `migrations.Run` refuses with `ErrNewerSchema` a database whose `schema_migrations` holds a
  version above this build's newest (image rollback, or a capsule from a newer build), before
  running anything. It takes only `sqlite` or `postgres`/`postgresql` and picks its placeholder
  from that.
- `GetAllSettings` returns any row scan error rather than omitting the row.
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
