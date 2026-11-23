# Tenancy: every paid plan an org on a shared, multi-server install (KyMessages-Native)

Date: 2026-11-23. Status: proposed design, docs only. Nothing here is built unless it says
"built". It extends `2026-11-22-tenancy-design.md` (called **K22** here) for the owner decisions
of 2026-11-22 and 2026-11-23. Where the two disagree, this spec wins. K22 §4 (the suite-peer
`org_id` wire contract) and §6.2 (multi-region cells) stay authoritative and are not repeated.

Sources:
- KyIdentity `docs/superpowers/specs/2026-11-19-tenancy-design.md` on `origin/master` (**T**).
- KyCalendar `docs/superpowers/specs/2026-11-20-tenancy-design.md` on `origin/main`, and its
  2026-11-23 amendment in KyCalendar PR #190 (D14, the org storage pool).
- KyNotes-server PR #176 (N8, N10, N15: object storage and the pool), so the apps read the pool
  and use object storage the same way.
- This repo's E2EE design, `2026-11-22-e2ee-design.md` (**E**).

Every `file:line` below was checked against `Busnes-app/KyMessages-Native` `origin/main` at
`126a190`. Anything not checked there says "unverified".

---

## 1. Owner decisions (fixed, not reopened)

1. One binary. `KY_TENANCY_MODE=single` (self-hosted, and Enterprise) is unchanged, byte for
   byte, on upgrade.
2. Orgs live under one KyIdentity issuer, and each account belongs to one org.
3. Only staff are administrators; customers are members, in every plan.
4. Stripe lives only in a separate billing service. KyMessages never sees a plan.
5. **Every paid account is an org** (2026-11-23): Personal (1 member), Couple (2), Family (up
   to 6) and Business (N seats). All four run on the **shared, multi-tenant, multi-server**
   install. Only Enterprise gets a dedicated install (cloud or on-prem), where single-tenant
   SQLite is fine. This supersedes every line that says businesses get their own install.
6. KyMessages is in the hosted launch and is sold in every plan.
7. **Multi-tenant needs multi-server** (2026-11-22). Multi mode runs as several replicas
   across hosts.
8. **Object storage** (2026-11-23). On the hosted install, primary content (for KyMessages:
   attachments) goes in S3-compatible object storage only. There is no disk-volume fallback
   for multi mode: launch waits for the object backend. Single-tenant keeps its existing
   disk path unchanged. Credentials never go in a log or in this spec.
9. **One storage pool per org, across all apps, required for launch** (2026-11-23). Personal
   20 GB, Couple 40 GB, Family 100 GB, Business 30 GB per seat (pooled), Enterprise custom.
   KyIdentity holds the pool. Each app checks it before a write that adds bytes and reports its
   usage. Today's per-upload and per-user caps may stay as safety limits.
10. Rooms and calls are end-to-end encrypted (E, merged in #25). Nothing here weakens that.

## 2. Summary

PR #18 built org isolation. PR #23 built the suite contract and the shared replay ledger. An
audit (PR #27, open) found that one hub bug leaked user-targeted call events to the whole room,
and that every user path is otherwise org-scoped. That audit's table is §6.

What is left for a shared, multi-server launch:

1. **Lifecycle gaps** (§7): KyMessages ignores T's `export_only` claim and `user.erased`, and
   `org.deleted` only flips a status, so no customer data is ever purged.
2. **Replica safety** (§8): migrations take no lock, every replica runs every background job,
   and sign-in limits, the proof-of-work ledger, meeting guests and calls live in one process.
3. **Attachments in object storage** (§9), behind one interface with today's disk store.
4. **The org storage pool** (§10): count, report and check, as KyCalendar D14 and KyNotes N10
   do.

## 3. Decisions this spec makes

| # | Decision | Why |
|---|---|---|
| M1 | KyMessages stays plan-blind. It never reads a plan, an org kind or a seat count. `tenants.plan` (default `'business'`, `internal/store/migrations/chat.go:11`) stays an inert column, and no rule reads it. | Decision 4. KyIdentity enforces seats (T "Entitlements"). Personal, Couple, Family and Business differ only in KyIdentity's numbers. |
| M2 | Multi mode needs PostgreSQL. It is already enforced at startup (`internal/config/config.go:313-316`). | SQLite is one writer on one host, and decision 7 needs several. |
| M3 | Every background job in multi mode runs under a PostgreSQL lease, so one replica runs it. Migrations run under one advisory lock. | §8. |
| M4 | Every limit or ledger that must hold across replicas lives in PostgreSQL. No Redis or other new service. | The shared database and its `LISTEN/NOTIFY` bus (`internal/chat/pgbus.go:16`, `:139`) already exist. |
| M5 | Attachments go behind one `blobs` interface with two backends, `disk` (today's code) and `s3`. Single-tenant always uses `disk`; hosted multi mode requires `s3`. | Decision 8. |
| M6 | The S3 client comes from ky-primitives, so KyMessages adds no dependency. | It is the same request KyNotes makes (PR #176 open question 1). One signed-request implementation in the suite, not one per app. |
| M7 | The org's storage figure is its attachment bytes (§10). Message text is not counted. | Text is small and bounded per message. Refusing text when the pool is full would break chat for a full KyDrive. Open question 1. |
| M8 | Over the pool, KyMessages refuses only a new attachment upload. Reading, downloading, deleting, sending text and calls keep working. | A full pool must never lock anyone out of their messages. |
| M9 | A token carrying `export_only: true` is refused at sign-in, the same way as a suspended org. | KyMessages has no export route yet, and under E2EE the server holds only ciphertext. Admitting the token would give full access during `deletion_scheduled`. Open question 3. |

## 4. Current state, verified

### Built

- **Mode lock and org binding** (PR #18): `EnsureTenancyMode` locks `tenancy.mode`
  (`cmd/server/main.go:107`). Multi mode requires `org_id` in the ID token
  (`internal/api/sso_handlers.go:92-96`) and refuses a cross-org rebind
  (`internal/api/sso_handlers.go:145-146`).
- **Staff-only admin.** `KY_STAFF_ORG_ID` must be a canonical UUID in multi mode, and SCIM is
  forced off (`internal/config/config.go:317-320`).
- **Org lifecycle.** `org.suspended`, `org.resumed` and the old name `org.unsuspended` are all
  handled (`internal/sso/kyidentity.go:213`, `:276-281`), in revision order
  (`internal/store/chat.go:188-200`). PR #27 adds a test for `org.resumed`. Keep
  `org.unsuspended` until KyIdentity confirms it never sends that name.
- **Org-scoped data.** Rooms, members, messages, attachments, meetings, call sessions, room
  webhooks, push subscriptions and upload reservations carry `tenant_id` (§5).
- **The bus.** Sixteen `LISTEN/NOTIFY` shards for rooms, plus a user bus
  (`internal/chat/pgbus.go:16`, `:139`). Optional read replica `KY_DB_READ_REPLICA_DSN`
  (`internal/config/config.go:349`).
- **The suite replay ledger** `suite_replay_events` in the shared database, pruned every minute
  (`cmd/server/maintenance.go:13-25`).
- **A per-org attachment cap.** Admission holds a PostgreSQL advisory lock per tenant
  (`internal/store/chat.go:1316-1327`) and counts posted, staged and reserved bytes
  (`:1329`). The cap is one install-wide value applied per tenant,
  `KY_ATTACHMENTS_MAX_TOTAL_BYTES` (default 1 GiB, `internal/config/config.go:97-98`), with a
  25 MiB upload limit (`:91-92`) and a per-user staging cap.

### The survey, checked

| Survey item | Verdict | Evidence |
|---|---|---|
| PostgreSQL is selectable but not supported | **Partly wrong.** CI runs the whole race suite on PostgreSQL 17.6 (`.github/workflows/ci.yml:79-105`), and multi mode requires it. What is missing is the operations around it: backups and the migration lock (the next two rows). | `internal/config/config.go:240-248`, `:313-316` |
| Backups are SQLite only | **True.** The capsule refuses any other driver (`internal/backup/payload.go:42-43`). `docs/RESTORE.md:32-35` tells PostgreSQL operators to use `pg_dump` and WAL archiving. | §8.4 |
| Migrations take no lock | **True.** `migrations.Run` checks and applies each version in its own transaction, with no advisory lock (`internal/store/migrations/migrations.go:397-480`). Two replicas starting together both see version N missing. One fails on the `schema_migrations` key, or on DDL that is not idempotent, and stops. | §8.1 |
| Guest codes live in memory | **True.** Meeting guest sessions, including the session secret a guest presents, live only in `LobbyManager` maps (`internal/chat/meetings.go:59-63`, `:171`). A guest whose next request reaches another replica is unknown there. | §8.3 |
| The proof-of-work spent-challenge cache is in memory | **True.** `PoWSpender.spent` (`internal/auth/pow.go:75-79`). One solved challenge buys one login per replica until it expires. | §8.2 |
| Sign-in limits are in memory | **True.** `attemptLimiter` (`internal/api/server.go:148-153`, built at `:246-247`, used at `internal/api/auth_handlers.go:103-104`). The suite's hourly budgets use the same limiter (`internal/api/suite.go:397`). N replicas give an attacker N times the budget. | §8.2 |
| The office-network allowlist doesn't refresh on other replicas | **Does not apply.** KyMessages-Native has no office-network allowlist. A search of `internal/`, `cmd/` and `web/src/` finds none. The only network list is `KY_TRUSTED_PROXIES`, read from the environment at start (`internal/config/config.go:167`), so every replica reads the same value. | — |
| Meeting changes lock in-process only | **Worse: there is no lock.** `UpsertMeeting` reads, then inserts or updates, inside a plain transaction (`internal/store/chat_rtc.go:140-175`). On PostgreSQL's default isolation, two concurrent `PUT`s for a new meeting both insert. One fails on the key and returns 500, and two concurrent updates both apply, so the last one wins. `meetings.id` is a global key, not `(tenant_id, id)` (`internal/store/migrations/chat.go:95-96`). | §8.3 |
| Background jobs have no lease | **True.** Every replica starts the backup scheduler, agent expiry, attachment sweep and maintenance loops (`cmd/server/main.go:116-133`). They are idempotent deletes today, so the harm is duplicated work, duplicated audit rows and backup runs, not lost data. | §8.1 |
| Directory sync (not in the survey) | **Safe across replicas.** `syncMu` serialises in-process (`internal/sso/kyidentity.go:34`, `:228`), and ordering is a conditional upsert in the write transaction (`internal/store/sqlstore.go:369-371`). | — |
| Calls (not in the survey) | **In memory.** `CallManager` holds calls and seats per process (`internal/chat/calls.go:92-101`). Both peers must reach the same replica. | §8.3 |
| `KY_ATTACHMENTS_S3_*` | **Planned only.** It appears only in K22 §6.1 and §8. No code reads it. Blobs are files under `KY_ATTACHMENTS_DIR` (`internal/config/config.go:389`), behind the concrete `blobs.Store` (`internal/blobs/store.go:44-50`). | §9 |

## 5. Store inventory

Tables after every migration on `origin/main`. **T** means the table has `tenant_id` (or
`users.org_id`). **P** means it is install-wide on purpose. **U** means it is reached only
through an org-bound user or row.

| Table | Scope | Notes |
|---|---|---|
| `tenants` | P | One row per org, plus `default` (`internal/store/migrations/chat.go:7-21`). §10 adds the pool columns. |
| `users` | T (`org_id`, added in `migrations.go:270-276`) | Immutable `(sub, org_id)` binding. |
| `sessions`, `mfa_challenges`, `device_pairings` | U | Revoked with the user. |
| `groups`, `group_members` | P | SCIM only, and SCIM is off in multi mode (`internal/config/config.go:320`). |
| `audit_records` | P | Install-wide, staff only. Usernames from every org are visible to staff (open question 6). |
| `server_settings` | P | Holds `tenancy.mode`. |
| `suite_replay_events` | P | Event IDs are unique per sender. |
| `directory_sync_state`, `directory_sync_events` | P | Keyed by provider and subject. |
| `agents` (native bots) | U (`owner_user_id`) | Scoped through the owner's org (PR #27 audit). |
| `rooms`, `room_members`, `messages`, `attachments`, `call_sessions`, `room_webhooks` | T | `internal/store/migrations/chat.go:23-151` |
| `message_reactions`, `meeting_windows`, `meeting_guests` | U | Reached through a T row. |
| `meetings` | T | Global key on `id` (§8.3). |
| `push_subscriptions`, `attachment_upload_reservations` | T | `migrations.go:297`, `:315` |
| Postgres full-text index on `messages` | T | Over `plain_v1` rows only (`chat.go:154`). Under E it never indexes ciphertext. |

State outside the database:

| State | Where | Multi-server target |
|---|---|---|
| Attachment blobs | `KY_ATTACHMENTS_DIR` | S3 only (§9); no multi-mode disk fallback |
| Attachment backup mirror | `<KY_BACKUP_DIR>/attachments` (`internal/backup/AGENTS.md`) | Off in multi mode. The bucket's own versioned copy is the backup (§9.4). |
| Encryption key (TOTP secrets) | `KY_ENCRYPTION_KEY`, else `data/encryption.key`, **created when missing** (`internal/config/config.go:259-267`) | Multi mode requires `KY_ENCRYPTION_KEY` or a shared file, and refuses to create one |
| Session secret (signs PoW challenges) | `KY_SESSION_SECRET`, required only when `env=production`, else **random per process** (`internal/config/config.go:251-257`) | Multi mode requires it, so a challenge from one replica verifies on another |
| S3 seal key | `KY_ATTACHMENTS_S3_SEAL_KEY_FILE`, required with the `s3` backend (§9.3) | The same 32 bytes on every replica, from the secret store. It is never created at start and never stored in the bucket. |
| `data/attachments.key` | Data directory, made by the backup collector for the mirror (`internal/backup/attachments.go:54`) | Unused in multi mode: the mirror is off there (§9.4) |
| VAPID push key | `KY_VAPID_PRIVATE_KEY`, else `data/vapid.key`, **created when missing** (`internal/push/vapid.go:98-110`) | Multi mode requires `KY_VAPID_PRIVATE_KEY` (or a file every replica shares), so replicas never sign pushes under different keys |
| Limiters, PoW ledger, guest sessions, calls | Process memory | PostgreSQL (§8) |

## 6. Cross-org matrix

Multi mode, `origin/main` plus PR #27. Every row has a cross-org test in
`internal/api/tenancy_test.go` unless it says otherwise.

| Path | Rule | Status |
|---|---|---|
| `GET /api/v1/users` | `UserFilter.OrgID = tenantID` (`internal/api/chat_handlers.go:196-199`). An org-less account is refused (`requireUserTenant`). | Built, tested (`tenancy_test.go:212-216`). The demo that listed every account was single-tenant or an older build (unverified which). |
| DM create, channel `member_ids`, instant meeting, `POST /rooms/{id}/members` | Another org's user gets the same 404 as an unknown ID | Built, tested (PR #27) |
| Every `/rooms/{id}/…` route | `requireRoomMember(tenantID, …)` returns 404 | Built, tested (PR #27: 13 routes, channel and DM) |
| Search | Caller's rooms in the caller's tenant | Built, tested |
| Mentions, push | Room members only. `ListPushRecipients` joins on tenant | Built, tested (PR #27) |
| WebSocket fan-out | Room IDs from `ListUserRoomIDs(tenantID…)` | Built, tested (PR #27) |
| User-targeted events (call SDP/ICE, LiveKit tokens, lobby decisions) | Sent to that user only | **Fixed in PR #27** (`internal/chat/hub.go` `Dispatch`). It leaked to the whole room in both modes. |
| Guest links `/api/meet/{token}` | The hashed token resolves one meeting, whose tenant must be active | Built, tested |
| KyCalendar `PUT /api/meetings/{id}` | `resolveSub` drops other-org users | Built, tested. Today a meeting ID taken by another org fails with 500. §8.3 gives each org its own ID space. |
| `/api/suite/chat` | Same body for a cross-org and an unknown target | Built, tested |
| Suite presence | K22 §4.5 | **Not on main.** PR #24 merged into a feature branch after its base had merged. Its commits ride on `feat/e2ee-core` (PR #26). |
| Admin agents | Owner's tenant (`internal/api/agent_handlers.go:107-113`) | Built |
| Admin SCIM users | Empty list in multi mode (`internal/api/scim_admin.go:22-28`) | Built |
| Admin audit | Install-wide, staff only | By design (open question 6) |
| Attachments in S3 | Object key under `orgs/<tenant_id>/` (§9) | Not built |
| Pool usage report | Per org, signed (§10) | Not built |

## 7. Lifecycle gaps

1. **`export_only` is ignored.** The ID token claims struct has no such field
   (`internal/sso/oauth.go:105-130`). T issues the claim to every member allowed an export
   session while the org is `deletion_scheduled`, for any app the plan enables, so for
   KyMessages. Whether KyMessages also gets an org event at `deletion_scheduled` is unverified.
   T lists `org.deletion_scheduled` only among billing's platform events. Today such a token
   signs in with full access. **Fix (M9):** in multi mode, refuse a token whose `export_only` is
   true, with the suspended-org answer, and audit `sso.export_only_refused` with no subject.
   Single mode never sees the claim, so it does not change.
2. **`user.erased` is acknowledged and dropped.** Unknown types return nil
   (`internal/sso/kyidentity.go:249`). T means it as "delete this person's data" (T, "A member
   deletes only themselves", step 3). **Fix:** delete the user row and everything derived from
   it: sessions, pairings, push subscriptions, agents, staged attachments, and DM rooms whose
   other member is gone too. Their messages in shared rooms become tombstones (body and
   attachments removed, the row kept so the thread's order holds; open question 4). Blobs are
   deleted before their rows, as in the purge (§7.3). Audit rows name the opaque ID only. Acknowledge with 200 once done, and make it idempotent.
3. **`org.deleted` purges nothing.** `ApplyTenantLifecycle` sets `status` only
   (`internal/store/chat.go:188-200`). **Fix:** after the status write commits, a leased job
   (§8.1) purges the org in batches. For each batch of `attachments` rows it deletes the blobs
   first, then the rows, so an interrupted run leaves rows that still point at every remaining
   blob, and the next run finishes them. A missing blob counts as deleted. When no attachment
   rows remain, it deletes the other tables, child tables first. In S3 a final
   `DeletePrefix("orgs/<org_id>/")` catches any object without a row, such as one whose upload
   died between `PUT` and commit. The `tenants` row stays as a tombstone, so
   a late event cannot revive it.
4. **A restore must not bring back a deleted org or an erased person.** A backup taken before
   the deletion has no tombstone, so the restored database cannot be the authority. KyIdentity
   is. Multi mode re-reads `GET /api/suite/erased` from `since=0` and the org list
   `GET /api/suite/orgs`, as T requires of every app after a restore (T,
   "`GET /api/suite/erased`"). A PostgreSQL restore bypasses the app, so the server cannot know
   one happened. The re-read is therefore not triggered by a restore. It always runs:
   - **incrementally**, on every tick of the leased tenancy-sync job (§8.1, about every 5
     minutes), from the erased-list and org-list revisions stored in the database. Each
     successful tick also refreshes `tenancy.kyidentity_synced_at` (below). A restore rewinds that stored revision with everything else, so the next
     successful tick replays every erasure the restore undid, without detecting the restore;
   - **daily**, from `since=0`, in the same tenancy-sync job, as a backstop;
   - on **every start** of every replica, before it serves. If KyIdentity cannot be reached,
     the replica still serves, and keeps retrying, as long as the database records a successful
     sync, incremental or full (`server_settings`, `tenancy.kyidentity_synced_at`), less than 24
     hours old. Ticks run every 5 minutes, so in normal operation the record is minutes old, and a
     KyIdentity outage has about 24 hours before a restart is refused. A
     database with no such record or an older one (a fresh install, or a restore from a backup
     more than a day old) does not serve until the reads succeed. This bounds the coupling: an
     ordinary restart or a rolling deploy during a KyIdentity outage stays up. The
     `RESTORE.md` multi section (PR 2) says to restart every replica after a restore.

   Each erased subject is erased again (§7.2). An org is purged (§7.3) **only** on an explicit
   deletion: an `org.deleted` event, or an entry in `/api/suite/orgs` whose `status` is
   `deleted`. T's downstream contract says the same: "Keep its data unless the status is
   `deleted`" (T, "Downstream contract", item 5), so T lists deleted orgs with that status.
   Other cases never purge:
   - Missing-org detection (this rule and the guard below) runs **only** on a full read from
     `since=0`, never on an incremental one, which by design lists only changed orgs. An org
     that is missing from a complete, fully paged full read gets `tenants.missing_since` set.
     That is a local flag, not a lifecycle status, so it never touches KyIdentity's `revision`
     order (`ApplyTenantLifecycle`). The org stops serving as if suspended, its data is kept, the
     read audits `tenancy.org_missing`, and the operator is alerted. The next complete full read
     (at most a day later, or at the next start) that lists the org with `status: active` clears
     the flag and audits `tenancy.org_found`. A transient glitch therefore heals by itself.
     Staff can also clear the flag at once.
   - A read that is not complete (a page error, a short page without `next`) changes nothing.
   - **Sanity guard on missing orgs:** if one read finds more than max(5% of active orgs, 3)
     orgs missing,
     the sync suspends none of them, audits `tenancy.sync_aborted`, and alerts. A start-up read
     never suspends a missing org; it only alerts. A wrong issuer, a paging bug or an empty
     answer during an incident therefore cannot take every org offline, and none of them can
     purge anything.
   - An explicit `deleted` status always applies, because it names one of our org IDs with
     KyIdentity's signed answer. A wrong KyIdentity cannot name our IDs, and an empty answer
     names none.

   Both erasure and purge are idempotent, so a re-read that finds nothing new changes nothing.
   KyMessages does not read either list today (its only suite-API call is `dir.Peer`,
   `internal/api/suite.go:173-180`), so this adds two reads to the existing `suitedir` client
   (`internal/sso/kyidentity.go:418-424`).
5. **Mail-style 550s do not apply.** KyMessages has no inbound mail.

## 8. Replica safety

### 8.1 Migrations and jobs

- **Migration lock.** On PostgreSQL, `migrations.Run` takes
  `pg_advisory_lock(hashtext('kymessages:migrate'))` on one connection, holds it for the whole
  loop, and re-reads `schema_migrations` under it. SQLite does not change.
- **Job leases.** One table, `job_leases (name PRIMARY KEY, holder, expires_at)`. A job runs a
  tick only after a conditional upsert wins the lease (`expires_at < now OR holder = me`), and
  renews it each tick. A run that may outlast a tick (the org purge, the daily re-read) renews
  the lease from a heartbeat every third of the lease while it runs. Before each batch it
  checks that it still holds the lease, by a conditional renewal that must update one row. If
  that fails, it stops, so two replicas never run the same batch. The lease lasts three ticks, so a dead replica's job moves within three
  ticks. Jobs: agent expiry, attachment sweep, pairing and
  replay sweeps, the org purge (§7.3), tenancy sync (§7.4), the pool reporter (§10). Single mode skips the lease and
  runs as today. The capsule backup scheduler is never leased: it runs only in single mode (§8.4).

### 8.2 Limits and the PoW ledger

- `attemptLimiter` gains a PostgreSQL implementation behind the same `allow(key, limit, window)`:
  one row per key and window, `INSERT … ON CONFLICT DO UPDATE SET count = count + 1 RETURNING
  count`, pruned by the sweep job. The keys stay as they are (no caller bytes, IPv6 per /64). The
  10 000-key cap (`internal/api/server.go:169`) becomes a sweep bound. Single mode keeps memory.
- `PoWSpender` writes the challenge signature to a `pow_spent (sig PRIMARY KEY, expires_at)`
  table. A key conflict means already spent. Multi mode only.

### 8.3 Meetings, guests and calls

- **Meeting key.** `meetings` moves to `PRIMARY KEY (tenant_id, id)`. `meeting_windows` and
  `meeting_guests` gain `tenant_id` and reference `meetings (tenant_id, id)`
  (`internal/store/migrations/chat.go:95-120`), and every lookup by meeting ID also matches
  `tenant_id`. So does every key outside the database. Today `LobbyManager` keys a guest's
  live session by meeting ID and guest key (`byMeetingKey`, `internal/chat/meetings.go:63`,
  `:466`). That key, the `meeting_guest_sessions` rows, and every bus event that names a meeting
  carry `tenant_id` too. Each org then has its own ID space. A
  `PUT /api/meetings/{id}` for an ID another org holds gets exactly the answer an unknown ID
  gets, which creates the caller's own meeting, as K22 §4 requires. Nothing reveals the other
  org's meeting. In single mode every row is in `default`, so the answers do not change, and the
  upgrade test proves it.
- **Meeting upserts** take `pg_advisory_xact_lock` on `(tenant_id, id)`, the same pair as the
  key, before the read, like the quota lock (`internal/store/chat.go:1316-1327`). Two writers of
  one org's meeting are serialised, and writers in different orgs no longer share a key.
- **Guest sessions** move to a `meeting_guest_sessions` table keyed by the SHA-256 of the
  secret, with tenant, meeting, status and expiry. The in-memory maps become a cache that the
  user bus invalidates. Lobby decisions already cross pods through the bus (PR #27).
- **Calls.** K22 §6.1 left two choices: shared call state in PostgreSQL, or route each room's
  WebSocket and call to one replica. **Recommend** routing by room, with the existing
  `call_sessions` table as the record that another replica can rebuild from, because seats and
  SDP relays are latency-bound and already ride the bus. Open question 5.

### 8.4 Backups

The SQLite capsule stays for single-tenant and Enterprise. In multi mode the capsule scheduler
is off, and its status says why. The database is backed up by PostgreSQL tooling (WAL archive
and base backups, off-host), and attachments by the bucket's versioning or replica copy (§9.4).
The shared secrets (§5: VAPID key, encryption key, session secret, and the S3 seal key) live
in the operator's secret store, never in the bucket. `RESTORE.md`
gets a multi-mode section. It says to restart every replica after a restore, so each re-reads
KyIdentity's erased and org lists before serving (§7.4).

## 9. Attachments in S3-compatible storage (decision 8)

### 9.1 Interface

`internal/blobs` exposes the attachment operations through one interface: `Put`, `Open`
(an `io.ReadSeekCloser` and size, preserving range responses), `Delete`, `DeletePrefix` and
`SweepStaleTemps`. PR 6 adds `Erase` for every version of one object; `DeletePrefix` removes
every version under the org prefix. Keys stay random bare identifiers validated by `ValidKey`;
the backend builds `orgs/<tenant_id>/att/<blob_key>`.

- Single mode uses `disk`, with its existing flat layout and wire behavior unchanged.
- Hosted multi mode requires `s3`. A disk backend or incomplete S3 configuration refuses startup.
  The release startup gate stays closed until this is built and verified.
- PR 5's org-layout disk constructor, store-ID check and flat relocation support internal
  migration/isolation tests of the interface while startup is gated. They do not authorize a
  hosted volume deployment or a mixed-version rolling deployment. Older multi-mode experiments
  must be stopped and migrated offline before the S3-only hosted release is enabled.

### 9.2 Configuration

`KY_ATTACHMENTS_S3_ENDPOINT` (HTTPS only, no credentials in the URL), `KY_ATTACHMENTS_S3_REGION`,
`KY_ATTACHMENTS_S3_BUCKET`, and the keys from `KY_ATTACHMENTS_S3_ACCESS_KEY_FILE` and
`KY_ATTACHMENTS_S3_SECRET_FILE`, or from `KY_ATTACHMENTS_S3_ACCESS_KEY` and
`KY_ATTACHMENTS_S3_SECRET`. The secret never reaches a log, an error string, the admin health
answer or an audit row. The health answer says only "reachable" or "unreachable". All of them
must be set together, or startup fails. A single-mode server that sets them fails startup, so
single mode cannot change by accident.

### 9.3 Keys and content

- Object key: `orgs/<tenant_id>/att/<blob_key>`. `blob_key` stays the random attachment ID
  (`att_<uuidv7>`, `internal/store/chat.go:1437-1444`), never a content hash, so no two orgs
  share an object and nobody can probe for a file's existence. The org prefix makes the purge one
  prefix delete.
- Uploads stream to a private temp file on the replica, hashing and sniffing as today, then make
  one `PUT`. The MIME rules (`internal/blobs/AGENTS.md`) do not change. A download is a proxied
  `GET` through KyMessages, which checks membership first. The `s3` backend fetches the whole
  object into a private temp file on the replica, verifies the GCM tag, and only then serves it,
  ranges included, from that file. It never serves unauthenticated bytes. One object is at most
  `KY_MAX_UPLOAD_BYTES` (25 MiB by default, 100 MiB at most, `internal/config/config.go:91-95`),
  so a whole-object fetch is bounded.
- **Verified cache.** Media players send many small `Range` requests per view. So the verified
  temp file stays in a per-replica cache, keyed by object key and S3 version ID, and later
  ranges are served from it. The cache directory is private (0700, files 0600) and holds
  plaintext only until E5. It is bounded by size (`KY_ATTACHMENTS_S3_CACHE_BYTES`, default
  1 GiB) and by idle time (10 minutes), evicting least recently used. An attachment delete, an
  erasure or an org purge evicts the entry on every replica, through an event on the existing
  PostgreSQL bus (`internal/chat/pgbus.go`). Every request still checks membership before touching the cache.
  Chunked sealing, which would make ranged `GET`s verifiable, is not needed at these sizes.
- A download is never a presigned URL, so a revoked member cannot reuse a link.
- **Content.** Under E5, every file is already ciphertext from the client, and quota uses
  ciphertext size (E §5). Keep it that way: the server never decrypts and never thumbnails. Until
  E5 ships, uploads are plaintext. The `s3` backend therefore seals every object with AES-256-GCM
  under its own 32-byte key, `KY_ATTACHMENTS_S3_SEAL_KEY_FILE` (required with `s3`, shared by
  every replica, never stored in the bucket), reusing the backup mirror's per-blob sealing code
  (`internal/backup`), so the provider never holds plaintext. The GCM tag also detects tampering. Sealing stays after E5, because it
  still covers pre-E5 files and any client that uploads without encrypting (open question 2).

### 9.4 Backup copy and deletion

The bucket uses versioning or a provider replica as its backup copy. The owner decided there
is **no automatic version pruning at launch**: every retained previous version counts in the
org pool until a person explicitly removes it. PR 6 must extend the usage ledger to account for
those retained bytes and provide explicit removal; attachment-row totals alone are insufficient
once versions survive a row deletion. Provider lifecycle rules must not silently delete versions.

A person's erasure and an org purge delete every version of each affected object immediately,
and the same objects on a provider replica. Neither waits for retention. The local attachment
mirror remains off in multi mode.

### 9.5 What KyMessages needs from ky-primitives

An S3 type with `PUT`, `GET`, `HEAD`, `DELETE`, list by prefix, and versioned
delete, both of one object and of every version under a prefix (list object versions, then
delete each version ID), using SigV4 signing over `net/http`, with no new module dependency. KyNotes asks for the
same type (PR #176). One shared type is the default (open question 8).

## 10. The org storage pool (decision 9)

KyIdentity holds the pool and defines the API (worker `kyint-ki-plans`, board
`kyidentity-business-orgs`, not merged at the time of writing). KyMessages' half follows
KyCalendar D14 and KyNotes N10 so every app behaves the same.

### 10.1 What KyMessages counts

An org's charged bytes are the sum of `attachments.size_bytes` for its tenant (posted and
staged) plus its live upload reservations. That is the figure `attachmentQuotaUsageTx` already
computes under the advisory lock (`internal/store/chat.go:1329-1360`). Under E5 these are
ciphertext sizes. Not counted (M7): message text, reactions, metadata, push subscriptions, audit
rows. A message body is bounded per message and refusing text would break chat.

### 10.2 Check

- `tenants` gains `pool_allowance_bytes`, `pool_checked_at` and `pool_low`. The allowance is
  the pool less what every other app reports, as KyIdentity's headroom answer gives it.
- **A new org** starts with `pool_allowance_bytes` and `pool_checked_at` NULL, which means
  unknown. Unknown never passes a write that adds bytes, so the pool is never unenforced. Two
  steps fetch it early: the first event that creates the tenant row (`EnsureTenant`, from sign-in
  or a directory event: `internal/api/sso_handlers.go:99`, `internal/sso/kyidentity.go:347`) starts a
  best-effort headroom read, and an upload that finds the allowance unknown makes one
  synchronous headroom read before it reserves. That read runs outside the tenant lock, with a
  5-second timeout, and stores the answer. If KyIdentity cannot answer, the upload gets `503
  pool_unavailable`, and shrinking writes still pass. So a new org's first upload succeeds
  whenever KyIdentity is up, without waiting for the reporter.
- `ReserveAttachmentQuota` and `CommitAttachmentWithQuota` already take the tenant lock and
  count. In multi mode they also compare the count plus the new bytes with
  `pool_allowance_bytes`, inside the same transaction. No network call on the write path.
- A write that would pass the allowance is refused with `413` and code `org_storage_full`.
  The web app shows "Your plan's storage is full" and points to KyIdentity. It never names the
  other apps or their usage. Freeing space (deleting an attachment, the staged sweep) always
  passes.
- A write that leaves less than a tenth of the allowance sets `pool_low`, and the reporter
  refreshes that org at once.
- Two of today's limits stay in multi mode as safety limits: `KY_MAX_UPLOAD_BYTES` and the
  per-user staging cap (`KY_ATTACHMENTS_MAX_PENDING_USER_BYTES`). The per-tenant cap
  `KY_ATTACHMENTS_MAX_TOTAL_BYTES` does **not** apply in multi mode, because the pool replaces
  it. It is one install-wide value, so it could never fit Business (30 GB per seat) and Personal
  at once. In multi mode the value is ignored, and startup logs one warning naming the
  variable. Ignoring it, rather than refusing to start, means an existing multi deployment that
  sets it keeps starting after the upgrade. PR 7's notes and the README's configuration list say
  so. Single mode keeps it unchanged (§10.4).
- **If KyIdentity is unreachable,** writes keep checking the last allowance for 15 minutes
  after `pool_checked_at`. After that, a write that adds bytes is refused with `503
  pool_unavailable`, and shrinking writes still pass. The 15 minutes match KyCalendar (its open
  question 11).

### 10.3 Report

The leased reporter job (§8.1) does two separate things:

- **Report.** It sends each active org's absolute total to KyIdentity's usage report. It sends
  about every 60 seconds when the total changed, at once after a purge or a `pool_low` mark, and
  at least every 5 minutes for every active org anyway. That last rule covers a restore, which
  the server cannot detect (§7.4): the next report carries the restored database's true total.
  It sends an absolute total, not a delta, so a retry or a lost report cannot drift. The report
  is signed with `syncauth` under KyIdentity's pair secret, carries `org_id`, and contains no
  names, file names or room IDs. Its revision is `max(now_ms, last_sent + 1)`.
  `last_sent` is stored per org in `tenants` and updated in the same step as the send. A lease
  handover to a replica with a slower clock therefore never sends a lower revision, and
  KyIdentity keeps the newest report per org and app. A restore rewinds `last_sent`, but
  `now_ms` has moved past every revision sent before the restore, unless a clock jumped back.
  Then reports pause until that clock passes the old revision, and the first one after it
  repairs the total.
- **Refresh.** It reads every active org's allowance from KyIdentity's headroom answer at least
  every 5 minutes, and sets `pool_allowance_bytes` and `pool_checked_at`. This read does not
  depend on a report being accepted, so a refused or stale report never ages an org's
  allowance. An idle org's `pool_checked_at` therefore never passes the 15-minute limit while
  KyIdentity is up.

### 10.4 Single-tenant

No pool, no reporter, no columns read. `KY_ATTACHMENTS_MAX_TOTAL_BYTES` stays the only org-wide
limit. The new columns get defaults that single mode never reads, and the single-tenant upgrade
test proves the answers are byte for byte the same.

## 11. Threat model

| Threat | Defence |
|---|---|
| Org A lists, resolves, invites or messages org B's users | §6. Every path is tenant-scoped, and cross-org answers match unknown ones. |
| A user-targeted event reaches room members | PR #27: `Dispatch` sends `user_id` events to that user only. |
| A member signs in with full access during `deletion_scheduled` | M9: refuse `export_only` tokens. |
| An erased person's or deleted org's data stays, or a restore brings it back | §7.2, §7.3, §7.4: purge every object version, tombstone, and re-read KyIdentity's erased and org lists after a restore. |
| A short or wrong org list from KyIdentity purges or suspends live orgs | §7.4: purge only on an explicit `deleted` status or `org.deleted`. A missing org is suspended, never purged, never on a start-up read, and not at all past the guard (more than max(5%, 3) orgs missing). Incomplete reads change nothing. |
| N replicas give an attacker N sign-in budgets, or N uses of one PoW | §8.2: shared counters and a shared spent table. |
| Two replicas migrate at once and one stops | §8.1: advisory lock. |
| A guest is lost, or let in twice, across replicas | §8.3: guest sessions in PostgreSQL, keyed by a hash of the secret. |
| The object store provider reads files | §9.3: E5 ciphertext, and server sealing until then. |
| An object key or URL is guessed or reused | Random IDs, never content hashes. Proxied downloads with a membership check. No presigned URLs. |
| S3 credentials leak | Environment or file only. Never logged, returned or audited. HTTPS only. |
| One org fills the pool or the bucket for others | The pool per org, plus the per-user staging cap and the upload limit. Bucket capacity is watched by the operator's alerts. |
| A forged or replayed usage report | Signed with `syncauth`, whose event ID and ±5-minute timestamp window are the replay guard. The revision is `max(now_ms, last_sent + 1)`, stored per org, so it only grows across replicas and lease handovers (§10.3). Totals are absolute, so order never changes a sum. |
| Pool overshoot while KyIdentity is down | Bounded to 15 minutes of other apps' growth. Then fail closed for adding writes. |
| Single-tenant changes by accident | Every change is gated on `IsMultiTenant()`. S3 settings refuse to start in single mode. Golden and upgrade tests. |

### Authoritative admission and per-app quota acceptance (implemented, startup still gated)

`tenant_directory` (migration 62) records each verified org-list entry's revision, status,
app enablement and narrowed quotas. A token or user event cannot admit an org. All multi-mode
access and org-bound grant issuance require an active/enabled valid snapshot at least as new
as the lifecycle revision. A newer webhook therefore cannot resume access on older quotas.
Deletion is terminal; stale entries cannot widen access, and conflicting equal revisions are
refused. Non-active entries persist revocation work; access stays fenced until it succeeds.

KyMessages accepts these optional keys in this app's `quotas` object:

| Key | Accepted bytes | Default |
|---|---|---|
| `max_upload_bytes` | Integer 1,024–104,857,600 | Install upload cap |
| `max_pending_user_bytes` | Integer 1,024–9,007,199,254,740,992 | Install per-user staging cap |

Values only narrow the configured install safety limits. Unknown keys, nulls, nonintegers
and invalid bounds hold the org offline; a newer valid snapshot recovers it after pending
revocation completes. The shared org storage pool remains a separate admission check.
Reservation and commit both check the current quotas under the same tenant quota lock, so
parallel replicas cannot overspend staging capacity and an in-flight upload cannot bypass a
new lower upload limit. Single mode keeps its existing limits and wire responses.

### Permanent erased-subject fences (implemented, startup still gated)

Migration 63 retains opaque KyIdentity subject/org tombstones independently of account and
org purge. Every accepted erasure records the fence before discovering local accounts; unknown
subjects are fenced too, and wrong-org bindings remain unchanged. Native account insert and
reactivation triggers enforce it across sign-in, directory replay and revision resets. A
PostgreSQL identity lock serializes first provisioning with erasure. Upgrade backfill uses only
exact retained erasure provenance. Single-mode org-less accounts stay outside this contract.
Tenancy reconciliation applies the erased feed before org snapshots can restore access.
Shared-room successor handover is implemented: room locks serialize erasure and ordinary
member departure; surviving ownership passes to the longest-standing room admin, else member
(the app has no editor role). Existing surviving owners retain ownership. Disabled members
still count; erased actors and wrong-org accounts cannot inherit. Only owned rooms and DMs
with no remaining member are deleted. Cleanup failure/replay preserves the committed successor,
other members' messages/files, and the single completion audit. Distributed calls remain separate work.

### Full call notifications (transport prerequisite implemented, startup still gated)

In multi mode, PostgreSQL `call.signal`, `call.migrate` and `call.state` events up to 128 KiB
are carried whole in 2 KiB notification parts. A bounded decoder keeps at most 128 incomplete
events (16 MiB of content), expires them after 10 seconds, and verifies the complete event
before delivery. User targeting remains unchanged; corrupt/incomplete parts are never client
frames. Single-mode notification bytes and ordinary message refetch behavior are unchanged.
This does not provide room-owner routing, call-seat ownership or failover reconstruction;
PR 4 remains unbuilt until those and the room-scoped WebSocket path are implemented.

### Call ownership and cleanup foundation (implemented, startup still gated)

Migration 64 adds database-clock room-owner generations, opaque account/peer/session seat
links and durable SFU cleanup independent of deleted user/room rows. Stale owner/media epochs
cannot rewrite a current call or issue a seat. Revocation retires the media address and queues
the old SFU room before removing seats; retries cannot target a later media epoch. Erasure
completion and the terminal org-purge mark wait for SFU cleanup, including when the original
owner is absent. Offline grant invalidation also fences restored owner leases/seats and queues
known old media rooms. Single-mode call records and notification/grant wire behavior stay
unchanged. Runtime room affinity, client call sockets and owner reconstruction remain required
to finish PR 4.

## 12. Phased build plan

Each PR is gated on the tenancy mode, carries its negative tests (wrong org, single mode,
replay or stale revision where it applies, oversize input), and runs CI on SQLite and PostgreSQL.

| PR | Scope | Blocks launch | Depends on |
|---|---|---|---|
| 0 | **#27 (open):** the hub fix and the cross-org tests | Yes | — |
| 1a | Lifecycle, webhook side (§7.1, §7.2): refuse `export_only`, handle `user.erased` (rows, plus blob deletes by key through today's `blobs.Store`) | Yes | — |
| 1b | Lifecycle, job side (§7.3, §7.4): the leased org purge, and the leased tenancy-sync job with the start-up check | Yes | 2 (leases), 5 (blob interface and `DeletePrefix`) |
| 2 | Replica safety I (§8.1, §8.4, §5): migration lock, `job_leases`, the capsule scheduler off in multi mode, `RESTORE.md` multi section, multi mode requires the shared VAPID key, encryption key and session secret (§5; the S3 seal key is PR 6's) | Yes | — |
| 3 | Replica safety II (§8.2, §8.3): shared limiters, the PoW table, the meetings key per org and the upsert lock, guest sessions in PostgreSQL | Yes | 2 |
| 4 | Calls across replicas (§8.3), as open question 5 decides | Yes | 3 |
| 5 | The blob interface and internal org-layout disk migration/isolation checks (§9.1); hosted startup stays gated | Yes (interface prerequisite) | 2 |
| 6 | The `s3` backend, sealing, the purge by prefix, and versioned deletes for erasure and purge (§9.2-§9.5). The interface gains `Erase(key)`, which removes every version (on `disk` it is `Delete`). Erasure and purge call it, and PR 1a's per-key deletes switch to it here. A user's own delete keeps `Delete` (current version only, §9.4). | Yes | 5, the ky-primitives S3 type |
| 7 | The org pool: columns, check, `org_storage_full`, reporter (§10) | Yes | 2 (leases), KyIdentity's pool API |
| 8 | Multi-region cells (K22 §6.2, its PR D) | No | 3, 4 |

Tests each PR must add, beyond its own:
- **Cross-org:** the §6 matrix keeps passing. New: an org-B attachment key is never readable from
  org A, through either backend.
- **Two replicas:** two servers on one PostgreSQL schema (`internal/testdb`). Two orgs holding the
  same meeting ID, each with a waiting guest, never share lobby state or admission. A migration race, a
  lease handover, a sign-in budget shared across both, a PoW spent on one and refused on the
  other, a guest admitted on one and recognised on the other.
- **Tenancy sync:** a fake KyIdentity returns an empty `/api/suite/orgs`, then a partial one, with
  no tombstones. Every tenant stays non-deleted, with its attachment rows and blobs. Missing orgs
  are not suspended on a start-up read or past the guard. An incremental read that lists only
  changed orgs suspends nothing. A missing org that a later full read lists as active serves
  again, with its `revision` unchanged. On a small install (10 active orgs),
  one missing org is suspended, and four missing are not. A `deleted` entry purges exactly
  that org. Run on SQLite and PostgreSQL.
- **Pool:** a new org's first upload (allowance unknown: fetched and then admitted, or `503`
  with KyIdentity down), at the allowance, one byte over, a stale allowance before and after 15 minutes,
  shrinking writes while over, two concurrent uploads on two replicas that together pass the
  allowance (one is refused).
- **Single-tenant:** the upgrade test from the last release, and the answers byte for byte.

## 13. Residual risks

- Until PR 4, a call needs both peers on one replica. The bus carries signalling, but seats are
  local.
- A stale allowance can let the pool be overshot by other apps' growth for up to 15 minutes.
- Retained object versions continue to consume the org pool until explicitly removed; there is
  no automatic pruning at launch.
- Staff see every org's usernames in the install-wide audit (open question 6).
- An org that KyIdentity stops listing without a `deleted` status is held offline and kept, not
  purged, until a later full read lists it again or staff resolve it. Its data costs storage
  until then.
- A restore to a point less than a day old, made while KyIdentity is unreachable, can serve an
  erased person's or a deleted org's restored data until KyIdentity answers again. Then the
  incremental re-read replays the erasures (§7.4).

## 14. Open questions, each with a default

1. **Count message text in the pool?** *Default:* no (M7). If yes, count `length(body)` of live
   messages, and still never refuse text.
2. **Keep server sealing of S3 objects after E5?** *Default:* yes. It costs one AES pass, and it
   keeps pre-E5 files sealed.
3. **What may an `export_only` session do in KyMessages?** *Default:* nothing; the token is
   refused (M9). Under E2EE the export is done on the user's own device, before the deletion
   date. A server export of plaintext rooms from before E2 would be a later feature.
4. **A `user.erased` person's messages in shared rooms.** *Default:* tombstone them (body and
   attachments removed, "deleted message" shown). The other choice is to drop the rows, which
   breaks reply chains.
5. **Calls across replicas: route by room, or shared state?** *Default:* route by room, with
   `call_sessions` as the record to rebuild from.
6. **Staff audit shows usernames from every org.** *Default:* keep (platform operations),
   staff only, and say so in `docs/PRODUCT.md`.
7. **Retained versions (decided).** No automatic pruning at launch. Every kept version counts
   in the pool until explicitly removed; erasure and org purge remove all versions immediately.
8. **The S3 client:** one ky-primitives type shared with KyNotes. *Default:* yes. The other
   choice, a KyMessages-only SigV4 client, duplicates signing code.
9. **`org.unsuspended`:** *Default:* keep accepting it until KyIdentity confirms it never sends it,
   then remove it in its own PR.
