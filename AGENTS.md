# KyMessages repository

KyMessages is a native team chat, voice/video calling, and operator console server built on the
Ky suite server base. It ships channels, DMs, attachments, Web Push, native bot/agent accounts,
optional LiveKit SFU / WebRTC calls and KyCalendar guest meetings, KyIdentity SSO/directory sync,
SCIM 2.0, and encrypted KyRecovery backup capsules.

- `kymessages` is the binary and local image name; `KY_APP_NAME` defaults to
  `KyMessages`. `internal/config.AppVersion` is shared by CLI and capsule paths.
  Preserve explicit legacy service names for existing pairing pins/capsules.
- Compose is a loopback local preview by default and runs `ghcr.io/busnes-app/kymessage-server:stable`
  (`KY_IMAGE` pins a verified digest); it never runs an upstream base image. The build overlay
  builds `kymessages:local`, never pulled. The app never runs as root: the image's `USER` is 10001 (owning
  its own `/app/data` and `/app/backups`); Compose runs it as `KY_UID:KY_GID` (required, the
  owner of `./data` and `./backups`) with `cap_drop: [ALL]`, `no-new-privileges`,
  `read_only: true` and a `/tmp` tmpfs; `scripts/check-compose-proxy.sh` fails if any of that is lost.
  Dockerfile base images are pinned by tag and digest (Dependabot's `docker` entry bumps them). Preserve existing overlay chains. The release target is SQLite, one instance.
- `make clean` removes generated artifacts only; never runtime data or backups.
- `cmd/server` `bootstrapAdmin` creates the local admin on an empty database as
  `KY_ADMIN_USERNAME` (default `admin`, passed through by Compose); a failed user count stops
  startup rather than reading as empty. `init-admin` reads the password from stdin (no echo on
  a terminal) and has no `-password` flag: argv is world-readable. A KyIdentity user whose
  username another account holds is refused, never merged: a webhook create gets 409 with
  sync reason `username_conflict` (recovery: rename, then Resync Directory in KyIdentity), an
  update keeps the old username and applies the rest, both audit `sso.sync_conflict`; sign-in
  gets 409 with `sso.login_conflict`.

- Read [docs/PRODUCT.md](docs/PRODUCT.md) before product scope changes; it is the product
  definition: what ships, what is later or out of scope, and known risks. Keep it
  in step when a shipped capability or approved decision changes.
- Root owns product definition and cross-domain documentation in `docs/`; children
  own the runtime domains indexed below. Keep product plans distinct from shipped
  capabilities and verify claims against code before publishing them.

# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences
- Bootstrap passwords and passwords installed by `init-admin` must be replaced before privileged use. Operator resets atomically revoke sessions, MFA challenges and device pairings. Untouched existing accounts are not retroactively flagged.

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

- Container network IP configuration belongs to Compose: the optional
  `docker-compose.static-ip.yml` overlay requires `KY_CONTAINER_IP` and `KY_NETWORK_SUBNET`.
  Preserve existing overlays when updating `COMPOSE_FILE`; the base keeps automatic addressing.
- `docker-compose.proxy.yml` names the network `kymessages-net`, publishes no port and sets
  `KY_ENV=production`; `scripts/check-compose-proxy.sh` checks it, including with the static-IP
  overlay. Guide: [docs/Reverse_Proxy_Networking.md](docs/Reverse_Proxy_Networking.md).
- Voice and video calls use native WebRTC signalling (`internal/rtc`) with configurable STUN
  (`KY_STUN_URLS`) and an optional LiveKit SFU (`KY_LIVEKIT_URL`, `KY_LIVEKIT_API_KEY`,
  `KY_LIVEKIT_API_SECRET`). KyCalendar meeting rooms (`KY_MEETING_SYNC_SECRET`) admit external
  guests from a waiting room during the meeting.
- `chat.Hub.Dispatch` sends an event that carries `user_id` only to that user's sockets, even when
  it also names a room (call signals, call migrations with their LiveKit token, lobby decisions);
  only events without `user_id` fan out to a room (`TestHubUserEventWithRoomReachesOnlyThatUser`).

## Tenancy

- Only `KY_TENANCY_MODE=single` (default) can start until the final tenancy build phase.
  Preserve the first-boot `tenancy.mode` database lock, including on refused startup.
  Exercise the multi-tenant contracts below through internal constructors. Product contract: [docs/PRODUCT.md](docs/PRODUCT.md).
- Signed suite peer routes (`/api/suite/*`, `/api/meetings/*`) follow the `org_id` wire contract in
  `docs/superpowers/specs/2026-11-22-tenancy-design.md` §4: required canonical UUID in `multi`,
  refused (even `""`/`null`) in `single`, cross-org callers and targets answered exactly like
  unknown ones. Event IDs go to the shared `suite_replay_events` ledger; a 429/503 releases them.
  Suite presence (`internal/presence` decoders, `store.PresenceStore` keyed by tenant and user)
  serves `/api/suite/presence/{lookup,out-of-office,calendar,me}`.
- End-to-end encryption (`docs/superpowers/specs/2026-11-22-e2ee-design.md`): `web/crypto` is a
  Rust wasm-bindgen wrapper over vodozemac. Its committed build `web/src/crypto/pkg` must equal
  `web/crypto/build.sh` output (pinned Rust in `rust-toolchain.toml`, `wasm-bindgen-cli` 0.2.130;
  CI job "Crypto core"). The key server (`internal/api/e2ee_handlers.go`, `store.E2EEStore`)
  holds public keys and Olm ciphertext only; devices sign `api.E2EEDeviceSigned` and
  `api.E2EEOneTimeKeySigned` strings, which clients verify again.
- Only the staff org (`KY_STAFF_ORG_ID`) holds administrators (`config.TenancyConfig.MayAdminister`,
  enforced in directory sync and the `admin` middleware). Org-less local operators keep the
  install-wide console; per-org admin pages need a staff-org account.
- Org lifecycle webhooks apply in KyIdentity's per-org `revision` order
  (`ChatStore.ApplyTenantLifecycle`; deletion is terminal). Tenant status is read from the
  primary. Grant issuance (`withPassword`) locks an org-bound account's active tenant row, and
  suspension publishes `tenant.revoked` so every pod drops that org's meeting guests.
- Every route that names a user or room answers another org's ID exactly like an unknown one,
  and no live event crosses orgs (`TestMultiTenantCrossOrgUserPaths`). The resume event is
  `org.resumed`; `org.unsuspended` stays accepted until KyIdentity confirms the name.
- The shared multi-server install (every paid plan is an org), replica safety, attachments in
  S3-compatible storage and the per-org storage pool are designed in
  `docs/superpowers/specs/2026-11-23-tenancy-design.md`. Its PR 2 (migration lock, job leases,
  shared secrets, capsule scheduler off) and PR 3 (shared sign-in limits and proof-of-work,
  per-org meeting IDs, guest sessions in PostgreSQL) are built; the rest is not. It extends the 2026-11-22
  spec, whose §4 wire contract stays authoritative.
- Single mode must not change: `TestSingleTenantGolden` replays a fixed single-mode script and
  compares it with `internal/api/testdata/single-tenant-golden.txt`, recorded before the tenancy
  build. Regenerate (`-update-golden`) only for an intended single-mode change.

## Installer setup

- `kymessages apply-setup` is the container-local installer boundary; see
  [docs/INSTALLER_SETUP.md](docs/INSTALLER_SETUP.md) for protected inputs and deployment gates.
  Stock Compose sets nothing setup refuses: SCIM and backup retention/interval pass through
  only when `.env` sets them (`TestStockComposeEnvironmentAcceptsInstallerSetup`).
- Common envelope service `kymessage` owns new exact KyIdentity subjects and immutable
  configuration; it preserves the native product/capsule name `KyMessages`.

## Verification

CI (`.github/workflows/ci.yml`) runs on every push and pull request:
- `make lint` equivalent: gofmt, `go vet`, `go mod tidy`/`verify`, and `scripts/check-compose-proxy.sh`
- `go test -race` with coverage on SQLite, and the same suite against PostgreSQL 17
- Bounded fuzzing (`go test -fuzz=… -fuzztime=Nx`, one step per target) of `FuzzClientIP`,
  `FuzzParseTrustedProxies`, `FuzzValidateName` and `FuzzNormalizePNG`; a crasher kept under
  `testdata/fuzz/<Target>/` replays in the normal test run
- Frontend vitest suite, then typecheck/build plus a check that committed `web/dist` matches source, untracked files included (it is embedded in the binary)
- `govulncheck` and `npm audit --audit-level=high`
- `scripts/backup-acceptance.py` starts its own loopback process and disposable
  SQLite/local-copy directories. It exercises real scheduler ticks (~3 minutes),
  live schedule changes, local-destination failure/retry timing, pruning and
  shutdown. Time injection changes only its scratch database's last-attempt row.
  No live identity or recovery destination is contacted. CI's smoke job runs it.
- `scripts/smoke-test.sh`: runs the built binary and asserts CLI, auth, session, and SPA behavior
- Docker image build and container HTTP check
- Chromium and Firefox regressions against the built server: production CSP/worker, themes, responsive layout, sign-in landing in chat with Settings reached from its rail, the Create channel modal, the chat modals and their teammate and search pickers by keyboard, proof-of-work sign-in on a second server, and the Health, Audit (with Directory & SCIM reached from it by keyboard), Overview, Backup and Settings branding (rename by keyboard, logo upload and resets) pages; these checks remain release gates.
- Container builds use `npm ci`. CI builds/runs `kymessages:ci` and publishes nothing.
  `.github/workflows/release-image.yml` is the only publisher: on a published release `vX.Y.Z`
  it requires every version source (`internal/config/config.go`, `web/package.json`, both
  `web/package-lock.json` entries) to equal X.Y.Z and every ci.yml job, by name, to have passed
  on the tagged commit, then pushes `:X.Y.Z` (SBOM, provenance), attests and verifies it, and
  moves `:stable` only forward and never to a prerelease. A new ci.yml job joins its `REQUIRED`
  list; its action pins match KyPulse's. Keep the deployed identity gates explicit.

`make lint` and `make ci` need docker compose v2.24 or later and jq for
the compose checks. Run the same checks locally with `make ci` (`tidy-check lint test-race test-web smoke`); add `make test-postgres` when a Postgres instance is available.

## Child DOX Index

- [internal/config/AGENTS.md](internal/config/AGENTS.md): Configuration management and environment loader.
- [internal/store/AGENTS.md](internal/store/AGENTS.md): Pluggable database abstraction layer (SQLite & PostgreSQL).
- [internal/crypto/AGENTS.md](internal/crypto/AGENTS.md): Cryptographic primitives (AES-256-GCM, HMAC, SHA-256, randomness, PKCE).
- [internal/auth/AGENTS.md](internal/auth/AGENTS.md): Authentication, MFA (TOTP), recovery codes, sessions, and CAPTCHA.
- [internal/sso/AGENTS.md](internal/sso/AGENTS.md): KyIdentity OIDC sign-in and signed directory webhooks.
- [internal/scim/AGENTS.md](internal/scim/AGENTS.md): SCIM 2.0 user and group provisioning engine.
- [internal/branding/AGENTS.md](internal/branding/AGENTS.md): Product name validation and PNG normalisation behind console settings.
- [internal/health/AGENTS.md](internal/health/AGENTS.md): Per-request component health probes (service, database, optional LiveKit).
- [internal/blobs/AGENTS.md](internal/blobs/AGENTS.md): Local chat attachment blob store: confined keys, atomic writes, sniffed MIME types.
- [internal/push/AGENTS.md](internal/push/AGENTS.md): Web Push: VAPID key, payload encryption, endpoint validation and the bounded delivery pool.
- [internal/backup/AGENTS.md](internal/backup/AGENTS.md): Product-side adapters over `ky-primitives/recoveryclient`: payload collection, attachment mirroring, drill checks, settings and sealer glue.
- [internal/devices/AGENTS.md](internal/devices/AGENTS.md): 90-second ephemeral QR device pairing and push registration.
- [internal/testdb/AGENTS.md](internal/testdb/AGENTS.md): Test-only isolated database provisioning (SQLite or PostgreSQL).
- [internal/api/AGENTS.md](internal/api/AGENTS.md): HTTP REST API endpoints, routing, and middleware.
- [agent-skill/AGENTS.md](agent-skill/AGENTS.md): The `kymessages` skill for chat agents (OpenClaw, Hermes Agent) and the console's config blocks.
- [web/AGENTS.md](web/AGENTS.md): React 19 + TypeScript + Vite PWA frontend and KySecurity design system.

`cmd/server` owns the scheduler: `backupLoop` builds the server capsule's `RunConfig` and the client once
and returns with `scheduler disabled: ...` if that fails, because a run that never stamps its
attempt would log and audit the same failure every minute forever; it audits that once as
`admin.backup_scheduler`, and backup status reports it as `scheduler_error`. Each tick `backupTick`, when due, takes
`backup.Lock` (busy: logged, unstamped, retried next tick) and runs the
server capsule. After a successful capsule run, `backupTick`, `deposit` and the HTTP run route also mirror chat attachments (`backup.MirrorAttachments`, `internal/backup/AGENTS.md`); a mirror failure is logged and never fails the capsule. The `deposit`, `backup-drill`, and `export-capsule` commands open through `openForSeal`, which loads the stored installer setup as `runServer` does, so a managed console's credentials are sealed (`TestCLISealIncludesInstallerCredentials`); they seal the server capsule under `backup.Lock` (exiting while it is held); `backup-drill` exits non-zero when a check fails (`TestBackupDrillFailureIsAnError`). `export-capsule` refuses an existing `-out` and writes through a synced temporary file hard-linked into place.
The loop closes its `done` channel
only where it returns, between runs, and `runServer` cancels and waits on that channel after
`httpServer.Shutdown` and before the store closes, then waits on `api.Server.WaitDetached()` for
the pair, pin-key, unpair, deposit, export and drill handlers, which detach or run long and can outlive
`Shutdown`. In `KY_TENANCY_MODE=multi` (refused at startup in this release; `internal/config`) the capsule scheduler returns at once (`backup.MultiTenantOff`, which backup status reports as `scheduler_error`; no audit row), and each other loop runs a tick only while it holds that job's `job_leases` row (`leasedJobs`: jobs `maintenance`, `agent_expiry`, `attachment_sweep`; lease three ticks, renewed each tick; `maintenance` also runs `PruneShared` in multi mode). Single mode passes `everyReplica` and runs every tick as before. `kymessages invalidate-grants` runs `InvalidateRestoredGrants` on the configured database, for a PostgreSQL restore (docs/RESTORE.md, multi section).
`maintenanceLoop` sweeps expired device pairings, expired suite replay IDs
(`suite_replay_events`) and to-device mail older than `api.E2EEMailboxTTL` (30 days) every
minute, each with a 30-second deadline; `agentExpiryLoop` revokes idle or inactive-owner bot tokens every hour; `attachmentSweepLoop` expires staged attachments older than `KY_ATTACHMENTS_PENDING_TTL` at start and every 15 minutes. All background loops join the backup scheduler's wait before the same shutdown drain finishes. Nothing writes
into a closed store. Both waits run under one `backupWaitTimeout`
context (20m) -- a context, not a timer channel,
which delivers once and would leave the second wait unbounded; the HTTP drain is `shutdownTimeout`
(5s). `docker-compose.yml` grants a `stop_grace_period` (21m) above their sum, so the guarantee holds
in the shipped deployment instead of assuming a supervisor grace period;
`TestComposeGracePeriodCoversTheShutdownBudget` keeps the three in step. Past the deadline the
work is abandoned with a log line rather than killed silently.

`cmd/server/restore.go` delegates custodian handling and extraction to recoveryclient,
requires a regular nonempty `data/ky_server.db` and a valid 32-byte deployment key,
then opens the offline SQLite snapshot (running migrations; a schema from a newer build is refused and the extraction removed), invalidates
restored grants (sessions, MFA challenges, device pairings, push subscriptions, meeting guest sessions, and active agent tokens) and closes it before reporting success. Before extraction it resolves symlinked parents and checks the real path up to `/`: an existing target must be a non-symlink directory owned by the current user, each ancestor owned by the current user or root, and none group- or world-writable except a root-owned sticky ancestor (`/tmp`). It creates an absent target (`os.Mkdir`, so the parent must exist; a target that appears meanwhile is refused), opens an `os.Root` on it, checks the opened directory against the target rule and the path (`checkTarget`), and refuses a nonempty target without touching it. A library failure is rolled back by the library; only a created target is then removed. After extraction it requires the path to still name that directory. A later failure removes what was extracted through the handle, never by path (and the target itself if restore created it).
`restore-attachments -mirror <KY_BACKUP_DIR>/attachments -data-dir <restored>/data -to <KY_ATTACHMENTS_DIR>` decrypts the attachment mirror with the restored `data/attachments.key`; until it runs, downloads answer 404.
Users sign in again with fresh suite authentication. Root owns this policy and `docs/RESTORE.md`.

The KyRecovery wire contract is `kyrecovery-server/zero_code_pairing_handoff_spec.md` (v2.0.0, sealed-capsule deposit); the product half is `ky-primitives/recoveryclient`, wired through `internal/backup` and `internal/api` so every server built on this base inherits it. Operator documents: `README.md` covers the source-built local preview and configuration; `docs/RESTORE.md` covers the tested SQLite and attachment restore.
The K80/K81 deployment is owned by `busnes.app/ky-kubernetes`.
