# KyMessages product definition

KyMessages is a native team chat, voice/video calling, and KyCalendar meeting server built as a
single Go binary with an embedded React/TypeScript web application (PWA). Setup and operation:
[README](../README.md). Disaster recovery: [RESTORE.md](RESTORE.md). Installer boundary:
[INSTALLER_SETUP.md](INSTALLER_SETUP.md). Reverse proxy and media networking:
[Reverse_Proxy_Networking.md](Reverse_Proxy_Networking.md).

Each release publishes an attested container image (`ghcr.io/busnes-app/kymessage-server` — or
renamed upon release cutover). Historical Matrix-era specifications are archived under
`docs/superpowers/`.

## Promise and audience

**Private team conversations, calls, and meetings on infrastructure you control.**

- **Single-organization deployments** run with `KY_TENANCY_MODE` unset or set to `single`,
  using SQLite or PostgreSQL. First boot locks the database to its tenancy mode.
- **Planned multi-organization deployments** use one KyIdentity org per paid plan (Personal,
  Couple, Family, Business). Enterprise gets a dedicated single-tenant install.
  This release refuses `KY_TENANCY_MODE=multi` and databases already locked to `multi`.
  The multi-tenant contracts below remain under development until the final phase of
  [the tenancy build](superpowers/specs/2026-11-23-tenancy-design.md).
  Built so far, for multi mode: migrations under a PostgreSQL lock, background jobs leased to one
  replica, secrets every replica shares, the capsule scheduler off in `multi` (PostgreSQL tooling
  backs it up), sign-in limits and proof-of-work shared by every replica, a meeting ID space per
  org, and meeting guest sessions in PostgreSQL, and attachments stored per org on one shared
  volume. Calls still need both peers on one replica. Each org's attachments count against its
  KyIdentity storage pool; a full pool refuses new attachments only ("Your plan's storage is
  full"), never reading, deleting, text or calls. Object storage is not built.
- **Invite-only:** accounts come from KyIdentity (OIDC + signed directory sync webhooks) or local
  admin provisioning in single-tenant mode. No public sign-up. External guests can join only
  scheduled or instant meeting rooms through time-bounded guest links with host-approved lobby
  admission.
- **Ky-integrated:** KyIdentity sign-in and real-time offboarding, KyCalendar meeting room sync,
  KyRecovery sealed server backups, and the KyMessages operator console.

## What ships

**Messaging & realtime.**
- Direct messages, group channels, threads, reactions, mentions (`@username`, `@here`, `@channel`),
  typing indicators, read receipts, unread badges, and message search that runs on the device: each
  browser indexes the messages it has read in IndexedDB, encrypted at rest, and deletes the index
  on sign-out. A browser finds only what it has read. The server has no search endpoint.
- Room messages and edits are end-to-end encrypted by the web client (Olm + Megolm, E2 of
  `docs/superpowers/specs/2026-11-22-e2ee-design.md`): each browser is a device with its own
  keys, members' sessions may post only `e2ee_room_v1` envelopes, and the server stores
  ciphertext it cannot open. Bots (`kybot_` tokens) still post plaintext, shown as "Not encrypted
  (bot)"; older messages show "Sent before encryption"; files stay plaintext, shown as "File not
  encrypted", until E5; meeting guests cannot read members' messages. Not released: no encryption
  release is published until E1-E5 ship together, and until E3 keys go to every device the server
  lists for a member. Because the server cannot read an encrypted message, the `mentions`
  notification mode does not fire for one.
- Native WebSocket fan-out (`/api/v1/ws`) with presence and immediate revocation disconnects.
- File and image attachments stored on local disk (`KY_ATTACHMENTS_DIR`) with SHA-256 content
  hashing, per-upload/per-user/per-tenant quotas, inline image thumbnails, and encrypted backup
  mirroring.
- Incoming room webhooks are removed: rooms are becoming end-to-end encrypted, and the server cannot
  encrypt for a webhook. `/api/v1/webhooks/in/{id}` answers `410 gone` to every sender; integrations
  post through a bot (Bots & Agents). Migration 52 left an audit row (`webhook.removed`) per live
  webhook.

**Voice, video & KyCalendar meetings.**
- Hybrid calling: direct peer-to-peer WebRTC (signaled over `/api/v1/ws`) for 1:1 / small calls,
  with optional LiveKit SFU (`KY_LIVEKIT_URL`, `KY_LIVEKIT_API_KEY`, `KY_LIVEKIT_API_SECRET`) for
  larger group calls and automatic escalation.
- KyCalendar meeting sync (`PUT`/`DELETE /api/meetings/{id}`, signed with `KY_MEETING_SYNC_SECRET`)
  creates meeting-scoped rooms with scheduled time windows, attendee resolution, and external
  guest links (`/api/meet/{token}`) gated by an interactive waiting-room lobby.
- End-to-end encryption groundwork (not yet in use): a key server holds devices' public keys,
  claim-once one-time keys and a mailbox of Olm ciphertext between devices in the same org
  (`/api/v1/keys/*`, `/api/v1/to-device`), and the web app ships the vodozemac crypto core. Messages
  stay `plain_v1` until the encrypted-rooms phase ships
  (`docs/superpowers/specs/2026-11-22-e2ee-design.md`).
- Chat from mail and calendar: `POST /api/suite/chat` (`kypost.chat.open`, `kycalendar.chat.open`)
  answers a same-org colleague's `#dm=<user id>` link, which the PWA opens as a direct message.
  Signed suite requests carry `org_id` only in `KY_TENANCY_MODE=multi`, and every event ID is
  recorded in a shared replay ledger (`suite_replay_events`). Contract:
  [the tenancy spec §4](superpowers/specs/2026-11-22-tenancy-design.md).
- Coarse colleague status for mail and calendar: `POST /api/suite/presence/lookup` (up to 50
  same-org people), fed by KyPost out-of-office (`/out-of-office`), KyCalendar busy blocks
  (`/calendar`) and the user's own switch and manual status (`/me`). Sharing off hides the user
  and drops every input; reply text, event titles and last-active times are never stored.
- Instant meetings (`POST /api/v1/meetings`) and room guest invite links
  (`POST /api/v1/rooms/{id}/meeting/guest-link`) for ad-hoc external calls.

**Web Push notifications & PWA.**
- Installable Progressive Web App with a service worker (`web/public/sw.js`) and RFC 8291/8292
  Web Push delivery (`internal/push`) using a self-generated or operator-supplied VAPID P-256 key
  (`data/vapid.key` or `KY_VAPID_PRIVATE_KEY`, `KY_VAPID_SUBJECT`; disable with
  `KY_PUSH_ENABLED=false`).
- Per-room notification preferences (`all`, `mentions`, `mute`), push subscription management
  (`/api/v1/push/*`), and automatic pruning of stale `404`/`410` browser endpoints.
- Only current room members with active human accounts in an active org get a push. A message's
  sender and room, and the text "New message" (never its content), pass through the browser
  vendor's push service, encrypted to
  the browser (RFC 8291). Signing out, offboarding, org suspension and a restore remove
  subscriptions.

**Sign-in, tenancy & offboarding.**
- KyIdentity back-channel logout (`POST /api/sso/kyidentity/logout`) ends one IdP session
  and its paired-device sessions and bound notification registrations by `sid`, or all of a
  subject's sessions when `sid` is omitted.
  Shared replay records and issuance fences work across replicas, including a first sign-in
  whose local account has not yet been provisioned. Configure this URI on the
  OAuth client. Existing sessions, pairings and notification registrations stay on upgrade.
  Legacy sessions have no IdP sid: a sid logout also ends every unbound session for its verified
  subject and org. New suite sign-ins require and retain the IdP sid.
- Signed `user.mfa_reset` revokes sessions, MFA challenges, device pairings and push
  subscriptions even when role/status are unchanged or a newer profile event arrived first.
  Reset replay is tracked independently so a duplicate preserves subsequent sign-ins. Reset, deletion and installer-managed
  directory events compare the account's org binding before acting.
- Primary sign-in via KyIdentity OIDC (`KY_KYIDENTITY_*`) with PKCE and step-up freshness checks
  for privileged console actions.
- Signed KyIdentity directory webhooks (`POST /api/sso/kyidentity/sync`) synchronize user creation,
  profile updates, deactivation, deletion, MFA resets, and — in `KY_TENANCY_MODE=multi` — org
  lifecycle events (`org.suspended`, `org.unsuspended`, `org.deleted`). Each carries KyIdentity's
  per-org `revision`; one at or below the last applied revision changes nothing, so a delayed
  event never undoes a newer one, and deletion is never undone. Tenant status is read from the
  primary database, never a read replica.
- Deactivation, deletion, or org suspension immediately revokes sessions, push subscriptions, and
  active WebSocket connections, and blocks API calls and guest meeting links.
  No new session, MFA challenge or pairing is issued to an inactive org, including one in flight
  when the suspension lands. Org suspension or deletion also ejects that org's meeting guests, waiting or admitted, from the
  lobby, their sockets and their calls on every server instance.
- In `KY_TENANCY_MODE=multi`, KyIdentity's org list is the authority for each org's status: every
  replica re-reads it in full at start and daily, and incrementally every 5 minutes. An org listed
  as `deleted` has all its data purged (blobs, then rows); the org record stays so it cannot come
  back. An org the list stops naming is held offline with its data kept, never purged, and a
  sanity guard stops a short or empty list from taking many orgs offline.
- In `KY_TENANCY_MODE=multi`, KyIdentity's `user.erased` (a member used Delete everything) deletes
  that person's data: account, bots, attachments, and owned rooms or DMs nobody else uses.
  Shared rooms pass to their longest-standing room admin, else longest-standing member; other
  members' messages and files stay. Disabled members retain their shared content. Their messages in
  rooms others still use stay as "deleted message" tombstones with no text, name or files.
  An opaque subject tombstone permanently prevents reprovisioning, including a subject this
  install never held. Restore reconciliation applies erasures before admitting listed orgs. A
  sign-in with an `export_only` token (the org is scheduled for deletion) is refused like a
  suspended org's: KyMessages has no export, and encrypted rooms are exported on the device.
- In `KY_TENANCY_MODE=multi`, every user account is bound immutably to `(sub, org_id)`, tokens or
  webhooks without `org_id` are refused, cross-org `org_id` reassignment is rejected with HTTP 409
  and audited (`sso.org_mismatch`), and inbound SCIM (`/scim/v2/*`) is forced off (404).
- In `KY_TENANCY_MODE=multi`, customer orgs have no administrators. An `admin` role from KyIdentity
  is honoured only for the staff org named by `KY_STAFF_ORG_ID` (unset: no directory
  administrators), and the console refuses any account bound to another org or to an inactive
  staff org. Local operator accounts, which belong to no org, keep the install-wide console
  (backups, audit, health, settings); per-org pages (Agents, Media policy) need a staff-org
  administrator and answer 403 to an account with no org. The audit log is install-wide, so
  staff can see the usernames of every org's members in it. The console shows no message content.
- Local operator login remains available for single-tenant recovery/console access, with mandatory
  initial password replacement and optional TOTP MFA with recovery codes.

**Agents (bots).**
- Admins can provision native bot/agent accounts (`agent-<name>`) owned by an organization member,
  minting one-time scoped bearer tokens with generated skill configs for supported agent runtimes.
- Agents inherit their owner's organization (`org_id`), follow their owner's offboarding state,
  auto-expire after 90 days of inactivity, and cannot join voice/video calls.

**Backups & disaster recovery.**
- Sealed server capsules to KyRecovery and/or `KY_BACKUP_DIR` on schedule or on demand: SQLite
  snapshot (`data/ky_server.db`), `data/encryption.key`, `data/attachments.key`, `data/vapid.key`,
  `data/recovery.pub`, and installer credentials when present.
- Encrypted incremental attachment mirror in `KY_BACKUP_DIR/attachments` opened only by the
  capsule's `data/attachments.key`.
- Offline restoration via `kymessages restore` and `kymessages restore-attachments`, which
  atomically invalidate pre-backup sessions, MFA challenges, device pairings, and push
  subscriptions before the server returns to service.

**Operator console.**
- Built-in admin UI (`/console`) with 10-minute fresh-sign-in step-up and full audit logging:
  overview metrics, user/session management, agent management, media/call policy, branding
  (product name, logo, accent), KyIdentity sync health, backup schedules/drills, and read-only
  audit logs.

## Out of scope

- Matrix protocol / Synapse / MAS / Element Web / server-to-server federation (retired; see
  `docs/superpowers/` for historical records).
- A released end-to-end encryption claim, for now: encrypted rooms (E2) are built, but identity
  verification (E3), bot devices (E4), file encryption (E5) and calls (E6) are not, so no release
  says "end-to-end encrypted" yet (`docs/superpowers/specs/2026-11-22-e2ee-design.md` §10).
  Bot messages, files and messages from before the upgrade are stored readable by the operator.
- Call recording or third-party hosted calling SaaS.


## Planned guest-meeting qualification

Owner-approved hosted suite priority 3 (2026-11-23), after critical tenancy, isolation,
reliability, security and launch/startup gates: validate existing KyMessages meeting capability,
then scope external-person browser invitation/join links, screen sharing and host controls.
This extends the existing product; it does not create another meetings product or expand the
third-party installer catalog. Existing link/lobby/call/screen-sharing code is not evidence of
hosted qualification. The [existing tenancy plan §15](superpowers/specs/2026-11-23-tenancy-design.md#15-owner-approved-guest-meeting-planning)
records the acceptance inventory and still-unselected host permissions, limits and guest-media
encryption contracts. Guest confinement and the existing call-encryption release gate remain.

No first-party password manager is planned; compatibility with existing managers is sufficient
and no new integration is required. VPN/AI are optional, with no new work requested.
