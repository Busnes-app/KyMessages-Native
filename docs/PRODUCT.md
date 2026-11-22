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

- **One binary, two tenancy modes:**
  - `KY_TENANCY_MODE=single` (default): self-hosted single-organization deployment backed by
    SQLite (zero external dependencies) or PostgreSQL.
  - `KY_TENANCY_MODE=multi`: multi-organization SaaS deployment isolating multiple KyIdentity
    organizations strictly by verified `org_id` inside one deployment. Tenancy mode is locked in
    the database on first boot and cannot be flipped in place.
- **Invite-only:** accounts come from KyIdentity (OIDC + signed directory sync webhooks) or local
  admin provisioning in single-tenant mode. No public sign-up. External guests can join only
  scheduled or instant meeting rooms through time-bounded guest links with host-approved lobby
  admission.
- **Ky-integrated:** KyIdentity sign-in and real-time offboarding, KyCalendar meeting room sync,
  KyRecovery sealed server backups, and the KyMessages operator console.

## What ships

**Messaging & realtime.**
- Direct messages, group channels, threads, reactions, mentions (`@username`, `@here`, `@channel`),
  typing indicators, read receipts, unread badges, and full-text search (SQLite FTS5 / Postgres
  `tsvector`).
- Native WebSocket fan-out (`/api/v1/ws`) with presence and immediate revocation disconnects.
- File and image attachments stored on local disk (`KY_ATTACHMENTS_DIR`) with SHA-256 content
  hashing, per-upload/per-user/per-tenant quotas, inline image thumbnails, and encrypted backup
  mirroring.
- Incoming room webhooks (`/api/v1/webhooks/in/{id}`) with hashed bearer tokens and per-org status
  enforcement.

**Voice, video & KyCalendar meetings.**
- Hybrid calling: direct peer-to-peer WebRTC (signaled over `/api/v1/ws`) for 1:1 / small calls,
  with optional LiveKit SFU (`KY_LIVEKIT_URL`, `KY_LIVEKIT_API_KEY`, `KY_LIVEKIT_API_SECRET`) for
  larger group calls and automatic escalation.
- KyCalendar meeting sync (`PUT`/`DELETE /api/meetings/{id}`, signed with `KY_MEETING_SYNC_SECRET`)
  creates meeting-scoped rooms with scheduled time windows, attendee resolution, and external
  guest links (`/api/meet/{token}`) gated by an interactive waiting-room lobby.
- Instant meetings (`POST /api/v1/meetings`) and room guest invite links
  (`POST /api/v1/rooms/{id}/meeting/guest-link`) for ad-hoc external calls.

**Web Push notifications & PWA.**
- Installable Progressive Web App with a service worker (`web/public/sw.js`) and RFC 8291/8292
  Web Push delivery (`internal/push`) using a self-generated or operator-supplied VAPID P-256 key
  (`data/vapid.key` or `KY_VAPID_PRIVATE_KEY`, `KY_VAPID_SUBJECT`; disable with
  `KY_PUSH_ENABLED=false`).
- Per-room notification preferences (`all`, `mentions`, `mute`), push subscription management
  (`/api/v1/push/*`), and automatic pruning of stale `404`/`410` browser endpoints.

**Sign-in, tenancy & offboarding.**
- Primary sign-in via KyIdentity OIDC (`KY_KYIDENTITY_*`) with PKCE and step-up freshness checks
  for privileged console actions.
- Signed KyIdentity directory webhooks (`POST /api/sso/kyidentity/sync`) synchronize user creation,
  profile updates, deactivation, deletion, MFA resets, and — in `KY_TENANCY_MODE=multi` — org
  lifecycle events (`org.suspended`, `org.unsuspended`, `org.deleted`). Each carries KyIdentity's
  per-org `revision`; one at or below the last applied revision changes nothing, so a delayed
  event never undoes a newer one, and deletion is never undone. Tenant status is read from the
  primary database, never a read replica.
- Deactivation, deletion, or org suspension immediately revokes sessions, push subscriptions, and
  active WebSocket connections, and blocks API calls, incoming webhooks, and guest meeting links.
  No new session, MFA challenge or pairing is issued to an inactive org, including one in flight
  when the suspension lands. Org suspension or deletion also ejects that org's meeting guests, waiting or admitted, from the
  lobby, their sockets and their calls on every server instance.
- In `KY_TENANCY_MODE=multi`, every user account is bound immutably to `(sub, org_id)`, tokens or
  webhooks without `org_id` are refused, cross-org `org_id` reassignment is rejected with HTTP 409
  and audited (`sso.org_mismatch`), and inbound SCIM (`/scim/v2/*`) is forced off (404).
- In `KY_TENANCY_MODE=multi`, customer orgs have no administrators. An `admin` role from KyIdentity
  is honoured only for the staff org named by `KY_STAFF_ORG_ID` (unset: no directory
  administrators), and the console refuses any account bound to another org or to an inactive
  staff org. Local operator accounts, which belong to no org, keep the install-wide console
  (backups, audit, health, settings); per-org pages (Agents, Media policy) need a staff-org
  administrator and answer 403 to an account with no org.
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
- Client-side end-to-end encryption (messages are protected in transit via TLS and stored on the
  operator's database with server-side full-text search and native attachment storage).
- Call recording or third-party hosted calling SaaS.
