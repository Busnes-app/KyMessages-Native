# KyMessages installer boundary

Run `/app/kymessages apply-setup --file /app/data/installer/bundle.json` inside the selected
running container (any absolute path; stock Compose's writable data directory is `/app/data`).
`--check` compares retained authority/config and its runtime snapshot without audits, account
changes, migrations, or key creation. `--capabilities` reads no configuration. The setup CLI reads
`KY_DATA_DIR` (default `./data`); it must match the running server.

## With the stock Compose files

A refusal prints `product setup refused or is busy (a refusal's reason is in the server log: ...)`;
`docker logs kymessages` shows `[INSTALLER] setup refused: <reason>`. Each start re-applies the
stored setup, so a conflicting environment override added later stops the server with
`Installer configuration unavailable: ...`. Setup refuses to replace an operator's explicit choice:

- Leave `KY_SCIM_ENABLED`, `KY_SCIM_TOKEN`, `KY_BACKUP_KEEP`, and `KY_BACKUP_DEPOSIT_INTERVAL`
  unset in `.env`; Compose passes them only when set. Setup turns inbound SCIM off.
- `KY_KYIDENTITY_ISSUER`, `KY_KYIDENTITY_CLIENT_ID`, `KY_KYIDENTITY_SECRET`, and
  `KY_KYIDENTITY_HMAC_SECRET` must be unset or equal to the setup's values.
- `KY_BACKUP_DIR` is `/app/backups`, the container's writable backup location; a setup
  `backup.directory` must be `/app/backups` or omitted.
- `KY_TENANCY_MODE` defaults to `single` for self-hosted installer deployments. If set to `multi`,
  the database locks to multi-tenant mode on first boot, inbound SCIM is permanently disabled
  (`/scim/v2/*` returns JSON 404), and every OIDC sign-in and directory webhook must carry a
  verified `org_id`. Set `KY_STAFF_ORG_ID` to KyIdentity's staff org: only its accounts may be
  administrators, and customer orgs have none.

## Setup bundle contract (`ky.product-setup/1`)

The common `ky.product-setup/1` service name is `kymessage`, distinct from the default product and
capsule name `KyMessages`. Inputs include:

- `setupId` UUID
- `sso`: canonical HTTPS issuer, client ID, protected absolute client/directory credential paths,
  and exact callback URL (`<KY_APP_URL>/api/sso/kyidentity/callback`)
- At least one dedicated `admins` identity and optional `everyday` identities, each with exact
  issuer, subject, and a valid unique username.

Credential files must be process-owned regular `0600` files; inputs carry file paths, never
plaintext secrets. Use a dedicated OIDC client with assigned users only and a directory webhook
that emits app role `kymessage.admin` for console administrators.

Configuration, new subjects, ownership, and native SQL audit commit atomically in one transaction.
Existing account names/subjects and conflicting configuration are refused, never adopted. The
setup envelope is immutable; a rerun inspects it without creating duplicate accounts or audits.
A drifted, offboarded, or missing owned identity requires explicit operator resolution and is
never silently repaired.

Committed configuration awaiting runtime activation reports `pending: activation/restart`.
`apply-setup --restart` requests a graceful server shutdown over private IPC so HTTP requests,
WebSocket connections, and detached work drain cleanly before the container restart policy brings
the server back up. KyQuickStart verifies the activated snapshot before reporting success.

## Authentication, directory sync & revocation

- Sign-in requires a verified OIDC ID token matching the exact owned issuer, subject, username,
  and role (plus verified `org_id` in `KY_TENANCY_MODE=multi`). Global admin claims, email, and
  username alone do not grant console access. Missing protected credential files fail closed.
- Independent local recovery administrators retain their native login and mandatory password
  replacement rules in single-tenant deployments.
- `POST /api/installer/directory` (and `/api/sso/kyidentity/sync`) accepts signed SCIM User
  desired-state events (plus `org.suspended`, `org.unsuspended`, and `org.deleted` lifecycle
  webhooks in multi-tenant mode, each with KyIdentity's per-org `revision`; a stale one is ignored). Canonical positive `meta.version` revisions and body/event
  digests are stored transactionally so exact retries are idempotent and stale/conflicting
  revisions fail cleanly.
- Offboarding (`active: false` / deletion), `user.mfa_reset`, and org suspension immediately
  revoke active sessions, MFA challenges, device pairings, Web Push subscriptions, and live
  WebSocket connections in the same revocation flow, preventing in-flight sign-ins or pairings
  from minting grants afterwards. Deletion retains `deleted` status permanently; later activation
  is refused.
- `GET /api/installer/network` exposes only client address, header trust, and scheme with
  `Cache-Control: no-store`, sharing `KY_TRUSTED_PROXIES` resolution with rate limiting, sessions,
  and audit logs.

## Backups with installer credentials

Managed sealed capsules include the installer client/directory credential files and their recorded
path map (`installer/credential-paths.json`). Restore those protected files (`0600`, process-owned)
to their original locations before restarting the restored server. Both the console and the CLI
commands (`deposit`, `export-capsule`, `backup-drill`) load the stored setup and seal these
credentials; `backup-drill` exits non-zero if any check fails.
