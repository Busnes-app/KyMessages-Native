# KyMessages

Private team conversations, voice and video calls, and guest meetings on infrastructure you control.

KyMessages is a native chat, calling, and operator console server built as a single Go binary with an embedded React/TypeScript Progressive Web App (PWA). It ships direct messages, group channels, threads, reactions, attachments, Web Push notifications, native bot/agent accounts, hybrid WebRTC calling with optional LiveKit SFU escalation, KyCalendar guest meetings, KyIdentity SSO/directory sync, SCIM 2.0, and encrypted KyRecovery backup capsules.

This native server supersedes the earlier Matrix-based `KyMessage-Server` architecture (now retired; historical Matrix-era specifications remain archived under `docs/superpowers/`).

## Documentation

- [Product definition](docs/PRODUCT.md) — shipped capabilities, encryption status, tenancy scope, and roadmap
- [Reverse proxy and media networking](docs/Reverse_Proxy_Networking.md) — `cloudflared`, `nginx`, WebSockets, and optional LiveKit SFU routing
- [Server restore runbook](docs/RESTORE.md) — offline KyRecovery capsule and encrypted attachment restoration
- [Installer setup boundary](docs/INSTALLER_SETUP.md) — container-local `apply-setup` contract for KyQuickStart
- [Agent skill](agent-skill/kymessages/SKILL.md) — `kymessages` skill for OpenClaw and Hermes Agent accounts
- [Repository contracts](AGENTS.md) — DOX architecture, tenancy invariants, and verification gates

## Build and inspect locally

Use the Go version in `go.mod` and a Node version supported by the pinned frontend packages in `web/package.json`. The committed `web/dist` bundle is embedded into the Go binary; rebuild it after UI changes:

```sh
make all
./kymessages version
```

To inspect the app and operator console with disposable local data, set a bootstrap password without putting it in shell history, then bind the server to loopback:

```sh
read -r -s -p 'Bootstrap operator password: ' KY_ADMIN_PASSWORD
export KY_ADMIN_PASSWORD
KY_HOST=127.0.0.1 ./kymessages
```

Open `http://localhost:8080`. Replace the bootstrap password before privileged use, then enable two-factor authentication under **Settings > Account security**.

To create or reset the local administrator from a shell, run:

```sh
./kymessages init-admin [-username <name>]
```

`init-admin` reads the password from stdin (no echo on a terminal) and never accepts a password on the command line. The local administrator operates the service; everyday team sign-in uses KyIdentity OIDC. The default data directory is `./data`; keep `data/encryption.key`, `data/attachments.key`, and `data/vapid.key` with the database. `make clean` removes build artifacts only, never runtime data or backups.

## Container image and Docker Compose

`docker-compose.yml` runs the published container image `ghcr.io/busnes-app/kymessage-server:stable`. Each published release `vX.Y.Z` is also tagged `:X.Y.Z` with an SBOM and GitHub build provenance attestation after all CI jobs pass on the tagged commit. To pin a specific release by digest after verifying its attestation, set `KY_IMAGE` in `.env` (see the verification snippet in `docker-compose.yml`).

Protect `.env` with mode `0600` and export `KY_ADMIN_PASSWORD` as above. The container never runs as root: create `./data` and `./backups` as your unprivileged user and set `KY_UID` and `KY_GID` in `.env` to your `id -u` and `id -g` (Compose refuses to start without them). The container drops all Linux capabilities, disables privilege escalation, and runs with a read-only root filesystem (only `./data`, `./backups`, and `/tmp` are writable).

```sh
mkdir -p data backups
docker compose up -d
```

By default, Compose binds port `8080` to `127.0.0.1`.

### Compose overlays

Compose overlays are combined via `COMPOSE_FILE` in `.env` — append new overlays rather than replacing the existing chain with an ad-hoc `-f` list:

- **`docker-compose.build.yml`** — builds the local checkout as `kymessages:local` (`COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml`, then `docker compose up --build`).
- **`docker-compose.proxy.yml`** — production reverse-proxy mode (`KY_ENV=production`, publishes no host ports, creates `kymessages-net`, requires `KY_APP_URL`, `KY_SESSION_SECRET`, and `KY_TRUSTED_PROXIES`). See [docs/Reverse_Proxy_Networking.md](docs/Reverse_Proxy_Networking.md).
- **`docker-compose.static-ip.yml`** — pins the container IP on `kymessages-net` (requires `KY_CONTAINER_IP` and `KY_NETWORK_SUBNET`).
- **`docker-compose.lan-dns.yml`** — sets an explicit resolver via `KY_DNS`.

## Capabilities overview

- **Messaging and realtime:** Direct messages, group channels, threads, reactions, mentions, typing indicators, read receipts, file/image attachments with inline thumbnails, native WebSocket delivery (`/api/v1/ws`), and on-device encrypted IndexedDB message search.
- **Encryption status:** Room messages and edits are end-to-end encrypted in the web client using vodozemac (Olm/Megolm) compiled to WebAssembly (`web/crypto`). Identity verification, bot devices, encrypted attachments, and call media encryption are still in progress, so releases do not yet carry an end-to-end encrypted release claim — see [docs/PRODUCT.md](docs/PRODUCT.md) for exact boundaries.
- **Voice, video, and meetings:** Direct P2P WebRTC signaling over `/api/v1/ws` works out of the box with no extra services. Configure `KY_LIVEKIT_*` for optional LiveKit SFU escalation in larger group calls. Configure `KY_MEETING_SYNC_SECRET` for KyCalendar meeting room sync and time-bounded external guest links (`/api/meet/{token}`) with host-approved lobby admission.
- **Web Push notifications:** Installable PWA with RFC 8291/8292 Web Push delivery (`KY_PUSH_ENABLED=true` by default). Push payloads carry sender/room notification metadata only, never message text.
- **Native agent accounts:** Admins can provision `agent-<name>` bot accounts owned by a team member under **Agents** in the operator console, issuing one-time `kybot_` bearer tokens alongside ready-to-use OpenClaw and Hermes Agent config blocks and the downloadable `kymessages` skill (`agent-skill/kymessages/`). Tokens unused for 90 days are revoked automatically, and agents follow their owner's KyIdentity offboarding state.
- **Operator console (`/console`):** Built-in admin UI with 10-minute step-up re-authentication and full audit logging covering service health, network-path checks, users/sessions, agents, media policy, workspace branding, SCIM/KyIdentity directory sync, backup schedules/drills, and read-only audit logs.
- **Backups and restore:** Single-tenant SQLite deployments support scheduled and on-demand sealed KyRecovery capsules plus an encrypted incremental attachment mirror (`KY_BACKUP_DIR/attachments`). See [docs/RESTORE.md](docs/RESTORE.md) before relying on backups.

## Configuration

Key environment variables (see `internal/config/config.go` and `docker-compose.yml` for the full set):

| Variable | Purpose |
| --- | --- |
| `KY_APP_NAME` | Default `KyMessages`; also the backup capsule service name pinned at KyRecovery pairing |
| `KY_APP_URL` | Exact public origin used for OIDC callbacks and browser `Origin` checks |
| `KY_ENV` | `development` (default) or `production` (requires `KY_SESSION_SECRET` and `https://` `KY_APP_URL` unless `KY_COOKIE_SECURE=false`) |
| `KY_HOST`, `KY_PORT` | Listen address and port (defaults `0.0.0.0` / `8080` in container; bind `127.0.0.1` for local preview) |
| `KY_ADMIN_USERNAME`, `KY_ADMIN_PASSWORD` | Initial local operator account created on an empty database (`KY_ADMIN_USERNAME` defaults to `admin`; must be replaced before privileged use) |
| `KY_SESSION_SECRET` | Durable signing secret for sessions (generate once with `openssl rand -hex 32`) |
| `KY_COOKIE_SECURE` | Defaults to `true` in production or for `https://` `KY_APP_URL`; enables HSTS and `__Host-` cookie prefixes when `KY_COOKIE_DOMAIN` is unset |
| `KY_TRUSTED_PROXIES` | Comma-separated `/32` IP addresses of the reverse proxy only (never a whole bridge subnet) |
| `KY_DB_DRIVER` | `sqlite` (default, supported single-instance release target) or `postgres` (with PostgreSQL DSN) |
| `KY_DATA_DIR` | Runtime state directory (default `./data`; `/app/data` in Compose) |
| `KY_TENANCY_MODE` | `single` (default). `multi` startup remains gated until the hosted multi-tenant build is complete |
| `KY_SSO_ENABLED` | Default `true`; set `false` to disable KyIdentity OIDC routes |
| `KY_KYIDENTITY_ISSUER`, `KY_KYIDENTITY_CLIENT_ID`, `KY_KYIDENTITY_SECRET` | KyIdentity OIDC client; register `<KY_APP_URL>/api/sso/kyidentity/callback` and `<KY_APP_URL>/api/sso/kyidentity/logout` |
| `KY_KYIDENTITY_HMAC_SECRET` | Signing secret for KyIdentity directory webhooks (`<KY_APP_URL>/api/sso/kyidentity/sync`) |
| `KY_SCIM_ENABLED`, `KY_SCIM_TOKEN` | Optional inbound SCIM 2.0 provisioning (disabled when managed by `apply-setup`) |
| `KY_ATTACHMENTS_DIR`, `KY_MAX_UPLOAD_BYTES` | Attachment blob directory (default `<KY_DATA_DIR>/attachments`) and per-file upload cap (default 25 MiB, max 100 MiB) |
| `KY_PUSH_ENABLED`, `KY_VAPID_PRIVATE_KEY`, `KY_VAPID_SUBJECT` | Web Push delivery (enabled by default; auto-generates `data/vapid.key` if unset) |
| `KY_STUN_URLS` | Comma-separated `stun:`/`stuns:` URIs for WebRTC calls |
| `KY_LIVEKIT_URL`, `KY_LIVEKIT_API_KEY`, `KY_LIVEKIT_API_SECRET` | Optional LiveKit SFU origin and credentials (`*_FILE` variants supported) |
| `KY_MEETING_SYNC_SECRET` | Shared HMAC secret for KyCalendar meeting sync (`/api/meetings/{id}`) |
| `KY_BACKUP_DIR`, `KY_BACKUP_KEEP`, `KY_BACKUP_DEPOSIT_INTERVAL` | Local sealed capsule copies (keep newest 7, interval `24h` by default) |
| `KY_BACKUP_ALLOW_PRIVATE_RECOVERY` | Opt-in for LAN KyRecovery destinations (`false` by default; HTTPS remains mandatory) |

## CLI subcommands

The `kymessages` binary accepts:

- `kymessages` — start the HTTP/WebSocket server
- `kymessages init-admin [-username <name>]` — create or reset the local operator account (reads password from stdin)
- `kymessages apply-setup --file <path> [--check] [--restart] [--capabilities]` — container-local installer setup boundary ([docs/INSTALLER_SETUP.md](docs/INSTALLER_SETUP.md))
- `kymessages deposit` / `export-capsule` / `backup-drill` — seal and test SQLite server capsules
- `kymessages restore` / `restore-attachments` / `invalidate-grants` — offline disaster recovery ([docs/RESTORE.md](docs/RESTORE.md))
- `kymessages version` — print the server version

## Verification

Run the standard local CI checks with:

```sh
make ci
```

`make ci` runs `go mod tidy` verification, `gofmt`, `go vet`, Compose proxy/hardening checks (`scripts/check-compose-proxy.sh`), build-tag checks (`scripts/check-build-tags.sh`), Go race tests with coverage on SQLite, frontend unit tests (`web/`), and the live binary smoke test (`scripts/smoke-test.sh`).

Additional checks run by `.github/workflows/ci.yml`:

- `make test-postgres` — Go test suite against PostgreSQL 18
- S3 attachment integration tests (`internal/blobs/`)
- Rust/WASM crypto core tests, Clippy, and reproducible build check (`web/crypto/build.sh`)
- Chromium and Firefox browser regressions against a built production server (`web/browser/`)
- `python3 scripts/backup-acceptance.py` — live backup scheduler and local-mirror acceptance test
- `govulncheck`, `npm audit --audit-level=high`, and Docker release-build verification

Publishing a GitHub release `vX.Y.Z` triggers `.github/workflows/release-image.yml`, which verifies version consistency across `internal/config/config.go`, `web/package.json`, and `web/package-lock.json`, requires every CI job to have passed on the tagged commit, publishes and attests `:X.Y.Z`, and advances `:stable` for non-prerelease latest versions.

## Container-local installer integration

KyQuickStart configures KyMessages through `kymessages apply-setup`; see [docs/INSTALLER_SETUP.md](docs/INSTALLER_SETUP.md) for the `ky.product-setup/1` contract, protected credential files, and deployment gates.

## License

See [LICENSE.txt](LICENSE.txt).
