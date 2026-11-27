# Config

## Purpose
Manages environment and file-based configuration loading, defaults, and type conversions for KyMessages.

## Ownership
Owns environment variable parsing, configuration validation, default fallbacks, and security key generations.

## Local Contracts
- `DefaultAppName` is `KyMessages`; it is the default capsule service name as well
  as the visible product name. Keep explicit `KY_APP_NAME` overrides for already
  pinned recovery service names. `AppVersion` supplies CLI and HTTP/scheduled capsule
  paths so they cannot report different build versions.
- `LoadFromEnv() (*Config, error)` must supply safe, valid defaults for all subsystems.
- An empty boolean variable is unset and takes its default, like every other `getEnv*` helper; it never means false.
- Never log plaintext secrets or sensitive tokens.
- `KY_TRUSTED_PROXIES` is a comma-separated list of reverse-proxy IPs or CIDRs, empty by default, parsed once at startup into `[]netip.Prefix`; an unparsable entry fails startup. Only a request whose peer address is in the list may speak for another client through `X-Forwarded-For`. `0.0.0.0/0` and `::/0` are refused at startup; list only the proxy's own address or subnet.
- `KY_COOKIE_SECURE` (which also enables HSTS on the `KY_APP_URL` host) defaults to true when `KY_ENV=production` or `KY_APP_URL` is https. Production with a non-https app URL fails startup unless `KY_COOKIE_SECURE=false` is set explicitly.
- `KY_DB_DRIVER` is `sqlite` (default; DSN under `KY_DATA_DIR`) or `postgres`/`postgresql`, which requires `KY_DB_DSN` in every environment (`TestPostgresRequiresAnExplicitDSN`): there is no guessed default connection. Tests reach Postgres through `KY_TEST_POSTGRES_DSN` (`internal/testdb`), not this.
- `KY_SESSION_SECRET` signs proof-of-work challenges. A supplied value must be at least 32 bytes, and production and multi mode require an explicit value. Single-mode development generates a secret from 32 random bytes if unset. The encryption key comes from `KY_ENCRYPTION_KEY` when set, otherwise from the keyfile at `<DataDir>/encryption.key`, which `keyfile.LoadOrCreate` mints on first start.

- `KY_BACKUP_DEPOSIT_INTERVAL` is a Go duration (default `24h`), only the default for the schedule the admin screen stores; `0` is off, anything else below `MinDepositInterval` (15m) or negative fails startup. `KY_BACKUP_DIR` (default empty, off) is the sealed local-copy directory and `KY_BACKUP_KEEP` (default 7) how many to retain; below 1 fails startup because the lib refuses it at write time. `KY_BACKUP_ALLOW_PRIVATE_RECOVERY` (default false) admits RFC1918 and CGNAT KyRecovery destinations only.

- Suite sign-in reads `KY_KYIDENTITY_ISSUER`, `KY_KYIDENTITY_CLIENT_ID`, `KY_KYIDENTITY_SECRET` and `KY_KYIDENTITY_HMAC_SECRET`. Any nonempty `KY_KYSIGNON_*` fails startup naming its replacement, so a secret under the old name cannot leave sign-in silently unconfigured.

- Attachments fill `Config.Attachments`: `KY_ATTACHMENTS_DIR` (default `<KY_DATA_DIR>/attachments`), `KY_MAX_UPLOAD_BYTES` (per file, default 25 MiB, 1024 to 100 MiB), `KY_ATTACHMENTS_MAX_TOTAL_BYTES` (per tenant, default 1 GiB; ignored in multi mode, where each org's storage pool applies), `KY_ATTACHMENTS_MAX_PENDING_USER_BYTES` (one uploader's staged bytes, default 50 MiB) and `KY_ATTACHMENTS_PENDING_TTL` (staged lifetime, default 24h, 1m to 720h). The byte limits must be at least 1024, and `KY_MAX_UPLOAD_BYTES` cannot exceed `KY_ATTACHMENTS_MAX_PENDING_USER_BYTES` or `KY_ATTACHMENTS_MAX_TOTAL_BYTES` (every upload is staged first); a value out of range or inconsistent fails startup.

- `KY_ADMIN_USERNAME` (default `admin`) is `Security.AdminUsername`: the local admin `cmd/server` creates on an empty database and `init-admin`'s `-username` default. It must pass `ValidUsername` (3-64 of `[A-Za-z0-9._-]`, the rule `auth.ValidateUsername` shares), else startup fails.
- `KY_SCIM_TOKEN` is `SCIM.BearerToken`; unset, it is random per start and `SCIM.TokenSet` (`json:"-"`) is false, which the console reports without the token. The installer clears both.
- `LoadFromEnv` accepts `KY_TENANCY_MODE` unset or `single`. For `multi` it checks every multi requirement (below, plus `KY_ATTACHMENTS_S3_*`: no attachment disk in multi mode) in every build, then a release build refuses with `ErrMultiTenantRelease`. Multi mode never creates key files, so the refusal leaves nothing behind.
- The build gate is the constant `multiTenantBuild`: `false` in `gate_release.go`, `true` only in `gate_kye2e.go` (`go build -tags kye2e`, for KyCalendar's cross-app e2e run). No env, flag or `-ldflags -X` reaches it. A `kye2e` binary refuses, in either mode, any `KY_KYIDENTITY_ISSUER` that is not https under `.test`. `TestBuildGate*` run untagged and tagged in CI, expecting what `gate_*_test.go` (set by the same tag, not read from the gate) says; `scripts/check-build-tags.sh` keeps the tag out of every other file than those four and all tags out of release build inputs; `scripts/check-release-build.sh IMAGE` (CI `docker` job, release workflow before push) fails on a tagged binary or one that does not refuse a complete multi config.
- The gated multi configuration (`LoadForTenancy`, tests only) forces `SCIM.Enabled` off and requires `KY_DB_DRIVER=postgres` plus `KY_STAFF_ORG_ID` (`Tenancy.StaffOrgID`) as a canonical lowercase UUID (`IsCanonicalUUID`); `Tenancy.MayAdminister` allows the admin role only for that org. It also requires secrets every replica shares and never mints one: `KY_SESSION_SECRET`, `KY_ENCRYPTION_KEY` or an existing `<KY_DATA_DIR>/encryption.key` (`keyfile.Load`, not `LoadOrCreate`), and, unless `KY_PUSH_ENABLED=false`, `KY_VAPID_PRIVATE_KEY` or an existing `<KY_DATA_DIR>/vapid.key` (`multi_requires_shared_secrets`). Single mode keeps minting its files.
- `KY_KYPOST_URL`/`KY_KYPOST_SECRET_FILE` and `KY_KYCALENDAR_URL`/`KY_KYCALENDAR_SECRET_FILE` fill `Config.KyPost`/`Config.KyCalendar` (`PairConfig`; both or neither, `PeerOrigin` https origin, secret ≥ 32 bytes, `json:"-"`). Unset, the pair comes from KyIdentity's suite directory.
- Web Push fills `Config.Push`: `KY_PUSH_ENABLED` (default true; false means no dispatcher and bootstrap reports push unavailable), `KY_VAPID_PRIVATE_KEY` (overrides `<KY_DATA_DIR>/vapid.key`) and `KY_VAPID_SUBJECT` (else derived from `KY_APP_URL`). `Push.AllowPrivate` is tests only.
- `KY_CAPTCHA_PROVIDER` is `pow` (default) or `none`; anything else fails startup, because login verifies nothing else. `KY_CAPTCHA_POW_DIFFICULTY` defaults to 50000.

- Calls and meetings fill `Config.RTC`: optional LiveKit SFU via `KY_LIVEKIT_URL` (`http(s)` or `ws(s)` origin), `KY_LIVEKIT_API_KEY` / `KY_LIVEKIT_API_KEY_FILE`, and `KY_LIVEKIT_API_SECRET` / `KY_LIVEKIT_API_SECRET_FILE` (all three must be set together, or all unset for P2P-only calling). Secret files override environment values. The effective secret must be at least 32 bytes after trimming whitespace. Credentials are `json:"-"`. `KY_STUN_URLS` (default `stun:stun.l.google.com:19302`) accepts comma-separated `stun:`/`stuns:` URLs. KyCalendar meetings are signed with the `Config.KyCalendar` pair secret. A set `KY_MEETING_SYNC_SECRET` stops startup (`TestMeetingSyncSecretFailsStartup`).

- `ApplyInstallerConfiguration` narrows `ky.product-setup/1` (`kymessage`) into a startup
  snapshot with protected OIDC/directory file references. Explicit conflicting SSO, SCIM,
  automatic provisioning and unsupported recovery pairing are refused before writes.
  Restart applies committed config through the existing graceful shutdown/drain path.

- `LoadForMaintenance` is the offline `invalidate-grants` loader: it validates the full deployment configuration while accepting multi mode. Server startup exclusively uses the gated `LoadFromEnv`.

## Verification
- `go test -v ./internal/config/...`
- `go test -v ./internal/auth/ -run TestClientIP` (the helper that consumes the allowlist)

## Child DOX Index
None.
