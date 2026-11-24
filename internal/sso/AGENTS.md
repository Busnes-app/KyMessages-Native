# SSO

## Purpose
Provides KyIdentity sign-in (OpenID Connect) and KyIdentity's signed directory sync webhooks. There is no generic OIDC or SAML provider.

## Ownership
Owns the application adapters around KyIdentity OAuth/OIDC login and the HMAC-SHA256 signed directory sync webhooks. `syncstatus.go` owns the webhook record and the rejection counters.

## Local Contracts
- Org-list `quotas` is a JSON object: optional integer `max_upload_bytes` (1 KiB–100 MiB) and `max_pending_user_bytes` (1 KiB–2^53 bytes); omitted keys use install safety limits and configured values only narrow them. Unknown keys, null, noninteger or out-of-range values suspend that org rather than silently relaxing limits. Fixing a conflicting snapshot requires a newer org revision. The shared storage pool is independent. Explicit deleted listings retain a tombstone even for an org never held locally.

- `VerifyLogout` accepts only RS256 `logout+jwt` for the configured issuer/client, with a
  two-minute iat/exp window, jti, subject, back-channel event and no nonce/token_use.
  Multi mode requires a canonical org_id; the database compares it with the subject's account.
- `user.mfa_reset` uses `ResetDirectoryMFA`: independent reset replay record, credential fence
  and all grant/push deletion commit together without a profile upsert. Newer profile events
  cannot suppress an unseen reset; duplicate reset delivery preserves a later sign-in. Restore
  generations permit newly reused revisions while keeping old event IDs spent. A delayed reset
  after recorded deletion is an acknowledged no-op. Both reset and deletion compare an existing
  account's org_id before writing. Managed directory events apply the same binding check.
- `KyIdentityClient.HandleSyncWebhook` implements KyIdentity's suite-webhook contract: a bare SCIM 2.0 User body verified with `ky-primitives/syncauth` (event type and ID are signed headers, ±5 minutes) before any local change. Events: `user.created`, `user.updated` (`active:false` deactivates), `user.mfa_reset`, `user.deleted` and, in multi mode, `user.erased`; others (and `user.erased` in single mode) are ignored with success.
- `user.erased` (multi mode) is the bare inactive SCIM user with `org_id` (canonical UUID, else 400) and no `meta`. Under `syncMu` it erases every account the subject had: its current row and each kept in `user_subjects` (`ErasureTargets`). An accepted subject gets a permanent `erased_subjects` fence even when never held; a known different-org binding is acknowledged without change (audited `sso.org_mismatch`). Repeats retain the same fence and cleanup targets. Otherwise it calls `OnUserErased` (the API revokes the person's sockets, deletes their blobs, then `store.EraseUser`); an error fails the delivery so KyIdentity retries.
- Tenancy sync (`tenancy_sync.go`, multi mode). `SyncTenancy(full, startup)` reads `suitedir.Orgs` and `GET /api/suite/erased` (`SuiteRequest`: Basic suite credentials, https issuer, no redirects, bounded answer). The erased list is read and applied before org admission; failure cannot admit a restored org first. Both lists are read to their end in one run (the org list resumes past suitedir's page bound; the erased list has no page cap). An active listing with this app disabled is enforced as suspended. Listed orgs apply through `ApplyTenantDirectory` by their revision (`deletion_scheduled` and `suspended` stop serving; `deleted` is terminal), and every listed org whose resulting status is not active is revoked again, so a revocation that failed is retried. Listed subjects erase through `eraseSubject` (the same path as `user.erased`). Revisions are stored in `tenancy.orgs_revision` and `tenancy.erased_revision`, so a restore that rewinds them replays what it undid. Only a complete full read (`since=0`, not cut at the page bound) checks for missing orgs: an active org it does not list is held offline (`MarkTenantMissing`: suspended, `missing_since` set, revision untouched, audited `tenancy.org_missing`), unless more than max(5% of active, 3), or more than half the customer orgs, are missing (none held, `tenancy.sync_aborted`; an empty list never passes, `TestTenancySyncSmallInstallGuard`) or it is a start-up read (alert only). A missing org listed active again serves (`tenancy.org_found`) only if no newer lifecycle event applied meanwhile: `ClearTenantMissing` checks the listed revision, and `ApplyTenantLifecycle` clears the flag only when it applies, so a stale non-active listing changes nothing (`TestTenancySyncStaleListingCannotUndoANewerSuspension`, `TestTenancySyncStaleSuspendedListingKeepsRecovery`). `SuiteRequest` accepts an http issuer on `localhost` or a loopback address. Nothing here ever purges. `SettingFullSyncAt` advances only after a non-startup full read enforces missing detection, so successful restarts cannot postpone background reconciliation indefinitely. `StartupSync` is the full read before a replica serves; if KyIdentity cannot answer it may serve only on a `tenancy.kyidentity_synced_at` younger than 24 h (`TestTenancyStartupSync`).
- With `TenancyConfig.Cells`, `applyListedOrg` skips an org of another cell that has no tenant row, records the listed `home_region` otherwise (another cell's org is suspended), and gives the staff org the first served cell.

- ID tokens' `export_only` claim fills `IdentityClaims.ExportOnly`; the API refuses such a sign-in in multi mode (`sso.export_only_refused`). The SCIM `id` is the OIDC `sub`. A primary role of `admin` maps to admin, anything else to user. Unauthenticated is 401, a body without `id` or `meta.version` is 400.
- An acknowledged delivery (applied, superseded or duplicate; the same set that wakes the sweep) writes `kyidentity_webhook_last` (`WebhookRecordKey`, `WebhookRecord{at, kind}`) on a detached 5 s context. `syncstatus.go` is its only writer; a failed write is logged, never a failed delivery. Refused deliveries (`ErrSyncUnauthorized`, `ErrSyncMalformed`, `ErrSyncUsernameConflict`) are counted in memory only (`Rejections()`: count since start, last time, last reason); bodies are never kept. Reasons: `not_configured` (secret unset or shorter than `syncauth.MinKeyBytes`), `bad_signature` (missing or not matching), `stale` (outside ±5 minutes), `bad_headers` (event type, ID or timestamp missing or unparseable), `malformed` (signed, but not a usable SCIM user), `username_conflict` (signed, but a `user.created` whose username another account holds).
- A username another account holds (`store.ErrUsernameTaken`, exact case, including a write that lost a race) is never merged into or alters that account, and is logged once and audited `sso.sync_conflict` (resource the username, details `subject="..."`, plus `kept="..."` on an update). Other refusals reach neither the database nor the audit log.
  - On `user.created` it is `ErrSyncUsernameConflict` naming the username: 409, counted as `username_conflict`, nothing written (the event stays unspent). KyIdentity takes a 409 on a create as delivered and never resends it, so recovery is manual: rename the local account (`KY_ADMIN_USERNAME` only applies to an empty database) or change the KyIdentity user, then press Resync Directory on the system in KyIdentity, which sends the user as a new event.
  - On `user.updated` only the rename is refused: the user keeps its stored username and everything else (status, role, email, name) applies, sessions are revoked on a status or role change, and the delivery is acknowledged. A deactivation or downgrade carried with a clashing rename can never be dropped, and a 409 here would be retried and then marked failed by KyIdentity, losing it. `ErrSyncUnauthorized` wraps its cause with `%w`, so reasons are told apart with `errors.Is`. A delivery that fails on the database (500) is neither recorded nor counted.
- PKCE with `S256` is enforced on all OAuth/OIDC authorization requests.
- New ID-token sign-ins require provider signature, issuer, audience, expiry, one-time nonce,
  nonempty sid and iat before claims are trusted; the verified binding is retained in the session.
- OAuth discovery, authorization URLs, PKCE parameters, code exchange, and token verification are delegated to `golang.org/x/oauth2` and `coreos/go-oidc`; application code only maps verified claims.
- Login does not require `auth_time`, but a plausible signed one (positive, not after `iat`
  or now) becomes `IdentityClaims.AuthenticatedAt`, the session's credential time for
  step-up; the callback time never stands in for it. `BuildAuthURL(..., fresh)` adds
  `prompt=login` and `max_age=0`.
- Every IdP call (discovery, keys, code exchange) uses a client with `idpTimeout` (10 s) unless the caller's context carries one (`oidc.ClientContext`, tests); discovery also runs under that deadline, so a hung IdP cannot queue sign-ins behind the flow's discovery mutex (`TestDiscoveryAgainstAHungIdPTimesOut`).
- Profile and deletion events are ordered by KyIdentity's per-user revision (`meta.version` `W/"n"`), never by timestamp or arrival. Updates apply one at a time and only through `ApplyDirectoryProfile`/`CreateDirectoryUser`/`DeleteDirectoryUser`, which apply only a revision newer than the subject's persisted one; equal or older revisions (outbox retries, delayed deliveries) succeed without effect, across restarts and after deletion. Deletions of subjects with no local account still record their revision. `-1` is KyIdentity's post-restore resend and resets the order. Because a reset lowers the stored revision, every delivered event ID is also spent permanently in `directory_sync_events`, applied or refused, atomically with the write; a redelivered event is acknowledged without effect even across a reset. Status or role changes revoke the user's sessions.

- Managed setup requires verified issuer/sub ownership and reads the client credential
  from its protected reference per flow. Native global roles, email and usernames do not
  authorize managed account creation or administration.
- In managed mode the suite sync route uses the installer directory handler: positive
  canonical revisions, exact duplicate digest acceptance, stale/conflicting refusal and
  app claim `kymessage.admin`. Native unmanaged webhook behavior remains independent.

- Every tenancy sync drains durable `tenant_pending_revocations` before applying any listing; a failed missing-org revocation remains queued independently of active-org discovery. Missing detection queues and drains the same work before reporting success.

## Verification
- `go test -v ./internal/sso/...`

## Child DOX Index
None.
