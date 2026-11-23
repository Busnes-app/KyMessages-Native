# KyMessages server restore

These instructions cover offline disaster recovery for the native KyMessages server using sealed
KyRecovery capsules (SQLite deployments) and the encrypted chat attachment mirror. Restore with
the published container image or a matching/newer build of this repository. Do not substitute the
upstream `ky-server-base` image: it does not include KyMessages' restore policy.

## What recovery can restore

The `ky-primitives/recoveryclient` adapter seals the server capsule:

| File | Contents |
|---|---|
| `data/ky_server.db` | SQLite snapshot: users, tenants/orgs, rooms, messages, meetings, agents, MFA state, settings, audit logs, and sealed recovery token |
| `data/encryption.key` | Deployment key needed to open stored MFA secrets and the recovery token |
| `data/attachments.key` | AES-256-GCM key that opens the encrypted attachment mirror |
| `data/vapid.key` | Web Push VAPID private key (preserved so browser push subscriptions survive key continuity checks after users re-subscribe) |
| `data/recovery.pub` | Pinned suite recovery public key, when configured |
| `config/settings.json` | App name, URL, port, and database driver for operator reference; not automatically loaded |
| `installer/*` | Sealed installer OIDC/directory credential files and path map, when installer-managed |

Attachment files are not stored inside the capsule. They live in `KY_BACKUP_DIR/attachments` as
an encrypted mirror. Copy `KY_BACKUP_DIR/attachments` off the host alongside the capsules; only
the capsule's `data/attachments.key` can decrypt them.

Custodians together can open the capsule, including its operational secrets and database snapshot.
KyRecovery cannot. The expanded capsule limit is 256 MiB (counted with tar framing; the product
reserves 1 MiB). A larger payload fails the run with its size, and the console warns from 75%.
Allow roughly 2 GiB of memory near the limit, plus scratch disk space equal to the live SQLite
database during snapshot creation.

Only SQLite capsule backup/restore is supported by `kymessages restore`. For PostgreSQL
deployments (`KY_DB_DRIVER=postgres`), use standard PostgreSQL backup/PITR tooling (`pg_dump` /
WAL archiving) alongside off-host copies of `data/encryption.key`, `data/attachments.key`,
`data/vapid.key`, and the attachment directory.

## Restore offline

1. Obtain the intended capsule from KyRecovery using an operator session, or from the configured
   local backup directory. Product deposit tokens cannot download capsules. Record the trusted
   receipt's capsule ID, creation time, and SHA-256 digest, and verify `sha256sum backup.kycap`
   against it before restoring. Know the exact service name (`KY_APP_NAME`) used when sealed.
   After any refused attempt, restore into a fresh empty directory.
2. Obtain the ceremony's threshold number of custodian cards. Use a private terminal; do not paste
   shares into chat, argv, environment variables, or shell history. The command reads shares from
   stdin. Never regenerate the suite recovery key to make a capsule open.
3. Run `restore` into a new or empty directory:

   ```sh
   go build -o kymessages ./cmd/server
   ./kymessages restore -capsule ./backup.kycap -to ./restored -service 'KyMessages'
   ```

   Replace `KyMessages` with the capsule's exact service name (`KY_APP_NAME` at backup time).
   Paste one `ky2-...` share per line, then Ctrl-D. The command verifies the capsule, service name,
   key binding, and strict ownership/permissions on every ancestor directory up to `/` before
   extracting. A nonempty target directory is refused untouched.
4. Compare the printed authenticated manifest's capsule ID, service, creation time, recovery key ID,
   and payload hash against your trusted records. Preserve the receipt.

After extraction, `kymessages restore` verifies a nonempty SQLite file and a valid 32-byte hex
deployment key, runs migrations (refusing a database created by a newer build: restore with that
build or newer), and in one transaction invalidates all pre-backup sessions, MFA challenges,
device pairings, and Web Push subscriptions while recording `restore.grants_invalidated`. It
also deletes every unclaimed end-to-end encryption one-time key and all to-device mail: a key
claimed after the backup would otherwise be handed out again although its device already spent
it, and restored mail was already read. Devices re-upload one-time keys when their count runs
low; fallback keys stay.

If extraction or preparation fails, extracted files are removed via directory handle and the
command exits non-zero; nothing partial is left to serve. Repeat into a fresh empty directory.

## Restore chat attachments

Restore encrypted attachments before starting the server:

```sh
./kymessages restore-attachments \
  -mirror <KY_BACKUP_DIR>/attachments \
  -data-dir ./restored/data \
  -to <KY_ATTACHMENTS_DIR>
```

`KY_ATTACHMENTS_DIR` defaults to `<data dir>/attachments`. The command creates the directory
(`0700`), reads the attachment keys referenced by `<data-dir>/ky_server.db`, and restores only
referenced blobs from the mirror (falling back to `.pruned` for blobs deleted after the capsule
was sealed, without overwriting active blobs or resurrecting unreferenced ones). Until this runs,
attachment downloads return 404.

## Return to service

- Do not run old and restored servers simultaneously behind the same origin. Stop the old process
  before cutover and preserve its data directory and logs for investigation. Never copy a snapshot
  over a running SQLite file or mix old `-wal`/`-shm` files with a restored database.
- Match the original deployment configuration deliberately:
  - Same `KY_APP_NAME`, HTTPS `KY_APP_URL`, and KyIdentity OIDC callback registration.
  - Same `KY_TENANCY_MODE` (`single` or `multi`), and in `multi` the same `KY_STAFF_ORG_ID`. The database records its locked tenancy mode
    (the `tenancy.mode` server setting) and refuses to boot if `KY_TENANCY_MODE` disagrees.
  - Use the restored `data/encryption.key`; remove any stale `KY_ENCRYPTION_KEY` override that
    disagrees with it.
  - If using LiveKit SFU (`KY_LIVEKIT_*`) or KyCalendar meeting sync (`KY_MEETING_SYNC_SECRET`),
    restore those environment variables before starting. Active calls are not restored across
    restarts; members can rejoin rooms immediately.
  - Keep restored key files private (`0600`) and data directories `0700`.
- All users must sign in freshly and re-enable browser push notifications if desired; sessions,
  MFA challenges, device pairings, and push subscriptions from before the backup are invalidated.
- Review changes after the capsule timestamp using surviving audit logs and KyIdentity records:
  offboarded accounts, suspended orgs, passwords, or MFA enrollments may be newer than the
  snapshot. Resolve stale access before reopening traffic, then create a fresh sealed backup.

## Installer-managed console

When the restored database retains installer configuration, restore the sealed
`installer/client.secret` and `installer/directory.secret` files to their recorded protected paths
from `installer/credential-paths.json` (`0600`, process-owned) before restarting the server. See
[INSTALLER_SETUP.md](INSTALLER_SETUP.md).

## Verification

`go test -race ./cmd/server ./internal/store ./internal/backup/...` verifies a 2-of-3 capsule
round trip, wrong-service/key/threshold refusals, restored-grant invalidation, attachment mirror
restoration, and cleanup on failed preparation. `backup-drill` validates capsule sealing and
restore readiness with a disposable key; a periodic controlled restore using real custodian cards
remains an operator responsibility.
