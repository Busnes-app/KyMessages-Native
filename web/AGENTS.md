# Web

## Purpose
React 19 + TypeScript + Vite PWA frontend embedding KySecurity color tokens (Busnes light/dark defaults plus `Patina Ky`, `Cyber`, `Nord Dark` (`nord`), `Nord Light` (`paper`), `OLED`), 90-second ephemeral QR device pairing modals, client-side WebCrypto PoW CAPTCHA, and administrative management panels.

## Ownership
Owns user interface components, service worker caching, PWA installation manifests, and frontend theme switching.

## Local Contracts
- A hosted call join's validated `call_ws_path` selects a separate room-affine `ChatSocket`, owned by `HybridCallController`; a socket path must name the joined room. The controller waits for authenticated hello, refreshes its seat after route changes, uses only that socket for signaling/media control, and rejoins through room HTTP after owner reconnection. A signaling-only reconnect retains P2P links when verified call and peer IDs are unchanged, including the designated answerer; a changed call/seat rebuilds media and a refused rejoin closes it. A reconnecting designated offerer resends its own unanswered offer after rejoin; established descriptions remain untouched. Accepted SFU and P2P migrations advance the retained epoch, including P2P notifications that need no media change; older migrations cannot reconnect retired media. Hosted signaling and active roster application wait behind initial setup/recovery on the same bounded transition queue (at most 128 pending signals and one coalesced latest roster); ended current calls still stop media immediately, so early offers are applied only after identity and local media are ready. A session-targeted `peer_signaling_ready` notice resends only the designated offerer’s unanswered offer; outgoing negotiation is serialized per peer. Initial media setup, owner recovery and migrations use one controller-owned transition queue; disposal prevents queued work and rechecks after disconnect. New SFU epochs replace old media credentials. Ordinary chat reconnects do not tear down a separately routed call. Guest call HTTP uses the server's optional `call_room_id`; absent fields keep single-mode paths/behavior. `rtc/hybridCall.test.ts` covers the real socket class with controlled wire events/time, SFU epoch replacement, reconnect and path confinement. Multi-mode bootstrap/reconnect refreshes call rosters through authorized room state routes (four reads in flight, two-second deadline); a global pod snapshot alone is not authoritative. Per-room live revisions fence the entire bootstrap request: an intervening call event, closure, membership removal or local join wins over an older successful or failed owner read. Unchanged rooms still use authoritative results, including null; unavailable rooms retain the latest accessible snapshot. Call-state refs and revisions advance synchronously before React rendering. Room closure/ended-call events stop media and clear the controller from the calling page. Single-mode bootstrap makes no extra requests. This does not establish guest E2EE or a final host-control product model.
- The header, login page and Overview show `/api/settings` `app_name` (the admin's name, else `KY_APP_NAME`); a 64-character name wraps (`.app-brand`, the login `<h1>`) and never widens the shell. Document title and manifest use KyMessages. Do not imply a successful backup/crypto review from static dashboard text. Retain suite icon masters and existing theme choices.
- Web themes default to the Busnes.app cream/light and charcoal/dark palettes with orange accents, following the OS until a browser-local choice is saved. Preserve existing named themes and saved choices.
- A signed-in user with `must_change_password` sees only password replacement and sign-out. Replacement uses `secureFetch`, returns to login after session revocation, and never exposes the normal navigation before completion.
- Strict TypeScript type safety without unused imports.
- The authenticated shell uses a persistent sidebar; the selected page is marked by a quiet surface and slim accent rail, with a horizontal overflow navigation on small screens.
- Dynamic theme selection applies `data-theme` attribute to the root HTML document and persists to `localStorage`. Nord Dark/Light take ky-ui's suite palettes (`themes.js` `applyThemeVariables`, set inline on the root); the other named themes are local CSS in `styles/theme.css`.
- Authenticated state-changing requests use `secureFetch` so the CSRF cookie (`__Host-ky_csrf` on secure deployments without `KY_COOKIE_DOMAIN`, else `ky_csrf`) is mirrored into `X-CSRF-Token`.
- `TwoFactorSetup.tsx` ("Account security", mounted under the Settings page) reads `/api/auth/me` and renders nothing for non-local accounts. Off: set up shows the QR (`qrcode` `toDataURL`, a `data:` image the CSP allows) and the key, then confirms one code. The recovery codes from confirm are shown once, until "I have saved them". On: turning off takes a code or a recovery code. All calls use `adminFetch`; refused codes stay on the form (`TwoFactorSetup.test.tsx`).
- Register the service worker from the production JS bundle; keep `script-src 'self'` intact. Pairing uses a native modal dialog for focus containment, Escape and focus restoration. It shows only the QR code (no typed PIN) and treats poll status `consumed` as linked. `QRPairingModal` polls with `secureFetch` `POST /api/devices/pair/poll` and the secret in the JSON body, never in a URL; it aborts on close (timers start only after init resolves and an abort check), and stops with a visible error at 90 seconds or on any non-OK init or poll answer (`QRPairingModal.test.tsx`).
- `Login.tsx` labels its fields (`htmlFor`/`id`, `autoComplete` `username`, `current-password`, `one-time-code`); its error box is `role="alert"`; there is no subtitle under the product name. `CaptchaWidget` fetches and solves one challenge per mount, again when `round` changes (Login bumps it after every attempt: the server spends the token before checking the password) and on expiry (never sooner than a minute); never per render (`Login.test.tsx`).
- `App.tsx` validates `/api/auth/me` and `/api/settings` with `parseUser`/`parseSettings` (`dto.ts`) and shows a failure as an alert. Sign-out leaves the console only after the server confirms it; a refusal or network error keeps the session and says "You are still signed in" (`App.test.tsx`). `ErrorBoundary` wraps the app (`main.tsx`) and each page (keyed by tab), so a render failure shows a message instead of a blank page.
- `SCIMAdmin.tsx` lists `GET /api/admin/scim/users` (validated by `parseSCIMDirectory`), shows load errors, and says whether `KY_SCIM_TOKEN` is set; it never shows or copies a token (`SCIMAdmin.test.tsx`).
- Worker caching is limited to the same-origin public shell, manifest and assets. HTML is network-first with offline fallback so deployments refresh; dynamic/auth routes stay uncached.
- `Backup.tsx` validates every reply at the HTTP boundary (`parseBackupStatus`, run, drill, schedule and pairing replies; a malformed status is an error alert, not a blank page) and displays the
  recorded outcome independently of the older remote receipt. A non-empty `scheduler_error` is an error banner; its absence is normal. Pinning a key by hand asks `window.confirm` with the key ID (`recoveryKeyID`: hex SHA-256 of the decoded key, as the server derives it) and the k-of-n split; a first pairing (no key pinned) asks before KyRecovery's key is pinned and names the pinned key after. Local-only results,
  scheduled failures, partial success and unknown history must remain distinguishable.
- Admin calls that need a fresh sign-in use `adminFetch` (`api.ts`): a 403 `reauthentication_required` opens the single `ConfirmItsYou` dialog (mounted in the admin shell), which links a same-origin `/api/sso/` `reauth_url` in a new tab and retries only on the admin's Retry; Cancel returns the refusal. Concurrent refusals share one answer. A POST is never replayed after a redirect. Admin DTOs are validated with the `dto.ts` helpers.
- `Agents.tsx` drives `/api/admin/agents` for native bot/agent accounts: list (username, owner, last used, token state), create/rotate modal showing the one-time `kybot_` token plus OpenClaw/Hermes config blocks and skill download, one-click revoke, and confirmed delete. All calls use `adminFetch`; replies are validated (`parseAgentList`, `parseAgentTokenReveal`), and the plaintext token is dropped on dialog close and never written to a URL, storage, log, or error (`Agents.test.tsx`).
- `Backup.tsx` warns for as long as `database_driver` from `/api/backup/status` is not `sqlite`: only the SQLite path can snapshot a database into a capsule, so a Postgres deployment makes no capsules at all. It also shows `capsule_size` (highlighting `warning` at 75% of the limit) beside the capsule attempt.
- `Dashboard.tsx` (Overview) renders summary cards for Service health, Workspace directory, and Backups; each comes from its own route and fails alone, with its action calling `onNavigate('health'|'scim'|'backup')`.
- `Settings.tsx` shows the `db_driver` from `/api/settings` and warns whenever it is not `sqlite` (the supported target is SQLite on one instance; Postgres gets no capsules); it never claims Postgres support (`Settings.test.tsx`). It mounts `BrandingPanel`: name (Save, "Use default (<KY_APP_NAME>)"), logo upload (`image/png`, refused over 1 MiB before sending) and reset, all through `adminFetch`; the preview is `/app-icon.png?v=<sha256>` or `?v=default`, never a `blob:` URL (CSP `img-src 'self' data:`); `onBrandingChanged` makes the shell re-read `/api/settings`.
- `Health.tsx` lists components from `/api/admin/health` (`kymessages`, `database`, `postgres`, `livekit`) and embeds `NetworkCheck`. Versions render as text only; a `source` link is kept only when it is https under the `Busnes-app` or `postgres` GitHub repos. `Audit.tsx` is a read-only, paged (50) view of `/api/admin/audit` filtered by kind (`agents|auth|backup|branding|scim`); both validate DTOs with `dto.ts`.
- `crypto/` wraps the end-to-end encryption core: `crypto/pkg` is the committed wasm-bindgen
  build of `web/crypto` (vodozemac Olm/Megolm), never edited by hand; rebuild with
  `web/crypto/build.sh`, which CI reproduces byte for byte. `loadCrypto()` is idempotent once it
  succeeds and retries after a failure.
- `pqc/` is the post-quantum core: `pqc.wasm` and `wasm_exec.js` are `web/pqc-wasm/build.sh`
  output (Go `internal/e2eeid` for `js/wasm`), never edited by hand; `loadPQC()` is idempotent
  and retries after a failure; `pqc.test.ts` runs `internal/e2eeid/testdata/vectors.json`.
- E3 identity (`crypto/identity.ts`, used by `CryptoEngine`; spec §3.1): an unverified device
  trusts and pins no one. `verifiedDevices` gives room keys only to devices whose member's master
  key is validly self-bound for the query's org, has no pending change (`mchg:`, checked first),
  matches the pin (`mpin:` `{fingerprint, n, accepted, prev}`; the pin sync `beforeTrust` runs
  ahead of every trust check and a failed sync fails the check) and both cross-signed the device
  and lists it on its newest signed device list. First sights are only proposed
  (`trustedMaster`'s `sights`) and get keys only after `commitFirstSights` stored all of a
  check's in one pin-set compare-and-swap; a conflict evaluates the winner, and a different key
  pinned first becomes a pending change. A pending change follows a newer verified key, still
  untrusted. The
  list mark `dlh:<tenant>:<user>:<fingerprint>:<version>` holds the epoch and a member digest and
  only rises (`CryptoStore.update`, one transaction); rollbacks, same-epoch forks and a missing
  list after one was seen trust no device; a list no newer than the mark is checked without a
  write; a fork stays one (`fork` on the mark) until a higher signed epoch. Edits verify the
  predecessor against the local master key, check the `guard` (an enrollment stops once
  `identity:retiring` names this device) right before reserving, reserve the list's digest and
  sign for the epoch the server grants (the reservation itself carries the master key's
  `signDeviceListReserve` signature; never under a reservation known to have lapsed), poll a
  held reservation every second up to `LIST_WAIT_MAX_MS` (past the server's lease), back off
  four times on other conflicts, and record only a list the server took. `delist` publishes even
  an unchanged list (`publishUnchanged`), so it is ordered after an enrollment holding the list. A rolled-back or
  forked own list or pin set (`Rollback`) is reported as `status().problem`, never signed over;
  the gate offers a reset. `acceptIdentity(user, previous, fingerprint)` runs through `syncPins`'
  shared compare-and-swap, checking the pending change, the local pin and the shared pin (which
  must exist) on every attempt, adopts a shared pin that already is the new key as it is (and
  then refuses the click, keeping a newer pending candidate rebased onto it, when the prompt
  clicked was stale), and changes the local pin only after the signed write. `engine.encrypt`
  throws `NotVerified` before any session is made unless this device holds the identity and,
  from the send's own query (`verifiedDevices(ids, self)`), is cross-signed and listed by the
  identity published now (an `IdentityMoved` pin sync also reads as `NotVerified`); `roomKey`
  keeps a vouched Olm copy in charge of what it covers (an unvouched or earlier one only
  becomes the `inb:` cover), and a vouched copy supersedes an unvouched or restored primary. `engine.ownDeviceVerified(id, signal)`
  reads only the user's own entry, with the signal on the lock wait and the request. Pin sync adopts a differing pin only as an accepted change
  from exactly this device's pin (rewriting a prompt for another key to change from the new pin),
  otherwise keeps the synced pin and a local pending change,
  signs its writes, and refuses a counter below `pins:hwm:<tenant>:<fingerprint>:<version>`. Seeds are AES-GCM-wrapped under
  a key derived from the pickle key; a server answer only moves them to `identity:previous:*`.
  `prepareIdentity` reads the version it replaces up front, round-trips the wraps locally and
  uploads only on `commit` (a retry after a lost answer adopts its own stored identity). Only
  sessions from vouched senders (and own) queue (`bq:`) for the key backup, flushed as signed
  batches for the current backup generation (refetched after a `409`); entries the server
  refuses for its caps move to `bqf:`, retried on `status()` and shown as `backupFull` while any
  wait (a new identity or generation requeues them); decrypts from restored or
  unvouched sessions report `authenticated: false` (`e2ee.trust` `backup`|`unverified`, shown by
  `MessageRow`'s trust note, grouped rows too, and part of the row diff). A verified session
  keeps its record; an earlier-reaching backup copy is stored beside it (`inb:`) for older
  messages only. `PQCUnavailable` (and network and storage failures, `isTransient`) never
  drops a queue entry, advances the restore cursor or stores keys as unvouched. Restore
  pages forward under one lock per page with a stored cursor (`backup:restore`) that `status()`
  resumes, reopening waiting messages per page. Sign-out takes the device off the signed device
  list before deleting it (`identity:retiring` keeps it off), without the per-user lock and for
  at most 2 s of `RETIRE_MS`. Each pending device is its own `localStorage` key
  `kymessages-e2ee-retire:<user>:<device>` (`delisted`, `deleted`, flags only ever set; the old
  single `kymessages-e2ee-retire` list is read once into them), removed only once both are
  confirmed, by any tab, however late; pending ones run at start and again on
  `engine.onAdopted` (the identity is stored and listed, before backup paging). A refused logout
  replaces the device retirement touched (`replaceDevice(expected)`), once `RETIRE_MS` passed
  even if the `DELETE` hangs, and fences an attempt that had not reached a device yet; late
  confirmations only update a record still pending (`markAbandoned`); a stored device found pending at start is reset into a new one before it runs;
  a clean sign-out's wipe skips devices this tab settled.
  `pqc/index.ts` reloads a module that is not running, bounds a whole start (fetch, compile,
  hand-over) by `PQC_START_MS`, and starts Go with its generation in `argv`, which Go hands back
  to `kyPQCReady` with its call, so only the newest start installs one (a timeout is
  `PQCUnavailable`, as is a fetch, compile or run failure). `crypto/store.ts` rejects every
  IndexedDB failure or abort as `StorageUnavailable` (`Transient`); a mailbox drain acks only the
  prefix handled before such a failure and then throws it. `chat/e2ee.ts` `call` maps an
  unreachable server, `429` and `5xx` to `KeyServerUnavailable` (`Transient`), keeps aborts as
  aborts, and carries a `409`'s `retry_in_ms` on `Conflict`. Work that failed for availability
  (`engine.onTransient`, a failed start-up) is retried on a bounded schedule owned by the user's
  `RetrySession` (kept across that user's start-ups, ended at sign-out or a user switch) that
  awaits `engine.resumeWork()` (mailbox, then `identity.drain()`: unlocked listing, the restore
  and the backup queue), one run at a time, with one more pass when a failure arrives during a
  run (kept through a later verdict); `encryptionRetry()` `{pending, exhausted}` drives the
  gate's notice (also while loading) and `retryEncryptionNow`. `encryptionReadyFor(user)`, re-read
  on `onRoomKeys`/`onEncryptionPending`, is `Chat.tsx`'s readiness, so a recovered start-up
  makes the page usable and clears its own start-up error. `identity.drain()` also signs the
  device (a replacement whose signing failed), and runs the restore and backup after a listing
  rollback. Enrollment that fails for availability after the seed write (`identity:enrolling`)
  is finished there, and `onAdopted` fires once `enrolled()` confirms the current identity and a
  signed, current list naming the device (a failed confirmation keeps the marker and is retried).
  After a QR consume, the fresh identity read is retried a few times; `adopt` rechecks the
  published identity and the local baseline under the lock and calls a closed screen or a
  spent deadline off right before the seed write; a backup read failing afterwards stays
  pending. `withLock`'s signal ends only the wait for the lock, as Web Locks do. Status checks
  run per start-up `Entry` (`entry.status`); one asked of a replaced or ended entry rejects with
  `StaleStatus`, which the gate ignores; engines wire `onIdentityChange` at start, and a ready
  entry and a retry's verdict call `announceIdentity`. `ensureListed` under the lock (status) never waits on another
  device's reservation; lease deadlines use `performance.now()` from before the request. `onBackupStateChanged`
  updates the gate's full notice without a status check.
  `EARLY` (a message from before this device's session) is retryable, so backup pages reopen it.
  `components/chat/EncryptionIdentity.tsx` holds the screens: a non-blocking banner (with an
  error state and Retry) opens setup or verify-this-device (the joiner confirms the comparison
  code before taking keys), the header's shield (verified devices only) opens verify-a-device,
  and the room banner shows the full new fingerprint. The banner, and "Verify a device", also
  show with no room open; a verified device with a full backup, a rolled-back identity (with
  Reset identity) or encryption work waiting (with Retry now) gets a notice. QR screens poll for a
  bounded time with a few retries, abort their requests and waits when closed, and report
  verified only once the new device is cross-signed and listed (the lookup aborts on close or
  deadline); closing after the keys were sent never cancels the pairing, and the sender's
  cancel is unsealed-only. `ConfirmItsYou` is mounted for every chat user; a local account signs
  in again in place (password, TOTP; a refused code goes back to the password, and every attempt
  gets a fresh captcha token; submit needs the current round's token, which `CaptchaWidget`
  clears at each round and lets the user solve again after a failure), never by signing out. `chat/httpFake.ts` serves `fakeKeyServer.ts` over the HTTP routes for `chat/e2ee.test.ts`.
  Page tests stub all of it via `chat/e2eeFake.ts`.
- `components/chat/ChatModals.tsx` holds the chat modals (Create channel, New direct message, Search messages). Search reads `chat/searchIndex.ts`, the on-device IndexedDB index that `pages/Chat.tsx` fills from every message it loads (encrypted at rest under a non-extractable AES-GCM key). Searches page newest first through the `newest`/`room_newest` indexes, decrypt a page in parallel, stop at the limit and abort when superseded. Index writes (`put`, `remove`) run one at a time in call order, and `put` never replaces or drops a stored copy newer than the message it has (`edited_at`; tabs share the database; a deletion always drops it), so a slow batch cannot overwrite a newer edit. Matches are vetted inside `search`, in batches of at most the limit, by `freshHits` with `POST /api/v1/messages/state`, so rejected hits never crowd out older valid ones: a hit the server no longer vouches for (deleted, edited since it was indexed, or in a room the reader left) is dropped and removed from the index (`removeStale`: only while the stored copy is still that version, kept in the clear as `edited_at`, so an edit indexed meanwhile stays), and search fails closed when the server cannot be asked; live `message.delete` events, and `message.edit` for rooms not loaded, prune the index too. Sign-out (`App.tsx` `leave`) unmounts the app, then `forgetSearchIndex` deletes every index and rejects on failure, which the sign-in screen reports; every connection closes on `versionchange`, and `announceSignOut`/`onSignOutElsewhere` (BroadcastChannel) sign out other tabs, even one that missed the WebSocket revocation (`browser/chat-search-signout.spec.mjs`). Each is `ChatDialog`, on Base UI's `Dialog` (`@base-ui/react`, pinned exactly; unstyled, ky-ui tokens and the existing `chat-modal-*` classes, no Base UI styles), portalled to `body` above `.modal-backdrop` at z-index 1000: an `autoFocus` field keeps first focus, otherwise the first control; Tab wraps inside; Escape, Close and a backdrop press close it (not the backdrop while it is busy); focus returns to the opener, noted when the dialog first renders because the `autoFocus` field already holds focus when Base UI looks; the page behind is scroll-locked. A popup opened inside one must stack above 1000. Pickers keep the input focused and move a highlight (`aria-activedescendant`, styled by `[data-highlighted]`): New direct message's teammates and the search results are Base UI `Autocomplete` (inline, first option highlighted, Enter or a click runs the action); Create channel's teammates are a multi-select `Combobox` (arrows, Enter or a click toggle; Enter in its box never submits the form). Only `onValueChange` reasons `input-change` and `input-clear` count as typing. Options are `div`s, so `chat.css` gives them the global button rule's type and alignment; sizes match the old buttons (`ChatModals.test.tsx`, `browser/chat-pickers.spec.mjs`). Menu, Dialog, Autocomplete and Combobox inject no `<style>`; ScrollArea and Select with `alignItemWithTrigger` do, so do not use them.
- Encrypted rooms (E2 of `docs/superpowers/specs/2026-11-22-e2ee-design.md`). `crypto/engine.ts` (`CryptoEngine`) is one device: a vodozemac Account in `crypto/store.ts` (IndexedDB `kymessages-crypto-<user>`, pickles under a random 32-byte key wrapped by a non-extractable AES-GCM key; once a device's store opens, `persist.ts` `keepStorage` asks the browser for persistent storage, best effort), self-signed device keys and 50 signed one-time keys plus a fallback key, topped up after a pre-key message; when an upload answers `has_fallback_key: false` (a restore retired it) it publishes a new fallback key. Sending keeps one outbound Megolm session per room, shares its key from the current index as to-device `kymessages.room_key.v1` over Olm to every verified device of every member (signatures checked, device keys pinned on first sight), and rotates after 100 messages, 7 days, or when a member or one of their devices is gone. Receiving binds each room session to the sending device's curve25519 key, user and room; a message must name its room, an edit its message, and each (session, index) belongs to one message ID. Every locked crypto operation checks its cached device ID against the persisted record before work. Identity resets use that same per-user Web Lock and delete only the expected old ID, so concurrent late resets cannot erase a replacement. A `device-reset` message on the existing room-key BroadcastChannel invalidates and aborts matching peer entries (the engine reports its identity before upload, including pending starts); cache checks and a bounded operation retry cover missed notifications and reset/operation timing. Tabs then coalesce startup on the surviving shared identity. `chat/e2ee.ts` wires it to the key API: `client.ts` seals sends and edits and opens fetched and WebSocket messages (in order; opening never waits for a device still starting: the message reads as unavailable and is reopened once it is ready; sealed JSON is capped at 32 KiB so the envelope fits the server's 48 KiB), `parseMessage` keeps an envelope in `envelope`, never `body`, and `e2ee` says `decrypted`, `waiting` (shown "Waiting for this message's key", retried on `onRoomKeys`) or `failed` (with the reason). A failed device start keeps its user in a failed entry and closes its store; a subsequent send or mailbox/member event retries through `startE2EE`, which coalesces concurrent starts, without a socket reconnect. A `to_device` event or a reconnect reads the mailbox. Each mail's sender is checked against the self-signed `sender_keys` the server stored with it (signature and pin, as for listed devices), so room keys from a device that signed out since still arrive. Keys stored before a failed ack or mailbox read are still announced (`onKeys`), before replenishment uploads so a stalled upload cannot delay display. Every key arrival bumps `keyGeneration()` and is broadcast to other tabs (BroadcastChannel `kymessages-room-keys`; tabs share the device's store), and a waiting or retryable message records the generation it was opened at (`e2ee.gen`): `Chat.tsx` reopens such rows from an older generation whenever messages change (device start-up bumps it too), so a key that lands between an open and its display is not missed. A claimed key the crypto core refuses (non-contributory) skips only that device, so one bad device cannot block a room's key. Every send looks up the room's members and devices afresh (no cache: a cached list would miss a member's new device and could outlive a removal), and rotates when a device that had the key is gone; a `room.member` removal also drops the session at once (`roomMemberLeft`). Sign-out deletes the device (`DELETE /api/v1/keys/devices/{id}`, `retireDevice().wait` answers whether it is gone within `RETIRE_MS` (5 s), so a stuck start-up or request never blocks sign-out; a refused logout calls `replaceIfRetired`, which follows the eventual deletion result and replaces only the same still-current device, even when deletion succeeded after the deadline; a sign-out the server refuses after the device was retired starts a new device with `replaceDevice`; both that path and a startup key-upload 404 use `resetDevice`, which removes only the device's own keys (`device`, `account`, `fallback`, `olm:`, `out:`) and keeps received room keys, the replay log, pins and the store wrapping key, so history stays readable; if not, it is recorded as for a revocation) and every crypto store; a revoked session deletes the store and records the device in `localStorage` (`kymessages-e2ee-retire:<user>:<device>`, IDs and flags only) for deletion after its user next signs in here (`abandonDevice`). Inbound sessions and the replay log are keyed by sender curve25519 key and session ID, so a member re-sharing someone's session cannot displace it. `MessageRow` labels `plain_v1` "Sent before encryption" (people), "Not encrypted (bot)", "Not encrypted (guest)" or "Not encrypted (webhook)", and files "File not encrypted". `engine.test.ts` runs engines against `fakeKeyServer.ts`; page tests mock `chat/e2ee` with `chat/e2eeFake.ts`. The crypto store closes every connection on `versionchange` and tells its owner (`onClosed`), which drops the device engine; deletes resolve only on success and reject on error or after 5 s blocked, so `leave()` reports a store it could not delete (`browser/e2ee-store-signout.spec.mjs`). Before wiping, `forgetCryptoStore` records every store's registered device (`storedDevices`, other users of a shared browser included) as pending retirements, so each is removed from the key server at its user's next sign-in. Each device entry owns an AbortController for its key API requests. Stopping it (`stopE2EE`) aborts those requests before closing the store, releasing a per-user Web Lock held by a stalled upload or mailbox read, so the same user can sign in again without reloading. It also cancels start-up, and a cancelled start-up never reopens a store, so revocation (`abandonDevice`) deletes local keys at once. Mail is acknowledged only when handled or itself unreadable: a `Transient` or storage (`DOMException`) failure leaves it queued, and the Olm state a message changed is stored in the same transaction as the room key it carried. A storage error while checking that room key commits nothing, so the mail decrypts again on retry; only a definite refusal stores the spent Olm state. An open that throws is `NOT_YET`, retried like `UNAVAILABLE` (`retryable`).
- `NetworkCheck.tsx` renders on the admin-only Health page: it fetches `/api/admin/network-check`, validates the DTO at the boundary (a malformed or failed response shows `Network check unavailable.`), aborts on unmount and lists five Pass/Warn marks: trusted proxy peer, trusted `X-Forwarded-Proto: https`, https `KY_APP_URL`, host match, and `KY_TRUSTED_PROXIES` naming only single addresses (`trusted_proxies_narrow`). Tested by `NetworkCheck.test.tsx`.

## Verification
- Browser setup: build the frontend, run `go build -o .browser/server ./cmd/server` at the repo root, then `cd web && npx playwright install chromium firefox && npm run test:browser`. CI also installs browser OS dependencies.
- `make test-web` or `cd web && npm ci && npm test`, then `npm run build` (vitest with jsdom; `src/test-setup.ts` stubs the jsdom `<dialog>` methods; `src/pages/Backup.test.tsx` renders the recovery screen against a stubbed status route). Commit `web/dist` after a build; CI diffs it.

## Shared browser UI

- `src/ky-ui/` is generated from Busnes-app/ky-ui, pinned by `VERSION` file hashes. Change shared colors, navigation states and storage helpers upstream, then run its consumer sync with an explicit worktree map; do not hand-edit vendored files.
- Products own layout, routes, saved choice keys and named palettes. Busnes aliases consume shared tokens; mark primary navigation with `ky-nav-item` while preserving current-page semantics.
- Verify vendored files with `node src/ky-ui/check-vendor.mjs` from this document's directory. Builds/CI run that check.

## Child DOX Index
- [browser/AGENTS.md](./browser/AGENTS.md): Production-server browser regression harness and disposable test data.
