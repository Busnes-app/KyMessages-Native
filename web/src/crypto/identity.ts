// The user's post-quantum encryption identity on this device (E3 of
// docs/superpowers/specs/2026-11-22-e2ee-design.md, §3.1): the hybrid ML-DSA-65 + Ed25519 master
// key that vouches for the user's devices, the master-signed device list, TOFU pins of
// colleagues' master keys (synced between the user's own verified devices), the recovery key,
// the X-Wing key backup and QR device verification. Every primitive is the Go code in
// internal/e2eeid, run as WebAssembly (pqc/).
//
// Nothing the server says is trusted: master keys must carry a valid self-binding and match the
// pin, devices must carry the pinned master key's signature and be on its newest device list,
// recovery wraps and transfers must open to the very key the server publishes, and backup
// entries must carry the master key's MAC. A device that is not verified trusts nobody.
// Nothing the server says can delete this device's copy of the master and backup seeds.
import { InboundGroupSession } from './index';
import { b64, ensurePQC, pqc, PQCUnavailable, unb64, type BackupRef, type Hybrid } from '../pqc/index';
import type { CryptoStore } from './store';
import { backupCoverKey, backupQueueKey, backupRefusedKey, Conflict, IdentityMoved, inboundKey, isObj, isStr, isTransient, parseJSON, sleep, Transient, type InboundRecord } from './records';

// --- The key server, as the identity needs it (chat/e2ee.ts implements it over HTTP) ---

export interface DeviceList {
  epoch: number;
  device_ids: string[];
  signature: Hybrid;
}

export interface MasterKeyRecord {
  version: number;
  master_key: Hybrid;
  self_signature: Hybrid;
  device_list?: DeviceList;
}

export interface OwnMaster extends MasterKeyRecord {
  backup_key: { public_key: string; signature: Hybrid };
  /** Bumped by each deletion of the key backup; backup writes are signed for one generation. */
  backup_generation: number;
  recovery: { wrapped_master_key: string; wrapped_backup_key: string };
  pins: { counter: number; sealed: string };
}

export interface MasterPut {
  expected_version: number;
  master_key: Hybrid;
  self_signature: Hybrid;
  backup_key: { public_key: string; signature: Hybrid };
  recovery: { wrapped_master_key: string; wrapped_backup_key: string };
}

export interface BackupEntry extends BackupRef {
  sealed: string;
}

export interface BackupCursor {
  room_id: string;
  sender_key: string;
  session_id: string;
}

export interface PairingState {
  pairing_id: string;
  initiator_device: string;
  new_device: string;
  ephemeral_key: string;
  sealed: boolean;
}

/** Writes answer Conflict when the identity, pin set, device list or backup version moved on. */
export interface IdentityServer {
  /** signal: the asking screen closed or its deadline passed, so the read is dropped. */
  getMaster(signal?: AbortSignal): Promise<{ tenant_id: string; master: OwnMaster | null }>;
  putMaster(req: MasterPut): Promise<number>;
  /** signature: the master key's kymessages.pins-write.v1 signature over this write. */
  putPins(version: number, expectedCounter: number, sealed: string, signature: Hybrid): Promise<void>;
  /** Reserves the next epoch for the list with this digest while the list is at expectedEpoch,
   * answering the epoch to sign and how long the reservation holds; Conflict (with retryInMs
   * while another device's reservation holds it) otherwise. */
  /** signature: the master key's kymessages.device-list-reserve.v1 signature over the reservation. */
  reserveDeviceList(version: number, expectedEpoch: number, digest: string, signature: Hybrid): Promise<{ epoch: number; expires_in_ms: number }>;
  putDeviceList(version: number, expectedEpoch: number, epoch: number, deviceIds: string[], signature: Hybrid): Promise<void>;
  signDevice(deviceId: string, version: number, signature: Hybrid): Promise<void>;
  getBackup(version: number, after: BackupCursor): Promise<{ sessions: BackupEntry[]; more: boolean }>;
  /** signature: the master key's kymessages.backup-write.v1 signature over the batch, for one
   * backup generation. refused: indexes of entries that did not fit the server's caps. */
  putBackup(version: number, generation: number, sessions: BackupEntry[], signature: Hybrid): Promise<{ refused: number[] }>;
  pairingStart(deviceId: string): Promise<{ pairing_id: string; expires_in_ms: number }>;
  // signal: the screen that asked closed, so the request is dropped.
  pairingGet(id: string, signal?: AbortSignal): Promise<PairingState>;
  pairingJoin(id: string, deviceId: string, ephemeralKey: string): Promise<void>;
  pairingSeal(id: string, deviceId: string, sealed: string, signal?: AbortSignal): Promise<void>;
  /** The sealed keys, once; Conflict while none are waiting yet. */
  pairingConsume(id: string, deviceId: string, signal?: AbortSignal): Promise<{ initiator_device: string; sealed: string }>;
  /** unsealedOnly: cancel only while no keys were sealed to it (the verified device's cancel). */
  pairingCancel(id: string, unsealedOnly?: boolean): Promise<void>;
}

export type IdentityStatus =
  /** quarantined: this device set aside the seeds of an identity the server no longer lists. */
  | { state: 'none'; quarantined: boolean }
  | { state: 'unverified'; fingerprint: string; quarantined: boolean }
  /** restoring: sessions from the key backup are still being read in. backupFull: the server's
   * cap refused sessions, which stay queued here. problem: the server showed this identity's
   * device list or pin set older than this device has seen (rollback) or two lists at one epoch
   * (fork); nothing is trusted or signed over it, and resetting the identity is the way out. */
  | { state: 'verified'; fingerprint: string; restoring: boolean; backupFull: boolean; problem?: 'rollback' | 'fork' };

/** A colleague whose master key changed since it was pinned. */
export interface IdentityChange {
  user_id: string;
  fingerprint: string;
  previous: string;
}

export interface PairingOffer {
  /** What the QR code and the copyable code carry. */
  text: string;
  /** Milliseconds the pairing stays open, by the server's clock. */
  expiresInMs: number;
  /** The comparison code once the new device has joined. */
  poll(signal?: AbortSignal): Promise<{ code: string; device: string } | undefined>;
  /** Sends the keys to the device that showed the code poll returned. */
  approve(signal?: AbortSignal): Promise<void>;
  cancel(): Promise<void>;
}

export interface PairingJoin {
  /** The six digits to compare with the verified device's screen, before finish. */
  code: string;
  /** Waits for the verified device's approval, then verifies this device; returns restored sessions. */
  finish(signal?: AbortSignal): Promise<number>;
  cancel(): Promise<void>;
}

/** A colleague's trusted master key and the devices on its newest device list. */
export interface TrustedMaster {
  key: Hybrid;
  devices: ReadonlySet<string>;
}

// --- Stored records ---

interface LocalIdentity {
  tenant_id: string;
  version: number;
  fingerprint: string;
  master_key: Hybrid;
  backup_key: string;
  seeds: { iv: Uint8Array; ct: ArrayBuffer };
}

/**
 * A pinned colleague. n counts the pin's changes; an accepted change records the fingerprint it
 * replaced (prev), so another device adopts it only as a change from exactly its own pin.
 */
interface PinRecord {
  fingerprint: string;
  n: number;
  accepted: boolean;
  prev?: string;
}

interface RestoreCursor {
  version: number;
  after: BackupCursor;
  count: number;
}

const IDENTITY = 'identity';
const SIGNED = 'identity:signed';
/** The newest pin set counter seen for one identity: scoped to org, fingerprint and version. */
const pinsMark = (l: { tenant_id: string; fingerprint: string; version: number }) => `pins:hwm:${l.tenant_id}:${l.fingerprint}:${l.version}`;
const RESTORE = 'backup:restore';
interface EnrollingRecord {
  tenant_id: string;
  version: number;
  fingerprint: string;
}

/** Set while this device took on an identity but is not yet both signed and listed. */
const ENROLLING = 'identity:enrolling';

function abortable<T>(p: Promise<T>, signal?: AbortSignal, late?: () => Error | undefined): Promise<T> {
  if (!signal) return p;
  const timedOut = late?.();
  if (timedOut) return Promise.reject(timedOut);
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(late?.() ?? signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}
const previousKey = (fp: string, version: number) => `identity:previous:${fp}:${version}`;
const pinKey = (userId: string) => `mpin:${userId}`;
const changeKey = (userId: string) => `mchg:${userId}`;
/** The newest device list seen for one identity: scoped to org, user, fingerprint and version. */
const listKey = (tenantId: string, userId: string, fingerprint: string, version: number) => `dlh:${tenantId}:${userId}:${fingerprint}:${version}`;
const RETIRING = 'identity:retiring';
const BACKUP_BATCH = 100;
const BACKUP_PAGE_MAX = 200;
const BACKUP_MAX_SESSIONS = 2000;
const PAIRING_POLL_MS = 1500;
/** How long a new device waits for approval: a little past the server's pairing lifetime. */
const PAIRING_WAIT_MS = 4 * 60_000;
/** Consecutive failures (the network, the server) a pairing poll rides out before giving up. */
const PAIRING_RETRIES = 5;
/** Attempts at a device list edit. */
const LIST_ATTEMPTS = 4;
const LIST_BACKOFF_MS = 500;
/** The longest wait for another device's reservation to lapse: past the server's lease
 * (E2EEDeviceListReservation, 30 s), so an abandoned one never fails an edit early. */
export const LIST_WAIT_MAX_MS = 31_000;
const LIST_HOLD_POLL_MS = 1_000;

/** The server showed an identity's device list or pin set older than seen (or a forked list). */
export class Rollback extends Error {
  constructor(readonly kind: 'rollback' | 'fork', message: string) {
    super(message);
  }
}

const listVerdict = (kind: 'rollback' | 'fork') =>
  new Rollback(kind, kind === 'fork' ? 'The server showed two device lists at once.' : 'The server returned an older device list than this device has seen.');

// Signature checks are pure, and every send lists every member's keys again: verify each
// distinct (statement, signature) once. Keys are SHA-256 of the inputs, not the inputs; a
// check that threw (the module was not loaded) is not remembered.
const verified = new Map<string, boolean>();
// A module that is not running throws PQCUnavailable through: that is no verdict on the
// signature, so it must not read as "does not verify".
function memo(fields: string[], check: () => boolean): boolean {
  const key = pqc.hash(...fields);
  const hit = verified.get(key);
  if (hit !== undefined) return hit;
  let ok: boolean;
  try {
    ok = check();
  } catch (e) {
    if (isTransient(e)) throw e;
    return false;
  }
  if (verified.size >= 4096) verified.clear();
  verified.set(key, ok);
  return ok;
}

// A tagged hybridsig key is 2000 bytes and a signature 3389; base64 makes them 2667 and 4519.
const isHybrid = (v: unknown): v is Hybrid => isStr(v, 8192);

export function validMaster(v: unknown): v is MasterKeyRecord {
  return isObj(v) && typeof v.version === 'number' && v.version >= 1 && isHybrid(v.master_key) && isHybrid(v.self_signature);
}

function validList(v: unknown): v is DeviceList {
  return isObj(v) && typeof v.epoch === 'number' && v.epoch >= 1 && Array.isArray(v.device_ids) &&
    v.device_ids.every((d) => isStr(d, 64)) && isHybrid(v.signature);
}

const validPin = (p: unknown): p is PinRecord =>
  isObj(p) && isStr(p.fingerprint, 64) && /^[0-9a-f]{64}$/.test(p.fingerprint) && typeof p.n === 'number' && typeof p.accepted === 'boolean' &&
  (p.prev === undefined || isStr(p.prev, 64));

/** Pin sets compared by content, whatever order their keys arrived in. */
function canon(pins: Record<string, PinRecord>): string {
  return JSON.stringify(Object.keys(pins).sort().map((u) => [u, pins[u].fingerprint, pins[u].n, pins[u].accepted, pins[u].prev ?? '']));
}

/** Groups a 64-hex-digit fingerprint for people to compare. */
export function formatFingerprint(fp: string): string {
  return fp.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? fp;
}

const cursorAfter = (a: BackupCursor, b: BackupCursor) =>
  a.room_id !== b.room_id ? a.room_id > b.room_id : a.sender_key !== b.sender_key ? a.sender_key > b.sender_key : a.session_id > b.session_id;

export interface IdentityContext {
  userId: string;
  deviceId: string;
  curve25519: string;
  ed25519: string;
  server: IdentityServer;
  store: CryptoStore;
  pickleKey: Uint8Array;
  /** Runs fn under the device's per-user lock (not re-entrant). */
  locked<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T>;
  /** Called with the session IDs a restored backup page stored, so waiting messages reopen. */
  onRestored?(sessionIds: string[]): void;
  /** Called when background work (restore, backup) failed for availability and should be retried. */
  onTransient?(): void;
  /** Called when whether the backup refused sessions changes. */
  onBackupState?(full: boolean): void;
  /** Called once this device stored and listed the identity it took on. */
  onAdopted?(): void;
}

export class Identity {
  private readonly listeners = new Set<() => void>();
  private changed = false;
  private restoring?: Promise<number>;
  private backupGen?: { version: number; generation: number };
  private backupFull?: boolean;

  constructor(private readonly ctx: IdentityContext) {}

  /** Calls fn when this device's identity, a pinned identity or a pending change changes. */
  onChange(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private notify(): void {
    for (const fn of this.listeners) fn();
  }

  // --- Local secrets, under a key derived from the store's pickle key ---

  private async seedKey(): Promise<CryptoKey> {
    const base = await crypto.subtle.importKey('raw', this.ctx.pickleKey as BufferSource, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('kymessages.local.v1/identity') },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
  }

  private async sealLocal(tenantId: string, master: OwnMaster, masterSeed: string, backupSeed: string): Promise<LocalIdentity> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await this.seedKey(), new TextEncoder().encode(JSON.stringify({ master: masterSeed, backup: backupSeed })));
    return { tenant_id: tenantId, version: master.version, fingerprint: pqc.fingerprint(master.master_key), master_key: master.master_key, backup_key: master.backup_key.public_key, seeds: { iv, ct } };
  }

  private async seeds(l: LocalIdentity): Promise<{ master: string; backup: string }> {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: l.seeds.iv as BufferSource }, await this.seedKey(), l.seeds.ct);
    return JSON.parse(new TextDecoder().decode(pt)) as { master: string; backup: string };
  }

  private local(): Promise<LocalIdentity | undefined> {
    return this.ctx.store.get<LocalIdentity>(IDENTITY);
  }

  /** Whether this device holds the user's current master key (it is verified). */
  async isVerified(): Promise<boolean> {
    return (await this.local()) !== undefined;
  }

  /**
   * Sets this device's identity aside, never deleting it: a server answer (a bumped version, a
   * restore, no identity at all) cannot destroy the user's last copy of the seeds. It comes back
   * by itself if the server lists that same identity again.
   */
  private async quarantine(l: LocalIdentity): Promise<void> {
    await this.ctx.store.write([[previousKey(l.fingerprint, l.version), l]], [IDENTITY, SIGNED]);
  }

  private async hasQuarantined(): Promise<boolean> {
    return (await this.ctx.store.list('identity:previous:')).length > 0;
  }

  // --- Trust: what the engine shares room keys with ---

  /**
   * userId's master key from a key query, with the devices on its newest signed device list, if
   * this device is verified and the key is validly self-bound in tenantId, has no pending change
   * and matches the pin; undefined otherwise. A mismatch is recorded as a change (pin writes go
   * into writes). A first sight is only proposed, into sights: the caller trusts it after
   * commitFirstSights stored it in the synced pin set. Lock held.
   */
  async trustedMaster(userId: string, rec: unknown, tenantId: string, writes: [string, unknown][], sights: Map<string, string>): Promise<TrustedMaster | undefined> {
    const own = await this.local();
    // An unverified device cannot check anyone: it pins nobody and trusts nobody.
    if (!own || own.tenant_id !== tenantId) return undefined;
    if (!validMaster(rec)) return undefined;
    const k = rec.master_key;
    const s = rec.self_signature;
    if (!memo(['master', tenantId, userId, k, s], () => pqc.verifyMaster(k, tenantId, userId, s))) return undefined;
    const fp = pqc.fingerprint(k);
    if (userId === this.ctx.userId) {
      // The user's own key is pinned by verification itself, never by first sight.
      return own.fingerprint === fp && own.version === rec.version ? this.withList(userId, rec, tenantId) : undefined;
    }
    // A pending change blocks this member until it is accepted, even if the server goes back to
    // serving the old key. A newer verified key replaces the candidate shown, trusted no more.
    const c = await this.ctx.store.get<IdentityChange>(changeKey(userId));
    if (c) {
      if (fp !== c.fingerprint && fp !== c.previous) {
        writes.push([changeKey(userId), { ...c, fingerprint: fp } satisfies IdentityChange]);
        this.changed = true;
      }
      return undefined;
    }
    const pin = await this.ctx.store.get<PinRecord>(pinKey(userId));
    if (!pin) {
      // Not trusted until the synced pin set holds it: another of the user's devices may be
      // pinning a different key for this member right now.
      sights.set(userId, fp);
      return this.withList(userId, rec, tenantId);
    }
    if (pin.fingerprint !== fp) {
      writes.push([changeKey(userId), { user_id: userId, fingerprint: fp, previous: pin.fingerprint } satisfies IdentityChange]);
      this.changed = true;
      return undefined;
    }
    return this.withList(userId, rec, tenantId);
  }

  /**
   * Commits first sights to the synced pin set in one compare-and-swap (a conflict refetches and
   * evaluates the winner) and answers the members whose pin is now exactly the key proposed,
   * with no pending change. A failure commits nothing and throws. Lock held.
   */
  async commitFirstSights(sights: Map<string, string>): Promise<Set<string>> {
    const ok = new Set<string>();
    if (sights.size === 0) return ok;
    await this.syncPins(sights);
    for (const [user, fp] of sights) {
      const pin = await this.ctx.store.get<PinRecord>(pinKey(user));
      if (pin?.fingerprint === fp && !(await this.ctx.store.get(changeKey(user)))) ok.add(user);
    }
    return ok;
  }

  /**
   * The devices on rec's signed device list. The newest epoch seen per user and identity version
   * is remembered, so a server serving an older list (one that still names a removed device)
   * gets no device trusted.
   */
  private async withList(userId: string, rec: MasterKeyRecord, tenantId: string): Promise<TrustedMaster> {
    const none: TrustedMaster = { key: rec.master_key, devices: new Set() };
    const fp = pqc.fingerprint(rec.master_key);
    const dl = rec.device_list;
    if (dl !== undefined && !this.signedList(rec.master_key, tenantId, userId, rec.version, dl)) return none;
    // A rolled-back list (one that may still name a removed device), a fork at one epoch, or a
    // missing list after one was seen: no device of this user is trusted; for this device's own
    // current identity it is a rollback/fork verdict the gate must show.
    const seen = await this.observeList(tenantId, userId, fp, rec.version, dl);
    if (seen !== 'ok') {
      if (userId === this.ctx.userId) {
        const own = await this.local();
        if (own && own.tenant_id === tenantId && own.version === rec.version && own.fingerprint === fp) throw listVerdict(seen);
      }
      return none;
    }
    if (!dl) return none;
    return { key: rec.master_key, devices: new Set(dl.device_ids) };
  }

  /** Whether dl is canonical (sorted, distinct) and signed by key for exactly this identity. */
  private signedList(key: Hybrid, tenantId: string, userId: string, version: number, dl: unknown): dl is DeviceList {
    if (!validList(dl)) return false;
    const ids = dl.device_ids;
    if (ids.some((d, i) => i > 0 && ids[i - 1] >= d)) return false;
    return memo(['list', tenantId, userId, String(version), String(dl.epoch), JSON.stringify(ids), key, dl.signature],
      () => pqc.verifyDeviceList(key, tenantId, userId, version, dl.epoch, ids, dl.signature));
  }

  /**
   * Records dl as seen for one identity and says whether it is acceptable: 'ok' when it is the
   * newest seen (or exactly the newest), 'rollback' when older (or missing once one was seen),
   * 'fork' when another list was seen at the same epoch. The mark only rises, in one storage
   * transaction, so a status check and an unlocked sign-out cannot lower it; a list no newer
   * than the mark is checked without a write.
   */
  private async observeList(tenantId: string, userId: string, fp: string, version: number, dl: DeviceList | undefined): Promise<'ok' | 'rollback' | 'fork'> {
    const key = listKey(tenantId, userId, fp, version);
    // fork: two lists were seen at this epoch. It stays a fork, whichever of them the server
    // shows next, until a validly signed list at a higher epoch.
    type Mark = { epoch: number; digest: string; fork?: boolean };
    const seen = await this.ctx.store.get<Mark>(key);
    if (!dl) return seen ? 'rollback' : 'ok';
    const digest = pqc.hash('kymessages.device-list', ...dl.device_ids);
    const mark = seen && seen.epoch >= dl.epoch ? seen : await this.ctx.store.update<Mark>(key, (cur) => (!cur || dl.epoch > cur.epoch ? { epoch: dl.epoch, digest } : cur));
    if (!mark || mark.epoch > dl.epoch) return 'rollback';
    if (mark.fork) return 'fork';
    if (mark.digest === digest) return 'ok';
    await this.ctx.store.update<Mark>(key, (cur) => (cur && cur.epoch === dl.epoch ? { ...cur, fork: true } : cur));
    return 'fork';
  }

  /**
   * Runs before every trust check (a send, a room open, a mailbox read), with the lock held: a
   * verified device syncs the pin set first, so no first sight is decided against a stale set.
   * A failed sync fails the check; it never decides trust by itself.
   */
  async beforeTrust(): Promise<void> {
    if (await this.local()) await this.syncPins();
  }

  /** Whether device d of userId is on master's device list and carries its cross-signature. */
  deviceTrusted(master: TrustedMaster, tenantId: string, userId: string, d: { device_id: string; curve25519: string; ed25519: string; master_signature?: unknown }): boolean {
    const s = d.master_signature;
    if (!master.devices.has(d.device_id) || !isHybrid(s)) return false;
    return memo(['device', tenantId, userId, d.device_id, d.curve25519, d.ed25519, master.key, s],
      () => pqc.verifyDevice(master.key, tenantId, userId, d.device_id, d.curve25519, d.ed25519, s));
  }

  /** After trustedMaster's writes are stored: announce changes. */
  afterWrites(): void {
    if (this.changed) {
      this.changed = false;
      this.notify();
    }
  }

  changes(): Promise<IdentityChange[]> {
    return this.ctx.store.list<IdentityChange>('mchg:').then((rows) => rows.map(([, v]) => v));
  }

  /**
   * The viewer accepts userId's change from previous to fingerprint, exactly as shown. It syncs
   * the pin set first and checks, on every attempt, that the pending change is exactly that,
   * this device's pin is previous and the shared pin is previous (or already the new key): if
   * another tab or another of the user's devices moved either on, nothing is accepted and the
   * refreshed prompt shows. The pin changes here only once the signed shared write took it.
   */
  acceptChange(userId: string, previous: string, fingerprint: string): Promise<void> {
    return this.ctx.locked(async () => {
      try {
        await this.syncPins(new Map(), { user: userId, previous, fingerprint });
      } finally {
        this.notify();
      }
    });
  }

  // --- This device's state ---

  /**
   * Whether the user has an identity and this device holds it. A verified device makes sure it
   * is cross-signed and on the device list, resumes a key backup restore and drains its backup
   * queue. A device whose identity the server no longer lists sets its seeds aside.
   */
  status(): Promise<IdentityStatus> {
    return this.ctx.locked(async (): Promise<IdentityStatus> => {
      const { tenant_id, master } = await this.ctx.server.getMaster();
      let l = await this.local();
      if (!master) {
        if (l) {
          await this.quarantine(l);
          this.notify();
        }
        return { state: 'none', quarantined: await this.hasQuarantined() };
      }
      if (!validMaster(master) || !pqc.verifyMaster(master.master_key, tenant_id, this.ctx.userId, master.self_signature)) {
        throw new Error('The server sent an encryption identity that does not verify');
      }
      const fp = pqc.fingerprint(master.master_key);
      const current = (x?: LocalIdentity) => !!x && x.fingerprint === fp && x.version === master.version && x.tenant_id === tenant_id;
      if (!l) {
        // The server lists an identity set aside earlier again: take it back.
        const prev = await this.ctx.store.get<LocalIdentity>(previousKey(fp, master.version));
        if (current(prev)) {
          await this.ctx.store.write([[IDENTITY, prev]], [previousKey(fp, master.version)]);
          l = prev;
        }
      }
      if (l && current(l)) {
        this.backupGen = { version: master.version, generation: master.backup_generation };
        // A cross-signature that cannot be stored now (the network) is retried, not fatal.
        await this.signOwnDevice(l).catch((e: unknown) => {
          if (!isTransient(e)) throw e;
          this.later(e);
        });
        // A rolled-back or forked list or pin set is reported, never signed over: re-signing an
        // old roster, or an empty pin set, to get past the mark would bring back what the newer
        // state removed. Resetting the identity is the way out (the UI offers it).
        let problem: Rollback['kind'] | undefined;
        try {
          if (master.pins.counter < ((await this.ctx.store.get<number>(pinsMark(l))) ?? 0)) throw new Rollback('rollback', 'pin set rolled back');
          // Under the lock: a list another device holds is not waited for here, but retried.
          await this.ensureListed(l, false);
          await this.enrolled(true, l);
        } catch (e) {
          if (isTransient(e)) this.later(e);
          else if (!(e instanceof Rollback)) throw e;
          else problem = e.kind;
        }
        // A failed resume keeps its cursor, shows as restoring, and is retried.
        void this.resumeRestore().catch((e: unknown) => this.later(e));
        void this.ctx.locked(() => this.flushBackup(true)).catch((e: unknown) => this.later(e));
        const restoring = (await this.ctx.store.get(RESTORE)) !== undefined;
        const backupFull = (await this.ctx.store.list('bqf:')).length > 0;
        this.backupFull = backupFull;
        return { state: 'verified', fingerprint: fp, restoring, backupFull, ...(problem ? { problem } : {}) };
      }
      if (l) {
        await this.quarantine(l);
        this.notify();
      }
      return { state: 'unverified', fingerprint: fp, quarantined: await this.hasQuarantined() };
    });
  }

  /**
   * Resumes a pending key backup restore and drains the backup queue, refused entries included,
   * awaiting both; throws what stopped them. Nothing to do without an identity.
   */
  async drain(): Promise<void> {
    const l = await this.local();
    if (!l) return;
    // A cross-signature that failed (a replacement device signing itself) is retried here.
    await this.ctx.locked(() => this.signOwnDevice(l));
    // Unlocked: a listing given up under the lock (another device held the list) waits here. A
    // rollback or fork is a verdict the status reports; the restore and the backup still run.
    let verdict: Rollback | undefined;
    try {
      await this.ensureListed(l);
      await this.enrolled(false, l);
    } catch (e) {
      if (!(e instanceof Rollback)) throw e;
      verdict = e;
    }
    await this.resumeRestore();
    await this.ctx.locked(() => this.flushBackup(true));
    if (verdict) throw verdict;
  }

  /** Tells the UI when whether refused sessions wait changes; nothing is redone. */
  private async backupStateChanged(): Promise<void> {
    const full = (await this.ctx.store.list('bqf:')).length > 0;
    if (full === this.backupFull) return;
    this.backupFull = full;
    this.ctx.onBackupState?.(full);
  }

  /** A failure for availability asks for a retry and is swallowed; anything else is thrown. */
  private unlessTransient(e: unknown): void {
    if (!isTransient(e)) throw e;
    this.later(e);
  }

  /**
   * Once this device is signed and listed after taking on the identity, the enrollment is
   * durable: pending retirements can be signed now (before any backup page is read).
   * Confirmation and removal of ENROLLING run in one per-user lock transaction (reusing the
   * caller's lock when locked is true), bound to the identity/marker that is being confirmed.
   */
  private async enrolled(locked: boolean, expected?: { tenant_id: string; version: number; fingerprint: string }): Promise<void> {
    const run = <T>(fn: () => Promise<T>) => (locked ? fn() : this.ctx.locked(fn));
    try {
      const confirmed = await run(async () => {
        const l = await this.local();
        const marker = await this.ctx.store.get<EnrollingRecord | boolean>(ENROLLING);
        const signed = await this.ctx.store.get<{ version: number; device_id: string }>(SIGNED);
        if (!l || !marker || signed?.version !== l.version || signed.device_id !== this.ctx.deviceId) return false;
        if (expected && (l.tenant_id !== expected.tenant_id || l.version !== expected.version || l.fingerprint !== expected.fingerprint)) return false;
        if (typeof marker === 'object' && (marker.tenant_id !== l.tenant_id || marker.version !== l.version || marker.fingerprint !== l.fingerprint)) return false;
        // Confirmed only against the authenticated current master this device holds.
        const { tenant_id, master } = await this.ctx.server.getMaster();
        if (!master || !validMaster(master) || tenant_id !== l.tenant_id || master.version !== l.version ||
          pqc.fingerprint(master.master_key) !== l.fingerprint ||
          !pqc.verifyMaster(master.master_key, tenant_id, this.ctx.userId, master.self_signature)) return false;
        const dl = master.device_list;
        // An unauthenticated list neither confirms nor counts as absence. Once the current master
        // is authenticated, a missing list after an authenticated list was seen IS rollback and
        // keeps the marker; any authenticated list is observed before membership counts.
        if (dl !== undefined && !this.signedList(l.master_key, l.tenant_id, this.ctx.userId, l.version, dl)) return false;
        const seen = await this.observeList(l.tenant_id, this.ctx.userId, l.fingerprint, l.version, dl);
        if (seen !== 'ok') throw listVerdict(seen);
        if (!dl || !dl.device_ids.includes(this.ctx.deviceId)) return false;
        await this.ctx.store.write([], [ENROLLING]);
        return true;
      });
      if (confirmed) this.ctx.onAdopted?.();
    } catch (e) {
      // Enrollment already happened; failing to confirm it for availability is retried.
      if (e instanceof Rollback) throw e;
      this.unlessTransient(e);
    }
  }

  /** Background work that failed for availability asks for a retry. */
  private later(e: unknown): void {
    if (isTransient(e)) this.ctx.onTransient?.();
  }

  private async signOwnDevice(l: LocalIdentity): Promise<void> {
    // A device reset keeps the identity but makes a new device ID, which needs its own signature.
    const signed = await this.ctx.store.get<{ version: number; device_id: string }>(SIGNED);
    if (signed?.version === l.version && signed.device_id === this.ctx.deviceId) return;
    const seeds = await this.seeds(l);
    const sig = pqc.signDevice(seeds.master, l.tenant_id, this.ctx.userId, this.ctx.deviceId, this.ctx.curve25519, this.ctx.ed25519);
    await this.ctx.server.signDevice(this.ctx.deviceId, l.version, sig);
    await this.ctx.store.write([[SIGNED, { version: l.version, device_id: this.ctx.deviceId }]]);
  }

  /**
   * Rewrites the signed device list with change applied. The list it starts from must be signed
   * by this device's own master key for exactly this org, user and version, canonical, and not
   * older than (nor a fork of) the newest this device has seen (Rollback otherwise); a missing
   * list is a start only when this device has seen none. The next epoch is reserved for exactly
   * the proposed list before it is signed, so a proposal that loses to another device's is never
   * signed: on a conflict this refetches and applies change to the winner. guard, checked on
   * every attempt before reserving, can call the edit off: an edit that started before the guard
   * turned false either published first (and a later edit sees its result) or loses its
   * reservation and stops. Throws when the identity moved on or the list keeps changing.
   */
  private async editList(l: LocalIdentity, change: (ids: Set<string>) => void, opts: { guard?: () => Promise<boolean>; publishUnchanged?: boolean; waitHeld?: boolean } = {}): Promise<void> {
    const seeds = await this.seeds(l);
    const user = this.ctx.userId;
    const started = Date.now();
    let wait = 0;
    for (let attempt = 0; attempt < LIST_ATTEMPTS;) {
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      const { tenant_id, master } = await this.ctx.server.getMaster();
      if (!master || tenant_id !== l.tenant_id || master.version !== l.version || pqc.fingerprint(master.master_key) !== l.fingerprint) {
        throw new IdentityMoved('The encryption identity changed; the device list was not edited.');
      }
      const cur = master.device_list;
      if (cur !== undefined && !this.signedList(l.master_key, l.tenant_id, user, l.version, cur)) {
        throw new Error('The server’s device list is not signed by this identity.');
      }
      const seen = await this.observeList(l.tenant_id, user, l.fingerprint, l.version, cur);
      if (seen !== 'ok') throw listVerdict(seen);
      const ids = new Set(cur?.device_ids ?? []);
      const before = [...ids].join('\n');
      change(ids);
      const next = [...ids].sort();
      // A removal that changes nothing still publishes (publishUnchanged): reserving orders it
      // after any edit already holding the list, such as an enrollment of the device removed.
      if (cur && next.join('\n') === before && !opts.publishUnchanged) return;
      // Checked right before reserving, so an enrollment cannot reserve after a sign-out began.
      if (opts.guard && !(await opts.guard())) return;
      const expected = cur?.epoch ?? 0;
      try {
        // The lease is counted from before the request, on the monotonic clock: a grant that
        // arrives late has less left than it says, and one already spent is not signed under.
        // Reserving takes the master key too, so a session without the seed cannot hold the list.
        const digest = pqc.hash('kymessages.device-list', ...next);
        const proof = pqc.signDeviceListReserve(seeds.master, l.tenant_id, user, l.version, expected, digest);
        const asked = performance.now();
        const r = await this.ctx.server.reserveDeviceList(l.version, expected, digest, proof);
        const until = asked + r.expires_in_ms;
        // Signed only once reserved, for the epoch reserved, and never under a reservation known
        // to have lapsed; a lost reservation discards this signature unsent.
        if (performance.now() >= until) throw new Conflict('The reservation lapsed');
        const signature = pqc.signDeviceList(seeds.master, l.tenant_id, user, l.version, r.epoch, next);
        if (performance.now() >= until) throw new Conflict('The reservation lapsed');
        await this.ctx.server.putDeviceList(l.version, expected, r.epoch, next, signature);
        // Finalized: only a list the server took is recorded as seen.
        await this.observeList(l.tenant_id, user, l.fingerprint, l.version, { epoch: r.epoch, device_ids: next, signature: '' });
        return;
      } catch (e) {
        if (!(e instanceof Conflict)) throw e;
        if (e.retryInMs !== undefined && opts.waitHeld === false) throw new Transient('Another device is changing the device list');
        if (e.retryInMs !== undefined && Date.now() - started < LIST_WAIT_MAX_MS) {
          // Another device's reservation holds the list: look again shortly (its edit usually
          // lands at once) until it lapses, however long the server's lease.
          wait = Math.min(e.retryInMs + LIST_BACKOFF_MS, LIST_HOLD_POLL_MS);
          continue;
        }
        // The list moved on (or the wait ran out): back off briefly and edit the winner.
        wait = LIST_BACKOFF_MS * 2 ** attempt++;
      }
    }
    throw new Error('The device list kept changing; try again.');
  }

  /** Adds this device to the list unless it is retiring (a sign-out is taking it off), checked
   * right before every reservation so an enrollment in flight cannot undo a sign-out. waitHeld
   * false (under the per-user lock) gives up at once on a list another device holds. */
  private async ensureListed(l: LocalIdentity, waitHeld = true): Promise<void> {
    await this.editList(l, (ids) => ids.add(this.ctx.deviceId), { guard: async () => (await this.ctx.store.get<string>(RETIRING)) !== this.ctx.deviceId, waitHeld });
  }

  /**
   * Takes devices off the signed list (this one at sign-out, abandoned ones after) and resolves
   * once the signed removal is stored; throws otherwise. This device marks itself retiring first,
   * so nothing here adds it back. Not under the per-user lock: sign-out must never wait behind
   * another tab's crypto work, and the server's compare-and-swap orders concurrent edits.
   */
  async delist(deviceIds: string[]): Promise<void> {
    if (deviceIds.includes(this.ctx.deviceId)) await this.ctx.store.write([[RETIRING, this.ctx.deviceId]]);
    const l = await this.local();
    if (!l) {
      // With no identity, or none that lists devices, there is nothing to sign away.
      const { master } = await this.ctx.server.getMaster();
      if (!master?.device_list) return;
      throw new Error('Only a verified device can change the device list.');
    }
    await this.editList(l, (ids) => deviceIds.forEach((d) => ids.delete(d)), { publishUnchanged: true });
  }

  /**
   * A new identity for the user's first device (or a reset, which colleagues see as an identity
   * change). The version it replaces is read now, so commit never replaces an identity made
   * meanwhile. Nothing is uploaded until commit, which the UI calls only after the user confirms
   * they saved the recovery key; a commit retried after a lost answer is harmless.
   */
  async prepare(reset: boolean): Promise<{ recoveryKey: string; commit(): Promise<void> }> {
    const { tenant_id, master: current } = await this.ctx.server.getMaster();
    if (current && !reset) throw new Conflict('This account already has an encryption identity');
    const expected = current?.version ?? 0;
    const version = expected + 1;
    const user = this.ctx.userId;
    const master = pqc.masterGenerate();
    const backup = pqc.xwingGenerate();
    const recovery = pqc.recoveryGenerate();
    const own: OwnMaster = {
      version,
      master_key: master.public_key,
      self_signature: pqc.signMaster(master.seed, tenant_id, user),
      backup_key: { public_key: backup.public, signature: pqc.signBackupKey(master.seed, tenant_id, user, version, backup.public) },
      backup_generation: 0,
      recovery: {
        wrapped_master_key: pqc.recoveryWrap(recovery.key, 'master-key', tenant_id, user, master.seed),
        wrapped_backup_key: pqc.recoveryWrap(recovery.key, 'backup-key', tenant_id, user, backup.seed),
      },
      pins: { counter: 0, sealed: '' },
    };
    // What is uploaded must restore with the key the user is about to save.
    this.checkOwn(tenant_id, own,
      pqc.recoveryUnwrap(recovery.key, 'master-key', tenant_id, user, own.recovery.wrapped_master_key),
      pqc.recoveryUnwrap(recovery.key, 'backup-key', tenant_id, user, own.recovery.wrapped_backup_key),
      master.fingerprint);
    return {
      recoveryKey: recovery.text,
      commit: async () => {
        try {
          const stored = await this.ctx.server.putMaster({ expected_version: expected, master_key: own.master_key, self_signature: own.self_signature, backup_key: own.backup_key, recovery: own.recovery });
          if (stored !== version) throw new Conflict('The encryption identity changed meanwhile');
        } catch (e) {
          // A retry whose first answer was lost finds its own identity already stored.
          if (!(e instanceof Conflict)) throw e;
          const { master: now } = await this.ctx.server.getMaster();
          if (now?.master_key !== own.master_key || now.version !== version) throw e;
        }
        await this.adopt(tenant_id, master.fingerprint, master.seed, backup.seed);
      },
    };
  }

  /** Verifies this device with the recovery key; returns how many sessions the backup restored. */
  async restore(recoveryText: string): Promise<number> {
    let key: string;
    try {
      key = pqc.recoveryParse(recoveryText);
    } catch {
      throw new Error('That is not a valid recovery key. Check it for typos.');
    }
    const { tenant_id, master } = await this.ctx.server.getMaster();
    if (!master) throw new Error('This account has no encryption identity to restore.');
    let masterSeed: string;
    let backupSeed: string;
    try {
      masterSeed = pqc.recoveryUnwrap(key, 'master-key', tenant_id, this.ctx.userId, master.recovery.wrapped_master_key);
      backupSeed = pqc.recoveryUnwrap(key, 'backup-key', tenant_id, this.ctx.userId, master.recovery.wrapped_backup_key);
    } catch {
      throw new Error('That recovery key does not unlock this account.');
    }
    const fingerprint = pqc.fingerprint(master.master_key);
    this.checkOwn(tenant_id, master, masterSeed, backupSeed, fingerprint);
    return this.adopt(tenant_id, fingerprint, masterSeed, backupSeed);
  }

  /** The seeds must be exactly the published identity, whose statements must verify. */
  private checkOwn(tenantId: string, master: OwnMaster, masterSeed: string, backupSeed: string, fingerprint: string): void {
    const user = this.ctx.userId;
    const ok = validMaster(master) &&
      pqc.masterPublic(masterSeed).fingerprint === fingerprint && pqc.fingerprint(master.master_key) === fingerprint &&
      pqc.verifyMaster(master.master_key, tenantId, user, master.self_signature) &&
      pqc.xwingPublic(backupSeed) === master.backup_key.public_key &&
      pqc.verifyBackupKey(master.master_key, tenantId, user, master.version, master.backup_key.public_key, master.backup_key.signature);
    if (!ok) throw new Error('The keys do not match this account’s published identity.');
  }

  /**
   * Takes the identity on: stores it, signs this device and lists it, syncs pins, then reads the
   * key backup in (resumable, one page per lock) and seals what this device holds to it.
   */
  private async adopt(tenantId: string, fingerprint: string, masterSeed: string, backupSeed: string, abort?: { signal: AbortSignal; late: () => Error | undefined }): Promise<number> {
    // The screen's close and the deadline call this off at any point up to the seed write.
    const stop = () => {
      const timedOut = abort?.late();
      if (timedOut) throw timedOut;
      abort?.signal.throwIfAborted();
    };
    // Everything before the seed write is one sequence under the lock, ending with a fresh read
    // of the identity right before the write. A failure of that sequence for availability
    // releases the lock and runs it again whole (a few times), with the seeds held here: a
    // consumed transfer cannot be consumed again. Nothing after the write is replayed.
    let local: LocalIdentity | undefined;
    for (let attempt = 0; !local; attempt++) {
      stop();
      try {
        local = await this.ctx.locked(async () => {
          // Every verified room key this device already holds goes to the backup too.
          // A new identity has a new, empty backup: what an old one refused is tried again.
          const queue = (await this.ctx.store.list<InboundRecord>('in:')).filter(([, r]) => r.verified && !r.from_backup).map(([k]): [string, unknown] => [backupQueueKey(k), k]);
          const refused = (await this.ctx.store.list('bqf:')).map(([k]) => k);
          // The identity as published now: its org, master key and the backup key it signed,
          // which the seeds must derive; its backup generation is the one written for.
          const { tenant_id: tenantNow, master: now } = await this.ctx.server.getMaster(abort?.signal);
          if (!now || tenantNow !== tenantId || pqc.fingerprint(now.master_key) !== fingerprint) {
            throw new Error('This account’s encryption identity changed meanwhile. Start again.');
          }
          this.checkOwn(tenantId, now, masterSeed, backupSeed, fingerprint);
          // This browser's own baseline, checked on every try: another tab may have taken on a
          // newer identity, or another at the same version, which this one never overwrites;
          // an older one (a reset) is replaced as intended. The very same identity (another
          // attempt adopted it) keeps its restore and backup progress.
          const held = await this.local();
          const same = held?.tenant_id === tenantId && held.version === now.version && held.fingerprint === fingerprint;
          if (!same && held?.tenant_id === tenantId && held.version >= now.version) {
            throw new Error('This browser took on another encryption identity meanwhile. Start again.');
          }
          const next = same ? held : await this.sealLocal(tenantId, now, masterSeed, backupSeed);
          const restore: RestoreCursor = { version: next.version, after: { room_id: '', sender_key: '', session_id: '' }, count: 0 };
          // The last point the screen or its deadline can still call this off.
          stop();
          // The seeds are durable from here: enrollment (signing and listing this device) and
          // the backup read that then fail for availability are finished by the bounded retry.
          const enrolling: EnrollingRecord = { tenant_id: next.tenant_id, version: next.version, fingerprint: next.fingerprint };
          if (!same) await this.ctx.store.write([[IDENTITY, next], [RESTORE, restore], [ENROLLING, enrolling], ...queue], [SIGNED, ...refused]);
          this.backupGen = { version: now.version, generation: now.backup_generation };
          return next;
        }, abort?.signal);
      } catch (e) {
        // A deadline that ran out (waiting for the lock too) reads as the pairing's own timeout.
        const timedOut = abort?.late();
        if (timedOut) throw timedOut;
        if (abort?.signal.aborted || !isTransient(e) || attempt >= PAIRING_RETRIES) throw e;
        if (e instanceof PQCUnavailable) {
          await abortable(ensurePQC(), abort?.signal, abort?.late).catch((err: unknown) => {
            if (!(err instanceof PQCUnavailable)) throw err;
          });
        }
        await sleep(PAIRING_POLL_MS, abort?.signal).catch(() => undefined);
      }
    }
    // The seeds are durable from here: availability errors in post-write lock acquisition,
    // signing, listing, backup-state or confirmation use pending/retry handling, while permanent
    // verdicts still propagate and the closing notification always runs.
    try {
      await this.ctx.locked(async () => {
        await this.signOwnDevice(local).catch((e: unknown) => this.unlessTransient(e));
        await this.syncPins().catch((e: unknown) => {
          if (e instanceof Rollback) throw e;
          this.later(e);
        });
      }).catch((e: unknown) => this.unlessTransient(e));
      // Outside the lock: waiting out another device's reservation must not hold every tab.
      await this.ensureListed(local).catch((e: unknown) => this.unlessTransient(e));
      await this.backupStateChanged().catch((e: unknown) => this.unlessTransient(e));
      await this.enrolled(false, local);
    } finally {
      this.notify();
    }
    // The identity is taken on: a backup read that fails for availability now leaves its cursor
    // pending for the retry; it is not a failed verification.
    const restored = await this.resumeRestore().catch((e: unknown) => {
      this.unlessTransient(e);
      return 0;
    });
    await this.ctx.locked(() => this.flushBackup()).catch((e: unknown) => this.later(e));
    return restored;
  }

  // --- Pins shared with the user's other devices ---

  /**
   * Merges this device's pins with the sealed set on the server and writes the result back. A
   * pin never silently changes: a different fingerprint is adopted only as an accepted change
   * from exactly this device's pin, and any other disagreement is kept as a pending change. The
   * counter's high-water mark refuses a rolled-back set (Rollback). sights are first sights to
   * add: each is stored here only once the server took a set holding it, and one another device
   * pinned first wins (this device's key for that member becomes a pending change). Lock held.
   */
  async syncPins(sights: ReadonlyMap<string, string> = new Map(), accept?: { user: string; previous: string; fingerprint: string }): Promise<void> {
    const l = await this.local();
    if (!l) {
      if (accept) throw new Error('Only a verified device can accept an identity change.');
      return;
    }
    const seeds = await this.seeds(l);
    const mark = pinsMark(l);
    for (let attempt = 0; attempt < 3; attempt++) {
      const { tenant_id, master } = await this.ctx.server.getMaster();
      if (!master || !validMaster(master) || tenant_id !== l.tenant_id || master.version !== l.version ||
        pqc.fingerprint(master.master_key) !== l.fingerprint ||
        !pqc.verifyMaster(master.master_key, tenant_id, this.ctx.userId, master.self_signature)) {
        throw new IdentityMoved('The encryption identity changed; check this device again.');
      }
      const counter = master.pins.counter;
      if (counter < ((await this.ctx.store.get<number>(mark)) ?? 0)) throw new Rollback('rollback', 'The server returned an older pin set than this device has seen.');
      const dl = master.device_list;
      if (dl === undefined || this.signedList(l.master_key, l.tenant_id, this.ctx.userId, l.version, dl)) {
        const seen = await this.observeList(l.tenant_id, this.ctx.userId, l.fingerprint, l.version, dl);
        if (seen !== 'ok') throw listVerdict(seen);
      }
      const remote: Record<string, PinRecord> = {};
      if (counter > 0) {
        // A set that does not open is an error, never an empty set: local pins stay as they are.
        const p = parseJSON(unb64(pqc.pinsOpen(seeds.master, l.tenant_id, this.ctx.userId, counter, master.pins.sealed)));
        if (!isObj(p)) throw new Error('The synced pin set does not open.');
        for (const [u, r] of Object.entries(p)) if (validPin(r)) remote[u] = r;
      }
      await this.ctx.store.update<number>(mark, (cur) => (cur === undefined || counter > cur ? counter : cur));
      const local = new Map((await this.ctx.store.list<PinRecord>('mpin:')).filter(([, v]) => validPin(v)).map(([k, v]) => [k.slice(5), v]));
      const merged: Record<string, PinRecord> = {};
      const writes: [string, unknown][] = [];
      const deletes: string[] = [];
      // First sights become pins only after the server took them (tentative until then).
      const tentative: [string, unknown][] = [];
      for (const [user, fp] of sights) {
        if (user === this.ctx.userId || local.has(user)) continue;
        const r = remote[user];
        if (!r) {
          const pin: PinRecord = { fingerprint: fp, n: 1, accepted: false };
          merged[user] = pin;
          tentative.push([pinKey(user), pin]);
        } else if (r.fingerprint !== fp) {
          // Another device pinned a different key first: that pin stands, this one is a change.
          writes.push([changeKey(user), { user_id: user, fingerprint: fp, previous: r.fingerprint } satisfies IdentityChange]);
          this.changed = true;
        }
      }
      for (const user of new Set([...local.keys(), ...Object.keys(remote)])) {
        if (user === this.ctx.userId) continue;
        const a = local.get(user);
        const r = remote[user];
        if (!a || !r) {
          merged[user] = (a ?? r)!;
          if (!a) writes.push([pinKey(user), r]);
          continue;
        }
        if (a.fingerprint === r.fingerprint) {
          const newer = r.n > a.n ? r : a;
          const m: PinRecord = { fingerprint: a.fingerprint, n: Math.max(a.n, r.n), accepted: a.accepted || r.accepted, ...(newer.prev ? { prev: newer.prev } : {}) };
          merged[user] = m;
          if (canon({ x: m }) !== canon({ x: a })) writes.push([pinKey(user), m]);
          // Agreeing again settles a pending change to this same key.
          if ((await this.ctx.store.get<IdentityChange>(changeKey(user)))?.fingerprint === a.fingerprint) deletes.push(changeKey(user));
          continue;
        }
        if (r.accepted && r.n > a.n && r.prev === a.fingerprint) {
          // Accepted on another of the user's devices, as a change from exactly this pin. A
          // prompt here for that same key is settled; one for yet another key now changes from
          // the new pin, so it is never accepted against the pin it replaced.
          merged[user] = r;
          writes.push([pinKey(user), r]);
          const c = await this.ctx.store.get<IdentityChange>(changeKey(user));
          if (c?.fingerprint === r.fingerprint) deletes.push(changeKey(user));
          else if (c) writes.push([changeKey(user), { ...c, previous: r.fingerprint } satisfies IdentityChange]);
          this.changed = true;
          continue;
        }
        if (a.accepted && a.n > r.n && a.prev === r.fingerprint) {
          // Accepted here, as a change from exactly the synced pin: the set takes ours.
          merged[user] = a;
          continue;
        }
        // Two devices disagree (or a change came over more than one hop): the set keeps its pin,
        // this device keeps its own and a pending change, and the user decides here.
        merged[user] = r;
        const c = await this.ctx.store.get<IdentityChange>(changeKey(user));
        if (!c) {
          writes.push([changeKey(user), { user_id: user, fingerprint: r.fingerprint, previous: a.fingerprint } satisfies IdentityChange]);
          this.changed = true;
        }
      }
      await this.ctx.store.write(writes, deletes);
      if (this.changed || deletes.length > 0) {
        this.changed = false;
        this.notify();
      }
      // An accept is checked against the state just synced, not the one the prompt was drawn
      // from. The shared pin must be exactly the old key (then the new one replaces it) or already
      // the new key (another device accepted it, perhaps over more hops: that record is adopted
      // as it is). Anything else, a missing shared pin included, accepts nothing: this attempt
      // still writes the synced set, so the user retries against a confirmed baseline.
      let accepted: PinRecord | undefined;
      let adopted: PinRecord | undefined;
      let rebased: IdentityChange | undefined;
      let refused = false;
      if (accept) {
        const pin = await this.ctx.store.get<PinRecord>(pinKey(accept.user));
        const c = await this.ctx.store.get<IdentityChange>(changeKey(accept.user));
        const shared = remote[accept.user];
        if (shared?.fingerprint === accept.fingerprint) {
          // Settled already (another device accepted this key): the verified shared record is
          // adopted as it is. A pending change here for yet another key is not what the user
          // clicked: it stays, rebased onto the adopted pin, and the click is refused.
          adopted = shared;
          if (c && c.fingerprint !== accept.fingerprint) {
            rebased = { ...c, previous: shared.fingerprint };
            refused = true;
          }
        } else if (!shared || shared.fingerprint !== accept.previous || pin?.fingerprint !== accept.previous ||
          c?.previous !== accept.previous || c.fingerprint !== accept.fingerprint) {
          refused = true;
        } else {
          accepted = { fingerprint: accept.fingerprint, n: Math.max(pin.n, shared.n) + 1, accepted: true, prev: accept.previous };
          merged[accept.user] = accepted;
        }
      }
      if (canon(merged) !== canon(remote)) {
        const sealed = pqc.pinsSeal(seeds.master, l.tenant_id, this.ctx.userId, counter + 1, b64(JSON.stringify(merged)));
        const signature = pqc.signPinsWrite(seeds.master, l.tenant_id, this.ctx.userId, l.version, counter + 1, sealed);
        try {
          await this.ctx.server.putPins(l.version, counter, sealed, signature);
        } catch (e) {
          if (!(e instanceof Conflict)) throw e;
          continue; // refetch: the winner's set is merged (and an accept checked) again
        }
        await this.ctx.store.update<number>(mark, (cur) => (cur === undefined || counter + 1 > cur ? counter + 1 : cur));
      }
      // putIfAbsent: a pin another tab stored meanwhile is never overwritten.
      for (const [k, v] of tentative) await this.ctx.store.putIfAbsent(k, v);
      const took = accepted ?? adopted;
      if (accept && took) {
        await this.ctx.store.write([[pinKey(accept.user), took], ...(rebased ? [[changeKey(accept.user), rebased] as [string, unknown]] : [])], rebased ? [] : [changeKey(accept.user)]);
      }
      if (refused) throw new Error('This identity changed again. Check the new fingerprint before accepting.');
      return;
    }
    throw new Error('The synced pin set kept changing; try again.');
  }

  // --- Key backup ---

  /** The backup generation writes are signed for: cached from the identity, refetched after a
   * conflict (a deletion elsewhere starts a new one, and what it refused is tried again). */
  private async generation(l: LocalIdentity, refetch: boolean): Promise<number> {
    if (!refetch && this.backupGen?.version === l.version) return this.backupGen.generation;
    const { tenant_id, master } = await this.ctx.server.getMaster();
    if (!master || tenant_id !== l.tenant_id || master.version !== l.version) throw new Conflict('The encryption identity changed');
    const was = this.backupGen?.version === l.version ? this.backupGen.generation : undefined;
    this.backupGen = { version: l.version, generation: master.backup_generation };
    if (was !== undefined && master.backup_generation !== was) {
      const refused = await this.ctx.store.list<string>('bqf:');
      await this.ctx.store.write(refused.map(([, ik]): [string, unknown] => [backupQueueKey(ik), ik]), refused.map(([k]) => k));
    }
    return master.backup_generation;
  }

  /**
   * Seals queued room sessions to the backup key; a bad entry is dropped alone. Entries the
   * server refused for its caps stay queued apart (bqf:), retried with refused (on status) and
   * shown as the backup being full until they fit. Lock held.
   */
  async flushBackup(refused = false): Promise<void> {
    const l = await this.local();
    if (!l) return;
    let queue = await this.ctx.store.list<string>('bq:');
    if (refused) {
      // A session queued afresh while its refused entry waits is sent once: the refused entry
      // stays queued (it is kept until it lands), so its fresh twin goes now.
      const waiting = await this.ctx.store.list<string>('bqf:');
      const held = new Set(waiting.map(([, ik]) => ik));
      const twins = queue.filter(([, ik]) => held.has(ik));
      if (twins.length > 0) await this.ctx.store.write([], twins.map(([k]) => k));
      queue = [...queue.filter(([, ik]) => !held.has(ik)), ...waiting];
    }
    if (queue.length === 0) return;
    const seeds = await this.seeds(l);
    try {
      await this.flushBatches(l, seeds, queue);
    } finally {
      // What landed is durable even when a later batch failed: the notice follows it.
      await this.backupStateChanged().catch(() => undefined);
    }
  }

  private async flushBatches(l: LocalIdentity, seeds: { master: string; backup: string }, queue: [string, string][]): Promise<void> {
    for (let i = 0; i < queue.length; i += BACKUP_BATCH) {
      const entries: BackupEntry[] = [];
      const keys: [string, string][] = [];
      const done: string[] = [];
      for (const [qk, ik] of queue.slice(i, i + BACKUP_BATCH)) {
        done.push(qk);
        const rec = await this.ctx.store.get<InboundRecord>(ik);
        if (!rec || rec.from_backup || !rec.verified) continue;
        let s: InboundGroupSession | undefined;
        try {
          s = InboundGroupSession.fromPickle(rec.pickle, this.ctx.pickleKey);
          const ref: BackupRef = { room_id: rec.room_id, sender_key: rec.sender_key, session_id: s.sessionId, first_index: s.firstKnownIndex };
          const payload = { v: 1, ...ref, sender_user: rec.sender_user, sender_device: rec.sender_device, session_key: s.exportAtFirstKnownIndex() };
          entries.push({ ...ref, sealed: pqc.backupSeal(l.backup_key, seeds.master, ref, b64(JSON.stringify(payload))) });
          keys.push([qk, ik]);
        } catch (e) {
          // An unavailable module stops the flush with the queue kept; only an unreadable
          // pickle is dropped from it.
          if (isTransient(e)) throw e;
        } finally {
          s?.free();
        }
      }
      const keep: [string, unknown][] = [];
      if (entries.length > 0) {
        const put = async (refetch: boolean) => {
          const gen = await this.generation(l, refetch);
          return this.ctx.server.putBackup(l.version, gen, entries, pqc.signBackupWrite(seeds.master, l.tenant_id, this.ctx.userId, l.version, gen, entries));
        };
        const res = await put(false).catch((e: unknown) => {
          if (e instanceof Conflict) return put(true);
          throw e;
        });
        for (const n of new Set(res.refused)) {
          const k = keys[n];
          if (k) keep.push([backupRefusedKey(k[1]), k[1]]);
        }
      }
      // A refused entry moves to bqf: (or stays there); everything else in the batch is done.
      const kept = new Set(keep.map(([k]) => k));
      await this.ctx.store.write(keep, done.filter((k) => !kept.has(k)));
      // Durable now: the notice follows, even if a later batch stalls.
      await this.backupStateChanged();
    }
  }

  /** Reads the rest of the key backup in, if a restore is pending; one restore at a time. */
  private resumeRestore(): Promise<number> {
    this.restoring ??= this.restoreAll().finally(() => {
      this.restoring = undefined;
    });
    return this.restoring;
  }

  // Page by page, each under its own lock, so sends and other tabs are never held for a whole
  // backup. The cursor is stored after every page, so a reload resumes where this stopped.
  private async restoreAll(): Promise<number> {
    let total = 0;
    for (;;) {
      const step = await this.ctx.locked(() => this.restorePage());
      if (!step) return total;
      total += step.count;
      if (step.done) {
        this.notify();
        return total;
      }
    }
  }

  private async restorePage(): Promise<{ count: number; done: boolean } | undefined> {
    const l = await this.local();
    const cur = await this.ctx.store.get<RestoreCursor>(RESTORE);
    if (!l || !cur) return undefined;
    if (cur.version !== l.version) {
      await this.ctx.store.write([], [RESTORE]);
      return { count: 0, done: true };
    }
    const seeds = await this.seeds(l);
    const page = await this.ctx.server.getBackup(l.version, cur.after);
    if (page.sessions.length > BACKUP_PAGE_MAX) throw new Error('The key backup sent an oversized page');
    const writes: [string, unknown][] = [];
    const restored: string[] = [];
    let after = cur.after;
    let count = 0;
    for (const e of page.sessions) {
      // The server pages in a fixed order; going back (a loop) or sideways ends the restore.
      if (!cursorAfter(e, after)) throw new Error('The key backup did not page forward');
      after = { room_id: e.room_id, sender_key: e.sender_key, session_id: e.session_id };
      const rec = this.openEntry(seeds, e);
      if (!rec) continue;
      const key = inboundKey(rec.sender_key, e.session_id);
      const known = await this.ctx.store.get<InboundRecord>(key);
      if (known && (known.room_id !== rec.room_id || known.sender_user !== rec.sender_user || known.sender_device !== rec.sender_device || known.first_index <= rec.first_index)) continue;
      if (known?.verified && !known.from_backup) {
        // The verified copy stays in charge of what it covers; the backup's earlier reach is
        // kept beside it, for older messages only.
        const cover = await this.ctx.store.get<InboundRecord>(backupCoverKey(rec.sender_key, e.session_id));
        if (cover && cover.first_index <= rec.first_index) continue;
        writes.push([backupCoverKey(rec.sender_key, e.session_id), rec]);
      } else {
        writes.push([key, rec]);
      }
      restored.push(e.session_id);
      count++;
    }
    const seen = cur.count + page.sessions.length;
    const done = !page.more || page.sessions.length === 0 || seen >= BACKUP_MAX_SESSIONS;
    writes.push([RESTORE, { version: cur.version, after, count: seen } satisfies RestoreCursor]);
    await this.ctx.store.write(done ? writes.slice(0, -1) : writes, done ? [RESTORE] : []);
    if (restored.length > 0) this.ctx.onRestored?.(restored);
    return { count, done };
  }

  private openEntry(seeds: { master: string; backup: string }, e: BackupEntry): InboundRecord | undefined {
    let s: InboundGroupSession | undefined;
    try {
      const p = parseJSON(unb64(pqc.backupOpen(seeds.backup, seeds.master, e, e.sealed)));
      if (!isObj(p) || p.v !== 1 || p.room_id !== e.room_id || p.session_id !== e.session_id || p.sender_key !== e.sender_key ||
        p.first_index !== e.first_index || !isStr(p.session_key) || !isStr(p.sender_user, 128) || !isStr(p.sender_device, 64)) return undefined;
      s = InboundGroupSession.import(p.session_key);
      if (s.sessionId !== e.session_id || s.firstKnownIndex !== e.first_index) return undefined;
      return { pickle: s.pickle(this.ctx.pickleKey), room_id: e.room_id, sender_user: p.sender_user, sender_device: p.sender_device,
        sender_key: e.sender_key, first_index: s.firstKnownIndex, from_backup: true, verified: true };
    } catch (err) {
      // An entry that does not open is skipped; a module that is not running stops the page,
      // so the cursor does not move past entries never tried.
      if (isTransient(err)) throw err;
      return undefined;
    } finally {
      s?.free();
    }
  }

  // --- QR verification ---

  /** On a verified device: opens a pairing and the code to show the new device. */
  async offer(): Promise<PairingOffer> {
    const l = await this.local();
    if (!l) throw new Error('Only a verified device can verify another.');
    const { pairing_id: id, expires_in_ms } = await this.ctx.server.pairingStart(this.ctx.deviceId);
    const { secret, text } = pqc.qrNew(id, l.fingerprint);
    let joined: { key: string; device: string } | undefined;
    return {
      text,
      expiresInMs: expires_in_ms,
      poll: async (signal) => {
        const st = await this.ctx.server.pairingGet(id, signal);
        if (!st.new_device || !st.ephemeral_key) return undefined;
        joined = { key: st.ephemeral_key, device: st.new_device };
        return { code: pqc.comparisonCode(secret, id, st.new_device, st.ephemeral_key), device: st.new_device };
      },
      approve: async (signal) => {
        // Sealed to the very key and device whose code the user compared, never ones fetched
        // afterwards.
        if (!joined) throw new Error('No device has joined yet.');
        const seeds = await this.seeds(l);
        await this.ctx.server.pairingSeal(id, this.ctx.deviceId, pqc.transferSeal(joined.key, secret, id, this.ctx.deviceId, joined.device, seeds.master, seeds.backup), signal);
      },
      // A seal whose answer was lost may still have landed: never take those keys back.
      cancel: () => this.ctx.server.pairingCancel(id, true),
    };
  }

  /** On the new device: joins the pairing a verified device shows as text (QR or copied). */
  async join(text: string): Promise<PairingJoin> {
    let q: { pairing_id: string; secret: string; fingerprint: string };
    try {
      q = pqc.qrParse(text);
    } catch {
      throw new Error('That is not a verification code from KyMessages.');
    }
    const { tenant_id, master } = await this.ctx.server.getMaster();
    if (!master || !validMaster(master) || !pqc.verifyMaster(master.master_key, tenant_id, this.ctx.userId, master.self_signature) ||
      pqc.fingerprint(master.master_key) !== q.fingerprint) {
      throw new Error('This code belongs to another identity than the one the server lists for you.');
    }
    const eph = pqc.xwingGenerate();
    await this.ctx.server.pairingJoin(q.pairing_id, this.ctx.deviceId, eph.public);
    return {
      code: pqc.comparisonCode(q.secret, q.pairing_id, this.ctx.deviceId, eph.public),
      finish: async (signal) => {
        // Bounded: stops at the pairing's lifetime (the deadline aborts a request in flight too),
        // and after a few failures in a row; a pairing the server no longer has (404) ends it.
        const deadline = new AbortController();
        const timer = setTimeout(() => deadline.abort(new DOMException('The pairing wait ran out', 'TimeoutError')), PAIRING_WAIT_MS);
        const stop = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
        const late = () => new Error('The other device did not approve in time. Start again.');
        let failures = 0;
        let got: { initiator_device: string; sealed: string } | undefined;
        // The deadline and the screen's signal stay live through the fresh identity read and the
        // adoption's lock, up to the last check before the seeds are written.
        try {
          while (!got) {
            signal?.throwIfAborted();
            if (deadline.signal.aborted) throw late();
            try {
              got = await this.ctx.server.pairingConsume(q.pairing_id, this.ctx.deviceId, stop);
              break;
            } catch (e) {
              signal?.throwIfAborted();
              if (deadline.signal.aborted) throw late();
              if ((e as { status?: number }).status === 404) throw new Error('This verification was cancelled or expired. Start again.');
              if (!(e instanceof Conflict) && ++failures > PAIRING_RETRIES) throw e;
              if (e instanceof Conflict) failures = 0;
            }
            await sleep(PAIRING_POLL_MS, stop).catch(() => undefined);
          }
          const timedOut = () => (deadline.signal.aborted ? late() : undefined);
          let keys: { master_seed: string; backup_seed: string };
          for (let attempt = 0; ; attempt++) {
            signal?.throwIfAborted();
            if (deadline.signal.aborted) throw late();
            try {
              keys = pqc.transferOpen(eph.seed, q.secret, q.pairing_id, got.initiator_device, this.ctx.deviceId, got.sealed);
              break;
            } catch (e) {
              // Only module unavailability is retried (holding the consumed transfer response);
              // bad transfer data fails definitively at once.
              if (!(e instanceof PQCUnavailable)) {
                throw new Error('The keys from the other device did not open. Start again.');
              }
              signal?.throwIfAborted();
              if (deadline.signal.aborted) throw late();
              if (attempt >= PAIRING_RETRIES) throw e;
              try {
                await abortable(ensurePQC(), stop, timedOut);
              } catch (reloadErr) {
                if (!(reloadErr instanceof PQCUnavailable)) throw reloadErr;
                await sleep(PAIRING_POLL_MS, stop).catch(() => undefined);
              }
            }
          }
          // The approval may have taken minutes: adoption reads the identity again right before
          // it writes (its version, backup key and generation as published then) and checks the
          // seeds against that, so nothing stale is adopted.
          return await this.adopt(tenant_id, q.fingerprint, keys.master_seed, keys.backup_seed, { signal: stop, late: timedOut });
        } finally {
          clearTimeout(timer);
        }
      },
      cancel: () => this.ctx.server.pairingCancel(q.pairing_id),
    };
  }
}
