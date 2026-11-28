// The signed-in user's encrypted-room device (crypto/engine.ts) wired to the real key server, and
// the message-level helpers the chat client uses: messages are sealed before they are posted and
// opened as they arrive, so the rest of the app only ever sees decrypted text in `body`.
import { adminFetch, errorMessage } from '../api';
import { arr, bool, obj, str } from '../dto';
import { keepStorage } from '../persist';
import { Conflict, CryptoEngine, DeviceChanged, EARLY, type ClaimedKey, type DeviceKeys, type KeyServer, type Mail, type QueryResult, type RoomInner } from '../crypto/engine';
import type { BackupEntry, DeviceList, IdentityChange, IdentityStatus, MasterKeyRecord, OwnMaster, PairingJoin, PairingOffer } from '../crypto/identity';
import { loadCrypto } from '../crypto/index';
import { expectOriginal, messageFiles, needsOriginal, type OpenedEnvelope } from '../crypto/attachments';
import { ensurePQC, loadPQC, type BotDevice, type Hybrid } from '../pqc/index';
import { isTransient, Transient } from '../crypto/records';
import { type CryptoStore, deleteCryptoStores, openCryptoStore, storedDevices } from '../crypto/store';
import { parseRoomDetail, type ChatMessage, type E2EEState } from './types';

export class KeyServerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/** The key server could not be reached (status 0), is rate limiting (429) or failed (5xx):
 * availability, so the work is kept and retried. */
export class KeyServerUnavailable extends Transient {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

// Through adminFetch: a step-up refusal (identity setup, reset, backup deletion) opens
// "Confirm it's you" and retries once the user signed in again in place.
async function call(path: string, method: string, body?: unknown, signal?: AbortSignal): Promise<unknown> {
  let res: Response;
  try {
    res = await adminFetch(path, {
      method,
      signal,
      credentials: 'same-origin',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    // An abort keeps its meaning; anything else fetch throws is the network.
    if (signal?.aborted || (e instanceof DOMException && e.name === 'AbortError')) throw e;
    throw new KeyServerUnavailable(0, 'The key server could not be reached');
  }
  if (res.status === 409) {
    const o: unknown = await res.clone().json().catch(() => null);
    const retry = typeof o === 'object' && o !== null && typeof (o as { retry_in_ms?: unknown }).retry_in_ms === 'number' ? (o as { retry_in_ms: number }).retry_in_ms : undefined;
    throw new Conflict(await errorMessage(res, 'The encryption identity changed'), retry);
  }
  if (res.status === 429 || res.status >= 500) throw new KeyServerUnavailable(res.status, await errorMessage(res, 'The key server is unavailable'));
  if (!res.ok) throw new KeyServerError(res.status, await errorMessage(res, 'Encryption request failed'));
  return res.status === 204 ? null : res.json();
}

// hybridsig keys and signatures: base64 of the tagged encoding, which names the algorithm.
const hybrid = (v: unknown): Hybrid => str(v, 8192);

const device = (v: unknown): DeviceKeys => {
  const o = obj(v);
  const d: DeviceKeys = { device_id: str(o.device_id, 64), curve25519: str(o.curve25519, 64), ed25519: str(o.ed25519, 64), signature: str(o.signature, 128) };
  if (o.master_signature !== undefined) d.master_signature = hybrid(o.master_signature);
  return d;
};

const deviceList = (v: unknown): DeviceList | undefined => {
  if (v === undefined || v === null) return undefined;
  const o = obj(v);
  if (typeof o.epoch !== 'number') throw new Error('Invalid device list');
  return { epoch: o.epoch, device_ids: arr(o.device_ids).map((d) => str(d, 64)), signature: hybrid(o.signature) };
};

const masterRecord = (v: unknown): MasterKeyRecord => {
  const o = obj(v);
  if (typeof o.version !== 'number') throw new Error('Invalid master key');
  const dl = deviceList(o.device_list);
  return { version: o.version, master_key: hybrid(o.master_key), self_signature: hybrid(o.self_signature), ...(dl ? { device_list: dl } : {}) };
};

const ownMaster = (v: unknown): OwnMaster => {
  const o = obj(v);
  const bk = obj(o.backup_key);
  const rc = obj(o.recovery);
  const pins = obj(o.pins);
  return {
    ...masterRecord(o),
    backup_key: { public_key: str(bk.public_key, 4096), signature: hybrid(bk.signature) },
    backup_generation: typeof o.backup_generation === 'number' ? o.backup_generation : 0,
    recovery: { wrapped_master_key: str(rc.wrapped_master_key, 1024), wrapped_backup_key: str(rc.wrapped_backup_key, 1024) },
    pins: { counter: typeof pins.counter === 'number' ? pins.counter : 0, sealed: typeof pins.sealed === 'string' ? pins.sealed : '' },
  };
};

const pairingPath = (id: string) => `/api/v1/keys/pairings/${encodeURIComponent(id)}`;
/** The device's signal, and the asking screen's when it has one. */
const both = (a: AbortSignal, b?: AbortSignal) => (b ? AbortSignal.any([a, b]) : a);

const keyServer = (signal: AbortSignal): KeyServer => ({
  async upload(req) {
    const o = obj(await call('/api/v1/keys/upload', 'POST', req, signal));
    // Only an explicit false asks for a new fallback key.
    return { count: typeof o.one_time_key_count === 'number' ? o.one_time_key_count : 0, fallback: o.has_fallback_key !== false };
  },
  async query(userIds, screen) {
    const res = obj(await call('/api/v1/keys/query', 'POST', { user_ids: userIds }, both(signal, screen)));
    const devices = obj(res.devices);
    const masters = res.master_keys === undefined ? {} : obj(res.master_keys);
    const out: Record<string, DeviceKeys[]> = {};
    const master_keys: Record<string, MasterKeyRecord> = {};
    // Bots' lists stay as sent: the engine checks them (validBotList) and their owners' signatures.
    const bot_devices = res.bot_devices === undefined ? {} : obj(res.bot_devices);
    for (const id of userIds) {
      out[id] = arr(devices[id] ?? []).flatMap((d) => {
        try {
          return [device(d)];
        } catch {
          return [];
        }
      });
    }
    // The named users' master keys, and those of the bots' owners that came with them.
    for (const id of new Set([...userIds, ...Object.keys(masters).slice(0, 2 * userIds.length)])) {
      try {
        if (masters[id] !== undefined) master_keys[id] = masterRecord(masters[id]);
      } catch {
        // A malformed master key is no master key: none of that user's devices gets room keys.
      }
    }
    return { tenant_id: str(res.tenant_id, 128), devices: out, master_keys, bot_devices: bot_devices as QueryResult['bot_devices'] };
  },
  async claim(devices) {
    return arr(obj(await call('/api/v1/keys/claim', 'POST', { devices }, signal)).keys).flatMap((v): ClaimedKey[] => {
      try {
        const o = obj(v);
        return [{
          user_id: str(o.user_id, 128), device_id: str(o.device_id, 64),
          key_id: str(o.key_id, 64), key: str(o.key, 64), signature: str(o.signature, 128), fallback: bool(o.fallback),
        }];
      } catch {
        return [];
      }
    });
  },
  async sendToDevice(deviceId, messages) {
    await call('/api/v1/to-device', 'PUT', { device_id: deviceId, messages }, signal);
  },
  async mailbox(deviceId) {
    const page = obj(await call(`/api/v1/to-device?device_id=${encodeURIComponent(deviceId)}`, 'GET', undefined, signal));
    return arr(page.messages).flatMap((v): Mail[] => {
      const o = typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {};
      if (typeof o.id !== 'number') return [];
      try {
        return [{
          id: o.id, sender_user_id: str(o.sender_user_id, 128), sender_device_id: str(o.sender_device_id, 64),
          sender_keys: device(o.sender_keys), type: str(o.type, 64), content: str(o.content, 65536),
        }];
      } catch {
        // Malformed mail still has an ID: the engine refuses it and acknowledges it.
        return [{ id: o.id, sender_user_id: '', sender_device_id: '', sender_keys: { device_id: '', curve25519: '', ed25519: '', signature: '' }, type: '', content: '' }];
      }
    });
  },
  async ack(deviceId, ids) {
    await call('/api/v1/to-device/ack', 'POST', { device_id: deviceId, ids }, signal);
  },
  async putBotDevices(botId, body) {
    await call(`/api/v1/keys/bots/${encodeURIComponent(botId)}/devices`, 'PUT', body, signal);
  },
  async roomMembers(roomId) {
    return parseRoomDetail(await call(`/api/v1/rooms/${encodeURIComponent(roomId)}`, 'GET', undefined, signal)).members.map((m) => m.user_id);
  },
  async getMaster(screen) {
    const o = obj(await call('/api/v1/keys/master', 'GET', undefined, both(signal, screen)));
    return { tenant_id: str(o.tenant_id, 128), master: o.master === null ? null : ownMaster(o.master) };
  },
  async putMaster(req) {
    const o = obj(await call('/api/v1/keys/master', 'PUT', req, signal));
    return typeof o.version === 'number' ? o.version : 0;
  },
  async putPins(version, expected, sealed, signature) {
    await call('/api/v1/keys/pins', 'PUT', { version, expected_counter: expected, sealed, signature }, signal);
  },
  async signDevice(deviceId, version, signature) {
    await call(`/api/v1/keys/devices/${encodeURIComponent(deviceId)}/signature`, 'POST', { version, signature }, signal);
  },
  async reserveDeviceList(version, expectedEpoch, digest, signature) {
    const o = obj(await call('/api/v1/keys/devices/list/reserve', 'POST', { version, expected_epoch: expectedEpoch, digest, signature }, signal));
    if (typeof o.epoch !== 'number' || o.epoch <= expectedEpoch) throw new Error('Invalid device list reservation');
    return { epoch: o.epoch, expires_in_ms: typeof o.expires_in_ms === 'number' ? o.expires_in_ms : 0 };
  },
  async putDeviceList(version, expectedEpoch, epoch, deviceIds, signature) {
    await call('/api/v1/keys/devices/list', 'PUT', { version, expected_epoch: expectedEpoch, epoch, device_ids: deviceIds, signature }, signal);
  },
  async getBackup(version, after) {
    const q = new URLSearchParams({ version: String(version), after_room: after.room_id, after_sender: after.sender_key, after_session: after.session_id });
    const o = obj(await call(`/api/v1/keys/backup?${q}`, 'GET', undefined, signal));
    const sessions = arr(o.sessions).flatMap((v): BackupEntry[] => {
      try {
        const e = obj(v);
        return [{ room_id: str(e.room_id, 128), sender_key: str(e.sender_key, 64), session_id: str(e.session_id, 128), first_index: typeof e.first_index === 'number' ? e.first_index : 0, sealed: str(e.sealed, 16384) }];
      } catch {
        return [];
      }
    });
    return { sessions, more: o.more === true };
  },
  async putBackup(version, generation, sessions, signature) {
    const o = obj(await call('/api/v1/keys/backup', 'PUT', { version, generation, sessions, signature }, signal));
    return { refused: Array.isArray(o.refused) ? o.refused.filter((n): n is number => Number.isInteger(n)) : [] };
  },
  async pairingStart(deviceId) {
    const o = obj(await call('/api/v1/keys/pairings', 'POST', { device_id: deviceId }, signal));
    return { pairing_id: str(o.pairing_id, 64), expires_in_ms: typeof o.expires_in_ms === 'number' ? o.expires_in_ms : 0 };
  },
  async pairingGet(id, screen) {
    const o = obj(await call(pairingPath(id), 'GET', undefined, both(signal, screen)));
    return { pairing_id: str(o.pairing_id, 64), initiator_device: str(o.initiator_device, 64),
      new_device: typeof o.new_device === 'string' ? o.new_device : '', ephemeral_key: typeof o.ephemeral_key === 'string' ? o.ephemeral_key : '', sealed: o.sealed === true };
  },
  async pairingJoin(id, deviceId, ephemeralKey) {
    await call(`${pairingPath(id)}/join`, 'POST', { device_id: deviceId, ephemeral_key: ephemeralKey }, signal);
  },
  async pairingSeal(id, deviceId, sealed, screen) {
    await call(`${pairingPath(id)}/sealed`, 'PUT', { device_id: deviceId, sealed }, both(signal, screen));
  },
  async pairingConsume(id, deviceId, screen) {
    const o = obj(await call(`${pairingPath(id)}/consume`, 'POST', { device_id: deviceId }, both(signal, screen)));
    return { initiator_device: str(o.initiator_device, 64), sealed: str(o.sealed, 16384) };
  },
  async pairingCancel(id, unsealedOnly) {
    await call(pairingPath(id) + (unsealedOnly ? '?unsealed=1' : ''), 'DELETE', undefined, signal);
  },
});

// One device start-up. Stopping it (sign-out, revocation, another user) aborts its requests,
// releasing any per-user lock held over the network, closes the store and cancels start-up.
// A pending start-up can never keep keys alive or reopen a deleted store.
interface EntryHolds {
  active: Set<string>;
  timers: Map<string, ReturnType<typeof setTimeout>>;
  promise: Promise<void>;
  release: () => void;
  hadPeer: boolean;
}

interface Entry {
  userId: string;
  engine: Promise<CryptoEngine>;
  ready?: CryptoEngine;
  deviceId?: string;
  cancelled: boolean;
  failed: boolean;
  /** Replaced or reset under it (this tab or another): nothing it started is shown any more. */
  invalidated?: boolean;
  /** Set while this user's device is being reset (here or in another tab): no start-up begins. */
  replacing?: Promise<void>;
  /** Active local replaceDevice promise for this entry: a second call joins it instead of overwriting the fence. */
  replacingLocal?: Promise<void>;
  /** Per-entry hold table (correlated peer op tokens and local reset token). */
  holds?: EntryHolds;
  controller: AbortController;
  /** The user's retry session, shared by their later start-ups until sign-out. */
  retry: RetrySession;
  /** This start-up's identity status checks: one running, and one shared next. */
  status: { run?: Promise<IdentityStatus>; next?: Promise<IdentityStatus> };
  store?: CryptoStore;
}

let current: Entry | undefined;

/** Whether entry is still the device start-up in use: not stopped, replaced or reset under it. */
const isLive = (entry: Entry) => current === entry && !entry.cancelled && !entry.invalidated;
const keyListeners = new Set<() => void>();
// Bumped whenever room keys may have arrived. Tabs share one device and its store, so a tab that
// stores keys tells the others, which reopen what they show as waiting.
let keyGen = 0;
export const keyGeneration = () => keyGen;
const keyChannel = typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel('kymessages-room-keys');
// The generation at which each session's key last arrived (the newest few thousand), and the last
// arrival whose sessions are unknown (device start-up, an older tab): files waiting on one
// session's key are opened again only when that key may have come.
const sessionGen = new Map<string, number>();
const MAX_SESSIONS = 5000;
let unknownGen = 0;
function keysArrived(share: boolean, sessions?: string[]): void {
  keyGen++;
  if (sessions) {
    for (const id of sessions) {
      sessionGen.delete(id);
      sessionGen.set(id, keyGen);
    }
    for (const id of sessionGen.keys()) {
      if (sessionGen.size <= MAX_SESSIONS) break;
      sessionGen.delete(id);
    }
  } else {
    unknownGen = keyGen;
  }
  if (share) keyChannel?.postMessage(sessions ? { type: 'keys', sessions } : null);
  for (const fn of keyListeners) fn();
}
/** Whether the key to `session` (any key, when unknown) may have arrived after generation `since`. */
export function keysArrivedFor(session: string | undefined, since: number): boolean {
  return (session === undefined ? keyGen : Math.max(unknownGen, sessionGen.get(session) ?? 0)) > since;
}
const isKeys = (d: unknown): d is { sessions: string[] } =>
  typeof d === 'object' && d !== null && 'type' in d && d.type === 'keys' && 'sessions' in d
  && Array.isArray(d.sessions) && d.sessions.every((s) => typeof s === 'string');
// A tab resetting a device says so with a per-operation ID before it waits on the lock
// (device-reset), and again once the reset is stored or gave up (device-reset-done). A tab running
// that device stops it at once, holds start-up per entry until every applicable reset op (and any
// overlapping local reset) settles or times out (PEER_RESET_MS per op), then restarts directly.
const PEER_RESET_MS = 10_000;
if (keyChannel) keyChannel.onmessage = ({ data }: MessageEvent<unknown>) => {
  if (data === null) keysArrived(false);
  else if (isKeys(data)) keysArrived(false, data.sessions.slice(0, MAX_SESSIONS));
  else if (typeof data === 'object' && data !== null && 'type' in data && (data.type === 'device-reset' || data.type === 'device-reset-done')
    && 'user_id' in data && typeof data.user_id === 'string'
    && 'device_id' in data && typeof data.device_id === 'string'
    && 'op' in data && typeof data.op === 'string' && data.op.length > 0) {
    const entry = current;
    if (!entry || entry.cancelled || entry.userId !== data.user_id || entry.deviceId !== data.device_id) return;
    const token = `peer:${data.op}`;
    if (data.type === 'device-reset-done') {
      releaseHold(entry, token);
      return;
    }
    invalidateEntry(entry);
    addHold(entry, token, PEER_RESET_MS);
  }
};

function invalidateEntry(entry: Entry): void {
  entry.failed = true;
  entry.invalidated = true;
  entry.ready = undefined;
  entry.controller.abort(new DeviceChanged());
  entry.store?.close();
}

/** Adds token to entry's hold set (idempotent for duplicate delivery of the same op). */
function addHold(entry: Entry, token: string, peerTimeoutMs?: number): Promise<void> {
  let h = entry.holds;
  if (!h) {
    let release!: () => void;
    const promise = new Promise<void>((r) => { release = r; });
    h = { active: new Set(), timers: new Map(), promise, release, hadPeer: false };
    entry.holds = h;
    entry.replacing = promise;
  }
  if (h.active.has(token)) return h.promise;
  h.active.add(token);
  if (peerTimeoutMs !== undefined) {
    h.hadPeer = true;
    h.timers.set(token, setTimeout(() => releaseHold(entry, token), peerTimeoutMs));
  }
  return h.promise;
}

/** Releases token from entry's hold set; only resolves the hold once every applicable op settles. */
function releaseHold(entry: Entry, token: string): void {
  const h = entry.holds;
  if (!h || !h.active.delete(token)) return;
  const timer = h.timers.get(token);
  if (timer !== undefined) {
    clearTimeout(timer);
    h.timers.delete(token);
  }
  if (h.active.size > 0) return;
  entry.holds = undefined;
  entry.replacing = undefined;
  h.release();
  if (h.hadPeer) {
    // Let any waiter already queued on entry.replacing (e.g. an overlapping local replaceDevice or
    // fresh identityStatus) resume first; if entry is still current (even with no gate listener
    // subscribed), restart it directly. Never carry a restart across sign-out or account switch.
    queueMicrotask(() => {
      if (current !== entry || entry.cancelled || entry.retry.ended) return;
      void startE2EE(entry.userId).catch(() => undefined);
    });
  }
}

/** Clears and releases every active hold and timer on entry when it is stopped. */
function clearHolds(entry: Entry): void {
  const h = entry.holds;
  if (!h) return;
  for (const timer of h.timers.values()) clearTimeout(timer);
  h.timers.clear();
  h.active.clear();
  entry.holds = undefined;
  entry.replacing = undefined;
  h.release();
}
// Set when another tab deleted this tab's store (a sign-out). This tab may
// have missed that sign-out, so it must not create a new device and new private keys on its own:
// encryption stays off here until this tab signs out (which clears it) or reloads.
let deletedElsewhere = false;

class Cancelled extends Error {}

/** Opens (once) the device for userId: loads the crypto core, restores or creates keys, then reads waiting mail. */
export function startE2EE(userId: string): Promise<CryptoEngine> {
  // A reset under way finishes first; a sign-out or account switch meanwhile never starts this user again.
  const held = current;
  if (held?.userId === userId && held.replacing) {
    return held.replacing.then(() => (
      !held.retry.ended && current?.retry === held.retry && !current.cancelled
        ? startE2EE(userId)
        : Promise.reject(new DeviceChanged())
    ));
  }
  if (current?.userId === userId && !current.failed) {
    const entry = current;
    if (!entry.ready) return entry.engine;
    return entry.ready.assertCurrent().then(() => {
      if (current !== entry || entry.failed) throw new DeviceChanged();
      return entry.engine;
    }).catch((err: unknown) => {
      if (!(err instanceof DeviceChanged) && !entry.failed) throw err;
      if (current === entry) invalidateEntry(entry);
      if (current?.userId === userId) return startE2EE(userId);
      throw err; // a sign-out or account switch must never restart this user
    });
  }
  if (deletedElsewhere) return Promise.reject(new Error('Encryption was reset in another tab; reload this tab to continue.'));
  stopE2EE();
  const retry = sessionFor(userId);
  const entry = { userId, cancelled: false, failed: false, controller: new AbortController(), retry, status: {} } as Entry;
  const server = keyServer(entry.controller.signal);
  const live = () => {
    entry.controller.signal.throwIfAborted();
    if (entry.cancelled) throw new Cancelled('Device start-up was cancelled');
  };
  const onIdentity = (deviceId: string) => { entry.deviceId = deviceId; };
  const openStore = async () => {
    live();
    const s = await openCryptoStore(userId);
    if (entry.cancelled) {
      s.close();
      live();
    }
    entry.store = s;
    void keepStorage();
    // Another tab deleted the store on sign-out: drop this engine, so the next use
    // starts afresh instead of writing to a closed or deleted store.
    s.onClosed(() => {
      entry.controller.abort();
      if (current === entry) current = undefined;
      deletedElsewhere = true;
    });
    return s;
  };
  entry.engine = (async () => {
    await Promise.all([loadCrypto(), loadPQC()]);
    let e: CryptoEngine;
    const store = await openStore();
    // A stored device already pending retirement (a sign-out that did not finish) is never used
    // again: its local keys are replaced by a new device's before it starts, and its server row
    // is left for retireAbandoned, so the device running here is never the one being deleted.
    const stored = await store.get<{ device_id?: unknown }>('device');
    if (typeof stored?.device_id === 'string' && abandoned().some((d) => d.user_id === userId && d.device_id === stored.device_id)) {
      await resetDevice(userId, stored.device_id, store);
      live();
    }
    try {
      e = await CryptoEngine.open(userId, server, store, onIdentity);
    } catch (err) {
      store.close();
      // The server no longer knows this device (removed from another session): never revive it,
      // start over as a new device.
      if (entry.cancelled || !(err instanceof KeyServerError && err.status === 404)) throw err;
      const deviceId = entry.deviceId;
      if (!deviceId) throw err;
      entry.deviceId = undefined; // this entry already owns recovery from that identity
      const replacementStore = await openStore();
      await resetDevice(userId, deviceId, replacementStore);
      live();
      e = await CryptoEngine.open(userId, server, replacementStore, onIdentity);
    }
    if (entry.cancelled) {
      e.close();
      live();
    }
    void retireAbandoned(userId, entry.controller.signal, e).catch(() => undefined);
    e.onKeys((sessions) => keysArrived(true, sessions));
    e.onTransient(() => retryLater(retry));
    e.onBackupState((full) => { if (isLive(entry)) for (const fn of backupListeners) fn(full); });
    // Identity notices and live verdicts (Rollback / NotVerified) are wired at start-up, and
    // only the entry in use reaches the UI.
    e.onIdentityChange(() => { if (isLive(entry)) announceIdentity(); });
    e.onVerdict(() => { if (isLive(entry)) announceIdentity(); });
    // Verified now (QR or recovery key): retire pending devices, without waiting for the
    // backup restore that follows.
    e.onAdopted(() => void retireAbandoned(userId, entry.controller.signal, e).catch(() => undefined));
    return e;
  })();
  current = entry;
  // Ready first, then reopen what arrived while the device was starting (those messages read as
  // unavailable meanwhile).
  void entry.engine.then((e) => {
    if (current === entry && !entry.failed && !entry.cancelled) {
      entry.ready = e;
      keysArrived(false);
      // A replacement (or a start after a failure) is a new device state: the gate asks again.
      announceIdentity();
    }
  }, () => undefined);
  // Keep the user on a failed entry so the next send can retry without a socket reconnect.
  // Attach failure handling directly: it runs before a caller resumes from the rejected start.
  void entry.engine.then((e) => void e.receive().catch((err: unknown) => failedLater(retry, err)), (err: unknown) => {
    // A start-up that failed for availability (the module, the network) shows as waiting.
    if (!entry.cancelled) failedLater(retry, err);
    entry.failed = true;
    entry.controller.abort();
    entry.store?.close();
  });
  return entry.engine;
}

/** Stops the device now, even mid start-up; never waits on the network. */
function stopE2EE(): void {
  const old = current;
  current = undefined;
  if (!old) return;
  old.cancelled = true;
  clearHolds(old);
  old.controller.abort();
  old.store?.close();
  void old.engine.then((e) => e.close(), () => undefined);
}

function engine(): Promise<CryptoEngine> {
  return current ? startE2EE(current.userId) : Promise.reject(new Error('Encryption is not set up in this browser'));
}

/** Retry a reset that raced cache validation and lock acquisition, once; never revive a signed-out user. */
async function withEngine<T>(fn: (e: CryptoEngine) => Promise<T>): Promise<T> {
  let entry = current;
  try {
    const e = await engine();
    if (current?.ready === e) entry = current;
    return await fn(e);
  } catch (err) {
    if (!(err instanceof DeviceChanged) && !(entry?.controller.signal.reason instanceof DeviceChanged)) throw err;
    if (!entry || current?.userId !== entry.userId || deletedElsewhere) throw err;
    if (current === entry) invalidateEntry(entry);
    return fn(await engine());
  }
}

/** Whether userId's device is running here now (started, or restarted by a retry or a
 * replacement). It changes with onRoomKeys, which every start-up announces. */
export const encryptionReadyFor = (userId: string): boolean => current?.userId === userId && !current.failed && current.ready !== undefined;

/** Calls fn whenever room keys arrive, so messages waiting for them can be opened again. */
export function onRoomKeys(fn: () => void): () => void {
  keyListeners.add(fn);
  return () => keyListeners.delete(fn);
}

// --- Identity and verification (crypto/identity.ts), for the UI ---

const identityListeners = new Set<() => void>();
const backupListeners = new Set<(full: boolean) => void>();

/** Calls fn when whether the key backup is refusing sessions changes. */
export function onBackupStateChanged(fn: (full: boolean) => void): () => void {
  backupListeners.add(fn);
  return () => backupListeners.delete(fn);
}

/** Calls fn when this device's identity state or a member's pinned identity changes. */
export function onIdentityChanged(fn: () => void): () => void {
  identityListeners.add(fn);
  return () => identityListeners.delete(fn);
}

function announceIdentity(): void {
  for (const fn of identityListeners) fn();
}

// Identity notices are wired when each engine starts (startE2EE). An operation's own completion
// notice goes out only while the start-up it ran on is still the one in use.
async function identityEngine(): Promise<{ e: CryptoEngine; done: () => void }> {
  const e = await engine();
  const entry = current;
  return { e, done: () => {
    if (!entry || !isLive(entry) || entry.ready !== e) return;
    announceIdentity();
    keysArrived(true);
  } };
}

// Status checks are asked for by every identity, backup and retry notice, often several at once;
// each reads the identity from the server. One runs at a time, and requests arriving meanwhile
// share a single next run, so none misses a change made before it asked.
// The runs belong to the device start-up they were asked of: a request made of an entry that
// ended (a sign-out, another user) or was replaced never runs on, or waits for, the current one,
// and its answer is never shown: it rejects with StaleStatus, which the gate ignores (the new
// entry announces itself when it is ready, so the gate asks again).
export class StaleStatus extends Error {
  constructor() {
    super('The device this status was asked of is no longer the one in use');
  }
}

/** One status check of entry: StaleStatus once entry is no longer live, its start-up's own
 * failure otherwise. It never starts a device. */
async function statusOf(entry: Entry): Promise<IdentityStatus> {
  let st: IdentityStatus;
  try {
    if (!isLive(entry)) throw new StaleStatus();
    const e = await entry.engine;
    if (!isLive(entry)) throw new StaleStatus();
    st = await e.identityStatus();
  } catch (err) {
    // A device replaced while this ran fails here (DeviceChanged, an aborted request).
    if (!isLive(entry)) throw new StaleStatus();
    throw err;
  }
  if (!isLive(entry)) throw new StaleStatus();
  return st;
}

/** entry's status checks: one running, and requests meanwhile share one next run of entry. */
function statusFor(entry: Entry): Promise<IdentityStatus> {
  const s = entry.status;
  if (!s.run) {
    s.run = statusOf(entry).finally(() => { s.run = undefined; });
    return s.run;
  }
  s.next ??= s.run.catch(() => undefined).then(() => {
    s.next = undefined;
    return statusFor(entry);
  });
  return s.next;
}

export function identityStatus(): Promise<IdentityStatus> {
  const entry = current;
  if (!entry) return Promise.reject(new Error('Encryption is not set up in this browser'));
  // A fresh check of a failed or replaced start-up starts this user's device again (once a reset
  // under way is stored: startE2EE waits for it). The restart outcome stays bound to this session
  // and its resulting live engine; stale reset/cancel outcomes map to StaleStatus.
  if (entry.failed) {
    const owner = entry.retry;
    return startE2EE(entry.userId).then((restarted) => {
      const next = current;
      if (owner.ended || !next || next.retry !== owner || !isLive(next) || (next.ready !== undefined && next.ready !== restarted)) {
        throw new StaleStatus();
      }
      return statusFor(next);
    }, (err: unknown) => {
      if (err instanceof DeviceChanged || err instanceof Cancelled || owner.ended || current?.retry !== owner
        || (current !== entry && (current?.invalidated || current?.cancelled))) {
        throw new StaleStatus();
      }
      throw err;
    });
  }
  return statusFor(entry);
}

/** A new identity for this account: show recoveryKey, then commit once the user saved it. */
export async function prepareIdentity(reset = false): Promise<{ recoveryKey: string; commit(): Promise<void> }> {
  const { e, done } = await identityEngine();
  const p = await e.prepareIdentity(reset);
  return { recoveryKey: p.recoveryKey, commit: async () => { await p.commit(); done(); } };
}

export async function restoreIdentity(recoveryKey: string): Promise<number> {
  const { e, done } = await identityEngine();
  const n = await e.restoreIdentity(recoveryKey);
  done();
  return n;
}

export const offerVerification = (): Promise<PairingOffer> => identityEngine().then(({ e }) => e.offerVerification());

/** Whether the device a pairing handed keys to has verified itself (signed and listed). signal
 * (the screen closed, or its deadline passed) aborts the wait for the lock and the request. */
export async function ownDeviceVerified(deviceId: string, signal?: AbortSignal): Promise<boolean> {
  signal?.throwIfAborted();
  // The device may still be starting: an abort stops waiting for it, never the start-up itself.
  const started = engine();
  const e = signal ? await new Promise<CryptoEngine>((resolve, reject) => {
    const stop = () => {
      void started.catch(() => undefined);
      reject(signal.reason);
    };
    signal.addEventListener('abort', stop, { once: true });
    started.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
  }) : await started;
  return e.ownDeviceVerified(deviceId, signal);
}

export async function joinVerification(text: string): Promise<PairingJoin> {
  const { e, done } = await identityEngine();
  const j = await e.joinVerification(text);
  return { ...j, finish: async (signal) => { const n = await j.finish(signal); done(); return n; } };
}

/** A bot the signed-in user owns (GET /api/v1/bots), whose devices they may vouch for (E4). */
export interface OwnBot {
  user_id: string;
  username: string;
  display_name: string;
}

export async function ownBots(): Promise<OwnBot[]> {
  return arr(obj(await call('/api/v1/bots', 'GET')).bots).map((v) => {
    const o = obj(v);
    return { user_id: str(o.user_id, 128), username: str(o.username, 128), display_name: str(o.display_name, 256) };
  });
}

/** The bot's uploaded devices with their codes, and the ones this user's signed list vouches for. */
export const botDevices = (botId: string) => engine().then((e) => e.botDevices(botId));

/** Adds (code compared) or removes one device of the user's bot; the rest stay as signed. */
export const vouchForBot = (botId: string, expectedEpoch: number, change: { add?: BotDevice & { code: string }; remove?: string }) =>
  engine().then((e) => e.vouchForBot(botId, expectedEpoch, change));

export const identityChanges = (): Promise<IdentityChange[]> => identityEngine().then(({ e }) => e.identityChanges());

/** Accepts exactly the change the viewer saw, from previous to fingerprint. */
export async function acceptIdentity(userId: string, previous: string, fingerprint: string): Promise<void> {
  const { e } = await identityEngine();
  await e.acceptIdentity(userId, previous, fingerprint);
}

/** Checks a room's members' identities as it opens, so a change shows before anyone sends. */
export function checkRoomIdentities(roomId: string): void {
  void withEngine((e) => e.checkRoom(roomId)).catch(() => undefined);
}

/** Reads the device mailbox: on start, on a `to_device` wake and after a reconnect. */
export function receiveRoomKeys(): void {
  const s = session;
  void withEngine((e) => e.receive()).catch((err: unknown) => failedLater(s, err));
}

// Work that failed for availability (the post-quantum module, the network, the server, local
// storage, a device that could not start) is retried on a bounded schedule. A retry awaits the
// work itself (the mailbox, then a restore in progress, then the backup queue, refused entries
// included), so the attempt count resets and the pending notice clears only once it all
// finished. One retry runs at a time; a failure reported while it runs earns one more pass. The
// budget belongs to the signed-in user's session, not to one device start-up, so a start-up
// failing again does not refill it, and nothing from a session that ended (a sign-out, another
// user) can schedule or change the next one. Once the schedule is spent, exhausted says so;
// retryEncryptionNow runs it again by hand.
const RETRY_MS = [2_000, 5_000, 15_000, 30_000, 60_000];

interface RetrySession {
  userId: string;
  attempt: number;
  timer?: ReturnType<typeof setTimeout>;
  run?: Promise<void>;
  again: boolean;
  state: { pending: boolean; exhausted: boolean };
  ended: boolean;
}

let session: RetrySession | undefined;
const idle = { pending: false, exhausted: false };
const pendingListeners = new Set<() => void>();

/** Whether encryption work waits for a retry, and whether the automatic retries ran out. */
export const encryptionRetry = () => session?.state ?? idle;

/** Calls fn when encryptionRetry changes. */
export function onEncryptionPending(fn: () => void): () => void {
  pendingListeners.add(fn);
  return () => pendingListeners.delete(fn);
}

/** The retry session of userId: the current one if it is theirs, else a new one. */
function sessionFor(userId: string): RetrySession {
  if (session?.userId === userId) return session;
  endSession();
  session = { userId, attempt: 0, again: false, state: idle, ended: false };
  return session;
}

/** Ends the retry session (sign-out): its timers stop and late failures are ignored. */
function endSession(): void {
  const s = session;
  if (!s) return;
  s.ended = true;
  clearTimeout(s.timer);
  session = undefined;
  for (const fn of pendingListeners) fn();
}

function setRetry(s: RetrySession, pending: boolean, exhausted: boolean): void {
  if (s.ended || (s.state.pending === pending && s.state.exhausted === exhausted)) return;
  s.state = { pending, exhausted };
  for (const fn of pendingListeners) fn();
}

function failedLater(s: RetrySession | undefined, e: unknown): void {
  if (s && isTransient(e)) retryLater(s);
}

function retryLater(s: RetrySession): void {
  if (s.ended) return;
  if (s.run) {
    s.again = true; // the running pass schedules one more
    return;
  }
  if (s.timer !== undefined) return setRetry(s, true, false);
  if (s.attempt >= RETRY_MS.length) return setRetry(s, true, true);
  setRetry(s, true, false);
  s.timer = setTimeout(() => void runRetry(s), RETRY_MS[s.attempt++]);
}

function runRetry(s: RetrySession): Promise<void> {
  clearTimeout(s.timer);
  s.timer = undefined;
  s.run ??= (async () => {
    let again = false;
    s.again = false;
    try {
      await ensurePQC();
      if (s.ended || current?.userId !== s.userId) return;
      await withEngine((e) => e.resumeWork());
      if (s.ended) return;
      if (s.again) {
        again = true; // a failure while this ran: one more bounded pass
      } else {
        s.attempt = 0;
        setRetry(s, false, false);
      }
      keysArrived(false);
    } catch (e) {
      // A verdict (a rollback, bad data) is not retried; the identity status reports it. A
      // failure reported while this ran still earns its pass.
      again = isTransient(e) || s.again;
      if (!again) setRetry(s, false, false);
      // A verdict (a rollback or fork) is the identity status's to show, with its reset action;
      // never let a stale session refresh a newer account or entry.
      if (!isTransient(e) && !s.ended && current?.retry === s && isLive(current)) announceIdentity();
    } finally {
      s.run = undefined;
    }
    if (again) retryLater(s);
  })();
  return s.run;
}

/** Runs the waiting work now (joining a retry already running), and restarts the schedule. */
export function retryEncryptionNow(): Promise<void> {
  const s = current ? sessionFor(current.userId) : session;
  if (!s) return Promise.resolve();
  s.attempt = 0;
  if (!s.run) setRetry(s, true, false);
  return runRetry(s);
}

/** Starts a new room session when someone left or was removed, so they never get its key. */
export function roomMemberLeft(roomId: string): void {
  void withEngine((e) => e.memberLeft(roomId)).catch(() => undefined);
}

/** The reason shown while this browser's device could not start; such messages are retried. */
export const UNAVAILABLE = 'Encryption is not available in this browser yet.';
/** An open that threw (local storage, a store closed under the device): tried again later. */
export const NOT_YET = 'This message could not be opened yet.';
/** Whether a failed message is worth opening again when keys arrive or the device restarts: a
 * message from before this device's copy of its session may be covered by a backup page later. */
export const retryable = (reason: string) => reason === UNAVAILABLE || reason === NOT_YET || reason === EARLY;

// The plaintext limit members had before encryption; the envelope may be larger.
export const MAX_MESSAGE_BYTES = 16 << 10;
// Sealed JSON at most 32 KiB: base64 of that plus the Megolm header, MAC and signature and the
// envelope's fields stays under the server's 48 KiB envelope limit (maxEnvelopeLen).
export const MAX_INNER_BYTES = 32 << 10;

/** Encrypts a room message into an e2ee_room_v1 envelope. */
export async function sealRoomMessage(roomId: string, inner: Omit<RoomInner, 'room_id'>): Promise<string> {
  const bytes = (s: string) => new TextEncoder().encode(s).length;
  // The server takes envelopes up to 48 KiB. JSON escaping can grow text sixfold (control
  // characters), so the sealed JSON is bounded too, before a ratchet index is spent on it.
  if (bytes(inner.body) > MAX_MESSAGE_BYTES) throw new Error('Message is too long (16 KiB at most)');
  if (bytes(JSON.stringify({ ...inner, room_id: roomId })) > MAX_INNER_BYTES) {
    throw new Error(inner.files?.length
      ? 'Too much to send in one message: send fewer files, shorter file names or less text.'
      : 'Message is too long (16 KiB at most)');
  }
  return withEngine((e) => e.encrypt(roomId, inner));
}

/**
 * Decrypts an e2ee_room_v1 message; any other message is returned as it is. A device that is
 * still starting is never awaited, so neither live events nor history wait on key uploads: the
 * message reads as unavailable and is opened again once the device is up (onRoomKeys).
 */
export async function openMessage(m: ChatMessage): Promise<ChatMessage> {
  if (m.encoding !== 'e2ee_room_v1' || !m.envelope || m.deleted_at) return m;
  const shut = (e2ee: E2EEState): ChatMessage => ({ ...m, body: '', e2ee });
  const gen = keyGen;
  const e = current?.ready;
  if (!e) return shut({ kind: 'failed', reason: UNAVAILABLE, gen });
  try {
    const r = await e.decrypt({ id: m.id, room_id: m.room_id, sender_id: m.sender_id, body: m.envelope });
    if (r.state === 'waiting') return shut({ kind: 'waiting', gen });
    if (r.state === 'failed') return shut({ kind: 'failed', reason: r.reason, ...(retryable(r.reason) ? { gen } : {}) });
    const original = needsOriginal(r.inner) && m.original ? await openOriginal(e, m, m.original, expectOriginal(r.inner)) : undefined;
    const files = messageFiles(r.inner, original, m.attachments, gen);
    if (!files) return shut({ kind: 'failed', reason: 'This message is damaged.' });
    // The encrypted reply target is the true one; the server's copy is only a hint.
    const e2ee: E2EEState = r.authenticated ? { kind: 'decrypted' } : { kind: 'decrypted', trust: r.restored ? 'backup' : 'unverified' };
    return { ...m, body: r.inner.body, reply_to_id: r.inner.reply_to_id, e2ee, files: undefined, filesState: undefined, plainIds: undefined, provenance: undefined, ref: undefined, ...files };
  } catch {
    // Not a verdict on the message: the engine's own checks return 'failed' without throwing.
    return shut({ kind: 'failed', reason: NOT_YET, gen });
  }
}

// The envelope an edited message was first sent in, which describes its files; `expect` refuses a
// substitute before it can claim the index. An open that throws (local storage) is not a verdict:
// it reads as waiting, and is tried again when keys arrive.
async function openOriginal(e: CryptoEngine, m: ChatMessage, body: string, expect: ReturnType<typeof expectOriginal>): Promise<OpenedEnvelope> {
  try {
    return await e.decrypt({ id: m.id, room_id: m.room_id, sender_id: m.sender_id, body }, expect);
  } catch {
    return { state: 'waiting' };
  }
}

export function openMessages(list: ChatMessage[]): Promise<ChatMessage[]> {
  return Promise.all(list.map(openMessage));
}

export const RETIRE_MS = 5000;
// The part of RETIRE_MS sign-out spends taking the device off its signed list.
const DELIST_MS = 2000;

/**
 * Removes this browser's device from the key server, for sign-out: members stop sending it keys
 * and rotate their sessions. Call it while the session is still valid; it answers whether the
 * server no longer lists the device. When it does not, use abandonDevice so a later sign-in retires it.
 * `wait` gives up after RETIRE_MS, so sign-out never waits on a stuck start-up or request.
 * On a refused logout, `replaceIfRetired` follows the eventual result: once retirement touched
 * the device (it marked itself retiring, so it no longer lists itself) it is replaced by a new
 * one, which lists itself, and the old one stays pending until its removal and deletion are
 * both confirmed, however late either lands.
 */
export function retireDevice() {
  const entry = current;
  let touched: string | undefined;
  // Set once a refused logout gave up on an attempt that had not reached a device yet: a
  // start-up finishing later must not take the device then in use off the list or the server.
  let fenced = false;
  const attempt = (async () => {
    const e = await entry?.engine.catch(() => undefined);
    // Checked right before touching: a refused logout fenced this attempt, or the entry it
    // captured is no longer the device in use.
    if (!e || fenced || !entry || current !== entry || entry.cancelled || entry.failed) return false;
    touched = e.deviceId;
    // Pending from the start, per device: a refused or interrupted sign-out leaves it to retire.
    saveAbandoned({ user_id: e.userId, device_id: e.deviceId });
    // Off the signed device list first, so the server cannot bring the device back later;
    // bounded, so sign-out never waits long on it. A removal that did not become durable here
    // stays pending (it outlives this browser's store) until a verified device signs it.
    const me = { user_id: e.userId, device_id: e.deviceId };
    const delisting = e.delistDevices([e.deviceId]);
    void delisting.then(() => {
      markAbandoned({ ...me, delisted: true });
      settleAbandoned(me);
    }, () => undefined);
    await Promise.race([delisting.catch(() => undefined), new Promise((r) => setTimeout(r, DELIST_MS))]);
    try {
      await call(`/api/v1/keys/devices/${encodeURIComponent(e.deviceId)}`, 'DELETE', undefined, entry?.controller.signal);
    } catch (err) {
      if (!(err instanceof KeyServerError && err.status === 404)) return false;
    }
    markAbandoned({ ...me, deleted: true });
    settleAbandoned(me);
    return true;
  })();
  return {
    wait: Promise.race([attempt, new Promise<boolean>((r) => setTimeout(r, RETIRE_MS, false))]),
    async replaceIfRetired(): Promise<void> {
      // An attempt that has not touched a device by now never will: fenced at once, before any
      // wait, so a start-up finishing meanwhile keeps its device.
      if (!touched) {
        fenced = true;
        return;
      }
      // Bounded like wait: a DELETE that never answers must not leave the touched device in use.
      await Promise.race([attempt, new Promise((r) => setTimeout(r, RETIRE_MS))]);
      // The outcome may be unknown (a delist or DELETE still in flight): the touched device is
      // replaced, never a different one after another sign-out, sign-in or revocation.
      if (entry && current === entry) await replaceDevice(touched);
    },
  };
}

// Devices to retire later: abandoned when a session was revoked (the server no longer accepts
// that session), or signed out before their removal was confirmed. Each is removed from the key
// server, and from the signed list by a verified device, the next time its user's device starts
// here (or verifies); an entry goes only once both are done (deleted, delisted). Each device has
// its own key, so tabs recording different devices never overwrite each other, and a flag once
// set stays set.
const RETIRE_PREFIX = 'kymessages-e2ee-retire:';
/** The single list earlier builds kept; read once into per-device keys. */
const LEGACY_RETIRE_KEY = 'kymessages-e2ee-retire';
type Abandoned = { user_id: string; device_id: string; deleted?: boolean; delisted?: boolean };
const retireKey = (d: { user_id: string; device_id: string }) => `${RETIRE_PREFIX}${d.user_id}:${d.device_id}`;
const isAbandoned = (d: unknown): d is Abandoned =>
  typeof d === 'object' && d !== null && typeof (d as Abandoned).user_id === 'string' && typeof (d as Abandoned).device_id === 'string';

function abandoned(): Abandoned[] {
  try {
    const legacy: unknown = JSON.parse(localStorage.getItem(LEGACY_RETIRE_KEY) ?? 'null');
    if (Array.isArray(legacy)) for (const d of legacy) if (isAbandoned(d)) saveAbandoned(d);
    localStorage.removeItem(LEGACY_RETIRE_KEY);
    const out: Abandoned[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k?.startsWith(RETIRE_PREFIX)) continue;
      const d: unknown = JSON.parse(localStorage.getItem(k) ?? 'null');
      if (isAbandoned(d) && retireKey(d) === k) out.push({ user_id: d.user_id, device_id: d.device_id, deleted: d.deleted === true, delisted: d.delisted === true });
    }
    return out;
  } catch {
    return [];
  }
}

/** Records d as pending, keeping whatever was already confirmed for it. */
function saveAbandoned(d: Abandoned, onlyIfPending = false): void {
  try {
    const was: unknown = JSON.parse(localStorage.getItem(retireKey(d)) ?? 'null');
    const w = isAbandoned(was) ? was : undefined;
    if (onlyIfPending && !w) return;
    localStorage.setItem(retireKey(d), JSON.stringify({ user_id: d.user_id, device_id: d.device_id, deleted: !!(d.deleted || w?.deleted), delisted: !!(d.delisted || w?.delisted) }));
  } catch {
    // No storage: the device stays listed until it is removed by hand.
  }
}

/** Devices this tab saw fully retired: a sign-out's wipe must not record them as pending again. */
const settled = new Set<string>();

/** Records a confirmation for d only while it is still pending: one arriving after d was
 * settled (by this tab or another) never brings its record back. */
const markAbandoned = (d: Abandoned) => saveAbandoned(d, true);

/** Drops d once both its removal and its deletion are confirmed (by any tab). */
function settleAbandoned(d: Abandoned): void {
  try {
    const cur: unknown = JSON.parse(localStorage.getItem(retireKey(d)) ?? 'null');
    if (isAbandoned(cur) && cur.deleted && cur.delisted) {
      localStorage.removeItem(retireKey(d));
      settled.add(retireKey(d));
    }
  } catch {
    // Kept: retried at the next start.
  }
}

async function retireAbandoned(userId: string, signal: AbortSignal, e?: CryptoEngine): Promise<void> {
  const pending = abandoned().filter((d) => d.user_id === userId);
  const toDelist = pending.filter((d) => !d.delisted).map((d) => d.device_id);
  // A verified device takes them off the signed device list; an unverified one cannot sign, so
  // they stay pending. Deleting the server row alone does not complete a retirement.
  const delisted = toDelist.length > 0 && !!e && await e.delistDevices(toDelist).then(() => true, () => false);
  for (const d of pending) {
    let deleted = d.deleted;
    if (!deleted) {
      try {
        await call(`/api/v1/keys/devices/${encodeURIComponent(d.device_id)}`, 'DELETE', undefined, signal);
        deleted = true;
      } catch (err) {
        deleted = err instanceof KeyServerError && err.status === 404;
      }
    }
    markAbandoned({ ...d, deleted, delisted: d.delisted || delisted });
    settleAbandoned(d);
  }
}


/**
 * For a revoked session: deletes the local store now and removes the device from the key server
 * after its user next signs in here, so members stop sending keys to a device nobody holds.
 */
export async function abandonDevice(): Promise<void> {
  // Never wait for a start-up still on the network: the store's device record says which device
  // to retire, and forgetCryptoStore records it before deleting.
  await forgetCryptoStore();
}

/**
 * Closes the device and deletes every crypto store in this browser, for sign-out. Each store's
 * device (other users of a shared browser included) is first remembered, so it is removed from
 * the key server at its user's next sign-in here instead of being left listed with nobody
 * holding it. The signed-in user's device may already be retired; its later delete is a 404.
 */
const DEVICE_READ_MS = 1000;

export async function forgetCryptoStore(): Promise<void> {
  stopE2EE();
  endSession();
  deletedElsewhere = false;
  // Best effort: a device read that fails or stalls must never stop the wipe.
  const devices = await Promise.race([storedDevices().catch(() => []), new Promise<[]>((r) => setTimeout(r, DEVICE_READ_MS, []))]);
  for (const d of devices) if (!settled.has(retireKey(d))) saveAbandoned(d);
  await deleteCryptoStores();
}

/**
 * Replaces this browser's device with a new one, for a sign-out the server refused after the old
 * device was retired; only if the device is still expected (when given). resetDevice deletes only
 * the device's own keys (`device`, `account`, `fallback`, `olm:`, `out:`); the identity seeds,
 * room keys (`in:`, `inb:`), replay log, pins and backup queue stay.
 */
export async function replaceDevice(expected?: string): Promise<void> {
  const entry = current;
  if (!entry) return;
  const old = await entry.engine;
  if (current !== entry || entry.cancelled || (expected !== undefined && old.deviceId !== expected)) return;
  if (entry.replacingLocal) return entry.replacingLocal;
  invalidateEntry(entry);
  // Keep entry.deviceId intact while holds run so overlapping peer resets for this device join
  // the same hold, and keep entry.replacingLocal so a second replaceDevice call joins instead of
  // overwriting the active local fence.
  const token = `local:${crypto.randomUUID()}`;
  const held = addHold(entry, token);
  const run = (async () => {
    let store: CryptoStore | undefined;
    try {
      store = await openCryptoStore(entry.userId);
      await resetDevice(entry.userId, old.deviceId, store);
    } finally {
      store?.close();
      releaseHold(entry, token);
    }
    await held;
    if (current === entry && !entry.cancelled && !entry.retry.ended) await startE2EE(entry.userId);
  })();
  entry.replacingLocal = run;
  await run;
}

/** Wake stale peers before waiting on their lock, then reset only the expected identity; peers
 * hear again once it is stored (or failed), and only then start. */
async function resetDevice(userId: string, deviceId: string, store: CryptoStore): Promise<void> {
  const op = crypto.randomUUID();
  keyChannel?.postMessage({ type: 'device-reset', user_id: userId, device_id: deviceId, op });
  try {
    await CryptoEngine.resetDevice(userId, deviceId, store);
  } finally {
    keyChannel?.postMessage({ type: 'device-reset-done', user_id: userId, device_id: deviceId, op });
  }
}
