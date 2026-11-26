// The signed-in user's encrypted-room device (crypto/engine.ts) wired to the real key server, and
// the message-level helpers the chat client uses: messages are sealed before they are posted and
// opened as they arrive, so the rest of the app only ever sees decrypted text in `body`.
import { errorMessage, secureFetch } from '../api';
import { arr, bool, obj, str } from '../dto';
import { keepStorage } from '../persist';
import { Conflict, CryptoEngine, DeviceChanged, type ClaimedKey, type DeviceKeys, type KeyServer, type Mail, type RoomInner } from '../crypto/engine';
import type { BackupEntry, IdentityChange, IdentityStatus, MasterKeyRecord, OwnMaster, PairingJoin, PairingOffer } from '../crypto/identity';
import { loadCrypto } from '../crypto/index';
import { loadPQC, type Hybrid } from '../pqc/index';
import { type CryptoStore, deleteCryptoStores, openCryptoStore, storedDevices } from '../crypto/store';
import { parseRoomDetail, type ChatMessage, type E2EEState } from './types';

export class KeyServerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function call(path: string, method: string, body?: unknown, signal?: AbortSignal): Promise<unknown> {
  const res = await secureFetch(path, {
    method,
    signal,
    credentials: 'same-origin',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 409) throw new Conflict(await errorMessage(res, 'The encryption identity changed'));
  if (!res.ok) throw new KeyServerError(res.status, await errorMessage(res, 'Encryption request failed'));
  return res.status === 204 ? null : res.json();
}

const hybrid = (v: unknown): Hybrid => {
  const o = obj(v);
  if (o.alg !== 'mldsa65+ed25519') throw new Error('Unknown signature algorithm');
  return { alg: o.alg, mldsa65: str(o.mldsa65, 8192), ed25519: str(o.ed25519, 128) };
};

const device = (v: unknown): DeviceKeys => {
  const o = obj(v);
  const d: DeviceKeys = { device_id: str(o.device_id, 64), curve25519: str(o.curve25519, 64), ed25519: str(o.ed25519, 64), signature: str(o.signature, 128) };
  if (o.master_signature !== undefined) d.master_signature = hybrid(o.master_signature);
  return d;
};

const masterRecord = (v: unknown): MasterKeyRecord => {
  const o = obj(v);
  if (typeof o.version !== 'number') throw new Error('Invalid master key');
  return { version: o.version, master_key: hybrid(o.master_key), self_signature: hybrid(o.self_signature) };
};

const ownMaster = (v: unknown): OwnMaster => {
  const o = obj(v);
  const bk = obj(o.backup_key);
  const rc = obj(o.recovery);
  const pins = obj(o.pins);
  return {
    ...masterRecord(o),
    backup_key: { public_key: str(bk.public_key, 4096), signature: hybrid(bk.signature) },
    recovery: { wrapped_master_key: str(rc.wrapped_master_key, 1024), wrapped_backup_key: str(rc.wrapped_backup_key, 1024) },
    pins: { counter: typeof pins.counter === 'number' ? pins.counter : 0, sealed: typeof pins.sealed === 'string' ? pins.sealed : '' },
  };
};

const pairingPath = (id: string) => `/api/v1/keys/pairings/${encodeURIComponent(id)}`;

const keyServer = (signal: AbortSignal): KeyServer => ({
  async upload(req) {
    const o = obj(await call('/api/v1/keys/upload', 'POST', req, signal));
    // Only an explicit false asks for a new fallback key.
    return { count: typeof o.one_time_key_count === 'number' ? o.one_time_key_count : 0, fallback: o.has_fallback_key !== false };
  },
  async query(userIds) {
    const res = obj(await call('/api/v1/keys/query', 'POST', { user_ids: userIds }, signal));
    const devices = obj(res.devices);
    const masters = res.master_keys === undefined ? {} : obj(res.master_keys);
    const out: Record<string, DeviceKeys[]> = {};
    const master_keys: Record<string, MasterKeyRecord> = {};
    for (const id of userIds) {
      out[id] = arr(devices[id] ?? []).flatMap((d) => {
        try {
          return [device(d)];
        } catch {
          return [];
        }
      });
      try {
        if (masters[id] !== undefined) master_keys[id] = masterRecord(masters[id]);
      } catch {
        // A malformed master key is no master key: none of that user's devices gets room keys.
      }
    }
    return { tenant_id: str(res.tenant_id, 128), devices: out, master_keys };
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
  async roomMembers(roomId) {
    return parseRoomDetail(await call(`/api/v1/rooms/${encodeURIComponent(roomId)}`, 'GET', undefined, signal)).members.map((m) => m.user_id);
  },
  async getMaster() {
    const o = obj(await call('/api/v1/keys/master', 'GET', undefined, signal));
    return { tenant_id: str(o.tenant_id, 128), master: o.master === null ? null : ownMaster(o.master) };
  },
  async putMaster(req) {
    const o = obj(await call('/api/v1/keys/master', 'PUT', req, signal));
    return typeof o.version === 'number' ? o.version : 0;
  },
  async putPins(version, expected, sealed) {
    await call('/api/v1/keys/pins', 'PUT', { version, expected_counter: expected, sealed }, signal);
  },
  async signDevice(deviceId, version, signature) {
    await call(`/api/v1/keys/devices/${encodeURIComponent(deviceId)}/signature`, 'POST', { version, signature }, signal);
  },
  async getBackup(version, afterRoom, afterSession) {
    const q = new URLSearchParams({ version: String(version), after_room: afterRoom, after_session: afterSession });
    const o = obj(await call(`/api/v1/keys/backup?${q}`, 'GET', undefined, signal));
    const sessions = arr(o.sessions).flatMap((v): BackupEntry[] => {
      try {
        const e = obj(v);
        return [{ room_id: str(e.room_id, 128), session_id: str(e.session_id, 128), first_index: typeof e.first_index === 'number' ? e.first_index : 0, sealed: str(e.sealed, 16384) }];
      } catch {
        return [];
      }
    });
    return { sessions, more: o.more === true };
  },
  async putBackup(version, sessions) {
    await call('/api/v1/keys/backup', 'PUT', { version, sessions }, signal);
  },
  async pairingStart(deviceId) {
    const o = obj(await call('/api/v1/keys/pairings', 'POST', { device_id: deviceId }, signal));
    return { pairing_id: str(o.pairing_id, 64), expires_at: typeof o.expires_at === 'number' ? o.expires_at : Date.now() };
  },
  async pairingGet(id) {
    const o = obj(await call(pairingPath(id), 'GET', undefined, signal));
    return { pairing_id: str(o.pairing_id, 64), initiator_device: str(o.initiator_device, 64),
      new_device: typeof o.new_device === 'string' ? o.new_device : '', ephemeral_key: typeof o.ephemeral_key === 'string' ? o.ephemeral_key : '', sealed: o.sealed === true };
  },
  async pairingJoin(id, deviceId, ephemeralKey) {
    await call(`${pairingPath(id)}/join`, 'POST', { device_id: deviceId, ephemeral_key: ephemeralKey }, signal);
  },
  async pairingSeal(id, deviceId, sealed) {
    await call(`${pairingPath(id)}/sealed`, 'PUT', { device_id: deviceId, sealed }, signal);
  },
  async pairingConsume(id, deviceId) {
    const o = obj(await call(`${pairingPath(id)}/consume`, 'POST', { device_id: deviceId }, signal));
    return { initiator_device: str(o.initiator_device, 64), sealed: str(o.sealed, 16384) };
  },
  async pairingCancel(id) {
    await call(pairingPath(id), 'DELETE', undefined, signal);
  },
});

// One device start-up. Stopping it (sign-out, revocation, another user) aborts its requests,
// releasing any per-user lock held over the network, closes the store and cancels start-up.
// A pending start-up can never keep keys alive or reopen a deleted store.
interface Entry {
  userId: string;
  engine: Promise<CryptoEngine>;
  ready?: CryptoEngine;
  deviceId?: string;
  cancelled: boolean;
  failed: boolean;
  controller: AbortController;
  store?: CryptoStore;
}

let current: Entry | undefined;
const keyListeners = new Set<() => void>();
// Bumped whenever room keys may have arrived. Tabs share one device and its store, so a tab that
// stores keys tells the others, which reopen what they show as waiting.
let keyGen = 0;
export const keyGeneration = () => keyGen;
const keyChannel = typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel('kymessages-room-keys');
function keysArrived(share: boolean): void {
  keyGen++;
  if (share) keyChannel?.postMessage(null);
  for (const fn of keyListeners) fn();
}
if (keyChannel) keyChannel.onmessage = ({ data }: MessageEvent<unknown>) => {
  if (data === null) keysArrived(false);
  else if (typeof data === 'object' && data !== null && 'type' in data && data.type === 'device-reset'
    && 'user_id' in data && typeof data.user_id === 'string' && 'device_id' in data && typeof data.device_id === 'string') {
    if (current?.userId === data.user_id && current.deviceId === data.device_id) invalidateEntry(current);
  }
};

function invalidateEntry(entry: Entry): void {
  entry.failed = true;
  entry.ready = undefined;
  entry.controller.abort(new DeviceChanged());
  entry.store?.close();
}
// Set when another tab deleted this tab's store (a sign-out). This tab may
// have missed that sign-out, so it must not create a new device and new private keys on its own:
// encryption stays off here until this tab signs out (which clears it) or reloads.
let deletedElsewhere = false;

class Cancelled extends Error {}

/** Opens (once) the device for userId: loads the crypto core, restores or creates keys, then reads waiting mail. */
export function startE2EE(userId: string): Promise<CryptoEngine> {
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
  const entry = { userId, cancelled: false, failed: false, controller: new AbortController() } as Entry;
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
    void retireAbandoned(userId, entry.controller.signal).catch(() => undefined);
    e.onKeys(() => keysArrived(true));
    return e;
  })();
  current = entry;
  // Ready first, then reopen what arrived while the device was starting (those messages read as
  // unavailable meanwhile).
  void entry.engine.then((e) => {
    if (current === entry && !entry.failed && !entry.cancelled) {
      entry.ready = e;
      keysArrived(false);
    }
  }, () => undefined);
  // Keep the user on a failed entry so the next send can retry without a socket reconnect.
  // Attach failure handling directly: it runs before a caller resumes from the rejected start.
  void entry.engine.then((e) => void e.receive().catch(() => undefined), () => {
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

/** Calls fn whenever room keys arrive, so messages waiting for them can be opened again. */
export function onRoomKeys(fn: () => void): () => void {
  keyListeners.add(fn);
  return () => keyListeners.delete(fn);
}

// --- Identity and verification (crypto/identity.ts), for the UI ---

const identityListeners = new Set<() => void>();
let identityWired: CryptoEngine | undefined;

/** Calls fn when this device's identity state or a member's pinned identity changes. */
export function onIdentityChanged(fn: () => void): () => void {
  identityListeners.add(fn);
  return () => identityListeners.delete(fn);
}

function announceIdentity(): void {
  for (const fn of identityListeners) fn();
}

async function identityEngine(): Promise<CryptoEngine> {
  const e = await engine();
  if (identityWired !== e) {
    identityWired = e;
    e.onIdentityChange(announceIdentity);
  }
  return e;
}

export const identityStatus = (): Promise<IdentityStatus> => identityEngine().then((e) => e.identityStatus());

/** A new identity for this account: show recoveryKey, then commit once the user saved it. */
export async function prepareIdentity(reset = false): Promise<{ recoveryKey: string; commit(): Promise<void> }> {
  const p = (await identityEngine()).prepareIdentity(reset);
  return { recoveryKey: p.recoveryKey, commit: async () => { await p.commit(); announceIdentity(); keysArrived(true); } };
}

export async function restoreIdentity(recoveryKey: string): Promise<number> {
  const n = await (await identityEngine()).restoreIdentity(recoveryKey);
  announceIdentity();
  keysArrived(true);
  return n;
}

export const offerVerification = (): Promise<PairingOffer> => identityEngine().then((e) => e.offerVerification());

export async function joinVerification(text: string): Promise<PairingJoin> {
  const j = await (await identityEngine()).joinVerification(text);
  return { ...j, finish: async (signal) => { const n = await j.finish(signal); announceIdentity(); keysArrived(true); return n; } };
}

export const identityChanges = (): Promise<IdentityChange[]> => identityEngine().then((e) => e.identityChanges());

export async function acceptIdentity(userId: string): Promise<void> {
  await (await identityEngine()).acceptIdentity(userId);
  announceIdentity();
}

/** Reads the device mailbox: on start, on a `to_device` wake and after a reconnect. */
export function receiveRoomKeys(): void {
  void withEngine((e) => e.receive()).catch(() => undefined);
}

/** Starts a new room session when someone left or was removed, so they never get its key. */
export function roomMemberLeft(roomId: string): void {
  void withEngine((e) => e.memberLeft(roomId)).catch(() => undefined);
}

/** The reason shown while this browser's device could not start; such messages are retried. */
export const UNAVAILABLE = 'Encryption is not available in this browser yet.';
/** An open that threw (local storage, a store closed under the device): tried again later. */
export const NOT_YET = 'This message could not be opened yet.';
/** Whether a failed message is worth opening again when keys arrive or the device restarts. */
export const retryable = (reason: string) => reason === UNAVAILABLE || reason === NOT_YET;

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
  if (bytes(inner.body) > MAX_MESSAGE_BYTES || bytes(JSON.stringify({ ...inner, room_id: roomId })) > MAX_INNER_BYTES) {
    throw new Error('Message is too long (16 KiB at most)');
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
    if (r.state === 'failed') return shut({ kind: 'failed', reason: r.reason });
    // The encrypted reply target is the true one; the server's copy is only a hint.
    return { ...m, body: r.inner.body, reply_to_id: r.inner.reply_to_id, e2ee: { kind: 'decrypted' } };
  } catch {
    // Not a verdict on the message: the engine's own checks return 'failed' without throwing.
    return shut({ kind: 'failed', reason: NOT_YET, gen });
  }
}

export function openMessages(list: ChatMessage[]): Promise<ChatMessage[]> {
  return Promise.all(list.map(openMessage));
}

export const RETIRE_MS = 5000;

/**
 * Removes this browser's device from the key server, for sign-out: members stop sending it keys
 * and rotate their sessions. Call it while the session is still valid; it answers whether the
 * server no longer lists the device. When it does not, use abandonDevice so a later sign-in retires it.
 * `wait` gives up after RETIRE_MS, so sign-out never waits on a stuck start-up or request.
 * On a refused logout, `replaceIfRetired` follows the eventual result, including a late deletion.
 */
export function retireDevice() {
  const entry = current;
  const attempt = (async () => {
    const e = await entry?.engine.catch(() => undefined);
    if (!e) return false;
    try {
      await call(`/api/v1/keys/devices/${encodeURIComponent(e.deviceId)}`, 'DELETE', undefined, entry?.controller.signal);
      return true;
    } catch (err) {
      return err instanceof KeyServerError && err.status === 404;
    }
  })();
  return {
    wait: Promise.race([attempt, new Promise<boolean>((r) => setTimeout(r, RETIRE_MS, false))]),
    async replaceIfRetired(): Promise<void> {
      // Never reset a different device after another sign-out, sign-in or revocation.
      if (await attempt && entry && current === entry) await replaceDevice();
    },
  };
}

// Devices abandoned when a session was revoked: the server no longer accepts that session, so
// each is removed from the key server the next time its user's device starts here.
const RETIRE_KEY = 'kymessages-e2ee-retire';
type Abandoned = { user_id: string; device_id: string };

function abandoned(): Abandoned[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(RETIRE_KEY) ?? '[]');
    return Array.isArray(v) ? v.filter((d): d is Abandoned => typeof d?.user_id === 'string' && typeof d?.device_id === 'string') : [];
  } catch {
    return [];
  }
}

function saveAbandoned(list: Abandoned[]): void {
  const seen = new Set<string>();
  list = list.filter((d) => {
    const k = `${d.user_id}\u0000${d.device_id}`;
    return !seen.has(k) && !!seen.add(k);
  });
  try {
    if (list.length === 0) localStorage.removeItem(RETIRE_KEY);
    else localStorage.setItem(RETIRE_KEY, JSON.stringify(list.slice(-20)));
  } catch {
    // No storage: the device stays listed until it is removed by hand.
  }
}

async function retireAbandoned(userId: string, signal: AbortSignal): Promise<void> {
  const left: Abandoned[] = [];
  for (const d of abandoned()) {
    if (d.user_id !== userId) {
      left.push(d);
      continue;
    }
    try {
      await call(`/api/v1/keys/devices/${encodeURIComponent(d.device_id)}`, 'DELETE', undefined, signal);
    } catch (e) {
      if (!(e instanceof KeyServerError && e.status === 404)) left.push(d);
    }
  }
  saveAbandoned(left);
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
  deletedElsewhere = false;
  // Best effort: a device read that fails or stalls must never stop the wipe.
  const devices = await Promise.race([storedDevices().catch(() => []), new Promise<[]>((r) => setTimeout(r, DEVICE_READ_MS, []))]);
  saveAbandoned([...abandoned(), ...devices]);
  await deleteCryptoStores();
}

/** Replaces this browser's device with a new one, for a sign-out the server refused after the old device was retired. */
export async function replaceDevice(): Promise<void> {
  const entry = current;
  if (!entry) return;
  const old = await entry.engine;
  if (current !== entry) return;
  invalidateEntry(entry);
  entry.deviceId = undefined;
  const store = await openCryptoStore(entry.userId);
  try {
    await resetDevice(entry.userId, old.deviceId, store);
  } finally {
    store.close();
  }
  if (current === entry) await startE2EE(entry.userId);
}

/** Wake stale peers before waiting on their lock, then reset only the expected identity. */
async function resetDevice(userId: string, deviceId: string, store: CryptoStore): Promise<void> {
  keyChannel?.postMessage({ type: 'device-reset', user_id: userId, device_id: deviceId });
  await CryptoEngine.resetDevice(userId, deviceId, store);
}
