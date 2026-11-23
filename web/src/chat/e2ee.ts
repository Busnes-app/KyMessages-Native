// The signed-in user's encrypted-room device (crypto/engine.ts) wired to the real key server, and
// the message-level helpers the chat client uses: messages are sealed before they are posted and
// opened as they arrive, so the rest of the app only ever sees decrypted text in `body`.
import { errorMessage, secureFetch } from '../api';
import { arr, bool, obj, str } from '../dto';
import { CryptoEngine, type ClaimedKey, type DeviceKeys, type KeyServer, type Mail, type RoomInner } from '../crypto/engine';
import { loadCrypto } from '../crypto/index';
import { type CryptoStore, deleteCryptoStore, deleteCryptoStores, openCryptoStore, storedDevices } from '../crypto/store';
import { parseRoomDetail, type ChatMessage, type E2EEState } from './types';

export class KeyServerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function call(path: string, method: string, body?: unknown): Promise<unknown> {
  const res = await secureFetch(path, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new KeyServerError(res.status, await errorMessage(res, 'Encryption request failed'));
  return res.status === 204 ? null : res.json();
}

const device = (v: unknown): DeviceKeys => {
  const o = obj(v);
  return { device_id: str(o.device_id, 64), curve25519: str(o.curve25519, 64), ed25519: str(o.ed25519, 64), signature: str(o.signature, 128) };
};

export const httpKeyServer: KeyServer = {
  async upload(req) {
    const n = obj(await call('/api/v1/keys/upload', 'POST', req)).one_time_key_count;
    return typeof n === 'number' ? n : 0;
  },
  async query(userIds) {
    const devices = obj(obj(await call('/api/v1/keys/query', 'POST', { user_ids: userIds })).devices);
    const out: Record<string, DeviceKeys[]> = {};
    for (const id of userIds) out[id] = arr(devices[id] ?? []).flatMap((d) => {
      try {
        return [device(d)];
      } catch {
        return [];
      }
    });
    return out;
  },
  async claim(devices) {
    return arr(obj(await call('/api/v1/keys/claim', 'POST', { devices })).keys).flatMap((v): ClaimedKey[] => {
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
    await call('/api/v1/to-device', 'PUT', { device_id: deviceId, messages });
  },
  async mailbox(deviceId) {
    const page = obj(await call(`/api/v1/to-device?device_id=${encodeURIComponent(deviceId)}`, 'GET'));
    return arr(page.messages).flatMap((v): Mail[] => {
      const o = typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {};
      if (typeof o.id !== 'number') return [];
      try {
        return [{
          id: o.id, sender_user_id: str(o.sender_user_id, 128), sender_device_id: str(o.sender_device_id, 64),
          type: str(o.type, 64), content: str(o.content, 65536),
        }];
      } catch {
        // Malformed mail still has an ID: the engine refuses it and acknowledges it.
        return [{ id: o.id, sender_user_id: '', sender_device_id: '', type: '', content: '' }];
      }
    });
  },
  async ack(deviceId, ids) {
    await call('/api/v1/to-device/ack', 'POST', { device_id: deviceId, ids });
  },
  async roomMembers(roomId) {
    return parseRoomDetail(await call(`/api/v1/rooms/${encodeURIComponent(roomId)}`, 'GET')).members.map((m) => m.user_id);
  },
};

let current: { userId: string; engine: Promise<CryptoEngine>; ready?: CryptoEngine } | undefined;
const keyListeners = new Set<() => void>();

/** Opens (once) the device for userId: loads the crypto core, restores or creates keys, then reads waiting mail. */
export function startE2EE(userId: string): Promise<CryptoEngine> {
  if (current?.userId === userId) return current.engine;
  void stopE2EE();
  const engine = (async () => {
    await loadCrypto();
    let e: CryptoEngine;
    // Another tab deleted the store (sign-out, device reset): drop this engine, so the next use
    // starts afresh instead of writing to a closed or deleted store.
    const dropOnClose = (s: CryptoStore) => {
      s.onClosed(() => {
        if (current === entry) current = undefined;
      });
      return s;
    };
    const store = dropOnClose(await openCryptoStore(userId));
    try {
      e = await CryptoEngine.open(userId, httpKeyServer, store);
    } catch (err) {
      store.close();
      // The server no longer knows this device (removed from another session): never revive it,
      // start over as a new device.
      if (!(err instanceof KeyServerError && err.status === 404)) throw err;
      await deleteCryptoStore(userId);
      e = await CryptoEngine.open(userId, httpKeyServer, dropOnClose(await openCryptoStore(userId)));
    }
    void retireAbandoned(userId).catch(() => undefined);
    e.onKeys(() => {
      for (const fn of keyListeners) fn();
    });
    return e;
  })();
  const entry: NonNullable<typeof current> = { userId, engine };
  current = entry;
  // Ready first, then reopen what arrived while the device was starting (those messages read as
  // unavailable meanwhile).
  void engine.then((e) => {
    entry.ready = e;
    if (current === entry) for (const fn of keyListeners) fn();
  }, () => undefined);
  // A failed start (offline, a blocked database) is retried by the next call.
  engine.then((e) => void e.receive().catch(() => undefined)).catch(() => {
    if (current === entry) current = undefined;
  });
  return engine;
}

async function stopE2EE(): Promise<void> {
  const old = current;
  current = undefined;
  await old?.engine.then((e) => e.close()).catch(() => undefined);
}

function engine(): Promise<CryptoEngine> {
  return current?.engine ?? Promise.reject(new Error('Encryption is not set up in this browser'));
}

/** Calls fn whenever room keys arrive, so messages waiting for them can be opened again. */
export function onRoomKeys(fn: () => void): () => void {
  keyListeners.add(fn);
  return () => keyListeners.delete(fn);
}

/** Reads the device mailbox: on start, on a `to_device` wake and after a reconnect. */
export function receiveRoomKeys(): void {
  void engine().then((e) => e.receive()).catch(() => undefined);
}

/** Starts a new room session when someone left or was removed, so they never get its key. */
export function roomMemberLeft(roomId: string): void {
  void engine().then((e) => e.memberLeft(roomId)).catch(() => undefined);
}

/** The reason shown while this browser's device could not start; such messages are retried. */
export const UNAVAILABLE = 'Encryption is not available in this browser yet.';

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
  let e: CryptoEngine;
  try {
    e = await engine();
  } catch {
    throw new Error('Encryption is not available in this browser, so the message was not sent');
  }
  return e.encrypt(roomId, inner);
}

/**
 * Decrypts an e2ee_room_v1 message; any other message is returned as it is. A device that is
 * still starting is never awaited, so neither live events nor history wait on key uploads: the
 * message reads as unavailable and is opened again once the device is up (onRoomKeys).
 */
export async function openMessage(m: ChatMessage): Promise<ChatMessage> {
  if (m.encoding !== 'e2ee_room_v1' || !m.envelope || m.deleted_at) return m;
  const shut = (e2ee: E2EEState): ChatMessage => ({ ...m, body: '', e2ee });
  const e = current?.ready;
  if (!e) return shut({ kind: 'failed', reason: UNAVAILABLE });
  try {
    const r = await e.decrypt({ id: m.id, room_id: m.room_id, sender_id: m.sender_id, body: m.envelope });
    if (r.state === 'waiting') return shut({ kind: 'waiting' });
    if (r.state === 'failed') return shut({ kind: 'failed', reason: r.reason });
    // The encrypted reply target is the true one; the server's copy is only a hint.
    return { ...m, body: r.inner.body, reply_to_id: r.inner.reply_to_id, e2ee: { kind: 'decrypted' } };
  } catch {
    return shut({ kind: 'failed', reason: 'This message could not be decrypted.' });
  }
}

export function openMessages(list: ChatMessage[]): Promise<ChatMessage[]> {
  return Promise.all(list.map(openMessage));
}

/**
 * Removes this browser's device from the key server, for sign-out: members stop sending it keys
 * and rotate their sessions. Call it while the session is still valid; it answers whether the
 * server no longer lists the device. When it does not, use abandonDevice so a later sign-in retires it.
 */
export async function retireDevice(): Promise<boolean> {
  const e = await current?.engine.catch(() => undefined);
  if (!e) return false;
  try {
    await call(`/api/v1/keys/devices/${encodeURIComponent(e.deviceId)}`, 'DELETE');
    return true;
  } catch (err) {
    return err instanceof KeyServerError && err.status === 404;
  }
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

async function retireAbandoned(userId: string): Promise<void> {
  const left: Abandoned[] = [];
  for (const d of abandoned()) {
    if (d.user_id !== userId) {
      left.push(d);
      continue;
    }
    try {
      await call(`/api/v1/keys/devices/${encodeURIComponent(d.device_id)}`, 'DELETE');
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
  const e = await current?.engine.catch(() => undefined);
  if (e) saveAbandoned([...abandoned(), { user_id: e.userId, device_id: e.deviceId }]);
  await forgetCryptoStore();
}

/**
 * Closes the device and deletes every crypto store in this browser, for sign-out. Each store's
 * device (other users of a shared browser included) is first remembered, so it is removed from
 * the key server at its user's next sign-in here instead of being left listed with nobody
 * holding it. The signed-in user's device may already be retired; its later delete is a 404.
 */
export async function forgetCryptoStore(): Promise<void> {
  await stopE2EE();
  saveAbandoned([...abandoned(), ...(await storedDevices())]);
  await deleteCryptoStores();
}

/** Replaces this browser's device with a new one, for a sign-out the server refused after the old device was retired. */
export async function replaceDevice(): Promise<void> {
  const userId = current?.userId;
  await forgetCryptoStore();
  if (userId) await startE2EE(userId);
}
