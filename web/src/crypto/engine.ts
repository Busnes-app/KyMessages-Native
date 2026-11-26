// One device's end-to-end encryption for rooms (docs/superpowers/specs/2026-11-22-e2ee-design.md
// §3, §4, §9): a vodozemac Account with self-signed keys on the key server, pairwise Olm
// sessions that carry each room's Megolm key, one outbound Megolm session per room, and the
// inbound sessions that read everyone else's messages.
//
// Nothing the server says is trusted: device and one-time-key signatures are checked here, a
// device's keys are pinned the first time they are seen, a room key is accepted only from the
// device whose Olm identity sent it, and a decrypted message must name the room it arrived in
// and may not reuse another message's ratchet index. Room keys go only to devices that the
// member's pinned post-quantum master key signed (E3, identity.ts): an unverified device can
// send, but receives no keys until it is verified, and a changed identity stops keys to that
// member until the viewer accepts it.
//
// State lives in a CryptoStore and is re-read inside a lock for every operation, so several tabs
// of one user can share a device without overwriting each other's ratchets.
import { Account, GroupSession, InboundGroupSession, Session, verifyEd25519 } from './index';
import type { Hybrid } from '../pqc/index';
import { Identity, type IdentityChange, type IdentityServer, type IdentityStatus, type MasterKeyRecord, type PairingJoin, type PairingOffer } from './identity';
import { backupQueueKey, inboundKey, isObj, isStr, parseJSON, seenKey, Transient, type InboundRecord } from './records';
import type { CryptoStore } from './store';

export { Conflict } from './records';

export const ROOM_KEY_TYPE = 'kymessages.room_key.v1';
export const ROTATE_AFTER_MESSAGES = 100;
export const ROTATE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;
const BATCH = 100;
const MAILBOX_PAGE = 100;
const DEVICE_ID = /^[A-Za-z0-9_-]{8,64}$/;

export const deviceSigned = (userId: string, deviceId: string, curve: string, ed: string) =>
  `kymessages.device.v1\n${userId}\n${deviceId}\n${curve}\n${ed}`;
export const oneTimeKeySigned = (userId: string, deviceId: string, keyId: string, key: string) =>
  `kymessages.otk.v1\n${userId}\n${deviceId}\n${keyId}\n${key}`;

// --- The key server, as the engine needs it (chat/e2ee.ts implements it over HTTP) ---

export interface SignedKey {
  key_id: string;
  key: string;
  signature: string;
}

export interface UploadRequest {
  device_id: string;
  device_keys?: { curve25519: string; ed25519: string; signature: string };
  one_time_keys: SignedKey[];
  fallback_key?: SignedKey;
}

export interface DeviceKeys {
  device_id: string;
  curve25519: string;
  ed25519: string;
  signature: string;
  /** The user's master key's cross-signature; absent until the device is verified. */
  master_signature?: Hybrid;
}

/** A key query: the org the keys belong to, each user's devices and master key. */
export interface QueryResult {
  tenant_id: string;
  devices: Record<string, DeviceKeys[]>;
  master_keys: Record<string, MasterKeyRecord>;
}

export interface ClaimedKey extends SignedKey {
  user_id: string;
  device_id: string;
  fallback: boolean;
}

export interface ToDeviceMessage {
  user_id: string;
  device_id: string;
  type: string;
  content: string;
}

export interface Mail {
  id: number;
  sender_user_id: string;
  sender_device_id: string;
  /** The sender device's self-signed keys when it sent the mail (it may be signed out since). */
  sender_keys: DeviceKeys;
  type: string;
  content: string;
}

export interface KeyServer extends IdentityServer {
  /** POST /api/v1/keys/upload; answers the stored one-time key count and whether a fallback key is live. */
  upload(req: UploadRequest): Promise<{ count: number; fallback: boolean }>;
  query(userIds: string[]): Promise<QueryResult>;
  claim(devices: { user_id: string; device_id: string }[]): Promise<ClaimedKey[]>;
  sendToDevice(deviceId: string, messages: ToDeviceMessage[]): Promise<void>;
  mailbox(deviceId: string): Promise<Mail[]>;
  ack(deviceId: string, ids: number[]): Promise<void>;
  /** The user IDs of a room's current members. */
  roomMembers(roomId: string): Promise<string[]>;
}

// --- Messages ---

export type RoomMessageType = 'text' | 'reply' | 'attachment' | 'edit';

/** The plaintext inside an e2ee_room_v1 envelope. */
export interface RoomInner {
  room_id: string;
  type: RoomMessageType;
  body: string;
  reply_to_id?: string;
  /** For an edit: the message it replaces, so the edit cannot be moved onto another one. */
  message_id?: string;
}

export interface RoomEnvelope {
  alg: 'megolm.v1';
  sender_key: string;
  device_id: string;
  session_id: string;
  ciphertext: string;
}

/** A stored message as the server relays it. */
export interface SealedMessage {
  id: string;
  room_id: string;
  sender_id: string;
  body: string;
}

export type Opened =
  /** authenticated: the session came over Olm from a device its member's master key vouches
   * for; false for one from an unverified device or restored from the key backup. */
  | { state: 'decrypted'; inner: RoomInner; authenticated: boolean }
  | { state: 'waiting'; sessionId: string }
  | { state: 'failed'; reason: string };

// --- Stored records ---

interface DeviceRecord {
  device_id: string;
  registered: boolean;
}

interface OlmRecord {
  pickle: string;
  used: number;
}

interface PinRecord {
  curve25519: string;
  ed25519: string;
}

interface OutboundRecord {
  pickle: string;
  created_at: number;
  /** "user\ndevice" -> the curve25519 key the room key was sent to. */
  shared: Record<string, string>;
}

/** A member's device whose self-signature checked out and whose keys match the pin. */
export interface Target {
  user_id: string;
  device_id: string;
  curve25519: string;
  ed25519: string;
}

/** The Olm plaintext that carries a room key. */
interface RoomKeyPayload {
  type: typeof ROOM_KEY_TYPE;
  sender_user_id: string;
  sender_device_id: string;
  sender_ed25519: string;
  recipient_user_id: string;
  recipient_device_id: string;
  recipient_ed25519: string;
  content: { room_id: string; session_id: string; session_key: string; device_id: string };
}

const devKey = (t: { user_id: string; device_id: string }) => `${t.user_id}\n${t.device_id}`;

function randomDeviceId(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function parseEnvelope(body: string): RoomEnvelope | undefined {
  const e = parseJSON(body);
  if (!isObj(e) || e.alg !== 'megolm.v1') return undefined;
  if (!isStr(e.sender_key, 64) || !isStr(e.device_id, 64) || !isStr(e.session_id, 128) || !isStr(e.ciphertext)) return undefined;
  return e as unknown as RoomEnvelope;
}

const INNER_TYPES: readonly RoomMessageType[] = ['text', 'reply', 'attachment', 'edit'];

function parseInner(s: string): RoomInner | undefined {
  const i = parseJSON(s);
  if (!isObj(i) || !isStr(i.room_id, 128) || typeof i.body !== 'string') return undefined;
  if (!INNER_TYPES.includes(i.type as RoomMessageType)) return undefined;
  if (i.reply_to_id !== undefined && !isStr(i.reply_to_id, 128)) return undefined;
  if (i.message_id !== undefined && !isStr(i.message_id, 128)) return undefined;
  return {
    room_id: i.room_id,
    type: i.type as RoomMessageType,
    body: i.body,
    ...(i.reply_to_id ? { reply_to_id: i.reply_to_id as string } : {}),
    ...(i.message_id ? { message_id: i.message_id as string } : {}),
  };
}

// Serializes crypto work per user: Web Locks across tabs, a promise chain where there are none.
const chains = new Map<string, Promise<unknown>>();
function withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks?.request) {
    return navigator.locks.request(name, fn) as Promise<T>;
  }
  const run = (chains.get(name) ?? Promise.resolve()).then(fn, fn);
  chains.set(name, run.catch(() => undefined));
  return run;
}

export class DeviceChanged extends Error {
  constructor() { super('This browser device was replaced'); }
}

export class CryptoEngine {
  private readonly listeners = new Set<(sessionIds: string[]) => void>();
  private readonly identity: Identity;

  private constructor(
    readonly userId: string,
    readonly deviceId: string,
    readonly curve25519: string,
    readonly ed25519: string,
    private readonly server: KeyServer,
    private readonly store: CryptoStore,
    private readonly key: Uint8Array,
  ) {
    this.identity = new Identity({ userId, deviceId, curve25519, ed25519, server, store, pickleKey: key, locked: (fn) => this.locked(fn) });
  }

  /** Restores this browser's device for userId, or creates one, and publishes its keys. */
  static async open(userId: string, server: KeyServer, store: CryptoStore, onIdentity?: (deviceId: string) => void): Promise<CryptoEngine> {
    const key = await store.pickleKey();
    const ids = await withLock(lockName(userId), async () => {
      let device = await store.get<DeviceRecord>('device');
      let pickle = await store.get<string>('account');
      if (!device || !pickle) {
        const fresh = new Account();
        try {
          device = { device_id: randomDeviceId(), registered: false };
          pickle = fresh.pickle(key);
          await store.write([['device', device], ['account', pickle]]);
        } finally {
          fresh.free();
        }
      }
      const account = Account.fromPickle(pickle, key);
      try {
        return { deviceId: device.device_id, curve: account.curve25519, ed: account.ed25519 };
      } finally {
        account.free();
      }
    });
    const engine = new CryptoEngine(userId, ids.deviceId, ids.curve, ids.ed, server, store, key);
    onIdentity?.(engine.deviceId);
    await engine.publishKeys();
    // A device that holds the identity (one replaced by resetDevice too) makes sure it is signed.
    void engine.identity.status().catch(() => undefined);
    return engine;
  }

  /** Replace only this identity, under the same lock as crypto work; a concurrent replacement wins. */
  static resetDevice(userId: string, deviceId: string, store: CryptoStore): Promise<void> {
    return withLock(lockName(userId), async () => {
      if ((await store.get<DeviceRecord>('device'))?.device_id !== deviceId) return;
      const owned = [...(await store.list('olm:')), ...(await store.list('out:'))].map(([k]) => k);
      await store.write([], ['device', 'account', 'fallback', ...owned]);
    });
  }

  /** Fast cache check; locked operations repeat it so a reset cannot race the work. */
  async assertCurrent(): Promise<void> {
    if ((await this.store.get<DeviceRecord>('device'))?.device_id !== this.deviceId) throw new DeviceChanged();
  }

  close(): void {
    this.store.close();
  }

  /** Calls fn with the IDs of room sessions whose keys just arrived; returns an unsubscribe. */
  onKeys(fn: (sessionIds: string[]) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private locked<T>(fn: () => Promise<T>): Promise<T> {
    return withLock(lockName(this.userId), async () => {
      await this.assertCurrent();
      return fn();
    });
  }

  private async loadAccount(): Promise<Account> {
    const pickle = await this.store.get<string>('account');
    if (!pickle) throw new Error('This device has no encryption account');
    return Account.fromPickle(pickle, this.key);
  }

  // --- Publishing this device's keys ---

  /**
   * Registers the device's self-signed identity on first use and keeps the server stocked with
   * signed one-time keys (topped up to the account's maximum, 50) and a fallback key. Returns the
   * stored one-time key count.
   */
  publishKeys(): Promise<number> {
    return this.locked(async () => {
      const account = await this.loadAccount();
      try {
        const extra: [string, unknown][] = [];
        if (!(await this.store.get<boolean>('fallback'))) {
          account.generateFallbackKey();
          extra.push(['fallback', true]);
        }
        let up = await this.uploadPending(account, extra);
        if (!up.fallback) {
          // The server holds no live fallback key (a restore retired it): publish a new one.
          account.generateFallbackKey();
          up = await this.uploadPending(account, []);
        }
        let count = up.count;
        const max = account.maxOneTimeKeys();
        if (count < max) {
          account.generateOneTimeKeys(max - count);
          count = (await this.uploadPending(account, [])).count;
        }
        return count;
      } finally {
        account.free();
      }
    });
  }

  private async uploadPending(account: Account, extra: [string, unknown][]): Promise<{ count: number; fallback: boolean }> {
    const device = (await this.store.get<DeviceRecord>('device'))!;
    const sign = ([keyId, key]: [string, string]): SignedKey => ({
      key_id: keyId,
      key,
      signature: account.sign(oneTimeKeySigned(this.userId, this.deviceId, keyId, key)),
    });
    const otks = Object.entries(JSON.parse(account.oneTimeKeys()) as Record<string, string>).map(sign);
    const [fallback] = Object.entries(JSON.parse(account.fallbackKey()) as Record<string, string>).map(sign);
    // Keep the new keys before they leave, so a failed upload retries the same keys.
    await this.store.write([['account', account.pickle(this.key)], ...extra]);
    const result = await this.server.upload({
      device_id: this.deviceId,
      ...(device.registered
        ? {}
        : {
            device_keys: {
              curve25519: this.curve25519,
              ed25519: this.ed25519,
              signature: account.sign(deviceSigned(this.userId, this.deviceId, this.curve25519, this.ed25519)),
            },
          }),
      one_time_keys: otks,
      ...(fallback ? { fallback_key: fallback } : {}),
    });
    account.markKeysAsPublished();
    await this.store.write([
      ['account', account.pickle(this.key)],
      ['device', { ...device, registered: true } satisfies DeviceRecord],
    ]);
    return result;
  }

  // --- Devices ---

  /**
   * The devices of userIds whose self-signature verifies and whose keys match what this device
   * saw before, without this device. A device whose keys changed is dropped, never re-pinned.
   */
  async verifiedDevices(userIds: string[]): Promise<Target[]> {
    this.identity.startBatch();
    const out: Target[] = [];
    const pins: [string, unknown][] = [];
    for (let i = 0; i < userIds.length; i += BATCH) {
      const batch = userIds.slice(i, i + BATCH);
      let listed: QueryResult;
      try {
        listed = await this.server.query(batch);
      } catch (e) {
        throw new Transient(e instanceof Error ? e.message : 'Could not list devices');
      }
      for (const userId of batch) {
        // No pinned, validly self-bound master key (or this device is unverified): none of this
        // member's devices gets keys.
        const master = await this.identity.trustedMaster(userId, listed.master_keys?.[userId], listed.tenant_id, pins);
        if (!master) continue;
        for (const d of listed.devices?.[userId] ?? []) {
          if (userId === this.userId && isObj(d) && d.device_id === this.deviceId) continue;
          const checked = await this.checkDevice(userId, d);
          if (!checked || !this.identity.deviceTrusted(master, listed.tenant_id, userId, d)) continue;
          if (checked.pin) pins.push(checked.pin);
          out.push(checked.target);
        }
      }
    }
    await this.store.write(pins);
    this.identity.afterWrites();
    return out;
  }

  /**
   * A device of userId whose self-signature verifies and whose keys match its pin, with the pin
   * to store when it is new; undefined otherwise.
   */
  private async checkDevice(userId: string, d: unknown): Promise<{ target: Target; pin?: [string, unknown] } | undefined> {
    if (!isObj(d) || !isStr(d.device_id, 64) || !DEVICE_ID.test(d.device_id)) return undefined;
    if (!isStr(d.curve25519, 64) || !isStr(d.ed25519, 64) || !isStr(d.signature, 128)) return undefined;
    if (!verifyEd25519(d.ed25519, deviceSigned(userId, d.device_id, d.curve25519, d.ed25519), d.signature)) return undefined;
    const target: Target = { user_id: userId, device_id: d.device_id, curve25519: d.curve25519, ed25519: d.ed25519 };
    const pinKey = `pin:${devKey(target)}`;
    const pin = await this.store.get<PinRecord>(pinKey);
    if (pin && (pin.curve25519 !== d.curve25519 || pin.ed25519 !== d.ed25519)) return undefined;
    return { target, pin: pin ? undefined : [pinKey, { curve25519: d.curve25519, ed25519: d.ed25519 } satisfies PinRecord] };
  }

  /**
   * The room's members and their verified devices, looked up afresh for every send: a cached
   * list would miss a member's new device (which could then never read what is sent meanwhile)
   * and could outlive a removal (whose member would keep getting keys). Two small requests per
   * send buy both.
   */
  private async devicesInRoom(roomId: string): Promise<{ members: string[]; devices: Target[] }> {
    const members = [...new Set(await this.server.roomMembers(roomId))];
    return { members, devices: await this.verifiedDevices(members) };
  }

  /**
   * Call when someone leaves or is removed: the room's session is dropped, so the next message
   * starts a new one they never receive. (A send that finds a sharer gone rotates anyway.)
   */
  async memberLeft(roomId: string): Promise<void> {
    await this.locked(() => this.store.write([], [`out:${roomId}`]));
  }

  // --- Identity (identity.ts) ---

  /** Seals queued room sessions to the key backup, after the current locked operation. */
  private backupSoon(): void {
    setTimeout(() => void this.locked(() => this.identity.flushBackup()).catch(() => undefined), 0);
  }

  /** Whether the user has an encryption identity and this device is verified by it. */
  identityStatus(): Promise<IdentityStatus> {
    return this.identity.status();
  }

  /** A new identity (the first device, or a reset); upload happens on commit. */
  prepareIdentity(reset = false): Promise<{ recoveryKey: string; commit(): Promise<void> }> {
    return this.identity.prepare(reset);
  }

  /** Verifies this device with the recovery key; answers the number of sessions restored. */
  restoreIdentity(recoveryKey: string): Promise<number> {
    return this.identity.restore(recoveryKey);
  }

  /** On a verified device: a QR pairing to verify a new one. */
  offerVerification(): Promise<PairingOffer> {
    return this.identity.offer();
  }

  /** On a new device: joins a pairing from the code a verified device shows. */
  joinVerification(text: string): Promise<PairingJoin> {
    return this.identity.join(text);
  }

  identityChanges(): Promise<IdentityChange[]> {
    return this.identity.changes();
  }

  /** Accepts exactly the change shown (previous to fingerprint), or nothing. */
  acceptIdentity(userId: string, previous: string, fingerprint: string): Promise<void> {
    return this.identity.acceptChange(userId, previous, fingerprint);
  }

  /** Checks a room's members' identities when it opens, so a reader sees a change before sending. */
  checkRoom(roomId: string): Promise<void> {
    return this.locked(async () => {
      await this.devicesInRoom(roomId);
    });
  }

  /** Takes devices off the user's signed device list (this one at sign-out). */
  delistDevices(deviceIds: string[]): Promise<void> {
    return this.identity.delist(deviceIds);
  }

  onIdentityChange(fn: () => void): () => void {
    return this.identity.onChange(fn);
  }

  // --- Olm ---

  private async olmSessionFor(curve: string): Promise<[string, Session] | undefined> {
    const rows = await this.store.list<OlmRecord>(`olm:${curve}:`);
    if (rows.length === 0) return undefined;
    const [k, r] = rows.reduce((a, b) => (b[1].used > a[1].used ? b : a));
    return [k, Session.fromPickle(r.pickle, this.key)];
  }

  /** Claims one-time keys for targets with no Olm session and opens sessions to them. */
  private async openOlmSessions(targets: Target[]): Promise<void> {
    const missing: Target[] = [];
    for (const t of targets) {
      if ((await this.store.list<OlmRecord>(`olm:${t.curve25519}:`)).length === 0) missing.push(t);
    }
    const account = await this.loadAccount();
    try {
      for (let i = 0; i < missing.length; i += BATCH) {
        const batch = missing.slice(i, i + BATCH);
        const byDevice = new Map(batch.map((t) => [devKey(t), t]));
        const claimed = await this.server.claim(batch.map((t) => ({ user_id: t.user_id, device_id: t.device_id })));
        const puts: [string, unknown][] = [];
        for (const c of claimed) {
          const t = byDevice.get(devKey(c));
          if (!t || !isStr(c.key_id, 64) || !isStr(c.key, 64) || !isStr(c.signature, 128)) continue;
          if (!verifyEd25519(t.ed25519, oneTimeKeySigned(t.user_id, t.device_id, c.key_id, c.key), c.signature)) continue;
          byDevice.delete(devKey(c));
          let s: Session;
          try {
            s = account.createOutboundSession(t.curve25519, c.key);
          } catch {
            // A signed key the crypto core refuses (e.g. non-contributory): skip only this device,
            // so one bad device cannot stop the room's key reaching everyone else.
            continue;
          }
          try {
            puts.push([`olm:${t.curve25519}:${s.sessionId}`, { pickle: s.pickle(this.key), used: Date.now() } satisfies OlmRecord]);
          } finally {
            s.free();
          }
        }
        await this.store.write(puts);
      }
    } finally {
      account.free();
    }
  }

  /** Decrypts an Olm message from curve, starting an inbound session for a pre-key message. */
  // Decrypts one Olm message and returns the state it changed (the session, and for a pre-key
  // message the account whose one-time key it spent) without storing it: the caller stores it in
  // the same transaction as what the message delivered, so a failed write leaves both as they
  // were and the mail can be read again.
  private async olmDecrypt(curve: string, type: number, body: string): Promise<{ plaintext: string; preKey: boolean; writes: [string, unknown][] }> {
    for (const [k, r] of await this.store.list<OlmRecord>(`olm:${curve}:`)) {
      const s = Session.fromPickle(r.pickle, this.key);
      try {
        const plaintext = s.decrypt(type, body);
        return { plaintext, preKey: false, writes: [[k, { pickle: s.pickle(this.key), used: Date.now() } satisfies OlmRecord]] };
      } catch {
        // Not this session; try the next one.
      } finally {
        s.free();
      }
    }
    if (type !== 0) throw new Error('No Olm session for this message');
    const account = await this.loadAccount();
    try {
      const inbound = account.createInboundSession(curve, body);
      const s = inbound.takeSession();
      try {
        return {
          plaintext: inbound.plaintext,
          preKey: true,
          writes: [
            ['account', account.pickle(this.key)],
            [`olm:${curve}:${s.sessionId}`, { pickle: s.pickle(this.key), used: Date.now() } satisfies OlmRecord],
          ],
        };
      } finally {
        s.free();
        inbound.free();
      }
    } finally {
      account.free();
    }
  }

  // --- Sending ---

  private mustRotate(out: OutboundRecord, session: GroupSession, members: string[], devices: Target[]): boolean {
    if (session.messageIndex >= ROTATE_AFTER_MESSAGES || Date.now() - out.created_at >= ROTATE_AFTER_MS) return true;
    const memberSet = new Set(members);
    const current = new Map(devices.map((d) => [devKey(d), d.curve25519]));
    // Someone who had the key left, or one of their devices was removed or changed.
    return Object.entries(out.shared).some(([k, curve]) => !memberSet.has(k.split('\n')[0]) || current.get(k) !== curve);
  }

  /** Sends the session's key, from its current index, to targets over Olm. */
  private async shareRoomKey(roomId: string, session: GroupSession, targets: Target[]): Promise<Target[]> {
    await this.openOlmSessions(targets);
    const content = { room_id: roomId, session_id: session.sessionId, session_key: session.sessionKey(), device_id: this.deviceId };
    const messages: ToDeviceMessage[] = [];
    const sent: Target[] = [];
    const puts: [string, unknown][] = [];
    for (const t of targets) {
      const found = await this.olmSessionFor(t.curve25519);
      if (!found) continue; // the device has no one-time keys left: it gets the key next time
      const [k, s] = found;
      try {
        const payload: RoomKeyPayload = {
          type: ROOM_KEY_TYPE,
          sender_user_id: this.userId,
          sender_device_id: this.deviceId,
          sender_ed25519: this.ed25519,
          recipient_user_id: t.user_id,
          recipient_device_id: t.device_id,
          recipient_ed25519: t.ed25519,
          content,
        };
        const enc = s.encrypt(JSON.stringify(payload));
        try {
          messages.push({
            user_id: t.user_id,
            device_id: t.device_id,
            type: ROOM_KEY_TYPE,
            content: JSON.stringify({ algorithm: 'olm.v1', sender_key: this.curve25519, type: enc.type, body: enc.ciphertext }),
          });
        } finally {
          enc.free();
        }
        puts.push([k, { pickle: s.pickle(this.key), used: Date.now() } satisfies OlmRecord]);
        sent.push(t);
      } finally {
        s.free();
      }
    }
    // Ratchets are saved before anything leaves, so a crash never reuses a message key.
    await this.store.write(puts);
    for (let i = 0; i < messages.length; i += BATCH) {
      await this.server.sendToDevice(this.deviceId, messages.slice(i, i + BATCH));
    }
    return sent;
  }

  /**
   * Encrypts a room message into an e2ee_room_v1 envelope (a JSON string), sharing or rotating
   * the room's Megolm session first as needed.
   */
  encrypt(roomId: string, inner: Omit<RoomInner, 'room_id'>): Promise<string> {
    return this.locked(async () => {
      const { members, devices } = await this.devicesInRoom(roomId);
      const outKey = `out:${roomId}`;
      let out = await this.store.get<OutboundRecord>(outKey);
      let session = out ? GroupSession.fromPickle(out.pickle, this.key) : undefined;
      try {
        if (!out || !session || this.mustRotate(out, session, members, devices)) {
          session?.free();
          session = new GroupSession();
          out = { pickle: '', created_at: Date.now(), shared: {} };
          // This device reads its own messages through an inbound copy, like everyone else.
          const own = new InboundGroupSession(session.sessionKey());
          try {
            const k = inboundKey(this.curve25519, session.sessionId);
            await this.store.write([[k, {
              pickle: own.pickle(this.key),
              room_id: roomId,
              sender_user: this.userId,
              sender_device: this.deviceId,
              sender_key: this.curve25519,
              first_index: own.firstKnownIndex,
              verified: true,
            } satisfies InboundRecord], [backupQueueKey(k), k]]);
            this.backupSoon();
          } finally {
            own.free();
          }
        }
        const need = devices.filter((d) => out!.shared[devKey(d)] !== d.curve25519);
        if (need.length > 0) {
          for (const t of await this.shareRoomKey(roomId, session, need)) out.shared[devKey(t)] = t.curve25519;
        }
        const full: RoomInner = { ...inner, room_id: roomId };
        const ciphertext = session.encrypt(JSON.stringify(full));
        await this.store.write([[outKey, { ...out, pickle: session.pickle(this.key) } satisfies OutboundRecord]]);
        const envelope: RoomEnvelope = {
          alg: 'megolm.v1',
          sender_key: this.curve25519,
          device_id: this.deviceId,
          session_id: session.sessionId,
          ciphertext,
        };
        return JSON.stringify(envelope);
      } finally {
        session?.free();
      }
    });
  }

  // --- Receiving ---

  /**
   * Opens a stored e2ee_room_v1 message. The session must have come from the device that sent
   * it, for the room it is in; the plaintext must name that room; and its ratchet index may
   * belong to no other message.
   */
  async decrypt(m: SealedMessage): Promise<Opened> {
    const env = parseEnvelope(m.body);
    if (!env) return { state: 'failed', reason: 'This message is damaged.' };
    const rec = await this.store.get<InboundRecord>(inboundKey(env.sender_key, env.session_id));
    if (!rec) return { state: 'waiting', sessionId: env.session_id };
    if (rec.sender_key !== env.sender_key || rec.sender_device !== env.device_id || rec.sender_user !== m.sender_id) {
      return { state: 'failed', reason: 'This message did not come from the device it names.' };
    }
    if (rec.room_id !== m.room_id) return { state: 'failed', reason: 'This message was encrypted for another room.' };
    const session = InboundGroupSession.fromPickle(rec.pickle, this.key);
    let plaintext: string;
    let index: number;
    try {
      const d = session.decrypt(env.ciphertext);
      try {
        plaintext = d.plaintext;
        index = d.messageIndex;
      } finally {
        d.free();
      }
    } catch {
      return { state: 'failed', reason: 'This message was sent before this device could read the room.' };
    } finally {
      session.free();
    }
    const inner = parseInner(plaintext);
    if (!inner) return { state: 'failed', reason: 'This message is damaged.' };
    if (inner.room_id !== m.room_id) return { state: 'failed', reason: 'This message was encrypted for another room.' };
    if (inner.type === 'edit' && inner.message_id !== m.id) return { state: 'failed', reason: 'This edit belongs to another message.' };
    const owner = await this.store.putIfAbsent(seenKey(env.sender_key, env.session_id, index), m.id);
    if (owner !== m.id) return { state: 'failed', reason: 'This message is a replay of another message.' };
    return { state: 'decrypted', inner, authenticated: rec.verified === true && !rec.from_backup };
  }

  /**
   * Reads the device's to-device mailbox and stores the room keys in it. Mail is acknowledged
   * once it is handled, kept or refused; a network failure leaves the rest for the next wake.
   * Returns the IDs of the room sessions that arrived.
   */
  async receive(): Promise<string[]> {
    const fresh: string[] = [];
    let usedOneTimeKey = false;
    try {
      await this.receiveLocked(fresh, () => (usedOneTimeKey = true));
    } finally {
      // Keys already stored are announced even if a later ack or mailbox read fails: a retry
      // would find them known and announce nothing, leaving waiting messages stuck.
      if (fresh.length > 0) for (const fn of this.listeners) fn(fresh);
      if (usedOneTimeKey) await this.publishKeys().catch(() => undefined);
    }
    return fresh;
  }

  private receiveLocked(fresh: string[], spentOneTimeKey: () => void): Promise<void> {
    return this.locked(async () => {
      for (;;) {
        const mail = await this.server.mailbox(this.deviceId);
        if (mail.length === 0) return;
        const trusted = await this.trustedSenders(mail);
        const handled: number[] = [];
        let stop = false;
        for (const m of mail) {
          try {
            const r = await this.handleMail(m, trusted);
            if (r) {
              fresh.push(r.sessionId);
              if (r.preKey) spentOneTimeKey();
            }
          } catch (e) {
            // A network or local storage failure (IndexedDB raises DOMException: quota, an aborted
            // write, a store closed by another tab) keeps this mail and the rest for a retry; only
            // mail that is itself unreadable (bad shape, unverified sender, failed Olm) is dropped.
            if (e instanceof Transient || e instanceof DOMException) {
              stop = true;
              break;
            }
          }
          handled.push(m.id);
        }
        if (handled.length > 0) await this.server.ack(this.deviceId, handled);
        if (stop || mail.length < MAILBOX_PAGE) return;
      }
    });
  }

  /**
   * The senders of mail whose master key vouches for them, as "user\ndevice\ncurve25519".
   * Only their sessions go to the key backup, so no one can fill a member's backup or bake an
   * impersonation into it by mailing room keys. A lookup that fails trusts no one.
   */
  private async trustedSenders(mail: Mail[]): Promise<Set<string>> {
    const users = [...new Set(mail.map((m) => m.sender_user_id).filter((u) => isStr(u, 128)))];
    try {
      return new Set((await this.verifiedDevices(users)).map((t) => `${devKey(t)}\n${t.curve25519}`));
    } catch {
      return new Set();
    }
  }

  private async handleMail(m: Mail, trusted: Set<string>): Promise<{ sessionId: string; preKey: boolean } | undefined> {
    if (m.type !== ROOM_KEY_TYPE) throw new Error('Unknown mail type');
    const c = parseJSON(m.content);
    if (!isObj(c) || c.algorithm !== 'olm.v1' || !isStr(c.sender_key, 64) || (c.type !== 0 && c.type !== 1) || !isStr(c.body)) {
      throw new Error('Malformed mail');
    }
    // The Olm identity must be the verified key of the device the server says sent the mail. The
    // mail carries that device's self-signed keys from when it was sent, so it stays readable
    // after the sender signs out; they are checked like listed keys, against the same pins.
    const checked = isObj(m.sender_keys) && m.sender_keys.device_id === m.sender_device_id ? await this.checkDevice(m.sender_user_id, m.sender_keys) : undefined;
    if (!checked || checked.target.curve25519 !== c.sender_key) throw new Error('Mail from an unverified device');
    const sender = checked.target;
    const pin: [string, unknown][] = checked.pin ? [checked.pin] : [];
    const { plaintext, preKey, writes } = await this.olmDecrypt(sender.curve25519, c.type, c.body);
    // The Olm step succeeded, so its state is kept even if what it carried is refused below.
    let bad: unknown;
    let room: { sessionId: string; key: string; record: InboundRecord } | undefined;
    try {
      room = await this.roomKey(plaintext, sender, trusted.has(`${devKey(sender)}\n${sender.curve25519}`));
    } catch (e) {
      // A storage failure says nothing about the payload: keep the Olm state as it was, so the
      // queued mail decrypts again on retry. Only a definite refusal commits the spent state.
      if (e instanceof Transient || e instanceof DOMException) throw e;
      bad = e;
    }
    const backup: [string, unknown][] = room?.record.verified ? [[backupQueueKey(room.key), room.key]] : [];
    await this.store.write(room ? [...pin, ...writes, [room.key, room.record], ...backup] : [...pin, ...writes]);
    if (backup.length > 0) this.backupSoon();
    if (bad !== undefined) throw bad;
    return room ? { sessionId: room.sessionId, preKey } : undefined;
  }

  // Checks a decrypted room key and returns the record to store, or undefined when an equal or
  // better copy is already stored.
  private async roomKey(plaintext: string, sender: Target, verified: boolean): Promise<{ sessionId: string; key: string; record: InboundRecord } | undefined> {
    const p = parseJSON(plaintext);
    if (
      !isObj(p) || p.type !== ROOM_KEY_TYPE ||
      p.sender_user_id !== sender.user_id || p.sender_device_id !== sender.device_id || p.sender_ed25519 !== sender.ed25519 ||
      p.recipient_user_id !== this.userId || p.recipient_device_id !== this.deviceId || p.recipient_ed25519 !== this.ed25519 ||
      !isObj(p.content)
    ) {
      throw new Error('Room key addressed elsewhere');
    }
    const k = p.content;
    if (!isStr(k.room_id, 128) || !isStr(k.session_id, 128) || !isStr(k.session_key) || k.device_id !== sender.device_id) {
      throw new Error('Malformed room key');
    }
    const session = new InboundGroupSession(k.session_key);
    try {
      if (session.sessionId !== k.session_id) throw new Error('Room key does not match its session');
      const key = inboundKey(sender.curve25519, k.session_id);
      const known = await this.store.get<InboundRecord>(key);
      if (known) {
        // A session is bound to its first sender and room; a later copy may only reach further back.
        const same = known.sender_key === sender.curve25519 && known.sender_user === sender.user_id &&
          known.sender_device === sender.device_id && known.room_id === k.room_id;
        if (!same || known.first_index <= session.firstKnownIndex) return undefined;
      }
      return {
        sessionId: k.session_id,
        key,
        record: {
          pickle: session.pickle(this.key),
          room_id: k.room_id,
          sender_user: sender.user_id,
          sender_device: sender.device_id,
          sender_key: sender.curve25519,
          first_index: session.firstKnownIndex,
          verified,
        },
      };
    } finally {
      session.free();
    }
  }
}

function lockName(userId: string): string {
  return `kymessages-crypto-${userId}`;
}
