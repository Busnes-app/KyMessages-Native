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
import { Identity, Rollback, validBotList, type BotDeviceList, type TrustedMaster, type IdentityChange, type IdentityServer, type IdentityStatus, type MasterKeyRecord, type PairingJoin, type PairingOffer } from './identity';
import { pqc, type BotDevice, type Hybrid } from '../pqc/index';
import { backupCoverKey, backupQueueKey, IdentityMoved, inboundKey, isObj, isStr, isTransient, parseJSON, seenKey, Transient, type InboundRecord } from './records';
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

/** A key query: the org the keys belong to, each user's devices and master key, and each bot's
 * owner-signed device list (with the owner's master key in master_keys). */
export interface QueryResult {
  tenant_id: string;
  devices: Record<string, DeviceKeys[]>;
  master_keys: Record<string, MasterKeyRecord>;
  bot_devices?: Record<string, BotDeviceList>;
}

/**
 * The code a bot shows for one of its devices (agent-skill/kymessages/scripts/kybot.py prints the
 * same): 80 bits of SHA-256 over Fields(label, bot, device, curve25519, ed25519), in five groups
 * of four hex digits. Its owner vouches for a device only once the codes match, so a device the
 * server made up is never signed.
 */
export function botDeviceCode(d: { user_id?: string; device_id: string; curve25519: string; ed25519: string }, botId = d.user_id ?? ''): string {
  return pqc.hash('kymessages.bot-device-code.v1', botId, d.device_id, d.curve25519, d.ed25519).slice(0, 20).match(/.{4}/g)!.join('-');
}

/** Native bot accounts have bot_ user IDs (internal/api agent_handlers.go). */
export const isBotUser = (userId: string) => userId.startsWith('bot_');

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
  query(userIds: string[], signal?: AbortSignal): Promise<QueryResult>;
  claim(devices: { user_id: string; device_id: string }[]): Promise<ClaimedKey[]>;
  sendToDevice(deviceId: string, messages: ToDeviceMessage[]): Promise<void>;
  mailbox(deviceId: string): Promise<Mail[]>;
  ack(deviceId: string, ids: number[]): Promise<void>;
  /** The user IDs of a room's current members. */
  roomMembers(roomId: string): Promise<string[]>;
  /** PUT /api/v1/keys/bots/{id}/devices: the owner's signed list of their bot's devices (E4). */
  putBotDevices(botId: string, body: { version: number; expected_epoch: number; epoch: number; devices: BotDevice[]; signature: string }): Promise<void>;
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
  /** Encrypted attachment descriptors, checked by crypto/attachments.ts openFiles. */
  files?: unknown[];
  /** The sender's own ID for a message (its idempotency key), named again by its edits. */
  ref?: string;
  /** For an edit: what the edited message's files are, checked by crypto/attachments.ts. */
  original?: unknown;
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
  | { state: 'decrypted'; inner: RoomInner; authenticated: boolean; restored: boolean }
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
  if (i.files !== undefined && !Array.isArray(i.files)) return undefined;
  if (i.ref !== undefined && !isStr(i.ref, 128)) return undefined;
  return {
    room_id: i.room_id,
    type: i.type as RoomMessageType,
    body: i.body,
    ...(i.reply_to_id ? { reply_to_id: i.reply_to_id as string } : {}),
    ...(i.message_id ? { message_id: i.message_id as string } : {}),
    ...(i.files ? { files: i.files as unknown[] } : {}),
    ...(i.ref ? { ref: i.ref as string } : {}),
    ...(i.original !== undefined ? { original: i.original } : {}),
  };
}

// Serializes crypto work per user: Web Locks across tabs, a promise chain where there are none.
const chains = new Map<string, Promise<unknown>>();
// signal gives up waiting for the lock (and, passed on by fn, its work): an aborted wait never
// runs fn, so the lock is never taken for a caller that left.
function withLock<T>(name: string, fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks?.request) {
    return (signal ? navigator.locks.request(name, { signal }, fn) : navigator.locks.request(name, fn)) as Promise<T>;
  }
  // As Web Locks: the signal ends only the wait for the lock; once fn runs, its result stands.
  let started = false;
  const turn = () => {
    signal?.throwIfAborted();
    started = true;
    return fn();
  };
  const run = (chains.get(name) ?? Promise.resolve()).then(turn, turn);
  chains.set(name, run.catch(() => undefined));
  if (!signal) return run;
  return new Promise<T>((resolve, reject) => {
    const stop = () => { if (!started) reject(signal.reason); };
    if (signal.aborted) return stop();
    signal.addEventListener('abort', stop, { once: true });
    run.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
  });
}

/** An encrypted send from a device that is not verified (or an account with no identity yet). */
export class NotVerified extends Error {
  constructor() {
    super('Set up encryption or verify this device to send encrypted messages.');
  }
}

/** A key query that showed one member with two master keys: nothing of theirs is trusted. */
export class IdentityConflict extends Error {
  constructor(userId: string) { super(`The server showed two encryption identities for ${userId} at once, so neither is trusted. Nothing was sent.`); }
}

export class DeviceChanged extends Error {
  constructor() { super('This browser device was replaced'); }
}

/** A message from before the session this device holds starts: a key backup page (restored
 * later) or a re-shared session may still cover it, so it is worth opening again. */
export const EARLY = 'This message was sent before this device could read the room.';

export class CryptoEngine {
  private readonly listeners = new Set<(sessionIds: string[]) => void>();
  private readonly transient = new Set<() => void>();
  // A failure reported before anyone listened (the status check open starts): handed to the
  // first listener, so it is still retried.
  private missedTransient = false;
  private readonly backupState = new Set<(full: boolean) => void>();
  private readonly adopted = new Set<() => void>();
  private readonly verdicts = new Set<(e: Rollback | NotVerified) => void>();
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
    this.identity = new Identity({
      userId, deviceId, curve25519, ed25519, server, store, pickleKey: key, locked: (fn, signal) => this.locked(fn, signal),
      onRestored: (ids) => { for (const fn of this.listeners) fn(ids); },
      onTransient: () => this.reportTransient(),
      onBackupState: (full) => { for (const fn of this.backupState) fn(full); },
      onAdopted: () => { for (const fn of this.adopted) fn(); },
    });
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

  /** Calls fn when background work (key backup, restore) failed for availability and waits for
   * a retry (identityStatus runs it again); returns an unsubscribe. */
  onTransient(fn: () => void): () => void {
    this.transient.add(fn);
    if (this.missedTransient) {
      this.missedTransient = false;
      fn();
    }
    return () => this.transient.delete(fn);
  }

  private reportTransient(): void {
    if (this.transient.size === 0) this.missedTransient = true;
    for (const fn of this.transient) fn();
  }

  /** Calls fn when whether the key backup refused sessions (it is full) changes. */
  onBackupState(fn: (full: boolean) => void): () => void {
    this.backupState.add(fn);
    return () => this.backupState.delete(fn);
  }

  /** Calls fn once this device durably took on the identity (before any backup paging). */
  onAdopted(fn: () => void): () => void {
    this.adopted.add(fn);
    return () => this.adopted.delete(fn);
  }

  /** Calls fn when a live operation (mailbox read, room check, send, retry) hits Rollback or NotVerified. */
  onVerdict(fn: (e: Rollback | NotVerified) => void): () => void {
    this.verdicts.add(fn);
    return () => this.verdicts.delete(fn);
  }

  private reportVerdict(e: unknown): void {
    if (e instanceof Rollback || e instanceof NotVerified) {
      for (const fn of this.verdicts) fn(e);
    }
  }

  /**
   * The work a retry resumes, awaited to the end: the mailbox, then the key backup restore in
   * progress and the backup queue (refused entries too). Throws what stopped it.
   */
  async resumeWork(): Promise<void> {
    await this.receive();
    try {
      await this.identity.drain();
    } catch (e) {
      this.reportVerdict(e);
      throw e;
    }
  }

  /** Calls fn with the IDs of room sessions whose keys just arrived; returns an unsubscribe. */
  onKeys(fn: (sessionIds: string[]) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private locked<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    return withLock(lockName(this.userId), async () => {
      await this.assertCurrent();
      return fn();
    }, signal);
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
   * The devices of userIds this device trusts, without itself: one stage-then-commit trust
   * decision, the same rules as agent-skill's kybot.py `trusted_devices` (spec §8):
   * 1. Every lookup batch is collected before anything is decided.
   * 2. Each user's final identity is the one master key every batch showed. A first-seen user
   *    shown two keys fails the lookup (IdentityConflict); a pinned user shown another key, or
   *    any record that does not verify, is blocked (a change waits for acceptance).
   * 3. Each user's final device list is the newest signed one seen for that identity, checked
   *    after every list seen has raised the mark: an older list counts for nothing, and a fork
   *    or a refused newest list trusts no device.
   * 4. A device is a recipient only when it is on its user's final list, cross-signed by the
   *    final key (a bot: on the owner's final bot list with the same keys), and matches its pin.
   * 5. Nothing is pinned or shared before 1–4; first sights wait for the synced pin set.
   */
  async verifiedDevices(userIds: string[], self?: { trusted: boolean }): Promise<Target[]> {
    // A pin sync that fails: seeds of an identity the server no longer publishes mean this device
    // must verify again; a rolled-back pin set is the verdict the gate shows; anything else is
    // retried.
    function pinSyncFailed(e: unknown): never {
      if (e instanceof IdentityMoved) throw new NotVerified();
      if (e instanceof Rollback) throw e;
      throw new Transient(e instanceof Error ? e.message : 'Could not sync pinned identities');
    }
    // One authenticated pin sync before the whole check; a failure fails the check.
    await this.identity.beforeTrust().catch(pinSyncFailed);

    // 1. Collect every batch: each user's devices and bot list from the batch that named them,
    // and every master key record any batch showed (a bot's owner comes with its list).
    const ids = [...new Set(userIds)];
    const devices = new Map<string, DeviceKeys[]>();
    const botLists = new Map<string, unknown>();
    const records = new Map<string, unknown[]>();
    let tenant: string | undefined;
    for (let i = 0; i < ids.length; i += BATCH) {
      const batch = ids.slice(i, i + BATCH);
      let listed: QueryResult;
      try {
        listed = await this.server.query(batch);
      } catch (e) {
        throw new Transient(e instanceof Error ? e.message : 'Could not list devices');
      }
      if (tenant !== undefined && listed.tenant_id !== tenant) throw new Transient('The key server answered for another organization');
      tenant = listed.tenant_id;
      for (const u of batch) {
        devices.set(u, listed.devices?.[u] ?? []);
        if (isBotUser(u)) botLists.set(u, listed.bot_devices?.[u]);
      }
      if (isObj(listed.master_keys)) for (const [u, rec] of Object.entries(listed.master_keys)) records.set(u, [...(records.get(u) ?? []), rec]);
    }
    if (tenant === undefined) return [];
    const tenantId = tenant;

    // 2–3. Resolve each needed identity once, from every record seen. Warnings go into pins;
    // first sights into sights.
    const pins: [string, unknown][] = [];
    const sights = new Map<string, string>();
    const finals = new Map<string, TrustedMaster | undefined>();
    const resolve = async (user: string): Promise<TrustedMaster | undefined> => {
      if (finals.has(user)) return finals.get(user);
      const recs = records.get(user) ?? [];
      let blocked = recs.length === 0;
      // Every record raises the list mark, in the order seen, and must name the same key.
      for (const rec of recs) {
        const seen = sights.get(user);
        if (!(await this.identity.trustedMaster(user, rec, tenantId, pins, sights))) blocked = true;
        if (seen !== undefined && sights.get(user) !== seen) throw new IdentityConflict(user);
      }
      // The newest list (the first of equals), checked against the mark all of them raised.
      const final = blocked ? undefined : await this.identity.trustedMaster(user, recs.reduce((a, b) => (listEpoch(b) > listEpoch(a) ? b : a)), tenantId, pins, sights);
      finals.set(user, final);
      return final;
    };

    // 4. Derive recipients from final state only.
    const out: Target[] = [];
    const devicePins: [string, unknown][] = [];
    // What depends on a first-seen member, with the fingerprint it was checked against.
    const proposed: { user: string; fp: string; pins: [string, unknown][]; targets: Target[] }[] = [];
    for (const userId of ids) {
      // A bot has no key of its own: only its owner's final signed list vouches for its devices
      // (E4), so its trust waits on the owner's pin like the owner's own devices do.
      const bot = botLists.get(userId);
      if (isBotUser(userId) && !validBotList(bot)) continue;
      const pinUser = validBotList(bot) ? bot.owner_id : userId;
      const master = await resolve(pinUser);
      if (!master) continue;
      const fp = sights.get(pinUser);
      const staged = { user: pinUser, fp: fp ?? '', pins: [] as [string, unknown][], targets: [] as Target[] };
      const vouched = validBotList(bot) && (await this.identity.trustedBot(userId, pinUser, master, tenantId, bot, staged.pins));
      const trusted = (d: DeviceKeys) => {
        if (!vouched) return this.identity.deviceTrusted(master, tenantId, userId, d);
        const v = vouched.get(d.device_id);
        return v !== undefined && v.curve25519 === d.curve25519 && v.ed25519 === d.ed25519;
      };
      for (const d of devices.get(userId) ?? []) {
        if (userId === this.userId && isObj(d) && d.device_id === this.deviceId) {
          // This device itself, with exactly its own keys, checked like any other (self
          // reports it), never a target. Other keys under its ID are not this device.
          if (self && d.curve25519 === this.curve25519 && d.ed25519 === this.ed25519 &&
            (await this.checkDevice(userId, d)) && this.identity.deviceTrusted(master, tenantId, userId, d)) self.trusted = true;
          continue;
        }
        const checked = await this.checkDevice(userId, d);
        if (!checked || !trusted(d as DeviceKeys)) continue;
        if (checked.pin) staged.pins.push(checked.pin);
        staged.targets.push(checked.target);
      }
      if (fp !== undefined) proposed.push(staged);
      else {
        devicePins.push(...staged.pins);
        out.push(...staged.targets);
      }
    }

    // 5. Commit. A send this device may not make pins nobody: the warnings it found are kept,
    // the first sights (shared or this device's) wait for a send it may make.
    if (self && !self.trusted) {
      await this.store.write(pins);
      this.identity.afterWrites();
      throw new NotVerified();
    }
    await this.store.write(pins);
    // All first sights in one shared compare-and-swap, before any of them gets a key or any new
    // peer device pin is persisted: if the own identity moved, nothing new is pinned.
    let committed: Set<string>;
    try {
      committed = await this.identity.commitFirstSights(sights);
    } catch (e) {
      this.identity.afterWrites();
      pinSyncFailed(e);
    }
    const later: [string, unknown][] = [...devicePins];
    for (const c of proposed) {
      // Released only under exactly the fingerprint committed for its member.
      if (!committed.has(c.user) || sights.get(c.user) !== c.fp) continue;
      later.push(...c.pins);
      out.push(...c.targets);
    }
    await this.store.write(later);
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
  private async devicesInRoom(roomId: string, self?: { trusted: boolean }): Promise<{ members: string[]; devices: Target[] }> {
    const members = [...new Set(await this.server.roomMembers(roomId))];
    // The user's own entry is always read, so self can be answered from the same query.
    const ids = self && !members.includes(this.userId) ? [...members, this.userId] : members;
    return { members, devices: await this.verifiedDevices(ids, self) };
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
    setTimeout(() => void this.locked(() => this.identity.flushBackup()).catch((e: unknown) => {
      if (isTransient(e)) this.reportTransient();
    }), 0);
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

  /**
   * Whether one of the user's own devices is verified: self-signed, cross-signed by this
   * device's master key and on its newest list. Only the user's own entry is read (no pin sync,
   * no colleague), and signal ends the wait for the lock and the request.
   */
  ownDeviceVerified(deviceId: string, signal?: AbortSignal): Promise<boolean> {
    return this.locked(async () => {
      const listed = await this.server.query([this.userId], signal);
      const master = await this.identity.trustedMaster(this.userId, listed.master_keys?.[this.userId], listed.tenant_id, [], new Map());
      if (!master) return false;
      const d = (listed.devices?.[this.userId] ?? []).find((x) => isObj(x) && x.device_id === deviceId);
      return !!d && (await this.checkDevice(this.userId, d)) !== undefined && this.identity.deviceTrusted(master, listed.tenant_id, this.userId, d);
    }, signal);
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
      try {
        await this.devicesInRoom(roomId);
      } catch (e) {
        this.reportVerdict(e);
        throw e;
      }
    });
  }

  // --- Bots (E4) ---

  /**
   * The owner's view of their bot: the devices it uploaded (self-signed), each with its
   * verification code, which the owner compares with the one the bot shows; and the ones this
   * user's signed list vouches for now.
   */
  botDevices(botId: string): Promise<{ uploaded: (BotDevice & { code: string })[]; vouched: BotDevice[]; epoch: number }> {
    return this.locked(async () => {
      const listed = await this.server.query([botId]);
      const uploaded: (BotDevice & { code: string })[] = [];
      for (const d of listed.devices?.[botId] ?? []) {
        const c = await this.checkDevice(botId, d);
        if (c) uploaded.push({ device_id: c.target.device_id, curve25519: c.target.curve25519, ed25519: c.target.ed25519, code: botDeviceCode(c.target) });
      }
      const rec = listed.bot_devices?.[botId];
      const mine = validBotList(rec) && rec.owner_id === this.userId ? rec : undefined;
      let vouched: BotDevice[] = [];
      if (mine) {
        const master = await this.identity.trustedMaster(this.userId, listed.master_keys?.[this.userId], listed.tenant_id, [], new Map());
        if (master) vouched = [...(await this.identity.trustedBot(botId, this.userId, master, listed.tenant_id, mine)).values()];
      }
      return { uploaded, vouched, epoch: mine?.epoch ?? 0 };
    });
  }

  /**
   * Changes the user's signed list for their bot by one device, signed by this device's master
   * key at the epoch after expectedEpoch: add (named with the code the owner compared, so keys the
   * server swapped in since are refused) replaces any entry under its ID; remove drops one. Every
   * other entry is copied from the newest list this device verifies, never from uploaded keys.
   */
  async vouchForBot(botId: string, expectedEpoch: number, change: { add?: BotDevice & { code: string }; remove?: string }): Promise<void> {
    const { add, remove } = change;
    if (add && botDeviceCode(add, botId) !== add.code) throw new Error('A device does not match its code.');
    await this.locked(async () => {
      const listed = await this.server.query([botId]);
      const rec = listed.bot_devices?.[botId];
      const mine = validBotList(rec) && rec.owner_id === this.userId ? rec : undefined;
      if ((mine?.epoch ?? 0) !== expectedEpoch) throw new Error('The bot device list changed; reload it.');
      const master = mine && (await this.identity.trustedMaster(this.userId, listed.master_keys?.[this.userId], listed.tenant_id, [], new Map()));
      const kept = master ? await this.identity.trustedBot(botId, this.userId, master, listed.tenant_id, mine) : new Map<string, BotDevice>();
      if (remove !== undefined) kept.delete(remove);
      if (add) kept.set(add.device_id, { device_id: add.device_id, curve25519: add.curve25519, ed25519: add.ed25519 });
      const list = [...kept.values()].map(({ device_id, curve25519, ed25519 }) => ({ device_id, curve25519, ed25519 }))
        .sort((a, b) => (a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0));
      const epoch = expectedEpoch + 1;
      const { version, signature } = await this.identity.signBotDevices(botId, epoch, list);
      await this.server.putBotDevices(botId, { version, expected_epoch: expectedEpoch, epoch, devices: list, signature });
      const after = await this.server.query([botId]);
      await this.identity.publishedBotList(botId, after.tenant_id, epoch, list);
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
      try {
        // An unverified device trusts no one, so its message would reach no one, silently: it is
        // refused before any session is made or ratcheted, and sends once the device is verified.
        // Holding the seeds is not enough: this device must be cross-signed by the identity the
        // server publishes now and on its newest device list (not a stale or reset identity, not
        // a replacement still enrolling, not a retired device), judged from the send's own query.
        if (!(await this.identity.isVerified())) throw new NotVerified();
        // devicesInRoom refuses (NotVerified) unless this device is trusted by the send's own query.
        const { members, devices } = await this.devicesInRoom(roomId, { trusted: false });
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
      } catch (e) {
        this.reportVerdict(e);
        throw e;
      }
    });
  }

  // --- Receiving ---

  /**
   * Opens a stored e2ee_room_v1 message. The session must have come from the device that sent
   * it, for the room it is in; the plaintext must name that room; and its ratchet index may
   * belong to no other message. `expect` refuses an inner this message cannot be (its reason),
   * checked before the index is claimed for this message, so a substitute never takes it.
   */
  async decrypt(m: SealedMessage, expect?: (inner: RoomInner) => string | undefined): Promise<Opened> {
    const env = parseEnvelope(m.body);
    if (!env) return { state: 'failed', reason: 'This message is damaged.' };
    const rec = await this.store.get<InboundRecord>(inboundKey(env.sender_key, env.session_id));
    if (!rec) return { state: 'waiting', sessionId: env.session_id };
    if (rec.sender_key !== env.sender_key || rec.sender_device !== env.device_id || rec.sender_user !== m.sender_id) {
      return { state: 'failed', reason: 'This message did not come from the device it names.' };
    }
    if (rec.room_id !== m.room_id) return { state: 'failed', reason: 'This message was encrypted for another room.' };
    // An earlier-reaching copy from the key backup, bound to the same sender and room, reads only
    // what the verified copy cannot, and never as authenticated.
    const cover = await this.store.get<InboundRecord>(backupCoverKey(env.sender_key, env.session_id));
    const usable = cover && cover.room_id === rec.room_id && cover.sender_user === rec.sender_user && cover.sender_device === rec.sender_device ? cover : undefined;
    let opened = this.openWith(rec, env.ciphertext);
    let via = rec;
    if (!opened && usable) {
      opened = this.openWith(usable, env.ciphertext);
      via = usable;
    }
    if (!opened) return { state: 'failed', reason: EARLY };
    const { plaintext, index } = opened;
    const inner = parseInner(plaintext);
    if (!inner) return { state: 'failed', reason: 'This message is damaged.' };
    if (inner.room_id !== m.room_id) return { state: 'failed', reason: 'This message was encrypted for another room.' };
    if (inner.type === 'edit' && inner.message_id !== m.id) return { state: 'failed', reason: 'This edit belongs to another message.' };
    const refused = expect?.(inner);
    if (refused) return { state: 'failed', reason: refused };
    const owner = await this.store.putIfAbsent(seenKey(env.sender_key, env.session_id, index), m.id);
    if (owner !== m.id) return { state: 'failed', reason: 'This message is a replay of another message.' };
    return { state: 'decrypted', inner, authenticated: via.verified === true && !via.from_backup, restored: via.from_backup === true };
  }

  private openWith(rec: InboundRecord, ciphertext: string): { plaintext: string; index: number } | undefined {
    const session = InboundGroupSession.fromPickle(rec.pickle, this.key);
    try {
      const d = session.decrypt(ciphertext);
      try {
        return { plaintext: d.plaintext, index: d.messageIndex };
      } finally {
        d.free();
      }
    } catch {
      return undefined;
    } finally {
      session.free();
    }
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
    } catch (e) {
      this.reportVerdict(e);
      throw e;
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
        let failure: unknown;
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
            if (isTransient(e)) {
              stop = true;
              failure = e;
              break;
            }
          }
          handled.push(m.id);
        }
        // Only the prefix handled before a failure is acknowledged; the rest stays queued, and
        // the drain still fails so its retry comes (keys already stored are announced anyway).
        if (handled.length > 0) await this.server.ack(this.deviceId, handled);
        if (stop) throw failure;
        if (mail.length < MAILBOX_PAGE) return;
      }
    });
  }

  /**
   * The senders of mail whose master key vouches for them, as "user\ndevice\ncurve25519".
   * Only their sessions go to the key backup, so no one can fill a member's backup or bake an
   * impersonation into it by mailing room keys. A lookup that fails is a transient failure:
   * the mail stays queued rather than having its keys stored as unvouched.
   */
  private async trustedSenders(mail: Mail[]): Promise<Set<string>> {
    const users = [...new Set(mail.map((m) => m.sender_user_id).filter((u) => isStr(u, 128)))];
    try {
      return new Set((await this.verifiedDevices(users)).map((t) => `${devKey(t)}\n${t.curve25519}`));
    } catch (e) {
      // A rolled-back pin/device list or moved/unverified identity is a permanent verdict: the
      // mail stays queued without burning the transient retry budget, and the gate refreshes.
      if (isTransient(e) || e instanceof Rollback || e instanceof NotVerified) throw e;
      throw new Transient(e instanceof Error ? e.message : 'Could not check the senders');
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
    let room: { sessionId: string; key: string; record?: InboundRecord; cover?: InboundRecord } | undefined;
    try {
      room = await this.roomKey(plaintext, sender, trusted.has(`${devKey(sender)}\n${sender.curve25519}`));
    } catch (e) {
      // A storage failure says nothing about the payload: keep the Olm state as it was, so the
      // queued mail decrypts again on retry. Only a definite refusal commits the spent state.
      if (isTransient(e)) throw e;
      bad = e;
    }
    // Only a copy that authenticates is queued for the key backup; a cover never is.
    const backup: [string, unknown][] = room?.record?.verified ? [[backupQueueKey(room.key), room.key]] : [];
    const primary: [string, unknown][] = room?.record ? [[room.key, room.record]] : [];
    const cover: [string, unknown][] = room?.cover ? [[backupCoverKey(room.cover.sender_key, room.sessionId), room.cover]] : [];
    await this.store.write([...pin, ...writes, ...primary, ...cover, ...backup]);
    if (backup.length > 0) this.backupSoon();
    if (bad !== undefined) throw bad;
    return room ? { sessionId: room.sessionId, preKey } : undefined;
  }

  // Checks a decrypted room key and returns the record to store, or undefined when an equal or
  // better copy is already stored.
  private async roomKey(plaintext: string, sender: Target, verified: boolean): Promise<{ sessionId: string; key: string; record?: InboundRecord; cover?: InboundRecord } | undefined> {
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
      const record: InboundRecord = {
        pickle: session.pickle(this.key),
        room_id: k.room_id,
        sender_user: sender.user_id,
        sender_device: sender.device_id,
        sender_key: sender.curve25519,
        first_index: session.firstKnownIndex,
        verified,
      };
      if (!known) return { sessionId: k.session_id, key, record };
      // A session is bound to its first sender and room.
      const same = known.sender_key === sender.curve25519 && known.sender_user === sender.user_id &&
        known.sender_device === sender.device_id && known.room_id === k.room_id;
      if (!same) return undefined;
      // The primary copy authenticates what it covers when it came over Olm from a vouched
      // device. Such a copy is never replaced by one that does not (that would read later
      // messages as unauthenticated, or let an unvouched device speak for the sender); an earlier
      // reach from one is kept beside it, as the cover, for older messages only. A vouched copy
      // supersedes an unvouched or restored primary from its own index on, at an equal index
      // too, and the old one becomes the cover for what only it reaches.
      const authenticates = (r: InboundRecord) => r.verified === true && !r.from_backup;
      const asCover = async (c: InboundRecord): Promise<InboundRecord | undefined> => {
        const cur = await this.store.get<InboundRecord>(backupCoverKey(sender.curve25519, session.sessionId));
        return cur && cur.first_index <= c.first_index ? undefined : c;
      };
      if (authenticates(known)) {
        if (verified && record.first_index < known.first_index) return { sessionId: k.session_id, key, record };
        if (!verified && record.first_index < known.first_index) {
          const cover = await asCover(record);
          return cover ? { sessionId: k.session_id, key, cover } : undefined;
        }
        return undefined;
      }
      if (verified) {
        const cover = known.first_index < record.first_index ? await asCover(known) : undefined;
        return { sessionId: k.session_id, key, record, cover };
      }
      // Neither authenticates: the one reaching further back stays.
      return record.first_index < known.first_index ? { sessionId: k.session_id, key, record } : undefined;
    } finally {
      session.free();
    }
  }
}

/** The epoch of a master key record's device list, 0 without one (for picking the newest). */
function listEpoch(rec: unknown): number {
  return isObj(rec) && isObj(rec.device_list) && typeof rec.device_list.epoch === 'number' ? rec.device_list.epoch : 0;
}

function lockName(userId: string): string {
  return `kymessages-crypto-${userId}`;
}
