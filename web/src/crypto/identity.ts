// The user's post-quantum encryption identity on this device (E3 of
// docs/superpowers/specs/2026-11-22-e2ee-design.md, §3): the hybrid ML-DSA-65 + Ed25519 master
// key that vouches for the user's devices, TOFU pins of colleagues' master keys (synced between
// the user's own verified devices), the recovery key, the X-Wing key backup and QR device
// verification. Every primitive is the Go code in internal/e2eeid, run as WebAssembly (pqc/).
//
// Nothing the server says is trusted: master keys must carry a valid self-binding and match the
// pin, devices must carry the pinned master key's signature, recovery wraps and transfers must
// open to the very key the server publishes, and backup entries must carry the master key's MAC.
import { InboundGroupSession } from './index';
import { b64, pqc, unb64, type Hybrid } from '../pqc/index';
import type { CryptoStore } from './store';
import { backupQueueKey, Conflict, inboundKey, isObj, isStr, parseJSON, type InboundRecord } from './records';

// --- The key server, as the identity needs it (chat/e2ee.ts implements it over HTTP) ---

export interface MasterKeyRecord {
  version: number;
  master_key: Hybrid;
  self_signature: Hybrid;
}

export interface OwnMaster extends MasterKeyRecord {
  backup_key: { public_key: string; signature: Hybrid };
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

export interface BackupEntry {
  room_id: string;
  session_id: string;
  first_index: number;
  sealed: string;
}

export interface PairingState {
  pairing_id: string;
  initiator_device: string;
  new_device: string;
  ephemeral_key: string;
  sealed: boolean;
}

/** Writes answer Conflict when the identity, pin set or backup version moved on. */
export interface IdentityServer {
  getMaster(): Promise<{ tenant_id: string; master: OwnMaster | null }>;
  putMaster(req: MasterPut): Promise<number>;
  putPins(version: number, expectedCounter: number, sealed: string): Promise<void>;
  signDevice(deviceId: string, version: number, signature: Hybrid): Promise<void>;
  getBackup(version: number, afterRoom: string, afterSession: string): Promise<{ sessions: BackupEntry[]; more: boolean }>;
  putBackup(version: number, sessions: BackupEntry[]): Promise<void>;
  pairingStart(deviceId: string): Promise<{ pairing_id: string; expires_at: number }>;
  pairingGet(id: string): Promise<PairingState>;
  pairingJoin(id: string, deviceId: string, ephemeralKey: string): Promise<void>;
  pairingSeal(id: string, deviceId: string, sealed: string): Promise<void>;
  /** The sealed keys, once; Conflict while none are waiting yet. */
  pairingConsume(id: string, deviceId: string): Promise<{ initiator_device: string; sealed: string }>;
  pairingCancel(id: string): Promise<void>;
}

export type IdentityStatus =
  | { state: 'none' }
  | { state: 'unverified'; fingerprint: string }
  | { state: 'verified'; fingerprint: string };

/** A colleague (or this user) whose master key changed since it was pinned. */
export interface IdentityChange {
  user_id: string;
  fingerprint: string;
  previous: string;
}

export interface PairingOffer {
  /** What the QR code and the copyable code carry. */
  text: string;
  expiresAt: number;
  /** The comparison code once the new device has joined. */
  poll(): Promise<{ code: string; device: string } | undefined>;
  /** Sends the keys to the device that showed the code poll returned. */
  approve(): Promise<void>;
  cancel(): Promise<void>;
}

export interface PairingJoin {
  /** The six digits to compare with the verified device's screen. */
  code: string;
  /** Waits for the verified device's approval, then verifies this device; returns restored sessions. */
  finish(signal?: AbortSignal): Promise<number>;
  cancel(): Promise<void>;
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

interface PinRecord {
  fingerprint: string;
  at: number;
}

const IDENTITY = 'identity';
const SIGNED = 'identity:signed';
const pinKey = (userId: string) => `mpin:${userId}`;
const changeKey = (userId: string) => `mchg:${userId}`;
const BACKUP_BATCH = 100;
const PAIRING_POLL_MS = 1500;

// Signature checks are pure, and every send lists every member's keys again: verify each
// distinct (statement, signature) once.
const verified = new Map<string, boolean>();
function memo(key: string, check: () => boolean): boolean {
  const hit = verified.get(key);
  if (hit !== undefined) return hit;
  let ok = false;
  try {
    ok = check();
  } catch {
    ok = false;
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

/** Groups a 64-hex-digit fingerprint for people to compare. */
export function formatFingerprint(fp: string): string {
  return fp.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? fp;
}

export interface IdentityContext {
  userId: string;
  deviceId: string;
  curve25519: string;
  ed25519: string;
  server: IdentityServer;
  store: CryptoStore;
  pickleKey: Uint8Array;
  /** Runs fn under the device's per-user lock (not re-entrant). */
  locked<T>(fn: () => Promise<T>): Promise<T>;
}

export class Identity {
  private readonly listeners = new Set<() => void>();
  private pinsDirty = false;
  private changed = false;

  constructor(private readonly ctx: IdentityContext) {}

  /** Calls fn when a pinned identity changes or a change is accepted. */
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

  /** Whether this device holds the user's master key (it is verified). */
  async isVerified(): Promise<boolean> {
    return (await this.local()) !== undefined;
  }

  // --- Trust: what the engine shares room keys with ---

  /**
   * userId's master key from a key query, if it is validly self-bound in tenantId and matches
   * the pin; undefined otherwise. Pins a first sight (TOFU) and records a mismatch as an
   * identity change, both into writes. Call with the lock held.
   */
  async trustedMaster(userId: string, rec: unknown, tenantId: string, writes: [string, unknown][]): Promise<Hybrid | undefined> {
    const own = await this.local();
    if (own && own.tenant_id !== tenantId) return undefined; // the server named another org
    if (!validMaster(rec)) return undefined;
    const k = rec.master_key;
    const s = rec.self_signature;
    if (!memo(`m|${tenantId}|${userId}|${k}|${s}`, () => pqc.verifyMaster(k, tenantId, userId, s))) return undefined;
    const fp = pqc.fingerprint(k);
    if (userId === this.ctx.userId) {
      // The user's own key is pinned by verification itself, never by first sight.
      return own?.fingerprint === fp ? k : undefined;
    }
    const pin = await this.ctx.store.get<PinRecord>(pinKey(userId));
    if (!pin) {
      writes.push([pinKey(userId), { fingerprint: fp, at: Date.now() } satisfies PinRecord]);
      this.pinsDirty = true;
      return k;
    }
    if (pin.fingerprint === fp) return k;
    const seen = await this.ctx.store.get<IdentityChange>(changeKey(userId));
    if (seen?.fingerprint !== fp) {
      writes.push([changeKey(userId), { user_id: userId, fingerprint: fp, previous: pin.fingerprint } satisfies IdentityChange]);
      this.changed = true;
    }
    return undefined;
  }

  /** Whether device d of userId carries master's valid cross-signature. */
  deviceTrusted(master: Hybrid, tenantId: string, userId: string, d: { device_id: string; curve25519: string; ed25519: string; master_signature?: unknown }): boolean {
    const s = d.master_signature;
    if (!isHybrid(s)) return false;
    return memo(`d|${tenantId}|${userId}|${d.device_id}|${d.curve25519}|${d.ed25519}|${master}|${s}`,
      () => pqc.verifyDevice(master, tenantId, userId, d.device_id, d.curve25519, d.ed25519, s));
  }

  /** After trustedMaster's writes are stored: announce changes, and sync new pins to the
   * user's other devices once the caller's lock is released. */
  afterWrites(): void {
    if (this.changed) {
      this.changed = false;
      this.notify();
    }
    if (!this.pinsDirty) return;
    this.pinsDirty = false;
    setTimeout(() => void this.ctx.locked(() => this.syncPins(false)).catch(() => undefined), 0);
  }

  changes(): Promise<IdentityChange[]> {
    return this.ctx.store.list<IdentityChange>('mchg:').then((rows) => rows.map(([, v]) => v));
  }

  /** The viewer accepts userId's new identity: it is pinned and room keys flow to it again. */
  acceptChange(userId: string): Promise<void> {
    return this.ctx.locked(async () => {
      const c = await this.ctx.store.get<IdentityChange>(changeKey(userId));
      if (!c || userId === this.ctx.userId) return;
      await this.ctx.store.write([[pinKey(userId), { fingerprint: c.fingerprint, at: Date.now() } satisfies PinRecord]], [changeKey(userId)]);
      await this.syncPins(false).catch(() => undefined);
      this.notify();
    });
  }

  // --- This device's state ---

  /**
   * Whether the user has an identity and this device holds it. A verified device makes sure the
   * server lists its cross-signature; a device whose identity was replaced elsewhere drops it.
   */
  status(): Promise<IdentityStatus> {
    return this.ctx.locked(async () => {
      const { tenant_id, master } = await this.ctx.server.getMaster();
      const l = await this.local();
      if (!master) return { state: 'none' } as const;
      if (!validMaster(master) || !pqc.verifyMaster(master.master_key, tenant_id, this.ctx.userId, master.self_signature)) {
        throw new Error('The server sent an encryption identity that does not verify');
      }
      const fp = pqc.fingerprint(master.master_key);
      if (l && l.fingerprint === fp && l.version === master.version && l.tenant_id === tenant_id) {
        await this.signOwnDevice(l);
        return { state: 'verified', fingerprint: fp } as const;
      }
      if (l) {
        // Replaced from another device (a reset): this device must verify again.
        await this.ctx.store.write([], [IDENTITY, SIGNED]);
        this.notify();
      }
      return { state: 'unverified', fingerprint: fp } as const;
    });
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
   * A new identity for the user's first device (or a reset, which colleagues see as an identity
   * change). Nothing is uploaded until commit, which the UI calls only after the user confirms
   * they saved the recovery key.
   */
  prepare(reset: boolean): { recoveryKey: string; commit(): Promise<void> } {
    const master = pqc.masterGenerate();
    const backup = pqc.xwingGenerate();
    const recovery = pqc.recoveryGenerate();
    return {
      recoveryKey: recovery.text,
      commit: async () => {
        const { tenant_id, master: current } = await this.ctx.server.getMaster();
        if (current && !reset) throw new Conflict('This account already has an encryption identity');
        const expected = current?.version ?? 0;
        const version = expected + 1;
        const user = this.ctx.userId;
        const own: OwnMaster = {
          version,
          master_key: master.public_key,
          self_signature: pqc.signMaster(master.seed, tenant_id, user),
          backup_key: { public_key: backup.public, signature: pqc.signBackupKey(master.seed, tenant_id, user, version, backup.public) },
          recovery: {
            wrapped_master_key: pqc.recoveryWrap(recovery.key, 'master-key', tenant_id, user, master.seed),
            wrapped_backup_key: pqc.recoveryWrap(recovery.key, 'backup-key', tenant_id, user, backup.seed),
          },
          pins: { counter: 0, sealed: '' },
        };
        const stored = await this.ctx.server.putMaster({ expected_version: expected, master_key: own.master_key, self_signature: own.self_signature, backup_key: own.backup_key, recovery: own.recovery });
        if (stored !== version) throw new Conflict('The encryption identity changed meanwhile');
        await this.adopt(tenant_id, own, master.seed, backup.seed);
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
    this.checkOwn(tenant_id, master, masterSeed, backupSeed, pqc.fingerprint(master.master_key));
    return this.adopt(tenant_id, master, masterSeed, backupSeed);
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

  /** Takes the identity on: stores it, signs this device, syncs pins and the key backup. */
  private async adopt(tenantId: string, master: OwnMaster, masterSeed: string, backupSeed: string): Promise<number> {
    const local = await this.sealLocal(tenantId, master, masterSeed, backupSeed);
    return this.ctx.locked(async () => {
      // Every room key this device already holds goes to the backup too.
      const queue = (await this.ctx.store.list<InboundRecord>('in:')).filter(([, r]) => !r.from_backup).map(([k]): [string, unknown] => [backupQueueKey(k), k]);
      await this.ctx.store.write([[IDENTITY, local], ...queue], [SIGNED]);
      await this.signOwnDevice(local);
      await this.syncPins(true).catch(() => undefined);
      const restored = await this.restoreBackup(local).catch(() => 0);
      await this.flushBackup().catch(() => undefined);
      this.notify();
      return restored;
    });
  }

  // --- Pins shared with the user's other devices ---

  /**
   * Merges this device's pins with the sealed set on the server and writes the result back.
   * adoptRemote (on verification) lets the synced pins replace local first-sight ones, which this
   * device made before it could check them. Call with the lock held.
   */
  private async syncPins(adoptRemote: boolean): Promise<void> {
    const l = await this.local();
    if (!l) return;
    const seeds = await this.seeds(l);
    for (let attempt = 0; attempt < 3; attempt++) {
      const { master } = await this.ctx.server.getMaster();
      if (!master || master.version !== l.version) return;
      let remote: Record<string, PinRecord> = {};
      if (master.pins.counter > 0) {
        try {
          const p = parseJSON(unb64(pqc.pinsOpen(seeds.master, l.tenant_id, this.ctx.userId, master.pins.counter, master.pins.sealed)));
          if (isObj(p)) remote = p as Record<string, PinRecord>;
        } catch {
          // Not sealed by a device holding the master key: ignore it and write ours over it.
        }
      }
      const local = new Map((await this.ctx.store.list<PinRecord>('mpin:')).map(([k, v]) => [k.slice(5), v]));
      const merged: Record<string, PinRecord> = {};
      const writes: [string, unknown][] = [];
      for (const user of new Set([...local.keys(), ...Object.keys(remote)])) {
        if (user === this.ctx.userId) continue;
        const a = local.get(user);
        const r = remote[user];
        const valid = (p: PinRecord | undefined): p is PinRecord => !!p && /^[0-9a-f]{64}$/.test(p.fingerprint) && typeof p.at === 'number';
        const pick = !valid(r) ? a : !valid(a) || adoptRemote || r.at > a.at ? r : a;
        if (!pick) continue;
        merged[user] = pick;
        if (pick !== a) writes.push([pinKey(user), pick]);
      }
      await this.ctx.store.write(writes);
      if (JSON.stringify(merged) === JSON.stringify(remote)) return;
      const sealed = pqc.pinsSeal(seeds.master, l.tenant_id, this.ctx.userId, master.pins.counter + 1, b64(JSON.stringify(merged)));
      try {
        await this.ctx.server.putPins(l.version, master.pins.counter, sealed);
        return;
      } catch (e) {
        if (!(e instanceof Conflict)) throw e;
      }
    }
  }

  // --- Key backup ---

  /** Seals queued room sessions to the backup key. Call with the lock held. */
  async flushBackup(): Promise<void> {
    const l = await this.local();
    if (!l) return;
    const queue = await this.ctx.store.list<string>('bq:');
    if (queue.length === 0) return;
    const seeds = await this.seeds(l);
    for (let i = 0; i < queue.length; i += BACKUP_BATCH) {
      const entries: BackupEntry[] = [];
      const done: string[] = [];
      for (const [qk, ik] of queue.slice(i, i + BACKUP_BATCH)) {
        done.push(qk);
        const rec = await this.ctx.store.get<InboundRecord>(ik);
        if (!rec || rec.from_backup) continue;
        const s = InboundGroupSession.fromPickle(rec.pickle, this.ctx.pickleKey);
        try {
          const payload = {
            v: 1, room_id: rec.room_id, session_id: s.sessionId, sender_key: rec.sender_key, sender_user: rec.sender_user,
            sender_device: rec.sender_device, first_index: s.firstKnownIndex, session_key: s.exportAtFirstKnownIndex(),
          };
          entries.push({ room_id: rec.room_id, session_id: s.sessionId, first_index: s.firstKnownIndex,
            sealed: pqc.backupSeal(l.backup_key, seeds.master, rec.room_id, s.sessionId, b64(JSON.stringify(payload))) });
        } finally {
          s.free();
        }
      }
      if (entries.length > 0) await this.ctx.server.putBackup(l.version, entries);
      await this.ctx.store.write([], done);
    }
  }

  /** Imports every session in the backup that carries the master key's MAC. Lock held. */
  private async restoreBackup(l: LocalIdentity): Promise<number> {
    const seeds = await this.seeds(l);
    let afterRoom = '';
    let afterSession = '';
    let count = 0;
    for (;;) {
      const page = await this.ctx.server.getBackup(l.version, afterRoom, afterSession);
      const writes: [string, unknown][] = [];
      for (const e of page.sessions) {
        const rec = this.openEntry(seeds, e);
        if (!rec) continue;
        const key = inboundKey(rec.sender_key, e.session_id);
        const known = await this.ctx.store.get<InboundRecord>(key);
        if (known && (known.room_id !== rec.room_id || known.sender_user !== rec.sender_user || known.sender_device !== rec.sender_device || known.first_index <= rec.first_index)) continue;
        writes.push([key, rec]);
        count++;
      }
      await this.ctx.store.write(writes);
      if (!page.more || page.sessions.length === 0) return count;
      const last = page.sessions[page.sessions.length - 1];
      afterRoom = last.room_id;
      afterSession = last.session_id;
    }
  }

  private openEntry(seeds: { master: string; backup: string }, e: BackupEntry): InboundRecord | undefined {
    let s: InboundGroupSession | undefined;
    try {
      const p = parseJSON(unb64(pqc.backupOpen(seeds.backup, seeds.master, e.room_id, e.session_id, e.sealed)));
      if (!isObj(p) || p.v !== 1 || p.room_id !== e.room_id || p.session_id !== e.session_id || !isStr(p.session_key) ||
        !isStr(p.sender_key, 64) || !isStr(p.sender_user, 128) || !isStr(p.sender_device, 64)) return undefined;
      s = InboundGroupSession.import(p.session_key);
      if (s.sessionId !== e.session_id) return undefined;
      return { pickle: s.pickle(this.ctx.pickleKey), room_id: e.room_id, sender_user: p.sender_user, sender_device: p.sender_device,
        sender_key: p.sender_key, first_index: s.firstKnownIndex, from_backup: true };
    } catch {
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
    const { pairing_id: id, expires_at } = await this.ctx.server.pairingStart(this.ctx.deviceId);
    const { secret, text } = pqc.qrNew(id, l.fingerprint);
    let joined: { key: string; device: string } | undefined;
    return {
      text,
      expiresAt: expires_at,
      poll: async () => {
        const st = await this.ctx.server.pairingGet(id);
        if (!st.new_device || !st.ephemeral_key) return undefined;
        joined = { key: st.ephemeral_key, device: st.new_device };
        return { code: pqc.comparisonCode(secret, id, st.ephemeral_key), device: st.new_device };
      },
      approve: async () => {
        // Sealed to the very key whose code the user compared, never one fetched afterwards.
        if (!joined) throw new Error('No device has joined yet.');
        const seeds = await this.seeds(l);
        await this.ctx.server.pairingSeal(id, this.ctx.deviceId, pqc.transferSeal(joined.key, secret, id, this.ctx.deviceId, joined.device, seeds.master, seeds.backup));
      },
      cancel: () => this.ctx.server.pairingCancel(id),
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
      code: pqc.comparisonCode(q.secret, q.pairing_id, eph.public),
      finish: async (signal) => {
        let got: { initiator_device: string; sealed: string };
        for (;;) {
          signal?.throwIfAborted();
          try {
            got = await this.ctx.server.pairingConsume(q.pairing_id, this.ctx.deviceId);
            break;
          } catch (e) {
            if (!(e instanceof Conflict)) throw e;
          }
          await new Promise((r) => setTimeout(r, PAIRING_POLL_MS));
        }
        let keys: { master_seed: string; backup_seed: string };
        try {
          keys = pqc.transferOpen(eph.seed, q.secret, q.pairing_id, got.initiator_device, this.ctx.deviceId, got.sealed);
        } catch {
          throw new Error('The keys from the other device did not open. Start again.');
        }
        this.checkOwn(tenant_id, master, keys.master_seed, keys.backup_seed, q.fingerprint);
        return this.adopt(tenant_id, master, keys.master_seed, keys.backup_seed);
      },
      cancel: () => this.ctx.server.pairingCancel(q.pairing_id),
    };
  }
}
