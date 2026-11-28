// An in-memory stand-in for the key server (internal/api/e2ee_handlers.go) and room membership,
// for engine tests. It checks the same signatures the real server checks, and lets a test play a
// hostile server by editing what it stores.
import { Conflict, deviceSigned, isBotUser, oneTimeKeySigned, type ClaimedKey, type DeviceKeys, type KeyServer, type Mail, type SignedKey } from './engine';
import type { BackupEntry, BotDeviceList, MasterKeyRecord, OwnMaster } from './identity';
import { verifyEd25519 } from './index';
import { pqc, type BotDevice } from '../pqc/index';

export const TENANT = '00000000-0000-4000-8000-00000000000a';

interface Pairing {
  user: string;
  initiator: string;
  newDevice: string;
  ephemeral: string;
  sealed: string;
  expires: number;
}

const dk = (user: string, device: string) => `${user}\n${device}`;

export class FakeKeyServer {
  readonly devices = new Map<string, Map<string, DeviceKeys>>();
  readonly oneTimeKeys = new Map<string, SignedKey[]>();
  readonly fallbackKeys = new Map<string, SignedKey>();
  readonly mail = new Map<string, Mail[]>();
  readonly rooms = new Map<string, Set<string>>();
  readonly sent: { from: string; to: string; type: string }[] = [];
  readonly masters = new Map<string, OwnMaster>();
  readonly backups = new Map<string, Map<string, BackupEntry>>();
  readonly pairings = new Map<string, Pairing>();
  /** Each user's device list reservation, as the server keeps it: the digest, the list epoch it
   * was taken at, the epoch it grants and when it lapses. */
  readonly reservations = new Map<string, { digest: string; epoch: number; granted: number; until: number }>();
  reservationMs = 30_000;
  /** Each bot's owner (the agents table) and the list the owner signed (E4). */
  readonly botOwners = new Map<string, string>();
  readonly botLists = new Map<string, BotDeviceList>();
  /** The backup's session cap, as the server's E2EEBackupMaxSessions. */
  backupCap = 2000;
  private nextMail = 1;

  /** A backup deletion from another of the user's devices: empties it and bumps its generation. */
  deleteBackup(userId: string): void {
    const m = this.masters.get(userId);
    if (!m) return;
    this.backups.delete(userId);
    m.backup_generation++;
  }

  join(roomId: string, ...userIds: string[]): void {
    const set = this.rooms.get(roomId) ?? new Set();
    for (const u of userIds) set.add(u);
    this.rooms.set(roomId, set);
  }

  leave(roomId: string, userId: string): void {
    this.rooms.get(roomId)?.delete(userId);
  }

  private pairing(userId: string, id: string): Pairing {
    const p = this.pairings.get(id);
    if (!p || p.user !== userId || p.expires <= Date.now()) throw new Error('Unknown pairing');
    return p;
  }

  oneTimeKeyCount(userId: string, deviceId: string): number {
    return this.oneTimeKeys.get(dk(userId, deviceId))?.length ?? 0;
  }

  /** Whether d is on userId's current signed list (a bot's: its owner's, with the same keys). */
  listed(userId: string, d: DeviceKeys): boolean {
    const l = this.botLists.get(userId);
    if (isBotUser(userId)) return !!l && this.masters.get(l.owner_id)?.version === l.version && l.devices.some((v) => v.device_id === d.device_id && v.curve25519 === d.curve25519 && v.ed25519 === d.ed25519);
    return this.masters.get(userId)?.device_list?.device_ids.includes(d.device_id) ?? false;
  }

  /** The API as userId's session sees it. */
  as(userId: string): KeyServer {
    return {
      upload: async (req) => {
        let dev = this.devices.get(userId)?.get(req.device_id);
        if (req.device_keys) {
          const k = req.device_keys;
          if (!verifyEd25519(k.ed25519, deviceSigned(userId, req.device_id, k.curve25519, k.ed25519), k.signature)) {
            throw new Error('Device keys are not validly self-signed');
          }
          if (dev && (dev.curve25519 !== k.curve25519 || dev.ed25519 !== k.ed25519)) throw new Error('409');
          dev = { device_id: req.device_id, ...k };
          const mine = this.devices.get(userId) ?? new Map();
          mine.set(req.device_id, dev);
          this.devices.set(userId, mine);
        }
        if (!dev) throw new Error('Unknown device');
        const ok = (k: SignedKey) => verifyEd25519(dev!.ed25519, oneTimeKeySigned(userId, req.device_id, k.key_id, k.key), k.signature);
        const id = dk(userId, req.device_id);
        const stored = this.oneTimeKeys.get(id) ?? [];
        for (const k of req.one_time_keys) {
          if (!ok(k)) throw new Error('One-time keys must be validly signed');
          if (!stored.some((s) => s.key_id === k.key_id)) stored.push(k);
        }
        this.oneTimeKeys.set(id, stored);
        if (req.fallback_key) {
          if (!ok(req.fallback_key)) throw new Error('The fallback key must be validly signed');
          this.fallbackKeys.set(id, req.fallback_key);
        }
        return { count: stored.length, fallback: this.fallbackKeys.has(id) };
      },
      query: async (userIds) => {
        const devices: Record<string, DeviceKeys[]> = {};
        const master_keys: Record<string, MasterKeyRecord> = {};
        for (const u of userIds) {
          devices[u] = [...(this.devices.get(u)?.values() ?? [])].map((d) => ({ ...d }));
          const m = this.masters.get(u);
          if (m) master_keys[u] = { version: m.version, master_key: m.master_key, self_signature: m.self_signature, ...(m.device_list ? { device_list: structuredClone(m.device_list) } : {}) };
        }
        const bot_devices: Record<string, BotDeviceList> = {};
        for (const u of userIds) {
          const l = this.botLists.get(u);
          const owner = l && this.masters.get(l.owner_id);
          if (!l || owner?.version !== l.version) continue;
          bot_devices[u] = structuredClone(l);
          master_keys[l.owner_id] = { version: owner.version, master_key: owner.master_key, self_signature: owner.self_signature, ...(owner.device_list ? { device_list: structuredClone(owner.device_list) } : {}) };
        }
        return { tenant_id: TENANT, devices, master_keys, bot_devices };
      },
      getMaster: async () => {
        const m = this.masters.get(userId);
        return { tenant_id: TENANT, master: m ? structuredClone(m) : null };
      },
      putMaster: async (req) => {
        const cur = this.masters.get(userId);
        if ((cur?.version ?? 0) !== req.expected_version) throw new Conflict('409');
        const version = req.expected_version + 1;
        if (!pqc.verifyMaster(req.master_key, TENANT, userId, req.self_signature) ||
          !pqc.verifyBackupKey(req.master_key, TENANT, userId, version, req.backup_key.public_key, req.backup_key.signature)) {
          throw new Error('The encryption identity is not validly signed');
        }
        this.masters.set(userId, { version, master_key: req.master_key, self_signature: req.self_signature, backup_key: req.backup_key, backup_generation: 0, recovery: req.recovery, pins: { counter: 0, sealed: '' } });
        this.backups.delete(userId);
        this.reservations.delete(userId);
        for (const d of this.devices.get(userId)?.values() ?? []) delete d.master_signature;
        return version;
      },
      putPins: async (version, expected, sealed, signature) => {
        const m = this.masters.get(userId);
        if (!m || m.version !== version || m.pins.counter !== expected) throw new Conflict('409');
        if (!pqc.verifyPinsWrite(m.master_key, TENANT, userId, version, expected + 1, sealed, signature)) throw new Error('The pin set is not signed by the current master key');
        m.pins = { counter: expected + 1, sealed };
      },
      reserveDeviceList: async (version, expected, digest, signature) => {
        const m = this.masters.get(userId);
        if (m && !pqc.verifyDeviceListReserve(m.master_key, TENANT, userId, version, expected, digest, signature)) throw new Error('The device list reservation is not signed by the current master key');
        if (!m || m.version !== version || (m.device_list?.epoch ?? 0) !== expected) throw new Conflict('409');
        const r = this.reservations.get(userId);
        const now = Date.now();
        if (r && r.epoch === expected && r.digest !== digest && r.until > now) throw new Conflict('409', r.until - now);
        // As the server: the same digest keeps its epoch; another gets one above all granted.
        const granted = r && r.granted > expected ? (r.digest === digest ? r.granted : r.granted + 1) : expected + 1;
        this.reservations.set(userId, { digest, epoch: expected, granted, until: now + this.reservationMs });
        return { epoch: granted, expires_in_ms: Math.max(this.reservationMs - 1000, 0) };
      },
      putDeviceList: async (version, expected, epoch, deviceIds, signature) => {
        const m = this.masters.get(userId);
        if (!pqc.verifyDeviceList(m?.master_key ?? '', TENANT, userId, version, epoch, deviceIds, signature)) throw new Error('The device list is not validly signed');
        const r = this.reservations.get(userId);
        if (!m || m.version !== version || (m.device_list?.epoch ?? 0) !== expected || !r || r.epoch !== expected || r.granted !== epoch ||
          r.until <= Date.now() || r.digest !== pqc.hash('kymessages.device-list', ...deviceIds)) throw new Conflict('409');
        this.reservations.set(userId, { ...r, digest: '', until: 0 });
        m.device_list = { epoch, device_ids: [...deviceIds], signature };
      },
      signDevice: async (deviceId, version, signature) => {
        const m = this.masters.get(userId);
        const d = this.devices.get(userId)?.get(deviceId);
        if (!d) throw new Error('Unknown device');
        if (!m || m.version !== version) throw new Conflict('409');
        if (!pqc.verifyDevice(m.master_key, TENANT, userId, deviceId, d.curve25519, d.ed25519, signature)) throw new Error('The device signature does not verify');
        d.master_signature = signature;
      },
      getBackup: async (version, after) => {
        if (this.masters.get(userId)?.version !== version) throw new Conflict('409');
        const k = (e: { room_id: string; sender_key: string; session_id: string }) => [e.room_id, e.sender_key, e.session_id];
        const cmp = (a: string[], b: string[]) => (a[0] !== b[0] ? (a[0] < b[0] ? -1 : 1) : a[1] !== b[1] ? (a[1] < b[1] ? -1 : 1) : a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0);
        const rows = [...(this.backups.get(userId)?.values() ?? [])]
          .sort((a, b) => cmp(k(a), k(b)))
          .filter((e) => cmp(k(e), k(after)) > 0);
        return { sessions: rows.slice(0, 2).map((e) => ({ ...e })), more: rows.length > 2 };
      },
      putBackup: async (version, generation, sessions, signature) => {
        const m = this.masters.get(userId);
        if (m?.version !== version) throw new Conflict('409');
        if (!pqc.verifyBackupWrite(m.master_key, TENANT, userId, version, generation, sessions, signature)) throw new Error('The backup write is not signed by the current master key');
        if (m.backup_generation !== generation) throw new Conflict('409');
        const box = this.backups.get(userId) ?? new Map<string, BackupEntry>();
        const refused: number[] = [];
        sessions.forEach((e, i) => {
          const k = `${e.room_id}\n${e.sender_key}\n${e.session_id}`;
          const known = box.get(k);
          if (!known && box.size >= this.backupCap) refused.push(i);
          else if (!known || e.first_index < known.first_index) box.set(k, { ...e });
        });
        this.backups.set(userId, box);
        return { refused };
      },
      pairingStart: async (deviceId) => {
        const d = this.devices.get(userId)?.get(deviceId);
        if (!d?.master_signature) throw new Error('Only a verified device can verify another');
        for (const [k, p] of this.pairings) if (p.user === userId) this.pairings.delete(k);
        // As the server makes them: 16 random bytes, unpadded base64url.
        const id = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        this.pairings.set(id, { user: userId, initiator: deviceId, newDevice: '', ephemeral: '', sealed: '', expires: Date.now() + 180_000 });
        return { pairing_id: id, expires_in_ms: 180_000 };
      },
      pairingGet: async (id) => {
        const p = this.pairing(userId, id);
        return { pairing_id: id, initiator_device: p.initiator, new_device: p.newDevice, ephemeral_key: p.ephemeral, sealed: p.sealed !== '' };
      },
      pairingJoin: async (id, deviceId, ephemeralKey) => {
        const p = this.pairing(userId, id);
        if (p.newDevice || deviceId === p.initiator) throw new Conflict('409');
        p.newDevice = deviceId;
        p.ephemeral = ephemeralKey;
      },
      pairingSeal: async (id, deviceId, sealed) => {
        const p = this.pairing(userId, id);
        if (p.initiator !== deviceId || !p.newDevice || p.sealed) throw new Conflict('409');
        p.sealed = sealed;
      },
      pairingConsume: async (id, deviceId) => {
        const p = this.pairing(userId, id);
        if (p.newDevice !== deviceId || !p.sealed) throw new Conflict('409');
        this.pairings.delete(id);
        return { initiator_device: p.initiator, sealed: p.sealed };
      },
      pairingCancel: async (id, unsealedOnly) => {
        const p = this.pairing(userId, id);
        if (unsealedOnly && p.sealed) return;
        this.pairings.delete(id);
      },
      claim: async (devices) => {
        const out: ClaimedKey[] = [];
        for (const d of devices) {
          const id = dk(d.user_id, d.device_id);
          const k = this.oneTimeKeys.get(id)?.shift();
          const fb = this.fallbackKeys.get(id);
          if (k) out.push({ ...d, ...k, fallback: false });
          else if (fb) out.push({ ...d, ...fb, fallback: true });
        }
        return out;
      },
      sendToDevice: async (deviceId, messages) => {
        const sender = this.devices.get(userId)?.get(deviceId);
        if (!sender) throw new Error('Unknown device');
        // As the server: new mail only from a device on its user's current signed list.
        if (!this.listed(userId, sender)) throw new Error('403 This device is not on its signed device list');
        for (const m of messages) {
          const id = dk(m.user_id, m.device_id);
          const box = this.mail.get(id) ?? [];
          box.push({ id: this.nextMail++, sender_user_id: userId, sender_device_id: deviceId, sender_keys: { ...sender }, type: m.type, content: m.content });
          this.mail.set(id, box);
          this.sent.push({ from: userId, to: m.user_id, type: m.type });
        }
      },
      mailbox: async (deviceId) => (this.mail.get(dk(userId, deviceId)) ?? []).slice(0, 100),
      ack: async (deviceId, ids) => {
        const id = dk(userId, deviceId);
        this.mail.set(id, (this.mail.get(id) ?? []).filter((m) => !ids.includes(m.id)));
      },
      roomMembers: async (roomId) => [...(this.rooms.get(roomId) ?? [])],
      putBotDevices: async (botId, b) => {
        // As the server: only the bot's owner, signed by their current master key, epoch CAS.
        if (this.botOwners.get(botId) !== userId) throw new Error('No such bot');
        const m = this.masters.get(userId);
        if (!m || m.version !== b.version) throw new Conflict('409');
        if (!pqc.verifyBotDevices(m.master_key, TENANT, userId, b.version, botId, b.epoch, b.devices, b.signature)) throw new Error('The bot device list is not validly signed');
        const cur = this.botLists.get(botId);
        // As the server: expected 0 also replaces a list another owner identity signed.
        const stale = cur && (cur.owner_id !== userId || cur.version !== b.version);
        if (((stale && b.expected_epoch === 0) ? 0 : cur?.epoch ?? 0) !== b.expected_epoch || b.epoch <= b.expected_epoch) throw new Conflict('409');
        // As the server: a new or changed entry must be an upload; one kept unchanged need not.
        const same = (x: BotDevice, y: BotDevice) => x.device_id === y.device_id && x.curve25519 === y.curve25519 && x.ed25519 === y.ed25519;
        for (const d of b.devices) {
          if (!stale && b.expected_epoch > 0 && cur?.devices.some((p) => same(p, d))) continue;
          const up = this.devices.get(botId)?.get(d.device_id);
          if (!up || !same(up, d)) throw new Error('400 The bot has no such device');
        }
        this.botLists.set(botId, { owner_id: userId, version: b.version, epoch: b.epoch, devices: structuredClone(b.devices), signature: b.signature });
      },
    };
  }
}
