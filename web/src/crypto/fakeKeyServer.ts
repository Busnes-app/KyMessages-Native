// An in-memory stand-in for the key server (internal/api/e2ee_handlers.go) and room membership,
// for engine tests. It checks the same signatures the real server checks, and lets a test play a
// hostile server by editing what it stores.
import { deviceSigned, oneTimeKeySigned, type ClaimedKey, type DeviceKeys, type KeyServer, type Mail, type SignedKey } from './engine';
import { verifyEd25519 } from './index';

const dk = (user: string, device: string) => `${user}\n${device}`;

export class FakeKeyServer {
  readonly devices = new Map<string, Map<string, DeviceKeys>>();
  readonly oneTimeKeys = new Map<string, SignedKey[]>();
  readonly fallbackKeys = new Map<string, SignedKey>();
  readonly mail = new Map<string, Mail[]>();
  readonly rooms = new Map<string, Set<string>>();
  readonly sent: { from: string; to: string; type: string }[] = [];
  private nextMail = 1;

  join(roomId: string, ...userIds: string[]): void {
    const set = this.rooms.get(roomId) ?? new Set();
    for (const u of userIds) set.add(u);
    this.rooms.set(roomId, set);
  }

  leave(roomId: string, userId: string): void {
    this.rooms.get(roomId)?.delete(userId);
  }

  oneTimeKeyCount(userId: string, deviceId: string): number {
    return this.oneTimeKeys.get(dk(userId, deviceId))?.length ?? 0;
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
        const out: Record<string, DeviceKeys[]> = {};
        for (const u of userIds) out[u] = [...(this.devices.get(u)?.values() ?? [])].map((d) => ({ ...d }));
        return out;
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
    };
  }
}
