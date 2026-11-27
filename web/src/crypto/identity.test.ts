import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Conflict, CryptoEngine, deviceSigned, NotVerified, type KeyServer, type SealedMessage } from './engine';
import { FakeKeyServer, TENANT } from './fakeKeyServer';
import { Account, loadCryptoSync } from './index';
import { deleteCryptoStores, openCryptoStore } from './store';
import { b64, loadPQCFrom, pqc, PQCUnavailable } from '../pqc/index';
import { LIST_WAIT_MAX_MS, Rollback } from './identity';
import { isTransient, Transient } from './records';

beforeAll(async () => {
  loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm'));
  await loadPQCFrom(readFileSync('src/pqc/pqc.wasm'));
});

const opened: CryptoEngine[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const e of opened.splice(0)) e.close();
  await deleteCryptoStores();
});

/** A device of userId in its own browser store (storeName), not yet verified. */
async function open(server: FakeKeyServer, userId: string, storeName = userId, api: KeyServer = server.as(userId)): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(userId, api, await openCryptoStore(storeName));
  opened.push(e);
  return e;
}

/** A user's first device: it creates the identity and answers the recovery key. */
async function firstDevice(server: FakeKeyServer, userId: string, storeName = userId): Promise<[CryptoEngine, string]> {
  const e = await open(server, userId, storeName);
  const p = await e.prepareIdentity();
  await p.commit();
  return [e, p.recoveryKey];
}

let nextId = 1;
async function send(roomId: string, sender: CryptoEngine, body: string): Promise<SealedMessage> {
  return { id: `msg_${nextId++}`, room_id: roomId, sender_id: sender.userId, body: await sender.encrypt(roomId, { type: 'text', body }) };
}

async function read(reader: CryptoEngine, m: SealedMessage): Promise<string> {
  await reader.receive();
  const r = await reader.decrypt(m);
  if (r.state === 'decrypted') return r.inner.body;
  return r.state === 'waiting' ? 'waiting' : `failed: ${r.reason}`;
}

describe('device trust (master-key cross-signing)', () => {
  it('sends no room key to an unverified device, and none of the history once it is verified', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const bob = await open(server, 'u_bob'); // signed in, no identity yet
    server.join('r1', 'u_alice', 'u_bob');
    const before = await send('r1', alice, 'before bob verified');
    expect(await read(bob, before)).toBe('waiting');
    expect(server.sent.filter((s) => s.to === 'u_bob')).toHaveLength(0);
    // An unverified device trusts no one, so its message would reach no one: the send is refused,
    // visibly, before any session is made, and nothing goes out.
    await expect(bob.encrypt('r1', { type: 'text', body: 'from an unverified device' })).rejects.toBeInstanceOf(NotVerified);
    expect(server.sent.filter((s) => s.from === 'u_bob')).toHaveLength(0);

    await (await bob.prepareIdentity()).commit();
    // Verified now: the same send goes through, and alice reads it.
    expect(await read(alice, await send('r1', bob, 'from bob, verified'))).toBe('from bob, verified');
    const after = await send('r1', alice, 'after');
    expect(await read(bob, after)).toBe('after');
    // The key bob gets starts at the current index: what was sent before stays unreadable.
    expect(await read(bob, before)).toMatch(/^failed: This message was sent before/);
  });

  it('never shares with a device the server added, signed or not by the pinned master key', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    // A hostile server lists a device of its own for bob: self-signed, with no or a forged
    // cross-signature (made by a master key the server controls).
    const evil = await open(server, 'u_bob', 'evil'); // registers as bob through bob's session
    const forger = pqc.masterGenerate();
    const devs = server.devices.get('u_bob')!;
    const d = devs.get(evil.deviceId)!;
    for (const sig of [undefined, pqc.signDevice(forger.seed, TENANT, 'u_bob', d.device_id, d.curve25519, d.ed25519)]) {
      if (sig) d.master_signature = sig;
      else delete d.master_signature;
      const m = await send('r1', alice, 'not for the server');
      expect(await read(evil, m)).toBe('waiting');
    }
  });

  it('blocks keys to a colleague whose identity changed until the viewer accepts it', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(bob, await send('r1', alice, 'pinned'))).toBe('pinned');
    const changed = vi.fn();
    alice.onIdentityChange(changed);

    // Bob resets his identity (or the server swaps it): a new master key, his device re-signed.
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    const blocked = await send('r1', alice, 'held back');
    expect(await read(bob, blocked)).toBe('waiting');
    const changes = await alice.identityChanges();
    expect(changes.map((c) => c.user_id)).toEqual(['u_bob']);
    expect(changes[0].fingerprint).not.toBe(changes[0].previous);
    expect(changed).toHaveBeenCalled();

    // A user's own identity is never a change to accept.
    expect(await bob.identityChanges()).toEqual([]);
    // Accepting is compare-and-set on exactly the change the viewer saw.
    await expect(alice.acceptIdentity('u_bob', changes[0].previous, 'ab'.repeat(32))).rejects.toThrow(/changed again/);
    await alice.acceptIdentity('u_bob', changes[0].previous, changes[0].fingerprint);
    expect(await alice.identityChanges()).toEqual([]);
    expect(await read(bob, await send('r1', alice, 'flows again'))).toBe('flows again');
  });

  it('refuses a substituted master key even on a device that never saw it, through synced pins', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBeGreaterThan(0));

    // The server swaps bob's identity for one it made, then alice signs in on a new browser.
    const forger = pqc.masterGenerate();
    const bobMaster = server.masters.get('u_bob')!;
    bobMaster.master_key = forger.public_key;
    bobMaster.self_signature = pqc.signMaster(forger.seed, TENANT, 'u_bob');
    for (const d of server.devices.get('u_bob')!.values()) d.master_signature = pqc.signDevice(forger.seed, TENANT, 'u_bob', d.device_id, d.curve25519, d.ed25519);
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    await send('r1', laptop, 'not to the impostor');
    expect((await laptop.identityChanges()).map((c) => c.user_id)).toEqual(['u_bob']);
    expect(server.sent.filter((s) => s.to === 'u_bob' && s.from === 'u_alice')).toHaveLength(1); // only the first, pre-swap share
  });
});

describe('device reset', () => {
  it('keeps the identity across a device reset and signs the replacement device', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const store = await openCryptoStore('u_bob');
    await CryptoEngine.resetDevice('u_bob', bob.deviceId, store);
    store.close();
    const again = await open(server, 'u_bob');
    expect(again.deviceId).not.toBe(bob.deviceId);
    await vi.waitFor(() => expect(server.devices.get('u_bob')!.get(again.deviceId)!.master_signature).toBeTruthy());
    expect(await again.identityStatus()).toMatchObject({ state: 'verified' });
    expect(await read(again, await send('r1', alice, 'to the replacement'))).toBe('to the replacement');
  });
});

describe('recovery key and key backup', () => {
  it('restores the identity and the room history on a new device, without the recovery key reaching the server', async () => {
    const server = new FakeKeyServer();
    const bodies: string[] = [];
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const fromBob = await send('r1', bob, 'history from bob');
    expect(await read(alice, fromBob)).toBe('history from bob');
    const own = await send('r1', alice, 'my own history');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(2));

    // Record everything the new device sends.
    const api = server.as('u_alice');
    for (const [k, fn] of Object.entries(api)) {
      (api as unknown as Record<string, unknown>)[k] = (...args: unknown[]) => {
        bodies.push(JSON.stringify(args));
        return (fn as (...a: unknown[]) => unknown)(...args);
      };
    }
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'unverified' });
    await expect(laptop.restoreIdentity(rk.replace(/^./, rk[0] === 'A' ? 'B' : 'A'))).rejects.toThrow(/not a valid recovery key/);
    await expect(laptop.restoreIdentity(pqc.recoveryGenerate().text)).rejects.toThrow(/does not unlock/);
    expect(await laptop.restoreIdentity(rk)).toBe(2);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
    expect(await read(laptop, fromBob)).toBe('history from bob');
    expect(await read(laptop, own)).toBe('my own history');

    const key = pqc.recoveryParse(rk);
    const all = bodies.join('\n');
    expect(all).not.toContain(key);
    expect(all).not.toContain(rk);
    expect(all).not.toContain('session_key');
    // Bob now shares with the restored device, which carries the master key's signature.
    expect(await read(laptop, await send('r1', bob, 'to the laptop too'))).toBe('to the laptop too');
  });

  it('refuses a backup entry the server forged with the backup public key', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const m = server.masters.get('u_alice')!;
    const forger = pqc.masterGenerate();
    const ref = { room_id: 'r1', sender_key: 'k', session_id: 'x', first_index: 0 };
    const payload = { v: 1, ...ref, sender_user: 'u_bob', sender_device: 'D', session_key: 'AAAA' };
    server.backups.set('u_alice', new Map([['r1\nk\nx', { ...ref, sealed: pqc.backupSeal(m.backup_key.public_key, forger.seed, ref, b64(JSON.stringify(payload))) }]]));
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    expect(await laptop.restoreIdentity(rk)).toBe(0);
  });

  it('refuses recovery wraps that open to a key other than the published one', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    // The server republishes another master key next to the user's real wraps.
    const forger = pqc.masterGenerate();
    const m = server.masters.get('u_alice')!;
    m.master_key = forger.public_key;
    m.self_signature = pqc.signMaster(forger.seed, TENANT, 'u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow(/do not match/);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'unverified' });
  });
});

describe('QR verification', () => {
  it('verifies a new device in two layers, one time, with matching codes on both screens', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const history = await send('r1', bob, 'before the new device');
    expect(await read(alice, history)).toBe('before the new device');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));

    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await expect(laptop.offerVerification()).rejects.toThrow(/verified device/);
    const offer = await alice.offerVerification();
    expect(offer.text).toMatch(/^[A-Za-z0-9_-]{108}$/);
    expect(await offer.poll()).toBeUndefined();
    const join = await laptop.joinVerification(offer.text);
    const shown = await offer.poll();
    expect(shown).toEqual({ code: join.code, device: laptop.deviceId });
    const done = join.finish();
    await offer.approve();
    expect(await done).toBe(1);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
    expect(await read(laptop, history)).toBe('before the new device');
    expect(await read(laptop, await send('r1', bob, 'after'))).toBe('after');
    expect(server.pairings.size).toBe(0);
    await expect(laptop.joinVerification(offer.text)).rejects.toThrow();
  });

  it('shows a different code when the server substitutes the ephemeral key', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    const p = [...server.pairings.values()][0];
    p.ephemeral = pqc.xwingGenerate().public;
    expect((await offer.poll())!.code).not.toBe(join.code);
  });

  it('refuses a code whose fingerprint is not the account’s master key', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const offer = await alice.offerVerification();
    const q = pqc.qrParse(offer.text);
    const forged = pqc.qrNew(q.pairing_id, pqc.masterGenerate().fingerprint).text;
    await expect(laptop.joinVerification(forged)).rejects.toThrow(/another identity/);
    await expect(laptop.joinVerification('garbage')).rejects.toThrow(/not a verification code/);
  });
});

describe('Round 1 hardening', () => {
  it('keeps a pending change blocking even when the server goes back to the pinned key', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    const original = structuredClone(server.masters.get('u_bob')!);
    const origSigs = new Map([...server.devices.get('u_bob')!].map(([k, d]) => [k, d.master_signature]));
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    await send('r1', alice, 'sees the change');
    expect((await alice.identityChanges()).map((c) => c.user_id)).toEqual(['u_bob']);
    // The relay replays bob's old key and signatures: still blocked until alice accepts.
    server.masters.set('u_bob', original);
    for (const [k, d] of server.devices.get('u_bob')!) d.master_signature = origSigs.get(k);
    const before = server.sent.length;
    await send('r1', alice, 'still held');
    expect(server.sent.slice(before).filter((x) => x.to === 'u_bob')).toHaveLength(0);
    expect((await alice.identityChanges()).map((c) => c.user_id)).toEqual(['u_bob']);
  });

  it('never silently replaces a pin when two of the user’s devices disagree', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBeGreaterThan(0));
    // A second browser of alice's already pinned a different key for bob (say, one the server
    // showed it before it was verified). Verifying it must not overwrite either pin.
    const store = await openCryptoStore('alice_laptop');
    const other = 'cd'.repeat(32);
    await store.write([['mpin:u_bob', { fingerprint: other, n: 1, accepted: false }]]);
    store.close();
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    const changes = await laptop.identityChanges();
    expect(changes).toEqual([expect.objectContaining({ user_id: 'u_bob', previous: other })]);
    const kept = await openCryptoStore('alice_laptop');
    expect((await kept.get<{ fingerprint: string }>('mpin:u_bob'))!.fingerprint).toBe(other);
    kept.close();
    // Accepting it on the laptop is adopted by alice's first device as a change from its own pin.
    await laptop.acceptIdentity('u_bob', changes[0].previous, changes[0].fingerprint);
    expect(await read(laptop, await send('r1', laptop, 'agreed'))).toBe('agreed');
  });

  it('refuses a pin set the server rolled back to an older counter', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    await firstDevice(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBe(1));
    const old = structuredClone(server.masters.get('u_alice')!.pins);
    server.join('r2', 'u_alice', 'u_carol');
    await send('r2', alice, 'pins carol');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBe(2));
    server.masters.get('u_alice')!.pins = old;
    await firstDevice(server, 'u_dave');
    server.join('r3', 'u_alice', 'u_dave');
    await expect(alice.encrypt('r3', { type: 'text', body: 'to dave' })).rejects.toThrow(/older pin set/);
  });

  it('never shares with a removed device the server lists again, even with its old device list', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(laptop, await send('r1', alice, 'to both'))).toBe('to both');
    const oldList = structuredClone(server.masters.get('u_bob')!.device_list!);
    const oldRow = structuredClone(server.devices.get('u_bob')!.get(laptop.deviceId)!);
    // The laptop signs out: off the signed list, then deleted from the server.
    await laptop.delistDevices([laptop.deviceId]);
    server.devices.get('u_bob')!.delete(laptop.deviceId);
    await send('r1', alice, 'sees the new list');
    // The server brings the row back with its old cross-signature, first with the current
    // list, then with the list from before the removal.
    server.devices.get('u_bob')!.set(laptop.deviceId, oldRow);
    expect(await read(laptop, await send('r1', alice, 'not for the laptop'))).toBe('waiting');
    server.masters.get('u_bob')!.device_list = oldList;
    expect(await read(laptop, await send('r1', alice, 'still not'))).toBe('waiting');
    expect(await read(bob, await send('r1', alice, 'but bob reads'))).toBe('waiting'); // a rolled-back list trusts no device
  });

  it('sets local seeds aside, never deleting them, when the server bumps or drops the identity', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const m = server.masters.get('u_alice')!;
    m.version += 1;
    expect(await alice.identityStatus()).toMatchObject({ state: 'unverified', quarantined: true });
    const store = await openCryptoStore('u_alice');
    expect((await store.list('identity:previous:')).length).toBe(1);
    store.close();
    // The server lists the identity again: the device takes its seeds back.
    m.version -= 1;
    expect(await alice.identityStatus()).toMatchObject({ state: 'verified' });
    server.masters.delete('u_alice');
    expect(await alice.identityStatus()).toMatchObject({ state: 'none', quarantined: true });
  });

  it('stops a restore whose backup pages do not move forward, and keeps the device verified', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r1', bob, 'backed up'))).toBe('backed up');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    const api = server.as('u_alice');
    const real = api.getBackup;
    api.getBackup = async (version) => ({ ...(await real(version, { room_id: '', sender_key: '', session_id: '' })), more: true });
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow(/page forward/);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', restoring: true });
  });

  it('keeps room keys from a device its master key does not vouch for out of the backup', async () => {
    const server = new FakeKeyServer();
    // The server strips bob's cross-signature from what alice is shown: she no longer trusts his
    // device, though bob's device (which sees itself signed and listed) still shares with her.
    const api = server.as('u_alice');
    const query = api.query;
    api.query = async (ids, signal) => {
      const r = await query(ids, signal);
      if (r.devices.u_bob) r.devices.u_bob = r.devices.u_bob.map(({ master_signature: _, ...d }) => d);
      return r;
    };
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m = await send('r1', bob, 'unvouched');
    await alice.receive();
    const r = await alice.decrypt(m);
    expect(r).toMatchObject({ state: 'decrypted', authenticated: false });
    await new Promise((res) => setTimeout(res, 50));
    expect(server.backups.get('u_alice')?.size ?? 0).toBe(0);
  });
});

/** The master seed behind userId's identity on the fake server, as only its devices know it. */
function masterSeed(server: FakeKeyServer, userId: string, rk: string): string {
  const m = server.masters.get(userId)!;
  return pqc.recoveryUnwrap(pqc.recoveryParse(rk), 'master-key', TENANT, userId, m.recovery.wrapped_master_key);
}

describe('Round 2: device-list authority', () => {
  it('never signs over a predecessor it cannot verify, an older one, or a fork', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const m = server.masters.get('u_bob')!;
    const good = structuredClone(m.device_list!);
    // Forged by another key, naming a device of the server's.
    const forger = pqc.masterGenerate();
    const evil = [...good.device_ids, 'EVIL_DEVICE_001'].sort();
    m.device_list = { epoch: good.epoch + 1, device_ids: evil, signature: pqc.signDeviceList(forger.seed, TENANT, 'u_bob', m.version, good.epoch + 1, evil) };
    await expect(bob.delistDevices(['NOT_LISTED_0001'])).rejects.toThrow(/not signed by this identity/);
    // (A list out of order cannot be signed at all: DeviceListMessage refuses to encode it.)
    const seed = masterSeed(server, 'u_bob', rk);
    // Advance to epoch 2 for real, then serve epoch 1 again: a rollback.
    m.device_list = good;
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    await bob.identityStatus();
    const newest = structuredClone(m.device_list!);
    m.device_list = good;
    await expect(bob.delistDevices(['NOT_LISTED_0001'])).rejects.toThrow(/older device list/);
    // A second list at the newest epoch, validly signed (a concurrent or compromised signer).
    const fork = [...newest.device_ids, 'FORKED_DEVICE_1'].sort();
    m.device_list = { epoch: newest.epoch, device_ids: fork, signature: pqc.signDeviceList(seed, TENANT, 'u_bob', m.version, newest.epoch, fork) };
    await expect(bob.delistDevices(['NOT_LISTED_0001'])).rejects.toThrow(/two device lists/);
  });

  it('trusts no device from a fork at the newest epoch', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob, rk] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(bob, await send('r1', alice, 'seen the list'))).toBe('seen the list');
    const m = server.masters.get('u_bob')!;
    const fork = [...m.device_list!.device_ids, 'FORKED_DEVICE_1'].sort();
    m.device_list = { epoch: m.device_list!.epoch, device_ids: fork, signature: pqc.signDeviceList(masterSeed(server, 'u_bob', rk), TENANT, 'u_bob', m.version, m.device_list!.epoch, fork) };
    expect(await read(bob, await send('r1', alice, 'forked'))).toBe('waiting');
  });

  it('merges concurrent edits through compare-and-swap, and says when it keeps losing', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const devices: CryptoEngine[] = [];
    for (const name of ['bob_laptop', 'bob_tablet', 'bob_phone']) {
      const d = await open(server, 'u_bob', name);
      await d.restoreIdentity(rk);
      devices.push(d);
    }
    const [laptop, tablet, phone] = devices;
    await Promise.all([bob.delistDevices([tablet.deviceId]), laptop.delistDevices([phone.deviceId])]);
    expect(server.masters.get('u_bob')!.device_list!.device_ids).toEqual([bob.deviceId, laptop.deviceId].sort());
    const api = server.as('u_bob');
    vi.spyOn(api, 'putDeviceList');
    const stubborn = await open(server, 'u_bob', 'bob_stubborn', { ...api, putDeviceList: async () => { throw new Conflict('409'); } });
    await expect(stubborn.restoreIdentity(rk)).rejects.toThrow(/kept changing/);
    // Multiple real PQ signatures plus the bounded conflict retries can exceed 5 s on CI.
  }, 15_000);

  it('does not put a retiring device back on the list', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    await laptop.delistDevices([laptop.deviceId]);
    await laptop.identityStatus();
    expect(server.masters.get('u_bob')!.device_list!.device_ids).not.toContain(laptop.deviceId);
  });
});

describe('Round 2: pin sync ordering', () => {
  it('scopes the pin mark to the identity, so a reset elsewhere then reverifying still sends', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBeGreaterThan(0));
    // Another device of alice's resets her identity: counters start again at 0.
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const p = await laptop.prepareIdentity(true);
    await p.commit();
    expect(await alice.identityStatus()).toMatchObject({ state: 'unverified' });
    await alice.restoreIdentity(p.recoveryKey);
    await send('r1', alice, 'after the reset');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBeGreaterThan(0));
    // A rollback of the new identity's set is still refused.
    const now = server.masters.get('u_alice')!;
    now.pins = { counter: 0, sealed: '' };
    await expect(alice.encrypt('r1', { type: 'text', body: 'x' })).rejects.toThrow(/older pin set/);
  });

  it('keeps the synced pin through a multi-hop change, and converges once the user accepts', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBeGreaterThan(0));
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    // Bob resets twice; alice's laptop accepts each change while her first device is away.
    for (let i = 0; i < 2; i++) {
      await (await bob.prepareIdentity(true)).commit();
      await bob.identityStatus();
      await send('r1', laptop, `sees change ${i}`);
      const [c] = await laptop.identityChanges();
      await laptop.acceptIdentity('u_bob', c.previous, c.fingerprint);
    }
    // Alice's first device sees an accepted change two hops from its pin: it warns, and leaves
    // the synced pin as the laptop wrote it.
    const synced = structuredClone(server.masters.get('u_alice')!.pins);
    expect(await read(bob, await send('r1', alice, 'held'))).toBe('waiting');
    const [c] = await alice.identityChanges();
    expect(server.masters.get('u_alice')!.pins).toEqual(synced);
    await alice.acceptIdentity('u_bob', c.previous, c.fingerprint);
    expect(await read(bob, await send('r1', alice, 'converged'))).toBe('converged');
    expect(await laptop.identityChanges()).toEqual([]);
  });
});

describe('Round 2: availability is not a verdict', () => {
  it('keeps the backup queue and the restore cursor when the module is not running', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const seal = vi.spyOn(pqc, 'backupSeal').mockImplementation(() => { throw new PQCUnavailable(); });
    expect(await read(alice, await send('r1', bob, 'queued'))).toBe('queued');
    await new Promise((r) => setTimeout(r, 50));
    expect(server.backups.get('u_alice')?.size ?? 0).toBe(0);
    seal.mockRestore();
    await alice.identityStatus(); // drains the queue it kept
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));

    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const restored = vi.fn();
    laptop.onKeys(restored);
    const openSpy = vi.spyOn(pqc, 'backupOpen').mockImplementation(() => { throw new PQCUnavailable(); });
    // Verified, with the restore left pending for the retry (not a failed verification).
    expect(await laptop.restoreIdentity(rk)).toBe(0);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', restoring: true });
    openSpy.mockRestore();
    // The entry the module could not open is read now, not skipped: the cursor never moved.
    await vi.waitFor(() => expect(restored).toHaveBeenCalled());
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', restoring: false });
  });

  it('reads older history through the backup without letting it stand in for a vouched copy', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const early = await send('r1', bob, 'early');
    expect(await read(alice, early)).toBe('early');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    // Bob's session reaches the laptop over Olm from its current index on.
    const later = await send('r1', bob, 'later');
    await laptop.receive();
    expect(await laptop.decrypt(early)).toMatchObject({ state: 'decrypted', authenticated: false });
    expect(await laptop.decrypt(later)).toMatchObject({ state: 'decrypted', authenticated: true });
  });
});

describe('Round 2: QR waits', () => {
  it('rides out a few failed polls on the new device, and stops at once when the pairing is gone', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const consume = api.pairingConsume;
    let fail = 2;
    api.pairingConsume = async (id, d) => {
      if (fail-- > 0) throw new TypeError('network');
      return consume(id, d);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    await offer.poll();
    await offer.approve();
    expect(await join.finish()).toBeGreaterThanOrEqual(0);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });

    const tablet = await open(server, 'u_alice', 'alice_tablet', { ...server.as('u_alice'), pairingConsume: async () => { throw Object.assign(new Error('gone'), { status: 404 }); } });
    const offer2 = await alice.offerVerification();
    const join2 = await tablet.joinVerification(offer2.text);
    await expect(join2.finish()).rejects.toThrow(/cancelled or expired/);
  });
});

/** A validly self-bound identity for userId that the server made, with one device of its own
 * that it cross-signed and listed: what an equivocating server shows one of a user's browsers. */
function forgedIdentity(server: FakeKeyServer, userId: string, device: CryptoEngine) {
  const forger = pqc.masterGenerate();
  const d = server.devices.get(userId)!.get(device.deviceId)!;
  const ids = [device.deviceId];
  return {
    fingerprint: forger.fingerprint,
    master: {
      version: 1, master_key: forger.public_key, self_signature: pqc.signMaster(forger.seed, TENANT, userId),
      device_list: { epoch: 1, device_ids: ids, signature: pqc.signDeviceList(forger.seed, TENANT, userId, 1, 1, ids) },
    },
    device: { ...d, master_signature: pqc.signDevice(forger.seed, TENANT, userId, d.device_id, d.curve25519, d.ed25519) },
  };
}

describe('Round 3: first sight is committed before any key leaves', () => {
  it('batches every first sight into one synced write before sharing', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const puts = vi.spyOn(api, 'putPins');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    for (const u of ['u_bob', 'u_carol', 'u_dave']) await firstDevice(server, u);
    server.join('r1', 'u_alice', 'u_bob', 'u_carol', 'u_dave');
    puts.mockClear();
    await send('r1', alice, 'first sight of three');
    expect(puts).toHaveBeenCalledTimes(1);
    expect(server.sent.filter((s) => s.from === 'u_alice' && s.to !== 'u_alice').map((s) => s.to).sort()).toEqual(['u_bob', 'u_carol', 'u_dave']);
  });

  it('lets the first of two browsers win a first sight; the other gets a change and shares nothing', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    const evil = await open(server, 'u_bob', 'evil'); // a device the server registers as bob
    const forged = forgedIdentity(server, 'u_bob', evil);
    // The server shows alice's laptop the forged bob, and while the laptop commits its first
    // sight, alice's other browser commits the real one first.
    const api = server.as('u_alice');
    const query = api.query;
    api.query = async (ids) => {
      const r = await query(ids);
      if (ids.includes('u_bob')) {
        r.master_keys = { ...r.master_keys, u_bob: forged.master };
        r.devices = { ...r.devices, u_bob: [forged.device] };
      }
      return r;
    };
    const putPins = api.putPins;
    let raced = false;
    api.putPins = async (version, expected, sealed, signature) => {
      if (!raced) {
        raced = true;
        const seed = masterSeed(server, 'u_alice', rk);
        const real = { u_bob: { fingerprint: pqc.fingerprint(server.masters.get('u_bob')!.master_key), n: 1, accepted: false } };
        const s = pqc.pinsSeal(seed, TENANT, 'u_alice', expected + 1, b64(JSON.stringify(real)));
        await putPins(version, expected, s, pqc.signPinsWrite(seed, TENANT, 'u_alice', version, expected + 1, s));
      }
      return putPins(version, expected, sealed, signature);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    await laptop.restoreIdentity(rk);
    server.join('r1', 'u_alice', 'u_bob');
    server.sent.length = 0;
    await send('r1', laptop, 'not for the forged device');
    expect(server.sent.filter((s) => s.to === 'u_bob')).toEqual([]);
    expect(await laptop.identityChanges()).toEqual([expect.objectContaining({ user_id: 'u_bob', fingerprint: forged.fingerprint })]);
    // The winner's pin is the one alice's first browser trusts.
    expect(await read(bob, await send('r1', alice, 'to the real bob'))).toBe('to the real bob');
  });

  it('shares nothing with a first sight whose commit failed, and commits it on the next try', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const put = vi.spyOn(api, 'putPins').mockRejectedValueOnce(new TypeError('network'));
    await expect(alice.encrypt('r1', { type: 'text', body: 'x' })).rejects.toThrow();
    expect(server.sent.filter((s) => s.to === 'u_bob')).toEqual([]);
    const local = await openCryptoStore('u_alice');
    expect(await local.get('mpin:u_bob')).toBeUndefined();
    local.close();
    await send('r1', alice, 'after');
    expect(put).toHaveBeenCalledTimes(2);
    expect(server.sent.filter((s) => s.to === 'u_bob')).toHaveLength(1);
  });
});

describe('Round 3: device list reservations', () => {
  it('signs only reserved proposals, so the losing one of two concurrent edits is never signed', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const devices: CryptoEngine[] = [];
    for (const name of ['bob_laptop', 'bob_tablet', 'bob_phone']) {
      const d = await open(server, 'u_bob', name);
      await d.restoreIdentity(rk);
      devices.push(d);
    }
    const [laptop, tablet, phone] = devices;
    const epoch = server.masters.get('u_bob')!.device_list!.epoch;
    const signs = vi.spyOn(pqc, 'signDeviceList');
    await Promise.all([bob.delistDevices([tablet.deviceId]), laptop.delistDevices([phone.deviceId])]);
    const list = server.masters.get('u_bob')!.device_list!;
    expect(list.device_ids).toEqual([bob.deviceId, laptop.deviceId].sort());
    // Two edits published, two signatures: the one that lost its reservation never signed.
    expect(list.epoch).toBe(epoch + 2);
    expect(signs).toHaveBeenCalledTimes(2);
  });

  it('retries honestly after its reservation lapsed, and waits out one another device abandoned', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    const m = server.masters.get('u_bob')!;
    const epoch = m.device_list!.epoch;
    // A device took the server's full 30 s lease and went away; it lapses in a little over a
    // second. The edit waits it out (the wait bound is past the lease) instead of failing.
    expect(LIST_WAIT_MAX_MS).toBeGreaterThan(server.reservationMs);
    await server.as('u_bob').reserveDeviceList(m.version, epoch, 'ab'.repeat(32), pqc.signDeviceListReserve(masterSeed(server, 'u_bob', rk), TENANT, 'u_bob', m.version, epoch, 'ab'.repeat(32)));
    server.reservations.get('u_bob')!.until = Date.now() + 1_200;
    await bob.delistDevices([laptop.deviceId]);
    const list = server.masters.get('u_bob')!.device_list!;
    expect(list.device_ids).toEqual([bob.deviceId]);
    // A different list replacing the lapsed reservation gets an epoch of its own.
    expect(list.epoch).toBe(epoch + 2);
    // This device's reservation is known to have lapsed before it signs: it does not sign then.
    // Its next one lapses after it signed: the server refuses, and it reserves again.
    const api = server.as('u_bob');
    const reserve = api.reserveDeviceList;
    let call = 0;
    const signs = vi.spyOn(pqc, 'signDeviceList');
    const tablet = await open(server, 'u_bob', 'bob_tablet', { ...api, reserveDeviceList: async (v, e, d, s) => {
      const r = await reserve(v, e, d, s);
      call++;
      if (call === 1) return { ...r, expires_in_ms: 0 };
      if (call === 2) server.reservations.get('u_bob')!.until = 0;
      return r;
    } });
    await tablet.restoreIdentity(rk);
    expect(server.masters.get('u_bob')!.device_list!.device_ids).toContain(tablet.deviceId);
    expect(call).toBe(3);
    expect(signs).toHaveBeenCalledTimes(2);
  });

  it('reports a rolled-back list without signing over it, and a reset clears it', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const m = server.masters.get('u_bob')!;
    const old = structuredClone(m.device_list!);
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    await bob.identityStatus(); // sees the newer list
    m.device_list = old;
    const signs = vi.spyOn(pqc, 'signDeviceList');
    expect(await bob.identityStatus()).toMatchObject({ state: 'verified', problem: 'rollback' });
    expect(signs).not.toHaveBeenCalled();
    const reset = await bob.prepareIdentity(true);
    await reset.commit();
    const after = await bob.identityStatus();
    expect(after).toMatchObject({ state: 'verified' });
    expect(after).not.toHaveProperty('problem');
  });

  it('never re-lists a device whose sign-out started while its own enrollment was in flight', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_bob');
    const api = server.as('u_bob');
    const put = api.putDeviceList;
    let laptop: CryptoEngine | undefined;
    let signingOut: Promise<void> | undefined;
    const fenced = await open(server, 'u_bob', 'bob_laptop', { ...api, putDeviceList: async (v, e, epoch, ids, s) => {
      // The enrollment's write is on its way when sign-out starts (not under the lock).
      if (!signingOut && laptop && ids.includes(laptop.deviceId)) signingOut = laptop.delistDevices([laptop.deviceId]);
      return put(v, e, epoch, ids, s);
    } });
    laptop = fenced;
    await laptop.restoreIdentity(rk);
    await signingOut;
    await laptop.identityStatus(); // a status after the sign-out started lists nothing either
    expect(server.masters.get('u_bob')!.device_list!.device_ids).not.toContain(laptop.deviceId);
  });
});

describe('Round 3: pins and prompts', () => {
  it('moves a pending change to the newest key without trusting it, and accepts only against the current pin', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(bob, await send('r1', alice, 'pinned'))).toBe('pinned');
    const pinned = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    const original = structuredClone(server.masters.get('u_bob')!);
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    await send('r1', alice, 'sees the first change');
    const firstReset = structuredClone(server.masters.get('u_bob')!);
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    expect(await read(bob, await send('r1', alice, 'still held'))).toBe('waiting');
    const newest = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    expect(await alice.identityChanges()).toEqual([{ user_id: 'u_bob', previous: pinned, fingerprint: newest }]);
    // The server going back to the pinned key keeps the warning.
    const current = structuredClone(server.masters.get('u_bob')!);
    server.masters.set('u_bob', original);
    await send('r1', alice, 'old key again');
    expect(await alice.identityChanges()).toEqual([{ user_id: 'u_bob', previous: pinned, fingerprint: newest }]);
    server.masters.set('u_bob', current);

    // Alice's laptop is shown the first new key and accepts that change: this device's prompt
    // now changes from that pin, and the stale one is refused.
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    server.masters.set('u_bob', firstReset);
    await send('r1', laptop, 'laptop sees the first new key');
    const [lc] = await laptop.identityChanges();
    expect(lc.fingerprint).toBe(pqc.fingerprint(firstReset.master_key));
    await laptop.acceptIdentity('u_bob', lc.previous, lc.fingerprint);
    server.masters.set('u_bob', current);
    await send('r1', alice, 'syncs the accepted change');
    const [c] = await alice.identityChanges();
    expect(c.previous).toBe(lc.fingerprint);
    await expect(alice.acceptIdentity('u_bob', pinned, newest)).rejects.toThrow(/changed again/);
  });
});

describe('Round 3: key backup caps and generations', () => {
  it('keeps refused sessions queued and shows the backup full until they fit', async () => {
    const server = new FakeKeyServer();
    server.backupCap = 1;
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    server.join('r2', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r1', bob, 'one'))).toBe('one');
    expect(await read(alice, await send('r2', bob, 'two'))).toBe('two');
    await vi.waitFor(async () => expect(await alice.identityStatus()).toMatchObject({ backupFull: true }));
    expect(server.backups.get('u_alice')?.size).toBe(1);
    server.backupCap = 10;
    await alice.identityStatus(); // retries what was refused
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(2));
    expect(await alice.identityStatus()).toMatchObject({ backupFull: false });
  });

  it('signs backup writes for the current generation, so one from before a deletion cannot land', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const writes = vi.spyOn(api, 'putBackup');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r1', bob, 'one'))).toBe('one');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    const [version, gen, entries, sig] = writes.mock.calls[0];
    server.deleteBackup('u_alice'); // from another device
    await expect(server.as('u_alice').putBackup(version, gen, entries, sig)).rejects.toThrow(Conflict);
    expect(server.backups.get('u_alice')?.size ?? 0).toBe(0);
    // This device learns the new generation from the refusal and keeps backing up.
    server.join('r2', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r2', bob, 'two'))).toBe('two');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    expect(writes.mock.calls.at(-1)![1]).toBe(1);
  });
});

describe('Round 3: QR codes name the joining device', () => {
  it('shows a different code when the server swaps in another of the user’s devices', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const other = await open(server, 'u_alice', 'alice_other');
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    const p = [...server.pairings.values()][0];
    p.newDevice = other.deviceId; // same ephemeral key, another device
    expect((await offer.poll())!.code).not.toBe(join.code);
  });
});

describe('Round 3: background retries', () => {
  it('asks for a retry when a restore stops because the module is not running', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r1', bob, 'backed up'))).toBe('backed up');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const retry = vi.fn();
    laptop.onTransient(retry);
    const openSpy = vi.spyOn(pqc, 'backupOpen').mockImplementation(() => { throw new PQCUnavailable(); });
    // Verified, with the restore left pending for the retry (not a failed verification).
    expect(await laptop.restoreIdentity(rk)).toBe(0);
    await laptop.identityStatus(); // its resume fails too, in the background
    await vi.waitFor(() => expect(retry).toHaveBeenCalled());
    openSpy.mockRestore();
  });
});

describe('Round 4: a sign-out is ordered after an enrollment holding the list', () => {
  it('does not settle the removal of an absent device while its reserved enrollment can still publish', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_bob');
    const api = server.as('u_bob');
    const reserve = api.reserveDeviceList;
    const order: string[] = [];
    let laptop: CryptoEngine | undefined;
    let signingOut: Promise<void> | undefined;
    const enrolling = await open(server, 'u_bob', 'bob_laptop', { ...api, reserveDeviceList: async (v, e, d, s) => {
      const r = await reserve(v, e, d, s);
      if (!signingOut && laptop) {
        // The enrollment holds the list; the device is not on it yet when sign-out starts.
        signingOut = laptop.delistDevices([laptop.deviceId]).then(() => { order.push('delisted'); });
        await new Promise((res) => setTimeout(res, 100));
        order.push('enrollment publishing');
      }
      return r;
    } });
    laptop = enrolling;
    await laptop.restoreIdentity(rk);
    await signingOut;
    expect(order).toEqual(['enrollment publishing', 'delisted']);
    expect(server.masters.get('u_bob')!.device_list!.device_ids).not.toContain(laptop.deviceId);
  });
});

describe('Round 4: forks stay forks', () => {
  it('keeps trusting no device after a fork until a validly signed higher list', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(bob, await send('r1', alice, 'seen the list'))).toBe('seen the list');
    const m = server.masters.get('u_bob')!;
    const good = structuredClone(m.device_list!);
    const fork = [...good.device_ids, 'FORKED_DEVICE_1'].sort();
    m.device_list = { epoch: good.epoch, device_ids: fork, signature: pqc.signDeviceList(masterSeed(server, 'u_bob', rk), TENANT, 'u_bob', m.version, good.epoch, fork) };
    expect(await read(bob, await send('r1', alice, 'forked'))).toBe('waiting');
    // The server shows the first list again: still a fork for alice.
    m.device_list = good;
    expect(await read(bob, await send('r1', alice, 'old list again'))).toBe('waiting');
    // Bob's laptop never saw the fork and publishes the next epoch: trusted again.
    await laptop.delistDevices(['NOT_LISTED_0001']);
    expect(server.masters.get('u_bob')!.device_list!.epoch).toBeGreaterThan(good.epoch);
    expect(await read(bob, await send('r1', alice, 'after a higher list'))).toBe('after a higher list');
  });
});

describe('Round 4: an accept goes through the shared pin set', () => {
  it('refuses a stale prompt clicked right after another browser accepted a different key, and changes nothing', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(bob, await send('r1', alice, 'pinned'))).toBe('pinned');
    const pinned = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    // Bob resets; the laptop sees and accepts that key.
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    const first = structuredClone(server.masters.get('u_bob')!);
    await send('r1', laptop, 'laptop sees the change');
    // Bob resets again before alice's first browser looks: it is prompted for the newer key.
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    await send('r1', alice, 'alice sees the newer change');
    const [stale] = await alice.identityChanges();
    expect(stale.previous).toBe(pinned);
    const current = structuredClone(server.masters.get('u_bob')!);
    server.masters.set('u_bob', first);
    const [lc] = await laptop.identityChanges();
    await laptop.acceptIdentity('u_bob', lc.previous, lc.fingerprint);
    server.masters.set('u_bob', current);
    const shared = structuredClone(server.masters.get('u_alice')!.pins);
    // At once, no send or status in between: the click on the stale prompt is refused.
    await expect(alice.acceptIdentity('u_bob', stale.previous, stale.fingerprint)).rejects.toThrow(/changed again/);
    expect(server.masters.get('u_alice')!.pins).toEqual(shared);
    const local = await openCryptoStore('u_alice');
    expect((await local.get<{ fingerprint: string }>('mpin:u_bob'))!.fingerprint).toBe(lc.fingerprint);
    local.close();
    // The refreshed prompt changes from the laptop's accepted key, and accepting it lands.
    const [fresh] = await alice.identityChanges();
    expect(fresh).toEqual({ user_id: 'u_bob', previous: lc.fingerprint, fingerprint: stale.fingerprint });
    await alice.acceptIdentity('u_bob', fresh.previous, fresh.fingerprint);
    expect(await alice.identityChanges()).toEqual([]);
    expect(await read(bob, await send('r1', alice, 'accepted'))).toBe('accepted');
  });

  it('keeps the prompt and the pin when the shared write fails', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pinned');
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    await send('r1', alice, 'sees the change');
    const [c] = await alice.identityChanges();
    vi.spyOn(api, 'putPins').mockRejectedValueOnce(new TypeError('network'));
    await expect(alice.acceptIdentity('u_bob', c.previous, c.fingerprint)).rejects.toThrow();
    expect(await alice.identityChanges()).toEqual([c]);
    const local = await openCryptoStore('u_alice');
    expect((await local.get<{ fingerprint: string }>('mpin:u_bob'))!.fingerprint).toBe(c.previous);
    local.close();
  });
});

describe('Round 4: QR cancel after a seal', () => {
  it('never takes back keys whose seal answer was lost', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const seal = api.pairingSeal;
    const sender = await open(server, 'u_alice', 'u_alice', { ...api, pairingSeal: async (...a) => {
      await seal(...a);
      throw new TypeError('the answer was lost');
    } });
    void alice;
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const offer = await sender.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    await offer.poll();
    await expect(offer.approve()).rejects.toThrow();
    await offer.cancel(); // the screen closes after the error
    expect(await join.finish()).toBeGreaterThanOrEqual(0);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
  });
});

describe('Round 5: accepting needs the shared pin', () => {
  it('refuses while the shared set lacks the member, restores the baseline, then accepts', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pinned');
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    await send('r1', alice, 'sees the change');
    const [c] = await alice.identityChanges();
    // The shared set loses bob (a validly signed write without him).
    const seed = masterSeed(server, 'u_alice', rk);
    const m = server.masters.get('u_alice')!;
    const next = m.pins.counter + 1;
    const sealed = pqc.pinsSeal(seed, TENANT, 'u_alice', next, b64('{}'));
    await server.as('u_alice').putPins(m.version, m.pins.counter, sealed, pqc.signPinsWrite(seed, TENANT, 'u_alice', m.version, next, sealed));
    await expect(alice.acceptIdentity('u_bob', c.previous, c.fingerprint)).rejects.toThrow(/changed again/);
    expect(await alice.identityChanges()).toEqual([c]);
    // That attempt wrote the baseline back; accepting again now lands.
    await alice.acceptIdentity('u_bob', c.previous, c.fingerprint);
    expect(await alice.identityChanges()).toEqual([]);
    expect(await read(bob, await send('r1', alice, 'accepted'))).toBe('accepted');
  });

  it('adopts a change another device already accepted, keeping its record, one hop or several', async () => {
    for (const hops of [1, 2]) {
      const server = new FakeKeyServer();
      const [alice, rk] = await firstDevice(server, 'u_alice');
      const [bob] = await firstDevice(server, 'u_bob');
      server.join('r1', 'u_alice', 'u_bob');
      await send('r1', alice, 'pinned');
      const laptop = await open(server, 'u_alice', 'alice_laptop');
      await laptop.restoreIdentity(rk);
      for (let i = 0; i < hops; i++) {
        await (await bob.prepareIdentity(true)).commit();
        await bob.identityStatus();
        await send('r1', laptop, `laptop sees change ${i}`);
        const [lc] = await laptop.identityChanges();
        await laptop.acceptIdentity('u_bob', lc.previous, lc.fingerprint);
      }
      // Alice's first browser was prompted for the newest key before it synced the laptop's accept.
      const newest = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
      const shared = structuredClone(server.masters.get('u_alice')!.pins);
      const store = await openCryptoStore('u_alice');
      const pinned = (await store.get<{ fingerprint: string }>('mpin:u_bob'))!.fingerprint;
      await store.write([['mchg:u_bob', { user_id: 'u_bob', fingerprint: newest, previous: pinned }]]);
      store.close();
      await alice.acceptIdentity('u_bob', pinned, newest);
      expect(await alice.identityChanges()).toEqual([]);
      // The shared record (its predecessor too) is the laptop's, unchanged.
      expect(server.masters.get('u_alice')!.pins).toEqual(shared);
      expect(await read(bob, await send('r1', alice, `adopted after ${hops}`))).toBe(`adopted after ${hops}`);
      for (const e of opened.splice(0)) e.close();
      await deleteCryptoStores();
    }
  });
});

describe('Round 5: device list leases and the lock', () => {
  it('does not hold the lock through another device\'s lease, and lists itself once it lapses', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    await bob.delistDevices([laptop.deviceId]); // taken off by another device, not retiring
    const m = server.masters.get('u_bob')!;
    // A full 30 s lease, taken by another of bob's devices and abandoned.
    await server.as('u_bob').reserveDeviceList(m.version, m.device_list!.epoch, 'ab'.repeat(32), pqc.signDeviceListReserve(masterSeed(server, 'u_bob', rk), TENANT, 'u_bob', m.version, m.device_list!.epoch, 'ab'.repeat(32)));
    const retry = vi.fn();
    laptop.onTransient(retry);
    const t0 = Date.now();
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
    expect(Date.now() - t0).toBeLessThan(3_000);
    expect(retry).toHaveBeenCalled();
    // The lock is free meanwhile (a room check takes it; a send would be refused: the laptop is
    // not listed yet).
    server.join('r1', 'u_bob');
    await laptop.checkRoom('r1');
    server.reservations.get('u_bob')!.until = Date.now() + 800;
    await laptop.resumeWork(); // the retry waits (unlocked) for the lapse, then lists
    expect(server.masters.get('u_bob')!.device_list!.device_ids).toContain(laptop.deviceId);
  });

  it('never signs under a grant that arrived after its lease ran out', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_bob');
    const api = server.as('u_bob');
    const reserve = api.reserveDeviceList;
    let calls = 0;
    const tablet = await open(server, 'u_bob', 'bob_tablet', { ...api, reserveDeviceList: async (v, e, d, s) => {
      const r = await reserve(v, e, d, s);
      if (++calls > 1) return r;
      await new Promise((res) => setTimeout(res, 150)); // the answer stalls past its 100 ms lease
      return { ...r, expires_in_ms: 100 };
    } });
    const signs = vi.spyOn(pqc, 'signDeviceList');
    await tablet.restoreIdentity(rk);
    expect(calls).toBe(2);
    expect(signs).toHaveBeenCalledTimes(1);
    expect(server.masters.get('u_bob')!.device_list!.device_ids).toContain(tablet.deviceId);
  });
});

describe('Round 5: backup notice after a partial flush', () => {
  it('says the backup is full once refused entries are stored, even when a later batch fails', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    server.join('r1', 'u_alice');
    await send('r1', alice, 'own session');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    server.backups.delete('u_alice');
    server.backupCap = 0;
    // 150 queued entries: a first batch the cap refuses, then a second the network loses.
    const store = await openCryptoStore('u_alice');
    const [[ik]] = await store.list('in:');
    await store.write(Array.from({ length: 150 }, (_, i): [string, unknown] => [`bq:x${String(i).padStart(3, '0')}`, ik]));
    store.close();
    const put = api.putBackup;
    let n = 0;
    vi.spyOn(api, 'putBackup').mockImplementation(async (...a) => {
      if (++n === 2) throw new TypeError('network');
      return put(...a);
    });
    const full = vi.fn();
    alice.onBackupState(full);
    await expect(alice.resumeWork()).rejects.toThrow('network');
    expect(full).toHaveBeenCalledWith(true);
  });
});

describe('Round 6: an accept acts only on what the user saw', () => {
  it('refuses a stale prompt whose key is already shared, keeping the newer candidate across trust checks', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pinned');
    const p0 = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    await laptop.restoreIdentity(rk);
    // Bob resets; both of alice's browsers see that key, and alice's first one shows the prompt.
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    const p1 = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    await send('r1', alice, 'sees p1');
    await send('r1', laptop, 'laptop sees p1');
    const [shown] = await alice.identityChanges();
    expect(shown).toEqual({ user_id: 'u_bob', previous: p0, fingerprint: p1 });
    // While that prompt is open, bob resets again: alice's candidate becomes the newer key...
    await (await bob.prepareIdentity(true)).commit();
    await bob.identityStatus();
    const p2 = pqc.fingerprint(server.masters.get('u_bob')!.master_key);
    await send('r1', alice, 'sees p2');
    expect(await alice.identityChanges()).toEqual([{ user_id: 'u_bob', previous: p0, fingerprint: p2 }]);
    // ...and the laptop accepts the older one, which is now the shared pin.
    const [lc] = await laptop.identityChanges();
    await laptop.acceptIdentity('u_bob', lc.previous, lc.fingerprint);
    const shared = structuredClone(server.masters.get('u_alice')!.pins);
    // The click on the prompt as first shown is refused: the newer candidate stays, rebased.
    await expect(alice.acceptIdentity('u_bob', shown.previous, shown.fingerprint)).rejects.toThrow(/changed again/);
    const rebased = [{ user_id: 'u_bob', previous: p1, fingerprint: p2 }];
    expect(await alice.identityChanges()).toEqual(rebased);
    expect(server.masters.get('u_alice')!.pins).toEqual(shared);
    for (let i = 0; i < 2; i++) {
      expect(await read(bob, await send('r1', alice, `held ${i}`))).toBe('waiting');
      expect(await alice.identityChanges()).toEqual(rebased);
    }
    await alice.acceptIdentity('u_bob', p1, p2);
    expect(await read(bob, await send('r1', alice, 'accepted p2'))).toBe('accepted p2');
  });
});

describe('Round 6: retry paths', () => {
  it('still restores and backs up when listing reports a rollback', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    await bob.identityStatus();
    const m = server.masters.get('u_bob')!;
    server.backups.delete('u_bob');
    server.join('r1', 'u_bob');
    // The session's own flush is refused (the cap), so only the drain can store it.
    server.backupCap = 0;
    await send('r1', bob, 'own session');
    const local = await openCryptoStore('u_bob');
    await vi.waitFor(async () => expect(await local.list('bqf:')).toHaveLength(1));
    local.close();
    server.backupCap = 10;
    // Then the server rolls bob's device list back.
    const newest = structuredClone(m.device_list!);
    m.device_list = { epoch: newest.epoch - 1, device_ids: [bob.deviceId], signature: pqc.signDeviceList(masterSeed(server, 'u_bob', rk), TENANT, 'u_bob', m.version, newest.epoch - 1, [bob.deviceId]) };
    await expect(bob.resumeWork()).rejects.toThrow(/older device list/);
    expect(server.backups.get('u_bob')?.size).toBe(1);
  });

  it('retries the cross-signature of a replacement device that could not be stored', async () => {
    const server = new FakeKeyServer();
    const [bob] = await firstDevice(server, 'u_bob');
    const storeName = 'u_bob';
    const old = bob.deviceId;
    for (const e of opened.splice(0)) e.close();
    await CryptoEngine.resetDevice('u_bob', old, await openCryptoStore(storeName));
    const api = server.as('u_bob');
    const sign = api.signDevice;
    let fail = true;
    api.signDevice = async (...a) => {
      if (fail) {
        fail = false;
        throw new Transient('the network');
      }
      return sign(...a);
    };
    const fresh = await open(server, 'u_bob', storeName, api);
    expect(fresh.deviceId).not.toBe(old);
    // The failure was reported before anyone listened; the first listener gets it.
    const retry = vi.fn();
    await vi.waitFor(() => {
      fresh.onTransient(retry)();
      expect(retry).toHaveBeenCalled();
    });
    expect(server.devices.get('u_bob')!.get(fresh.deviceId)!.master_signature).toBeUndefined();
    await fresh.resumeWork();
    expect(server.devices.get('u_bob')!.get(fresh.deviceId)!.master_signature).toBeTruthy();
  });

  it('says the backup is full as soon as a refused batch is stored, while a later batch stalls', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    server.join('r1', 'u_alice');
    await send('r1', alice, 'own session');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    server.backups.delete('u_alice');
    server.backupCap = 0;
    const store = await openCryptoStore('u_alice');
    const [[ik]] = await store.list('in:');
    await store.write(Array.from({ length: 150 }, (_, i): [string, unknown] => [`bq:x${String(i).padStart(3, '0')}`, ik]));
    store.close();
    const put = api.putBackup;
    let n = 0;
    let unstall = () => {};
    const stalled = new Promise<never>((_, reject) => { unstall = () => reject(new TypeError('network')); });
    void stalled.catch(() => undefined); // cleanup can run before the second request arrives
    vi.spyOn(api, 'putBackup').mockImplementation(async (...a) => (++n === 2 ? stalled : put(...a)));
    const full = vi.fn();
    alice.onBackupState(full);
    const work = alice.resumeWork().catch(() => undefined);
    try {
      await vi.waitFor(() => expect(full).toHaveBeenCalledWith(true));
      await vi.waitFor(() => expect(n).toBe(2)); // wait for the second batch to enter the stall
    } finally {
      unstall(); // always free the per-user lock, including on an assertion failure
      await work;
    }
  });
});

describe('Round 6: the new device\'s wait ends at its deadline', () => {
  it('aborts a consume request in flight when the pairing wait runs out', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    let seen: AbortSignal | undefined;
    const api = server.as('u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop', { ...api, pairingConsume: (_id, _d, signal) => {
      seen = signal;
      return new Promise((_, reject) => signal?.addEventListener('abort', () => reject(signal.reason), { once: true }));
    } });
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const done = join.finish().catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(4 * 60_000 + 10);
      expect(String(await done)).toMatch(/did not approve in time/);
      expect(seen?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Round 6: taking on an identity', () => {
  it('adopts the identity as published when a delayed approval lands, and refuses one that changed', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const writes = vi.spyOn(api, 'putBackup');
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    await offer.poll();
    // While the user compares codes, the backup is deleted elsewhere: a new generation.
    server.deleteBackup('u_alice');
    await offer.approve();
    await join.finish();
    server.join('r1', 'u_alice');
    await send('r1', laptop, 'backed up at the new generation');
    await vi.waitFor(() => expect(writes).toHaveBeenCalled());
    expect(writes.mock.calls[0][1]).toBe(1); // signed for it at once, no stale first attempt

    // An identity reset while waiting: the seeds sent are the old identity's, and are refused.
    const tablet = await open(server, 'u_alice', 'alice_tablet');
    const offer2 = await alice.offerVerification();
    const join2 = await tablet.joinVerification(offer2.text);
    await offer2.poll();
    await offer2.approve();
    await (await laptop.prepareIdentity(true)).commit();
    await expect(join2.finish()).rejects.toThrow(/changed meanwhile/);
    expect(await tablet.identityStatus()).toMatchObject({ state: 'unverified' });
  });

  it('keeps the seeds when enrollment fails for availability, finishes it on retry, and only then announces it', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const sign = api.signDevice;
    let fail = true;
    api.signDevice = async (...a) => {
      if (fail) {
        fail = false;
        throw new Transient('the network');
      }
      return sign(...a);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    const retry = vi.fn();
    laptop.onTransient(retry);
    await laptop.restoreIdentity(rk); // the seeds are kept: no error, no recovery key again
    expect(retry).toHaveBeenCalled();
    expect(adopted).not.toHaveBeenCalled();
    expect(server.devices.get('u_alice')!.get(laptop.deviceId)!.master_signature).toBeUndefined();
    await laptop.resumeWork();
    expect(server.devices.get('u_alice')!.get(laptop.deviceId)!.master_signature).toBeTruthy();
    expect(server.masters.get('u_alice')!.device_list!.device_ids).toContain(laptop.deviceId);
    expect(adopted).toHaveBeenCalledTimes(1);
    await laptop.resumeWork();
    expect(adopted).toHaveBeenCalledTimes(1);
  });
});

describe('Round 6: enrollment announced only once listed', () => {
  it('waits for the listing too, when only that failed', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const reserve = api.reserveDeviceList;
    let fail = true;
    api.reserveDeviceList = async (...a) => {
      if (fail) {
        fail = false;
        throw new Transient('the network');
      }
      return reserve(...a);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    await laptop.restoreIdentity(rk);
    expect(server.devices.get('u_alice')!.get(laptop.deviceId)!.master_signature).toBeTruthy();
    expect(server.masters.get('u_alice')!.device_list!.device_ids).not.toContain(laptop.deviceId);
    expect(adopted).not.toHaveBeenCalled();
    await laptop.resumeWork();
    expect(server.masters.get('u_alice')!.device_list!.device_ids).toContain(laptop.deviceId);
    expect(adopted).toHaveBeenCalledTimes(1);
  });
});

describe('Round 6: restore and unvouched coverage', () => {
  it('lets a valid backup copy reach over an unvouched one, never as authenticated', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m = await send('r1', bob, 'from bob');
    expect(await read(alice, m)).toBe('from bob');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    // Alice's copy now reads as an unvouched one reaching less far than the backup's, on a
    // browser that no longer holds the identity (restoring the one it holds changes nothing).
    const store = await openCryptoStore('u_alice');
    const [[k, v]] = (await store.list<{ first_index: number }>('in:')).filter(([, r]) => (r as unknown as { sender_user: string }).sender_user === 'u_bob');
    await store.write([[k, { ...v, verified: false, first_index: 5 }]], ['identity']);
    await alice.restoreIdentity(rk);
    const now = (await store.get<{ first_index: number; from_backup?: boolean }>(k))!;
    store.close();
    expect(now).toMatchObject({ first_index: 0, from_backup: true });
    const r = await alice.decrypt(m);
    expect(r).toMatchObject({ state: 'decrypted', authenticated: false, restored: true });
  });
});

describe('Round 6: one upload per session', () => {
  it('sends a session queued afresh while its refused entry waits only once', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    server.join('r1', 'u_alice');
    server.backupCap = 0;
    await send('r1', alice, 'own session');
    const store = await openCryptoStore('u_alice');
    await vi.waitFor(async () => expect(await store.list('bqf:')).toHaveLength(1));
    const [[, ik]] = await store.list<string>('bqf:');
    await store.write([[`bq:${ik}`, ik]]); // the same session queued again
    server.backupCap = 10;
    const writes = vi.spyOn(api, 'putBackup');
    await alice.resumeWork();
    expect(writes).toHaveBeenCalledTimes(1);
    expect(writes.mock.calls[0][2]).toHaveLength(1);
    expect(await store.list('bq:')).toEqual([]);
    expect(await store.list('bqf:')).toEqual([]);
    store.close();
  });
});

describe('Round 7: a send needs this device signed and listed now', () => {
  const outbound = async (storeName: string) => {
    const s = await openCryptoStore(storeName);
    try {
      return (await s.list('out:')).length;
    } finally {
      s.close();
    }
  };

  it('refuses a replacement still enrolling, writes no session, and sends once enrolled', async () => {
    const server = new FakeKeyServer();
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_bob');
    const old = bob.deviceId;
    for (const e of opened.splice(0)) e.close();
    await CryptoEngine.resetDevice('u_bob', old, await openCryptoStore('u_bob'));
    const api = server.as('u_bob');
    const sign = api.signDevice;
    let down = true;
    api.signDevice = async (...a) => {
      if (down) throw new Transient('the network');
      return sign(...a);
    };
    const fresh = await open(server, 'u_bob', 'u_bob', api);
    await fresh.identityStatus(); // holds the seeds, but its signing keeps failing
    const before = await outbound('u_bob');
    await expect(fresh.encrypt('r1', { type: 'text', body: 'too early' })).rejects.toBeInstanceOf(NotVerified);
    expect(await outbound('u_bob')).toBe(before);
    down = false;
    await fresh.resumeWork(); // signs and lists it
    await expect(fresh.encrypt('r1', { type: 'text', body: 'now' })).resolves.toMatch(/megolm/);
  });

  it('refuses a device taken off the list, and one whose identity was reset elsewhere', async () => {
    const server = new FakeKeyServer();
    const [bob, rk] = await firstDevice(server, 'u_bob');
    const laptop = await open(server, 'u_bob', 'bob_laptop');
    await laptop.restoreIdentity(rk);
    server.join('r1', 'u_bob');
    await expect(laptop.encrypt('r1', { type: 'text', body: 'listed' })).resolves.toMatch(/megolm/);
    await bob.delistDevices([laptop.deviceId]);
    await expect(laptop.encrypt('r1', { type: 'text', body: 'removed' })).rejects.toBeInstanceOf(NotVerified);
    // A reset from another device: the seeds bob's first device holds are for the old identity.
    await (await laptop.prepareIdentity(true)).commit();
    await expect(bob.encrypt('r1', { type: 'text', body: 'stale identity' })).rejects.toBeInstanceOf(NotVerified);
    // The verified self-only send still works.
    await expect(laptop.encrypt('r1', { type: 'text', body: 'self only' })).resolves.toMatch(/megolm/);
  });
});

/** Another device resets userId's identity on the server: a new master and backup key. */
async function resetOnServer(server: FakeKeyServer, userId: string): Promise<void> {
  const m = pqc.masterGenerate();
  const b = pqc.xwingGenerate();
  const rk = pqc.recoveryGenerate();
  const cur = server.masters.get(userId)!;
  const version = cur.version + 1;
  await server.as(userId).putMaster({
    expected_version: cur.version, master_key: m.public_key, self_signature: pqc.signMaster(m.seed, TENANT, userId),
    backup_key: { public_key: b.public, signature: pqc.signBackupKey(m.seed, TENANT, userId, version, b.public) },
    recovery: { wrapped_master_key: pqc.recoveryWrap(rk.key, 'master-key', TENANT, userId, m.seed), wrapped_backup_key: pqc.recoveryWrap(rk.key, 'backup-key', TENANT, userId, b.seed) },
  });
}

describe('Round 7: from a consumed transfer to adoption', () => {
  // A laptop joining alice's pairing, whose API a test can interpose on after the consume.
  async function pairing(after: (api: KeyServer) => Partial<KeyServer>) {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    let consumed = 0;
    const consume = api.pairingConsume;
    const base: KeyServer = { ...api, pairingConsume: async (...a) => { const r = await consume(...a); consumed++; return r; } };
    const laptop = await open(server, 'u_alice', 'alice_laptop', { ...base, ...after(base) });
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    await offer.poll();
    await offer.approve();
    return { server, laptop, join, consumed: () => consumed };
  }
  const holds = async (name: string) => {
    const s = await openCryptoStore(name);
    try {
      return (await s.get('identity')) !== undefined;
    } finally {
      s.close();
    }
  };

  it('holds the transfer through a failed identity read, without a second consume', async () => {
    let afterConsume = false;
    let fails = 2;
    const p = await pairing((api) => ({
      pairingConsume: async (...a) => { const r = await api.pairingConsume(...a); afterConsume = true; return r; },
      getMaster: async (s) => {
        if (afterConsume && fails-- > 0) throw new Transient('the network');
        return api.getMaster(s);
      },
    }));
    expect(await p.join.finish()).toBeGreaterThanOrEqual(0);
    expect(p.consumed()).toBe(1);
    expect(await p.laptop.identityStatus()).toMatchObject({ state: 'verified' });
    // Includes key setup, signing and two real network-retry waits; keep the product deadline.
  }, 15_000);

  it('never writes seeds of an identity reset after the transfer was read', async () => {
    let afterConsume = false;
    let reads = 0;
    let server: FakeKeyServer | undefined;
    const p = await pairing((api) => ({
      pairingConsume: async (...a) => { const r = await api.pairingConsume(...a); afterConsume = true; return r; },
      getMaster: async (s) => {
        // The read under the adoption's lock, right before the write.
        if (afterConsume && ++reads === 1) await resetOnServer(server!, 'u_alice');
        return api.getMaster(s);
      },
    }));
    server = p.server;
    await expect(p.join.finish()).rejects.toThrow(/changed meanwhile/);
    expect(await holds('alice_laptop')).toBe(false);
  });

  it('writes nothing when the screen closes after the consume', async () => {
    const ac = new AbortController();
    let afterConsume = false;
    const p = await pairing((api) => ({
      pairingConsume: async (...a) => { const r = await api.pairingConsume(...a); afterConsume = true; return r; },
      getMaster: async (s) => {
        if (afterConsume) ac.abort(new DOMException('closed', 'AbortError'));
        return api.getMaster(s);
      },
    }));
    await expect(p.join.finish(ac.signal)).rejects.toThrow('closed');
    expect(await holds('alice_laptop')).toBe(false);
  });

  it('writes nothing when the screen closes while a failed read under the lock backs off', async () => {
    const ac = new AbortController();
    let afterConsume = false;
    const p = await pairing((api) => ({
      pairingConsume: async (...a) => { const r = await api.pairingConsume(...a); afterConsume = true; return r; },
      getMaster: async (s) => {
        if (afterConsume) {
          setTimeout(() => ac.abort(new DOMException('closed', 'AbortError')), 10);
          throw new Transient('the network');
        }
        return api.getMaster(s);
      },
    }));
    await expect(p.join.finish(ac.signal)).rejects.toThrow('closed');
    await new Promise((r) => setTimeout(r, 100)); // nothing is left to land later either
    expect(await holds('alice_laptop')).toBe(false);
    expect(p.consumed()).toBe(1);
  });

  it('keeps the enrollment unconfirmed while the list it would confirm against is forked', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const putList = api.putDeviceList;
    const getMaster = api.getMaster;
    let forkNext = false;
    api.putDeviceList = async (...a) => { await putList(...a); forkNext = true; };
    api.getMaster = async (s) => {
      const r = await getMaster(s);
      if (forkNext && r.master?.device_list) {
        // A second, validly signed list at the same epoch, still naming the laptop.
        forkNext = false;
        const dl = r.master.device_list;
        const ids = [...dl.device_ids, 'FORKED_DEVICE_1'].sort();
        r.master.device_list = { epoch: dl.epoch, device_ids: ids, signature: pqc.signDeviceList(masterSeed(server, 'u_alice', rk), TENANT, 'u_alice', r.master.version, dl.epoch, ids) };
      }
      return r;
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow(/two device lists/);
    expect(adopted).not.toHaveBeenCalled();
    const s = await openCryptoStore('alice_laptop');
    expect(await s.get('identity:enrolling')).toMatchObject({ version: 1 });
    s.close();
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', problem: 'fork' });
  });

  it('never reports a failure for an enrollment that landed, when only its confirmation failed', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const putList = api.putDeviceList;
    const getMaster = api.getMaster;
    let failNext = false;
    api.putDeviceList = async (...a) => { await putList(...a); failNext = true; };
    api.getMaster = async (s) => {
      if (failNext) {
        failNext = false;
        throw new Transient('the network');
      }
      return getMaster(s);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    await laptop.restoreIdentity(rk); // no error: the enrollment is durable
    expect(server.masters.get('u_alice')!.device_list!.device_ids).toContain(laptop.deviceId);
    expect(adopted).not.toHaveBeenCalled();
    await laptop.resumeWork();
    expect(adopted).toHaveBeenCalledTimes(1);
  });
});

describe('Round 7: a backup read failing after adoption', () => {
  it('leaves the restore pending for the retry, and never reports the verification as failed', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(await read(alice, await send('r1', bob, 'backed up'))).toBe('backed up');
    await vi.waitFor(() => expect(server.backups.get('u_alice')?.size).toBe(1));
    const api = server.as('u_alice');
    const page = api.getBackup;
    let down = true;
    api.getBackup = async (...a) => {
      if (down) throw new Transient('the network');
      return page(...a);
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const retry = vi.fn();
    laptop.onTransient(retry);
    expect(await laptop.restoreIdentity(rk)).toBe(0); // verified; nothing restored yet
    expect(retry).toHaveBeenCalled();
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', restoring: true });
    down = false;
    await laptop.resumeWork();
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', restoring: false });
  });
});

describe('Round 8: one bounded sequence up to the seed write', () => {
  // A laptop joining alice's pairing; getMaster wraps the laptop's identity reads, told whether
  // the transfer was consumed yet.
  async function pairing(getMaster: (real: KeyServer['getMaster'], consumed: () => boolean) => KeyServer['getMaster']) {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    let consumed = 0;
    const consume = api.pairingConsume;
    api.pairingConsume = async (...a) => { const r = await consume(...a); consumed++; return r; };
    api.getMaster = getMaster(api.getMaster, () => consumed > 0);
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const offer = await alice.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    await offer.poll();
    await offer.approve();
    return { server, laptop, join, consumed: () => consumed };
  }

  it('lets go of the lock while a failed decisive read backs off, then adopts on the same transfer', async () => {
    const order: string[] = [];
    let laptop: CryptoEngine | undefined;
    let fails = 1;
    const p = await pairing((real, consumed) => async (s) => {
      if (consumed() && fails-- > 0) {
        // Another tab's status check runs while this one waits to try again.
        void laptop!.identityStatus().then(() => order.push('status'));
        throw new Transient('the network');
      }
      return real(s);
    });
    laptop = p.laptop;
    await p.join.finish().then(() => order.push('finish'));
    expect(order).toEqual(['status', 'finish']);
    expect(p.consumed()).toBe(1);
    expect(await p.laptop.identityStatus()).toMatchObject({ state: 'verified' });
  });

  it('refuses an identity reset between two tries, writing nothing', async () => {
    let server: FakeKeyServer | undefined;
    let reads = 0;
    const p = await pairing((real, consumed) => async (s) => {
      if (consumed() && ++reads === 1) {
        await resetOnServer(server!, 'u_alice');
        throw new Transient('the network');
      }
      return real(s);
    });
    server = p.server;
    await expect(p.join.finish()).rejects.toThrow(/changed meanwhile/);
    expect(p.consumed()).toBe(1);
    const s = await openCryptoStore('alice_laptop');
    expect(await s.get('identity')).toBeUndefined();
    s.close();
  });

  it('keeps the progress of the very same identity adopted meanwhile', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    await laptop.restoreIdentity(rk);
    const s = await openCryptoStore('alice_laptop');
    const signed = await s.get('identity:signed');
    expect(signed).toBeDefined();
    await laptop.restoreIdentity(rk);
    expect(await s.get('identity:signed')).toEqual(signed);
    expect(await s.get('identity:enrolling')).toBeUndefined();
    s.close();
    expect(adopted).toHaveBeenCalledTimes(1);
  });
});

describe('Round 8: seeds stored are announced', () => {
  it('announces the identity taken on even when signing this device then refuses', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    api.signDevice = async () => { throw new Error('refused'); };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const changed = vi.fn();
    laptop.onIdentityChange(changed);
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow('refused');
    expect(changed).toHaveBeenCalled();
    const s = await openCryptoStore('alice_laptop');
    expect(await s.get('identity')).toBeDefined();
    expect(await s.get('identity:enrolling')).toMatchObject({ version: 1 });
    s.close();
  });
});

describe('Round 8: confirming enrollment against every authenticated list', () => {
  // The laptop restores; the read that confirms its enrollment (the first after its listing)
  // shows the list as edit() makes it.
  async function confirming(edit: (dl: { epoch: number; device_ids: string[] }, sign: (epoch: number, ids: string[]) => unknown) => unknown) {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice');
    const api = server.as('u_alice');
    const putList = api.putDeviceList;
    const getMaster = api.getMaster;
    let next = false;
    api.putDeviceList = async (...a) => { await putList(...a); next = true; };
    api.getMaster = async (s) => {
      const r = await getMaster(s);
      if (next && r.master?.device_list) {
        next = false;
        const m = r.master;
        r.master = { ...m, device_list: edit(structuredClone(m.device_list!),
          (epoch, ids) => pqc.signDeviceList(masterSeed(server, 'u_alice', rk), TENANT, 'u_alice', m.version, epoch, ids)) as typeof m.device_list };
      }
      return r;
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);
    const without = (ids: string[]) => ids.filter((d) => d !== laptop.deviceId);
    return { laptop, adopted, rk, without };
  }
  const enrolling = async () => {
    const s = await openCryptoStore('alice_laptop');
    try {
      return await s.get('identity:enrolling');
    } finally {
      s.close();
    }
  };

  it('moves the mark on a newer list leaving the device out, so an older naming one never confirms', async () => {
    let without: ((ids: string[]) => string[]) | undefined;
    const c = await confirming((dl, sign) => {
      const ids = without!(dl.device_ids);
      return { epoch: dl.epoch + 1, device_ids: ids, signature: sign(dl.epoch + 1, ids) };
    });
    without = c.without;
    await c.laptop.restoreIdentity(c.rk);
    expect(c.adopted).not.toHaveBeenCalled();
    // The server's list (older, naming the laptop) is a rollback now.
    await expect(c.laptop.resumeWork()).rejects.toThrow(/older device list/);
    expect(c.adopted).not.toHaveBeenCalled();
    expect(await enrolling()).toMatchObject({ version: 1 });
  });

  it('marks a fork on another list at the same epoch leaving the device out', async () => {
    let without: ((ids: string[]) => string[]) | undefined;
    const c = await confirming((dl, sign) => {
      const ids = without!(dl.device_ids);
      return { epoch: dl.epoch, device_ids: ids, signature: sign(dl.epoch, ids) };
    });
    without = c.without;
    await expect(c.laptop.restoreIdentity(c.rk)).rejects.toThrow(/two device lists/);
    await expect(c.laptop.resumeWork()).rejects.toThrow(/two device lists/);
    expect(c.adopted).not.toHaveBeenCalled();
    expect(await enrolling()).toMatchObject({ version: 1 });
    expect(await c.laptop.identityStatus()).toMatchObject({ state: 'verified', problem: 'fork' });
  });

  it('ignores a list that does not verify, and confirms on the authentic one', async () => {
    let without: ((ids: string[]) => string[]) | undefined;
    const c = await confirming((dl) => {
      const ids = without!(dl.device_ids);
      const other = pqc.masterGenerate();
      return { epoch: dl.epoch + 5, device_ids: ids, signature: pqc.signDeviceList(other.seed, TENANT, 'u_alice', 1, dl.epoch + 5, ids) };
    });
    without = c.without;
    await c.laptop.restoreIdentity(c.rk);
    expect(c.adopted).not.toHaveBeenCalled();
    await c.laptop.resumeWork();
    expect(c.adopted).toHaveBeenCalledTimes(1);
    expect(await enrolling()).toBeUndefined();
  });
});

describe('Round 8: trust verdicts and this device\'s own keys', () => {
  it('keeps the mailbox and reports the verdict when the pin set was rolled back', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    await firstDevice(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBe(1));
    const old = structuredClone(server.masters.get('u_alice')!.pins);
    server.join('r2', 'u_alice', 'u_carol');
    await send('r2', alice, 'pins carol');
    await vi.waitFor(() => expect(server.masters.get('u_alice')!.pins.counter).toBe(2));
    await send('r1', bob, 'waits in the mailbox');
    const waiting = () => server.mail.get(`u_alice\n${alice.deviceId}`)?.length ?? 0;
    expect(waiting()).toBeGreaterThan(0);
    const before = waiting();
    server.masters.get('u_alice')!.pins = old;
    const err = await alice.resumeWork().then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(Rollback);
    expect(isTransient(err)).toBe(false);
    expect(waiting()).toBe(before); // nothing acknowledged
    expect(await alice.identityStatus()).toMatchObject({ state: 'verified', problem: 'rollback' });
  });

  it('reads an identity reset while first sights are committed as this device not verified', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const query = api.query;
    let resetAfter = false;
    api.query = async (...a) => {
      const r = await query(...a);
      if (resetAfter) {
        resetAfter = false;
        await resetOnServer(server, 'u_alice');
      }
      return r;
    };
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    await firstDevice(server, 'u_bob');
    resetAfter = true;
    await expect(alice.verifiedDevices(['u_bob'])).rejects.toBeInstanceOf(NotVerified);
  });

  it('refuses a send when other validly signed keys are listed under this device ID, pinning no one', async () => {
    const server = new FakeKeyServer();
    const [alice, rk] = await firstDevice(server, 'u_alice');
    await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const acct = new Account();
    const curve = acct.curve25519;
    const ed = acct.ed25519;
    const forged = { device_id: alice.deviceId, curve25519: curve, ed25519: ed, signature: acct.sign(deviceSigned('u_alice', alice.deviceId, curve, ed)),
      master_signature: pqc.signDevice(masterSeed(server, 'u_alice', rk), TENANT, 'u_alice', alice.deviceId, curve, ed) };
    acct.free();
    server.devices.get('u_alice')!.set(alice.deviceId, forged);
    const counter = server.masters.get('u_alice')!.pins.counter;
    await expect(alice.encrypt('r1', { type: 'text', body: 'not as this device' })).rejects.toBeInstanceOf(NotVerified);
    // Bob was a first sight: neither the shared pin set nor this device pinned him.
    expect(server.masters.get('u_alice')!.pins.counter).toBe(counter);
    const s = await openCryptoStore('u_alice');
    expect((await s.list('pin:')).filter(([k]) => k.includes('u_bob'))).toHaveLength(0);
    s.close();
  });
});

describe('Round 9: transfer PQC retry, post-commit availability, atomic enrollment & deferred device pins', () => {
  it('retries transferOpen on PQCUnavailable without re-consuming the pairing transfer', async () => {
    const server = new FakeKeyServer();
    const [phone] = await firstDevice(server, 'u_alice', 'alice_phone');
    const api = server.as('u_alice');
    let consumes = 0;
    const consume = api.pairingConsume;
    api.pairingConsume = async (...a) => { consumes++; return consume(...a); };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);

    const offer = await phone.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    expect(await offer.poll()).toEqual({ code: join.code, device: laptop.deviceId });
    await offer.approve();

    const realOpen = pqc.transferOpen;
    let calls = 0;
    vi.spyOn(pqc, 'transferOpen').mockImplementation((...args) => {
      if (++calls === 1) throw new PQCUnavailable('wasm restarted');
      return realOpen(...args);
    });

    await join.finish();
    expect(consumes).toBe(1);
    expect(calls).toBe(2);
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
  });

  it('fails definitively without retrying when transferOpen rejects bad transfer data', async () => {
    const server = new FakeKeyServer();
    const [phone] = await firstDevice(server, 'u_alice', 'alice_phone');
    const laptop = await open(server, 'u_alice', 'alice_laptop');
    const offer = await phone.offerVerification();
    const join = await laptop.joinVerification(offer.text);
    expect(await offer.poll()).toEqual({ code: join.code, device: laptop.deviceId });
    await offer.approve();

    const spy = vi.spyOn(pqc, 'transferOpen').mockImplementation(() => { throw new Error('bad transfer'); });
    await expect(join.finish()).rejects.toThrow(/did not open/);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('treats a transient post-commit storage failure in adopt as retryable while announcing durable seeds', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice', 'alice_phone');
    const store = await openCryptoStore('alice_laptop');
    const realList = store.list.bind(store);
    let failPostCommit = true;
    store.list = (async (prefix: string) => {
      if (prefix === 'bqf:' && failPostCommit && (await store.get('identity')) !== undefined) {
        failPostCommit = false;
        throw new DOMException('database temporarily busy', 'UnknownError');
      }
      return realList(prefix);
    }) as typeof store.list;
    const laptop = await CryptoEngine.open('u_alice', server.as('u_alice'), store);
    opened.push(laptop);
    const changed = vi.fn();
    const retry = vi.fn();
    laptop.onIdentityChange(changed);
    laptop.onTransient(retry);

    await expect(laptop.restoreIdentity(rk)).resolves.toBe(0);
    expect(changed).toHaveBeenCalled();
    expect(retry).toHaveBeenCalled();
    expect(await store.get('identity')).toBeDefined();
  });

  it('observes a missing device_list on the authenticated current master as Rollback, keeps ENROLLING, and does not deadlock status()', async () => {
    const server = new FakeKeyServer();
    const [, rk] = await firstDevice(server, 'u_alice', 'alice_phone');
    const api = server.as('u_alice');
    const putList = api.putDeviceList;
    const getMaster = api.getMaster;
    let stripList = false;
    api.putDeviceList = async (...a) => { await putList(...a); stripList = true; };
    api.getMaster = async (sig) => {
      const r = await getMaster(sig);
      if (stripList && r.master) {
        return { ...r, master: { ...r.master, device_list: undefined } };
      }
      return r;
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);

    await expect(laptop.restoreIdentity(rk)).rejects.toBeInstanceOf(Rollback);
    expect(adopted).not.toHaveBeenCalled();
    const s = await openCryptoStore('alice_laptop');
    expect(await s.get('identity:enrolling')).toMatchObject({ version: 1 });
    s.close();
    // status() already holds the per-user lock; enrolled(true, l) must not re-lock/deadlock
    // and must report the missing-list rollback verdict.
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified', problem: 'rollback' });
  });

  it('does not let an older enrollment confirmation remove a newer enrollment marker', async () => {
    const server = new FakeKeyServer();
    const [, rk1] = await firstDevice(server, 'u_alice', 'alice_phone');
    const api = server.as('u_alice');
    const putList = api.putDeviceList;
    let injectedNewer = false;
    api.putDeviceList = async (...a) => {
      await putList(...a);
      if (!injectedNewer) {
        injectedNewer = true;
        // Between unlocked ensureListed(v1) and locked enrolled(false, v1), a newer enrollment (v2)
        // takes over local state under the per-user lock.
        const s = await openCryptoStore('alice_laptop');
        const id = await s.get<Record<string, unknown>>('identity');
        await s.write([
          ['identity', { ...id, version: 2, fingerprint: 'ff'.repeat(32) }],
          ['identity:enrolling', { tenant_id: TENANT, version: 2, fingerprint: 'ff'.repeat(32) }],
        ]);
        s.close();
      }
    };
    const laptop = await open(server, 'u_alice', 'alice_laptop', api);
    const adopted = vi.fn();
    laptop.onAdopted(adopted);

    await laptop.restoreIdentity(rk1);
    expect(adopted).not.toHaveBeenCalled();
    const s = await openCryptoStore('alice_laptop');
    expect(await s.get('identity:enrolling')).toEqual({ tenant_id: TENANT, version: 2, fingerprint: 'ff'.repeat(32) });
    s.close();
  });

  it('defers new device pins of already-pinned peers as well as fresh peers until commitFirstSights succeeds', async () => {
    const server = new FakeKeyServer();
    const api = server.as('u_alice');
    const query = api.query;
    let resetDuringSend = false;
    api.query = async (...a) => {
      const r = await query(...a);
      if (resetDuringSend) {
        resetDuringSend = false;
        await resetOnServer(server, 'u_alice');
      }
      return r;
    };
    const alice = await open(server, 'u_alice', 'u_alice', api);
    await (await alice.prepareIdentity()).commit();
    const [bob1, bobRk] = await firstDevice(server, 'u_bob', 'bob_1');
    server.join('r1', 'u_alice', 'u_bob');
    // Alice sends once so Bob (and bob1) is already pinned and r1 has an outbound session.
    await alice.encrypt('r1', { type: 'text', body: 'first' });

    const sBefore = await openCryptoStore('u_alice');
    const outBefore = await sBefore.get('out:r1');
    expect(await sBefore.get(`pin:u_bob\n${bob1.deviceId}`)).toBeDefined();
    sBefore.close();

    // Now Bob enrolls a second device (new device on an already-pinned peer) and Carol joins (fresh peer).
    const bob2 = await open(server, 'u_bob', 'bob_2');
    await bob2.restoreIdentity(bobRk);
    const [carol1] = await firstDevice(server, 'u_carol', 'carol_1');
    server.join('r1', 'u_carol');

    // During Alice's send, her identity moves before commitFirstSights runs.
    resetDuringSend = true;
    await expect(alice.encrypt('r1', { type: 'text', body: 'must fail' })).rejects.toBeInstanceOf(NotVerified);

    const sAfter = await openCryptoStore('u_alice');
    // Previously pinned bob1 stays, but neither bob2 (new device of already-pinned peer)
    // nor carol1 (fresh peer) nor any outbound ratchet update was persisted.
    expect(await sAfter.get(`pin:u_bob\n${bob1.deviceId}`)).toBeDefined();
    expect(await sAfter.get(`pin:u_bob\n${bob2.deviceId}`)).toBeUndefined();
    expect(await sAfter.get(`pin:u_carol\n${carol1.deviceId}`)).toBeUndefined();
    expect(await sAfter.get('mpin:u_carol')).toBeUndefined();
    expect(await sAfter.get('out:r1')).toEqual(outBefore);
    sAfter.close();
  });

  it('preserves NotVerified as a permanent verdict through receive(), keeps mail queued, and fires onVerdict', async () => {
    const server = new FakeKeyServer();
    const [alice] = await firstDevice(server, 'u_alice', 'alice_1');
    const [bob] = await firstDevice(server, 'u_bob', 'bob_1');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', bob, 'hello before reset');
    const waiting = () => server.mail.get(`u_alice\n${alice.deviceId}`)?.length ?? 0;
    expect(waiting()).toBeGreaterThan(0);

    // Move Alice's identity on the server so her commitFirstSights fails with IdentityMoved -> NotVerified.
    await resetOnServer(server, 'u_alice');
    const verdicts: unknown[] = [];
    alice.onVerdict((e) => verdicts.push(e));
    let caught: unknown;
    try {
      await alice.receive();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(NotVerified);
    expect(isTransient(caught)).toBe(false);
    expect(verdicts).toEqual([caught]);
    expect(waiting()).toBeGreaterThan(0);
  });
});
