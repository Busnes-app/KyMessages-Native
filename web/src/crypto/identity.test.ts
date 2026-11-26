import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Conflict, CryptoEngine, type KeyServer, type SealedMessage } from './engine';
import { FakeKeyServer, TENANT } from './fakeKeyServer';
import { loadCryptoSync } from './index';
import { deleteCryptoStores, openCryptoStore } from './store';
import { b64, loadPQCFrom, pqc, PQCUnavailable } from '../pqc/index';
import { LIST_WAIT_MAX_MS } from './identity';

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
    // An unverified device can still send, but it trusts no one, so no one gets its room key.
    const fromUnverified = await send('r1', bob, 'from an unverified device');
    expect(await read(alice, fromUnverified)).toBe('waiting');
    expect(server.sent.filter((s) => s.from === 'u_bob')).toHaveLength(0);

    await (await bob.prepareIdentity()).commit();
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
    const [alice] = await firstDevice(server, 'u_alice');
    const [bob] = await firstDevice(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    // The server strips bob's cross-signature: alice no longer trusts his device, though bob's
    // device still shares with her.
    delete server.devices.get('u_bob')!.get(bob.deviceId)!.master_signature;
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
  });

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
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow(PQCUnavailable);
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
    await server.as('u_bob').reserveDeviceList(m.version, epoch, 'ab'.repeat(32));
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
    const tablet = await open(server, 'u_bob', 'bob_tablet', { ...api, reserveDeviceList: async (v, e, d) => {
      const r = await reserve(v, e, d);
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
    await expect(laptop.restoreIdentity(rk)).rejects.toThrow(PQCUnavailable);
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
    const enrolling = await open(server, 'u_bob', 'bob_laptop', { ...api, reserveDeviceList: async (v, e, d) => {
      const r = await reserve(v, e, d);
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
    await server.as('u_bob').reserveDeviceList(m.version, m.device_list!.epoch, 'ab'.repeat(32)); // a full 30 s lease, abandoned
    const retry = vi.fn();
    laptop.onTransient(retry);
    const t0 = Date.now();
    expect(await laptop.identityStatus()).toMatchObject({ state: 'verified' });
    expect(Date.now() - t0).toBeLessThan(3_000);
    expect(retry).toHaveBeenCalled();
    // The lock is free meanwhile.
    server.join('r1', 'u_bob');
    await send('r1', laptop, 'not blocked');
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
    const tablet = await open(server, 'u_bob', 'bob_tablet', { ...api, reserveDeviceList: async (v, e, d) => {
      const r = await reserve(v, e, d);
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
