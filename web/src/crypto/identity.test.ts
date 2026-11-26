import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { CryptoEngine, type KeyServer, type SealedMessage } from './engine';
import { FakeKeyServer, TENANT } from './fakeKeyServer';
import { loadCryptoSync } from './index';
import { deleteCryptoStores, openCryptoStore } from './store';
import { b64, loadPQCFrom, pqc } from '../pqc/index';

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
  const p = e.prepareIdentity();
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
    // An unverified device can still send.
    expect(await read(alice, await send('r1', bob, 'from an unverified device'))).toBe('from an unverified device');

    await bob.prepareIdentity().commit();
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
    await bob.prepareIdentity(true).commit();
    await bob.identityStatus();
    const blocked = await send('r1', alice, 'held back');
    expect(await read(bob, blocked)).toBe('waiting');
    const changes = await alice.identityChanges();
    expect(changes.map((c) => c.user_id)).toEqual(['u_bob']);
    expect(changes[0].fingerprint).not.toBe(changes[0].previous);
    expect(changed).toHaveBeenCalled();

    // A user's own identity is never a change to accept.
    expect(await bob.identityChanges()).toEqual([]);
    await alice.acceptIdentity('u_bob');
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
    const payload = { v: 1, room_id: 'r1', session_id: 'x', sender_key: 'k', sender_user: 'u_bob', sender_device: 'D', first_index: 0, session_key: 'AAAA' };
    server.backups.set('u_alice', new Map([['r1\nx', { room_id: 'r1', session_id: 'x', first_index: 0,
      sealed: pqc.backupSeal(m.backup_key.public_key, forger.seed, 'r1', 'x', b64(JSON.stringify(payload))) }]]));
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
