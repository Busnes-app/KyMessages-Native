import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { CryptoEngine, DeviceChanged, deviceSigned, oneTimeKeySigned, parseEnvelope, ROTATE_AFTER_MESSAGES, ROTATE_AFTER_MS, type SealedMessage } from './engine';
import { FakeKeyServer } from './fakeKeyServer';
import { Account, GroupSession, loadCryptoSync } from './index';
import { loadPQCFrom } from '../pqc/index';
import { deleteCryptoStores, openCryptoStore } from './store';

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

// Each user's recovery key, so a test's later devices of that user verify as a person would.
const recoveryKeys = new WeakMap<FakeKeyServer, Map<string, string>>();

/** Gives e's user an identity (the first device) or verifies e with it (later devices). */
async function verify(server: FakeKeyServer, e: CryptoEngine): Promise<CryptoEngine> {
  const keys = recoveryKeys.get(server) ?? new Map<string, string>();
  recoveryKeys.set(server, keys);
  const status = await e.identityStatus();
  if (status.state === 'none') {
    const p = e.prepareIdentity();
    keys.set(e.userId, p.recoveryKey);
    await p.commit();
  } else if (status.state === 'unverified') {
    await e.restoreIdentity(keys.get(e.userId)!);
  }
  return e;
}

async function device(server: FakeKeyServer, userId: string, storeName = userId): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(userId, server.as(userId), await openCryptoStore(storeName));
  opened.push(e);
  return verify(server, e);
}

let nextId = 1;
// What the server stores when sender posts envelope in roomId.
function post(roomId: string, sender: CryptoEngine, envelope: string): SealedMessage {
  return { id: `msg_${nextId++}`, room_id: roomId, sender_id: sender.userId, body: envelope };
}

async function send(roomId: string, sender: CryptoEngine, body: string): Promise<SealedMessage> {
  return post(roomId, sender, await sender.encrypt(roomId, { type: 'text', body }));
}

async function read(reader: CryptoEngine, m: SealedMessage): Promise<string> {
  const r = await reader.decrypt(m);
  if (r.state === 'decrypted') return r.inner.body;
  return r.state === 'waiting' ? 'waiting' : `failed: ${r.reason}`;
}

describe('encrypted rooms between two client engines', () => {
  it('publishes signed keys, shares the room key over Olm and decrypts', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    expect(server.oneTimeKeyCount('u_bob', bob.deviceId)).toBe(50);

    const m1 = await send('r1', alice, 'hello bob');
    // The key travels as a to-device kymessages.room_key.v1 message; the envelope names its sender.
    expect(server.sent).toEqual([{ from: 'u_alice', to: 'u_bob', type: 'kymessages.room_key.v1' }]);
    expect(parseEnvelope(m1.body)).toMatchObject({ alg: 'megolm.v1', sender_key: alice.curve25519, device_id: alice.deviceId });
    expect(m1.body).not.toContain('hello');
    expect(server.oneTimeKeyCount('u_bob', bob.deviceId)).toBe(49);

    expect(await read(bob, m1)).toBe('waiting');
    const arrived = vi.fn();
    bob.onKeys(arrived);
    const sessions = await bob.receive();
    expect(sessions).toEqual([parseEnvelope(m1.body)!.session_id]);
    expect(arrived).toHaveBeenCalledWith(sessions);
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toEqual([]);
    expect(await read(bob, m1)).toBe('hello bob');
    expect(await read(alice, m1)).toBe('hello bob');
    // Bob's device used a one-time key and tops the server back up.
    expect(server.oneTimeKeyCount('u_bob', bob.deviceId)).toBe(50);

    // Later messages reuse the session and the Olm channel: no new key mail.
    const m2 = await send('r1', alice, 'second');
    expect(server.sent).toHaveLength(1);
    expect(await read(bob, m2)).toBe('second');

    // Bob answers over his own session.
    const m3 = await send('r1', bob, 'hi alice');
    await alice.receive();
    expect(await read(alice, m3)).toBe('hi alice');
  });

  it('serializes replacement and stale work, preserving inbound keys while concurrent resets converge', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const tabServer = server.as('u_alice');
    const otherTab = await CryptoEngine.open('u_alice', tabServer, await openCryptoStore('u_alice'));
    opened.push(otherTab);
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const history = await send('r1', bob, 'preserved peer history');
    await alice.receive();
    expect(await read(otherTab, history)).toBe('preserved peer history');
    const shared = await openCryptoStore('u_alice');
    try {
      const pins = await shared.list('pin:');
      const replay = await shared.list('seen:');
      expect(pins.length).toBeGreaterThan(0);
      expect(replay.length).toBeGreaterThan(0);
      let release = () => {};
      const held = new Promise<void>((resolve) => { release = resolve; });
      const query = tabServer.query;
      const querying = vi.fn(async (ids: string[]) => { await held; return query(ids); });
      tabServer.query = querying;
      const sending = send('r1', otherTab, 'before the reset');
      await vi.waitFor(() => expect(querying).toHaveBeenCalled());
      let replaced = false;
      const replacing = CryptoEngine.resetDevice('u_alice', alice.deviceId, shared).then(() => { replaced = true; });
      try {
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(replaced).toBe(false); // replacement cannot mutate an operation's account mid-flight
      } finally {
        release();
        await Promise.all([sending, replacing]);
      }
      server.devices.get('u_alice')!.delete(alice.deviceId);
      const fresh = await device(server, 'u_alice');
      await Promise.all([
        CryptoEngine.resetDevice('u_alice', alice.deviceId, shared),
        CryptoEngine.resetDevice('u_alice', alice.deviceId, shared),
      ]); // late resets of the retired ID cannot delete the new identity
      await expect(otherTab.encrypt('r1', { type: 'text', body: 'stale' })).rejects.toBeInstanceOf(DeviceChanged);
      expect(await read(fresh, history)).toBe('preserved peer history');
      expect(await shared.list('pin:')).toEqual(pins);
      expect(await shared.list('seen:')).toEqual(replay);
      await send('r1', fresh, 'valid replacement');
    } finally {
      shared.close();
    }
  });

  it('restores the device from IndexedDB', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'kept');
    await bob.receive();
    bob.close();
    opened.splice(opened.indexOf(bob), 1);
    const again = await device(server, 'u_bob');
    expect(again.deviceId).toBe(bob.deviceId);
    expect(again.curve25519).toBe(bob.curve25519);
    expect(await read(again, m1)).toBe('kept');
  });

  it('refuses a message moved into another room', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    server.join('r2', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'for r1 only');
    await bob.receive();
    expect(await read(bob, { ...m1, room_id: 'r2' })).toBe('failed: This message was encrypted for another room.');
    expect(await read(bob, m1)).toBe('for r1 only');
  });

  it('refuses a message whose sender the server rewrote', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    await device(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob', 'u_carol');
    const m1 = await send('r1', alice, 'from alice');
    await bob.receive();
    expect(await read(bob, { ...m1, sender_id: 'u_carol' })).toBe('failed: This message did not come from the device it names.');
  });

  it('refuses a replayed ciphertext but reopens the original', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'pay 10');
    await bob.receive();
    expect(await read(bob, m1)).toBe('pay 10');
    const replay = post('r1', alice, m1.body);
    expect(await read(bob, replay)).toBe('failed: This message is a replay of another message.');
    expect(await read(bob, m1)).toBe('pay 10');
  });

  it('binds an edit to the message it edits', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'draft');
    const m2 = await send('r1', alice, 'other');
    const edit = await alice.encrypt('r1', { type: 'edit', body: 'final', message_id: m1.id });
    await bob.receive();
    expect(await read(bob, { ...m1, body: edit })).toBe('final');
    expect(await read(bob, { ...m2, body: edit })).toBe('failed: This edit belongs to another message.');
  });

  it('rotates when a member leaves, so they cannot read what follows', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    const carol = await device(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob', 'u_carol');
    const before = await send('r1', alice, 'all three');
    await carol.receive();
    expect(await read(carol, before)).toBe('all three');

    server.leave('r1', 'u_carol');
    await alice.memberLeft('r1');
    const after = await send('r1', alice, 'carol is gone');
    expect(parseEnvelope(after.body)!.session_id).not.toBe(parseEnvelope(before.body)!.session_id);
    await bob.receive();
    await carol.receive();
    expect(await read(bob, after)).toBe('carol is gone');
    expect(await read(carol, after)).toBe('waiting');
  });

  it('rotates when a member is found gone without an event', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const before = await send('r1', alice, 'one');
    server.leave('r1', 'u_bob');
    const after = await send('r1', alice, 'two');
    expect(parseEnvelope(after.body)!.session_id).not.toBe(parseEnvelope(before.body)!.session_id);
  });

  it('discards a member list made stale by a removal during device discovery', async () => {
    const server = new FakeKeyServer();
    const aliceServer = server.as('u_alice');
    const alice = await CryptoEngine.open('u_alice', aliceServer, await openCryptoStore('u_alice'));
    opened.push(alice);
    const bob = await device(server, 'u_bob');
    const carol = await device(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob', 'u_carol');
    // The room's first send discovers its devices slowly; carol is removed while that is in flight.
    const query = aliceServer.query;
    let unblock: (() => void) | undefined;
    aliceServer.query = (ids) => new Promise((resolve) => { unblock = () => void query(ids).then(resolve); });
    const inFlight = alice.encrypt('r1', { type: 'text', body: 'racing the removal' });
    await vi.waitFor(() => expect(unblock).toBeDefined());
    server.leave('r1', 'u_carol');
    const left = alice.memberLeft('r1');
    unblock!();
    await inFlight;
    await left;
    aliceServer.query = query;
    // Every later message is sealed under a session carol never receives.
    const after = await send('r1', alice, 'carol is gone');
    await bob.receive();
    await carol.receive();
    expect(await read(bob, after)).toBe('carol is gone');
    expect(await read(carol, after)).toBe('waiting');
    const later = await send('r1', alice, 'still gone');
    await carol.receive();
    expect(await read(carol, later)).toBe('waiting');
  });

  it('publishes a new fallback key when the server has none live, as after a restore', async () => {
    const server = new FakeKeyServer();
    const bob = await device(server, 'u_bob');
    const id = `u_bob\n${bob.deviceId}`;
    const before = server.fallbackKeys.get(id)!.key_id;
    // A restore retires every key the device had published.
    server.fallbackKeys.delete(id);
    server.oneTimeKeys.delete(id);
    bob.close();
    const again = await CryptoEngine.open('u_bob', server.as('u_bob'), await openCryptoStore('u_bob'));
    opened.push(again);
    expect(again.deviceId).toBe(bob.deviceId);
    expect(server.fallbackKeys.get(id)?.key_id).toBeDefined();
    expect(server.fallbackKeys.get(id)!.key_id).not.toBe(before);
    expect(server.oneTimeKeyCount('u_bob', bob.deviceId)).toBe(50);
  });

  it('reads room keys queued by a device that signed out before they were read', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'sent before sign-out');
    // Alice signs out (her device leaves the key server) while Bob is offline.
    server.devices.get('u_alice')!.delete(alice.deviceId);
    await bob.receive();
    expect(await read(bob, m1)).toBe('sent before sign-out');
  });

  it('refuses mail whose carried sender keys are not validly signed', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'forged');
    const [mail] = server.mail.get(`u_bob\n${bob.deviceId}`)!;
    mail.sender_keys = { ...mail.sender_keys, signature: mail.sender_keys.signature.replace(/^./, (ch) => (ch === 'A' ? 'B' : 'A')) };
    await bob.receive();
    expect(await read(bob, m1)).toBe('waiting');
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toEqual([]);
  });

  it('keeps sharing with healthy devices when a member publishes a key the crypto core refuses', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    // Mallory's device validly signs a one-time key that is all zeros (non-contributory).
    const acct = new Account();
    const mid = 'MALLORYDEV1';
    const zero = btoa(String.fromCharCode(...new Uint8Array(32))).replace(/=+$/, '');
    await server.as('u_mallory').upload({
      device_id: mid,
      device_keys: { curve25519: acct.curve25519, ed25519: acct.ed25519, signature: acct.sign(deviceSigned('u_mallory', mid, acct.curve25519, acct.ed25519)) },
      one_time_keys: [{ key_id: 'AAAAAQ', key: zero, signature: acct.sign(oneTimeKeySigned('u_mallory', mid, 'AAAAAQ', zero)) }],
    });
    acct.free();
    server.join('r1', 'u_alice', 'u_bob', 'u_mallory');
    const m1 = await send('r1', alice, 'still delivered');
    await bob.receive();
    expect(await read(bob, m1)).toBe('still delivered');
  });

  it('announces stored room keys before a stalled replenishment upload finishes', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bobServer = server.as('u_bob');
    const bob = await CryptoEngine.open('u_bob', bobServer, await openCryptoStore('u_bob'));
    await verify(server, bob);
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const message = await send('r1', alice, 'read while upload stalls');
    const arrived = vi.fn();
    bob.onKeys(arrived);
    let release = () => {};
    const stalled = new Promise<void>((resolve) => { release = resolve; });
    const upload = bobServer.upload;
    const uploading = vi.fn(async (...args: Parameters<typeof upload>) => {
      await stalled;
      return upload(...args);
    });
    bobServer.upload = uploading;
    const receiving = bob.receive();
    try {
      await vi.waitFor(() => expect(uploading).toHaveBeenCalled());
      expect(arrived).toHaveBeenCalledWith([parseEnvelope(message.body)!.session_id]);
      expect(await read(bob, message)).toBe('read while upload stalls');
    } finally {
      release();
      await receiving;
    }
  });

  it('announces stored room keys even when acknowledging the mail fails', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bobServer = server.as('u_bob');
    const bob = await CryptoEngine.open('u_bob', bobServer, await openCryptoStore('u_bob'));
    await verify(server, bob);
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'acked later');
    const arrived = vi.fn();
    bob.onKeys(arrived);
    bobServer.ack = () => Promise.reject(new Error('offline'));
    await expect(bob.receive()).rejects.toThrow('offline');
    expect(arrived).toHaveBeenCalledWith([parseEnvelope(m1.body)!.session_id]);
    expect(await read(bob, m1)).toBe('acked later');
  });

  it('shares the key with a member’s new device on the very next send', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'before');
    // Bob signs in on a second browser; no event tells alice.
    const laptop = await CryptoEngine.open('u_bob', server.as('u_bob'), await openCryptoStore('u_bob_laptop'));
    await verify(server, laptop);
    opened.push(laptop);
    const m = await send('r1', alice, 'reaches the laptop');
    await laptop.receive();
    expect(await read(laptop, m)).toBe('reaches the laptop');
  });

  it('keeps the largest allowed message under the server envelope limit', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    server.join('r1', 'u_alice');
    // MAX_INNER_BYTES (32 KiB) of sealed JSON must fit maxEnvelopeLen (48 KiB) on the server.
    const overhead = JSON.stringify({ type: 'text', body: '', room_id: 'r1' }).length;
    const envelope = await alice.encrypt('r1', { type: 'text', body: 'x'.repeat((32 << 10) - overhead) });
    expect(envelope.length).toBeLessThan(48 << 10);
  });

  it('rotates after 100 messages and after 7 days', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    server.join('r1', 'u_alice');
    const first = parseEnvelope((await send('r1', alice, '0')).body)!.session_id;
    for (let i = 1; i < ROTATE_AFTER_MESSAGES; i++) await alice.encrypt('r1', { type: 'text', body: String(i) });
    const second = parseEnvelope((await send('r1', alice, '100')).body)!.session_id;
    expect(second).not.toBe(first);
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + ROTATE_AFTER_MS);
    const third = parseEnvelope((await send('r1', alice, 'a week later')).body)!.session_id;
    expect(third).not.toBe(second);
  });

  it('gives a new member the current session only, never older messages', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const old = await send('r1', alice, 'before dave');
    await bob.receive();

    const dave = await device(server, 'u_dave');
    server.join('r1', 'u_dave');
    const now = await send('r1', alice, 'welcome dave');
    // Same session (a join does not rotate), shared from its current index on.
    expect(parseEnvelope(now.body)!.session_id).toBe(parseEnvelope(old.body)!.session_id);
    await dave.receive();
    expect(await read(dave, now)).toBe('welcome dave');
    expect(await read(dave, old)).toBe('failed: This message was sent before this device could read the room.');
    expect(await read(bob, old)).toBe('before dave');
  });

  it('shares keys with a member’s other devices and its own other devices', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    // A second browser for alice: a separate store, so a separate device.
    const aliceStore = await openCryptoStore('u_alice_laptop');
    const laptop = await CryptoEngine.open('u_alice', server.as('u_alice'), aliceStore);
    await verify(server, laptop);
    opened.push(laptop);
    expect(laptop.deviceId).not.toBe(alice.deviceId);
    const m1 = await send('r1', alice, 'on every device');
    await bob.receive();
    await laptop.receive();
    expect(await read(bob, m1)).toBe('on every device');
    expect(await read(laptop, m1)).toBe('on every device');
  });

  it('sends no key to a device whose signatures do not check out', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob', 'u_mallory');
    // The server invents a device for mallory, signed by a key that is not the device's.
    const real = new Account();
    const other = new Account();
    server.devices.set('u_mallory', new Map([['MALLORY01', {
      device_id: 'MALLORY01', curve25519: real.curve25519, ed25519: real.ed25519,
      signature: other.sign(`kymessages.device.v1\nu_mallory\nMALLORY01\n${real.curve25519}\n${real.ed25519}`),
    }]]));
    // And swaps one of bob's one-time keys for one bob never signed.
    const bobKeys = server.oneTimeKeys.get(`u_bob\n${bob.deviceId}`)!;
    other.generateOneTimeKeys(1);
    const [forged] = Object.values(JSON.parse(other.oneTimeKeys()) as Record<string, string>);
    bobKeys[0] = { ...bobKeys[0], key: forged };
    real.free();
    other.free();

    await send('r1', alice, 'not for mallory');
    // Bob's forged key was refused, so he gets nothing this time; mallory never does.
    expect(server.sent).toEqual([]);
    const m2 = await send('r1', alice, 'second try');
    expect(server.sent.map((s) => s.to)).toEqual(['u_bob']);
    await bob.receive();
    expect(await read(bob, m2)).toBe('second try');
  });

  it('drops a device whose keys changed after they were pinned', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    await send('r1', alice, 'pins bob');
    // The server replaces bob's device keys with ones it holds, validly self-signed.
    const fake = new Account();
    const signed = `kymessages.device.v1\nu_bob\n${bob.deviceId}\n${fake.curve25519}\n${fake.ed25519}`;
    server.devices.get('u_bob')!.set(bob.deviceId, { device_id: bob.deviceId, curve25519: fake.curve25519, ed25519: fake.ed25519, signature: fake.sign(signed) });
    fake.free();
    expect(await alice.verifiedDevices(['u_bob'])).toEqual([]);
  });

  it('keeps the real sender’s session when a member re-shares it as their own first', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    const mallory = await device(server, 'u_mallory');
    server.join('r1', 'u_alice', 'u_bob', 'u_mallory');
    // Mallory, a member, learns the signed session key Alice shares with everyone.
    const keys: string[] = [];
    const real = GroupSession.prototype.sessionKey;
    vi.spyOn(GroupSession.prototype, 'sessionKey').mockImplementation(function (this: GroupSession) {
      const k = real.call(this);
      keys.push(k);
      return k;
    });
    const m1 = await send('r1', alice, 'from alice');
    const sessionId = parseEnvelope(m1.body)!.session_id;
    // She forwards it to Bob as her own session, and her mail reaches him before Alice's.
    const [bobDevice] = await mallory.verifiedDevices(['u_bob']);
    const forged = { sessionId, sessionKey: () => keys[0] } as unknown as GroupSession;
    await (mallory as unknown as { shareRoomKey(r: string, g: GroupSession, t: unknown[]): Promise<unknown> }).shareRoomKey('r1', forged, [bobDevice]);
    const box = server.mail.get(`u_bob\n${bob.deviceId}`)!;
    box.unshift(box.pop()!);
    expect(box[0].sender_user_id).toBe('u_mallory');
    await bob.receive();
    // Mallory re-posts Alice's ciphertext as hers first, aiming to claim its message index.
    const asMallory = { ...post('r1', mallory, JSON.stringify({ ...parseEnvelope(m1.body)!, sender_key: mallory.curve25519, device_id: mallory.deviceId })) };
    expect(await read(bob, asMallory)).toBe('from alice');
    // Alice's message still opens as hers, and is no replay.
    expect(await read(bob, m1)).toBe('from alice');
    const m2 = await send('r1', alice, 'still alice');
    expect(await read(bob, m2)).toBe('still alice');
  });

  it('refuses room keys from a device that is not the sender’s', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'hi');
    // The server relabels alice's key mail as coming from carol.
    await device(server, 'u_carol');
    for (const m of server.mail.get(`u_bob\n${bob.deviceId}`)!) m.sender_user_id = 'u_carol';
    expect(await bob.receive()).toEqual([]);
    // Refused mail is acknowledged, not retried forever.
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toEqual([]);
    expect(await read(bob, m1)).toBe('waiting');
  });

  it('reads mail without listing the sender, whose keys the mail carries', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bobServer = server.as('u_bob');
    const bob = await CryptoEngine.open('u_bob', bobServer, await openCryptoStore('u_bob'));
    await verify(server, bob);
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'later');
    const query = bobServer.query;
    bobServer.query = () => Promise.reject(new Error('offline'));
    await bob.receive();
    expect(await read(bob, m1)).toBe('later');
    bobServer.query = query;
  });

  it('keeps a room key whose write fails in local storage, even after its one-time key is spent', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const store = await openCryptoStore('u_bob');
    const write = store.write.bind(store);
    let fail = true;
    // The first write of a room session fails as a full disk would.
    store.write = async (puts, deletes) => {
      if (fail && puts.some(([k]) => k.startsWith('in:'))) {
        fail = false;
        throw new DOMException('quota exceeded', 'QuotaExceededError');
      }
      return write(puts, deletes);
    };
    const bob = await CryptoEngine.open('u_bob', server.as('u_bob'), store);
    await verify(server, bob);
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'kept for later'); // a pre-key message: spends a one-time key
    expect(await bob.receive()).toEqual([]);
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toHaveLength(1);
    expect(await read(bob, m1)).toBe('waiting');
    expect(await bob.receive()).toHaveLength(1);
    expect(await read(bob, m1)).toBe('kept for later');
  });

  it('keeps the Olm state when reading the stored room key fails, so the mail decrypts again', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const store = await openCryptoStore('u_bob');
    const get = store.get.bind(store);
    let fail = true;
    // The first lookup of a room session fails as a closed or broken store would.
    store.get = (async (key: string) => {
      if (fail && key.startsWith('in:')) {
        fail = false;
        throw new DOMException('store closed', 'InvalidStateError');
      }
      return get(key);
    }) as typeof store.get;
    const bob = await CryptoEngine.open('u_bob', server.as('u_bob'), store);
    await verify(server, bob);
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'read on retry'); // a pre-key message: spends a one-time key
    expect(await bob.receive()).toEqual([]);
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toHaveLength(1);
    expect(await bob.receive()).toHaveLength(1);
    expect(await read(bob, m1)).toBe('read on retry');
  });
});
