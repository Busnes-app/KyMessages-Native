import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { CryptoEngine, parseEnvelope, ROTATE_AFTER_MESSAGES, ROTATE_AFTER_MS, type SealedMessage } from './engine';
import { FakeKeyServer } from './fakeKeyServer';
import { Account, loadCryptoSync } from './index';
import { deleteCryptoStores, openCryptoStore } from './store';

beforeAll(() => {
  loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm'));
});

const opened: CryptoEngine[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const e of opened.splice(0)) e.close();
  await deleteCryptoStores();
});

async function device(server: FakeKeyServer, userId: string): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(userId, server.as(userId), await openCryptoStore(userId));
  opened.push(e);
  return e;
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
    await alice.membershipChanged('r1', true);
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
    await alice.membershipChanged('r1', false); // only a refresh, as after a missed event
    const after = await send('r1', alice, 'two');
    expect(parseEnvelope(after.body)!.session_id).not.toBe(parseEnvelope(before.body)!.session_id);
  });

  it('rotates after a removal missed while the connection was down', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bob = await device(server, 'u_bob');
    const carol = await device(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_bob', 'u_carol');
    const before = await send('r1', alice, 'all three');
    // The socket drops; carol is removed meanwhile and the room.member event never arrives.
    alice.setMembershipLive(false);
    server.leave('r1', 'u_carol');
    // Reconnected well inside the device-list cache's lifetime.
    alice.setMembershipLive(true);
    const after = await send('r1', alice, 'carol is gone');
    expect(parseEnvelope(after.body)!.session_id).not.toBe(parseEnvelope(before.body)!.session_id);
    await bob.receive();
    await carol.receive();
    expect(await read(bob, after)).toBe('carol is gone');
    expect(await read(carol, after)).toBe('waiting');
  });

  it('lists members again for every send while the connection is down', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const carol = await device(server, 'u_carol');
    server.join('r1', 'u_alice', 'u_carol');
    alice.setMembershipLive(false);
    const before = await send('r1', alice, 'one');
    server.leave('r1', 'u_carol');
    const after = await send('r1', alice, 'two');
    expect(parseEnvelope(after.body)!.session_id).not.toBe(parseEnvelope(before.body)!.session_id);
    await carol.receive();
    expect(await read(carol, after)).toBe('waiting');
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
    await alice.membershipChanged('r1', false);
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
    await alice.membershipChanged('r1', false);
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

  it('leaves mail for later when the server cannot list the sender', async () => {
    const server = new FakeKeyServer();
    const alice = await device(server, 'u_alice');
    const bobServer = server.as('u_bob');
    const bob = await CryptoEngine.open('u_bob', bobServer, await openCryptoStore('u_bob'));
    opened.push(bob);
    server.join('r1', 'u_alice', 'u_bob');
    const m1 = await send('r1', alice, 'later');
    const query = bobServer.query;
    bobServer.query = () => Promise.reject(new Error('offline'));
    expect(await bob.receive()).toEqual([]);
    expect(server.mail.get(`u_bob\n${bob.deviceId}`)).toHaveLength(1);
    bobServer.query = query;
    await bob.receive();
    expect(await read(bob, m1)).toBe('later');
  });
});
