import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { botDeviceCode, CryptoEngine, deviceSigned } from './engine';
import { Account } from './index';
import { FakeKeyServer, TENANT } from './fakeKeyServer';
import { loadCryptoSync } from './index';
import { loadPQCFrom, pqc } from '../pqc/index';
import { deleteCryptoStores, openCryptoStore } from './store';

// E4 (docs/superpowers/specs/2026-11-22-e2ee-design.md §8): a bot is a device its owner's master
// key vouches for. These play the key server honest and hostile, with real engines for people.

beforeAll(async () => {
  loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm'));
  await loadPQCFrom(readFileSync('src/pqc/pqc.wasm'));
});

const opened: CryptoEngine[] = [];
afterEach(async () => {
  for (const e of opened.splice(0)) e.close();
  await deleteCryptoStores();
});

async function person(server: FakeKeyServer, userId: string): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(userId, server.as(userId), await openCryptoStore(userId));
  opened.push(e);
  const p = await e.prepareIdentity();
  await p.commit();
  return e;
}

/** A bot's device: registered with self-signed keys, as the bundle in agent-skill/ does. */
async function botDevice(server: FakeKeyServer, botId: string, store = botId): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(botId, server.as(botId), await openCryptoStore(store));
  opened.push(e);
  return e;
}

const BOT = 'bot_helper';
const mailTo = (server: FakeKeyServer, d: CryptoEngine) => (server.mail.get(`${d.userId}\n${d.deviceId}`) ?? []).length;
const keysOf = (d: CryptoEngine) => ({ device_id: d.deviceId, curve25519: d.curve25519, ed25519: d.ed25519 });

async function setup() {
  const server = new FakeKeyServer();
  const alice = await person(server, 'u_alice');
  const bob = await person(server, 'u_bob');
  const bot = await botDevice(server, BOT);
  server.botOwners.set(BOT, 'u_alice');
  server.join('r1', 'u_alice', 'u_bob', BOT);
  return { server, alice, bob, bot };
}

/** The owner vouches for d as the server shows it, having matched its code; no d revokes all. */
async function vouch(owner: CryptoEngine, d?: CryptoEngine) {
  const view = await owner.botDevices(BOT);
  if (!d) {
    for (const [i, v] of view.vouched.entries()) await owner.vouchForBot(BOT, view.epoch + i, { remove: v.device_id });
    return;
  }
  await owner.vouchForBot(BOT, view.epoch, { add: view.uploaded.find((u) => u.device_id === d.deviceId)! });
}

describe('bots as devices (E4)', () => {
  it('derives the code the bot shows exactly as the bundle does', () => {
    // agent-skill/tests/test_kybot.py pins the same value.
    expect(botDeviceCode({ device_id: 'BOTDEVICE1', curve25519: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU', ed25519: 'MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY' }, 'bot_helper')).toBe('a375-b438-12e4-6bba-55a7');
  });

  it('gives room keys to a bot device its owner vouched for, and to no other', async () => {
    const { server, alice, bob, bot } = await setup();
    await bob.encrypt('r1', { type: 'text', body: 'before vouching' });
    expect(mailTo(server, bot)).toBe(0);

    await vouch(alice, bot);
    expect((await alice.botDevices(BOT)).vouched).toEqual([keysOf(bot)]);
    // A colleague's engine pins the owner, not the bot, and shares with the vouched device.
    await bob.encrypt('r1', { type: 'text', body: 'after vouching' });
    expect(mailTo(server, bot)).toBe(1);
  });

  it('refuses a bot device not signed by the owner’s master key', async () => {
    const { server, alice, bob, bot } = await setup();
    // The server forges the owner's list with another master key, then with Bob's, the owner of nothing.
    const mallory = pqc.masterGenerate();
    for (const seed of [mallory.seed]) {
      const devices = [keysOf(bot)];
      server.botLists.set(BOT, { owner_id: 'u_alice', version: 1, epoch: 1, devices, signature: pqc.signBotDevices(seed, TENANT, 'u_alice', 1, BOT, 1, devices) });
      await bob.encrypt('r1', { type: 'text', body: 'forged list' });
      expect(mailTo(server, bot)).toBe(0);
    }
    // A list signed by the owner for another bot does not vouch for this one.
    const other = await botDevice(server, 'bot_other');
    server.botOwners.set('bot_other', 'u_alice');
    const view = await alice.botDevices('bot_other');
    await alice.vouchForBot('bot_other', 0, { add: view.uploaded[0] });
    server.botLists.set(BOT, { ...server.botLists.get('bot_other')!, devices: [keysOf(bot)] });
    await bob.encrypt('r1', { type: 'text', body: 'list moved between bots' });
    expect(mailTo(server, bot)).toBe(0);
    expect(other.deviceId).toBeTruthy();
  });

  it('gives a revoked bot device no new room keys, even when the server shows the old list again', async () => {
    const { server, alice, bob, bot } = await setup();
    await vouch(alice, bot);
    await bob.encrypt('r1', { type: 'text', body: 'while trusted' });
    expect(mailTo(server, bot)).toBe(1);
    const old = structuredClone(server.botLists.get(BOT)!);

    await vouch(alice); // the owner revokes it: an empty list at the next epoch
    await bob.encrypt('r1', { type: 'text', body: 'after revocation' });
    // Bob's next message is under a new session (the bot had the old one), and the bot gets none.
    expect(mailTo(server, bot)).toBe(1);

    server.botLists.set(BOT, old); // rolled back
    await bob.encrypt('r1', { type: 'text', body: 'after rollback' });
    expect(mailTo(server, bot)).toBe(1);
    server.botLists.delete(BOT); // dropped once seen
    await bob.encrypt('r1', { type: 'text', body: 'after the list went missing' });
    expect(mailTo(server, bot)).toBe(1);
  });

  it('pins a bot’s owner, so the server cannot name another member to vouch for it', async () => {
    const { server, alice, bob, bot } = await setup();
    await vouch(alice, bot);
    await bob.encrypt('r1', { type: 'text', body: 'pins Alice as the owner' });
    // Mallory, a real colleague with a valid identity, signs a list for the bot with her device.
    const mallory = await person(server, 'u_mallory');
    const evil = await botDevice(server, BOT, 'mallory-bot');
    server.botOwners.set(BOT, 'u_mallory');
    const view = await mallory.botDevices(BOT);
    await mallory.vouchForBot(BOT, 0, { add: view.uploaded.find((d) => d.device_id === evil.deviceId)! });
    expect(server.botLists.get(BOT)!.owner_id).toBe('u_mallory');
    await bob.memberLeft('r1');
    await bob.encrypt('r1', { type: 'text', body: 'after the owner swap' });
    expect(mailTo(server, evil)).toBe(0);
  });

  it('never lets the server add a device to a bot', async () => {
    const { server, alice, bob, bot } = await setup();
    await vouch(alice, bot);
    // The server registers its own device for the bot (self-signed, as any upload is) and
    // splices it into the owner's list; then it swaps the vouched device's keys.
    const evil = await botDevice(server, BOT, 'evil-store');
    const signed = server.botLists.get(BOT)!;
    server.botLists.set(BOT, { ...signed, devices: [...signed.devices, keysOf(evil)].sort((a, b) => (a.device_id < b.device_id ? -1 : 1)) });
    await bob.encrypt('r1', { type: 'text', body: 'spliced' });
    expect(mailTo(server, evil)).toBe(0);
    // A bot can also never vouch for itself with a master key of its own.
    server.botLists.set(BOT, signed);
    const own = pqc.masterGenerate();
    server.masters.set(BOT, { version: 1, master_key: own.public_key, self_signature: pqc.signMaster(own.seed, TENANT, BOT), backup_key: { public_key: '', signature: '' }, backup_generation: 0, recovery: { wrapped_master_key: '', wrapped_backup_key: '' }, pins: { counter: 0, sealed: '' } });
    server.devices.get(BOT)!.get(evil.deviceId)!.master_signature = pqc.signDevice(own.seed, TENANT, BOT, evil.deviceId, evil.curve25519, evil.ed25519);
    await bob.encrypt('r1', { type: 'text', body: 'self-signed bot' });
    expect(mailTo(server, evil)).toBe(0);
    // Nor with no owner list at all: a bot the server keys up itself gets nothing.
    const rogue = await botDevice(server, 'bot_rogue');
    server.join('r1', 'bot_rogue');
    server.masters.set('bot_rogue', { ...server.masters.get(BOT)!, self_signature: pqc.signMaster(own.seed, TENANT, 'bot_rogue') });
    server.devices.get('bot_rogue')!.get(rogue.deviceId)!.master_signature = pqc.signDevice(own.seed, TENANT, 'bot_rogue', rogue.deviceId, rogue.curve25519, rogue.ed25519);
    server.masters.get('bot_rogue')!.device_list = { epoch: 1, device_ids: [rogue.deviceId], signature: pqc.signDeviceList(own.seed, TENANT, 'bot_rogue', 1, 1, [rogue.deviceId]) };
    await bob.encrypt('r1', { type: 'text', body: 'rogue bot' });
    await bob.encrypt('r1', { type: 'text', body: 'rogue bot, pinned' });
    expect(mailTo(server, rogue)).toBe(0);
    expect(mailTo(server, bot)).toBeGreaterThan(0);

    // The owner vouches only for a device whose code matches what the bot shows.
    const view = await alice.botDevices(BOT);
    const shown = view.uploaded.find((d) => d.device_id === bot.deviceId)!;
    expect(shown.code).toBe(botDeviceCode({ user_id: BOT, ...keysOf(bot) }));
    await expect(alice.vouchForBot(BOT, view.epoch, { add: { ...shown, ed25519: evil.ed25519 } })).rejects.toThrow(/code/);
  });

  it('never signs keys the server swapped in under a vouched device ID when another device changes', async () => {
    const { server, alice, bob, bot } = await setup();
    await vouch(alice, bot);
    // The server swaps the vouched device's keys for its own (self-signed, as any upload is);
    // Alice's browser has no pin for the bot's device.
    const acct = new Account();
    const swapped = { curve25519: acct.curve25519, ed25519: acct.ed25519, signature: acct.sign(deviceSigned(BOT, bot.deviceId, acct.curve25519, acct.ed25519)) };
    acct.free();
    Object.assign(server.devices.get(BOT)!.get(bot.deviceId)!, swapped);
    const view = await alice.botDevices(BOT);
    expect(view.uploaded.find((d) => d.device_id === bot.deviceId)!.ed25519).toBe(swapped.ed25519);
    expect(view.vouched).toEqual([keysOf(bot)]);
    // Alice vouches for a second device, then removes it: the first keeps its signed keys.
    const second = await botDevice(server, BOT, 'second-store');
    await vouch(alice, second);
    expect(server.botLists.get(BOT)!.devices).toEqual([keysOf(bot), keysOf(second)].sort((a, b) => (a.device_id < b.device_id ? -1 : 1)));
    await alice.vouchForBot(BOT, 2, { remove: second.deviceId });
    expect(server.botLists.get(BOT)!.devices).toEqual([keysOf(bot)]);
    await bob.encrypt('r1', { type: 'text', body: 'swapped keys' });
    // Nobody shares with the swapped keys either.
    expect(mailTo(server, bot)).toBe(0);
  });

  it('signs the kept entries only from a list that verifies, and refuses a stale epoch', async () => {
    const { server, alice, bot } = await setup();
    await vouch(alice, bot);
    const second = await botDevice(server, BOT, 'second-store');
    const view = await alice.botDevices(BOT);
    await expect(alice.vouchForBot(BOT, 0, { add: view.uploaded.find((d) => d.device_id === second.deviceId)! })).rejects.toThrow(/changed/);
    // A list the server forged (not Alice's signature) vouches for nothing, so nothing of it is kept.
    const forged = pqc.masterGenerate();
    const evil = [{ device_id: 'EVILDEVICE', curve25519: bot.curve25519, ed25519: bot.ed25519 }];
    server.botLists.set(BOT, { owner_id: 'u_alice', version: 1, epoch: 2, devices: evil, signature: pqc.signBotDevices(forged.seed, TENANT, 'u_alice', 1, BOT, 2, evil) });
    await alice.vouchForBot(BOT, 2, { add: view.uploaded.find((d) => d.device_id === second.deviceId)! });
    expect(server.botLists.get(BOT)!.devices).toEqual([keysOf(second)]);
  });
});
