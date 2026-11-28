import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CryptoEngine, type KeyServer, type SealedMessage } from './engine';
import { FakeKeyServer, TENANT } from './fakeKeyServer';
import { loadCryptoSync } from './index';
import { loadPQCFrom, pqc } from '../pqc/index';
import { deleteCryptoStores, openCryptoStore } from './store';

// agent-skill/tests/trust_scenarios.json (E2EE spec §8) through the browser engine; test_kybot.py
// Scenarios runs the same table through kybot.py. Dana (a_dana) has devices d1 and d2 and a bot
// vouched by d1; the sender is Erin (a_erin), whose lookup puts Dana alone in its first batch.

interface Scenario { name: string; expect: Record<string, boolean> }
const table = JSON.parse(readFileSync('../agent-skill/tests/trust_scenarios.json', 'utf8')) as { scenarios: Scenario[] };
const FILLERS = Array.from({ length: 99 }, (_, i) => `a_fill_${String(i).padStart(2, '0')}`);
const BOT = 'bot_helper';

beforeAll(async () => {
  loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm'));
  await loadPQCFrom(readFileSync('src/pqc/pqc.wasm'));
});

const opened: CryptoEngine[] = [];
afterEach(async () => {
  for (const e of opened.splice(0)) e.close();
  await deleteCryptoStores();
});

async function engine(userId: string, api: KeyServer, store: string): Promise<CryptoEngine> {
  const e = await CryptoEngine.open(userId, api, await openCryptoStore(store));
  opened.push(e);
  return e;
}

type Hook = (ids: string[], r: Awaited<ReturnType<KeyServer['query']>>) => void;

/** Dana's two devices and vouched bot, and Erin, whose key queries pass through hook. */
async function world() {
  const server = new FakeKeyServer();
  const d1 = await engine('a_dana', server.as('a_dana'), 'dana-d1');
  const p = await d1.prepareIdentity();
  await p.commit();
  const d2 = await engine('a_dana', server.as('a_dana'), 'dana-d2');
  await d2.restoreIdentity(p.recoveryKey);
  const bot = await engine(BOT, server.as(BOT), BOT);
  server.botOwners.set(BOT, 'a_dana');
  await d1.vouchForBot(BOT, 0, { add: (await d1.botDevices(BOT)).uploaded[0] });
  let hook: Hook | undefined;
  const base = server.as('a_erin');
  const erin = await engine('a_erin', { ...base, query: async (ids, signal) => {
    const r = await base.query(ids, signal);
    hook?.(ids, r);
    return r;
  } }, 'a_erin');
  await (await erin.prepareIdentity()).commit();
  const mailTo = (d: CryptoEngine) => (server.mail.get(`${d.userId}\n${d.deviceId}`) ?? []).length;
  return { server, d1, d2, bot, erin, mailTo, setHook: (h: Hook) => (hook = h) };
}

const masterView = (server: FakeKeyServer, user: string) => {
  const m = server.masters.get(user)!;
  return structuredClone({ version: m.version, master_key: m.master_key, self_signature: m.self_signature, device_list: m.device_list });
};

const post = (roomId: string, sender: CryptoEngine, body: string): SealedMessage => ({ id: `msg_${body}`, room_id: roomId, sender_id: sender.userId, body });

async function delisted(delayed: boolean) {
  const { server, d1, d2, erin } = await world();
  server.join('r', 'a_dana', 'a_erin');
  let sent: SealedMessage | undefined;
  const send = async () => { sent = post('r', d2, await d2.encrypt('r', { type: 'text', body: 'from d2' })); };
  if (delayed) await send();
  await d1.delistDevices([d2.deviceId]);
  if (!delayed) await send().catch(() => undefined);
  await erin.receive();
  const r = sent && (await erin.decrypt(sent));
  return { sent: sent !== undefined, readable: r?.state === 'decrypted' && r.inner.body === 'from d2' };
}

const scenarios: Record<string, () => Promise<Record<string, boolean>>> = {
  async removal_seen_late() {
    const { server, d1, d2, erin, mailTo, setHook } = await world();
    server.join('r', 'a_dana', ...FILLERS, BOT, 'a_erin');
    const old = masterView(server, 'a_dana');
    await d1.delistDevices([d2.deviceId]);
    // The batch naming Dana gets her old list; the later one, with her bot, the new one.
    setHook((ids, r) => { if (ids.includes('a_dana')) r.master_keys!.a_dana = structuredClone(old); });
    server.mail.clear();
    await erin.encrypt('r', { type: 'text', body: 'after the removal' });
    return { d1_gets_key: mailTo(d1) > 0, d2_gets_key: mailTo(d2) > 0 };
  },
  async stale_list_in_later_batch() {
    const { server, d1, d2, erin, mailTo, setHook } = await world();
    server.join('r', 'a_dana', ...FILLERS, BOT, 'a_erin');
    const old = masterView(server, 'a_dana');
    await d1.delistDevices([d2.deviceId]);
    // The batch naming Dana gets her new list; the later one, with her bot, the old one.
    setHook((ids, r) => { if (!ids.includes('a_dana')) r.master_keys!.a_dana = structuredClone(old); });
    server.mail.clear();
    await erin.encrypt('r', { type: 'text', body: 'after the removal' });
    return { d1_gets_key: mailTo(d1) > 0, d2_gets_key: mailTo(d2) > 0 };
  },
  async identity_conflict_across_batches() {
    const { server, d1, bot, erin, mailTo, setHook } = await world();
    server.join('r', 'a_dana', ...FILLERS, BOT, 'a_erin');
    await erin.encrypt('r', { type: 'text', body: 'pins Dana' });
    server.mail.clear();
    await erin.memberLeft('r');
    const mallory = pqc.masterGenerate();
    const forged = { version: 1, master_key: mallory.public_key, self_signature: pqc.signMaster(mallory.seed, TENANT, 'a_dana') };
    setHook((ids, r) => { if (!ids.includes('a_dana')) r.master_keys!.a_dana = forged; });
    await erin.encrypt('r', { type: 'text', body: 'two keys for Dana' });
    return { d1_gets_key: mailTo(d1) > 0, bot_gets_key: mailTo(bot) > 0 };
  },
  delisted_fresh_mail: () => delisted(false),
  delisted_delayed_mail: () => delisted(true),
};

describe('trust scenarios shared with kybot.py (spec §8)', () => {
  it('covers exactly the shared table', () => {
    expect(Object.keys(scenarios).sort()).toEqual(table.scenarios.map((s) => s.name).sort());
  });
  for (const s of table.scenarios) {
    it(s.name, async () => {
      expect(await scenarios[s.name]()).toEqual(s.expect);
    });
  }
});
