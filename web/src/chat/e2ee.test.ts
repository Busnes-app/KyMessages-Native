import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { abandonDevice, encryptionRetry, identityStatus, ownDeviceVerified, prepareIdentity, restoreIdentity, forgetCryptoStore, keyGeneration, NOT_YET, onRoomKeys, openMessage, receiveRoomKeys, replaceDevice, RETIRE_MS, retireDevice, retryable, retryEncryptionNow, sealRoomMessage, startE2EE, UNAVAILABLE } from './e2ee';
import { EARLY } from '../crypto/engine';
import { FakeKeyServer, TENANT } from '../crypto/fakeKeyServer';
import { pqc } from '../pqc/index';
import { isTransient } from '../crypto/records';
import { httpFake, type Block } from './httpFake';
import { openCryptoStore } from '../crypto/store';
import { parseMessage } from './types';

// Tests may replace the device read; everything else is the real store.
const deviceRead = vi.hoisted(() => ({ replace: undefined as undefined | (() => Promise<{ user_id: string; device_id: string }[]>) }));
vi.mock('../crypto/store', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/store')>();
  return { ...real, storedDevices: () => deviceRead.replace?.() ?? real.storedDevices() };
});

// jsdom cannot fetch the modules by URL; load them from disk instead.
vi.mock('../crypto/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/index')>();
  return { ...real, loadCrypto: async () => real.loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm')) };
});
vi.mock('../pqc/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../pqc/index')>();
  return { ...real, loadPQC: () => real.loadPQCFrom(readFileSync('src/pqc/pqc.wasm')) };
});

// Pending retirements, one localStorage key per device.
const pendingRetirements = () => Object.keys(localStorage).filter((k) => k.startsWith('kymessages-e2ee-retire:'))
  .map((k) => JSON.parse(localStorage.getItem(k) ?? 'null') as { user_id: string; device_id: string; deleted: boolean; delisted: boolean });

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(async () => {
  deviceRead.replace = undefined;
  await forgetCryptoStore();
  localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the signed-in device', () => {
  it('keeps decryptable inbound history, replay records and pins when startup gets a removed-device 404', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    const removed = new Set<string>();
    const uploads: { device_id: string; device_keys?: unknown; one_time_keys: unknown[] }[] = [];
    const serve = (user: string) => httpFake(server, user, { fn: (_method, path, body) => {
      if (user !== 'u_alice' || path !== '/api/v1/keys/upload') return undefined;
      uploads.push(body);
      return removed.has(body.device_id) ? json({ error: 'Unknown device' }, 404) : undefined;
    } });
    vi.stubGlobal('fetch', vi.fn(serve('u_alice')));
    const first = await startE2EE('u_alice');
    // Registered once, self-signed, then stocked with 50 one-time keys.
    expect(uploads[0].device_keys).toBeTruthy();
    expect(uploads.reduce((n, u) => n + u.one_time_keys.length, 0)).toBe(50);
    await (await prepareIdentity()).commit();

    const message = parseMessage({ id: 'old-message', room_id: 'r1', sender_id: 'u_alice', encoding: 'e2ee_room_v1', body: await first.encrypt('r1', { type: 'text', body: 'historical secret' }) });
    expect((await openMessage(message)).body).toBe('historical secret');
    const before = await openCryptoStore('u_alice');
    await before.write([['pin:u_peer\nDEVICE0001', { pinned: true }]]);
    const replay = await before.list('seen:');
    expect(replay).toHaveLength(1);
    before.close();

    vi.stubGlobal('fetch', vi.fn(serve('u_bob')));
    await startE2EE('u_bob'); // closes alice's device, keeping its store
    vi.stubGlobal('fetch', vi.fn(serve('u_alice')));
    removed.add(first.deviceId); // removed from another session
    server.devices.get('u_alice')?.delete(first.deviceId);
    const again = await startE2EE('u_alice');
    expect(again.deviceId).not.toBe(first.deviceId);
    expect(again.curve25519).not.toBe(first.curve25519);
    expect((await openMessage(message)).body).toBe('historical secret');
    const after = await openCryptoStore('u_alice');
    try {
      expect(await after.list('seen:')).toEqual(replay);
      expect(await after.get('pin:u_peer\nDEVICE0001')).toEqual({ pinned: true });
    } finally {
      after.close();
    }
  });

  it('retries a failed startup on concurrent sends after upload service recovery without reconnecting', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    let unavailable = false;
    const uploads: string[] = [];
    const serve = (user: string) => httpFake(server, user, { fn: (_method, path, body) => {
      if (user !== 'u_alice' || path !== '/api/v1/keys/upload') return undefined;
      uploads.push(body.device_id);
      return unavailable ? json({ error: 'Try later' }, 503) : undefined;
    } });
    vi.stubGlobal('fetch', vi.fn(serve('u_alice')));
    const device = await startE2EE('u_alice');
    await (await prepareIdentity()).commit(); // a verified device, which may send
    vi.stubGlobal('fetch', vi.fn(serve('u_bob')));
    await startE2EE('u_bob');
    vi.stubGlobal('fetch', vi.fn(serve('u_alice')));
    unavailable = true;
    uploads.length = 0;
    await expect(startE2EE('u_alice')).rejects.toThrow('Try later');
    unavailable = false; // the socket never reconnects; the next sends must restart startup
    const envelopes = await Promise.all(['one', 'two', 'three'].map((body) => sealRoomMessage('r1', { type: 'text', body })));
    // One failed upload, then one coalesced startup of the same device.
    expect(uploads.length).toBeGreaterThanOrEqual(2);
    expect(new Set(uploads)).toEqual(new Set([device.deviceId]));
    for (const [i, body] of envelopes.entries()) {
      const opened = await openMessage(parseMessage({ id: `sent-${i}`, room_id: 'r1', sender_id: 'u_alice', encoding: 'e2ee_room_v1', body }));
      expect(opened.body).toBe(['one', 'two', 'three'][i]);
    }
  });

  it('refuses an encrypted send from a device that is not verified, and sends once it is', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice')));
    await startE2EE('u_alice');
    await expect(sealRoomMessage('r1', { type: 'text', body: 'to no one' })).rejects.toThrow(/verify this device/i);
    expect(server.sent).toEqual([]);
    await (await prepareIdentity()).commit();
    await expect(sealRoomMessage('r1', { type: 'text', body: 'self only' })).resolves.toMatch(/megolm/);
  });

  it('retires a device abandoned by a revoked session after the next sign-in', async () => {
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') {
        deleted.push(decodeURIComponent(url.slice('/api/v1/keys/devices/'.length)));
        return new Response(null, { status: 204 });
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    const old = await startE2EE('u_alice');
    await abandonDevice(); // the session was revoked: nothing can be deleted yet
    expect(deleted).toEqual([]);
    const fresh = await startE2EE('u_alice');
    await vi.waitFor(() => expect(deleted).toEqual([old.deviceId]));
    expect(fresh.deviceId).not.toBe(old.deviceId);
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
  });

  it("retires another user's device whose store a sign-out wiped, at that user's next sign-in", async () => {
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') {
        deleted.push(decodeURIComponent(url.slice('/api/v1/keys/devices/'.length)));
        return new Response(null, { status: 204 });
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    const bob = await startE2EE('u_bob'); // Bob used this shared browser
    await startE2EE('u_alice'); // then Alice signed in
    await forgetCryptoStore(); // and signed out, wiping every store here
    const bobAgain = await startE2EE('u_bob');
    await vi.waitFor(() => expect(deleted).toContain(bob.deviceId));
    expect(bobAgain.deviceId).not.toBe(bob.deviceId);
  });

  it.each([
    ['fails', () => Promise.reject(new DOMException('disk failure', 'UnknownError'))],
    ['never finishes', () => new Promise<never>(() => undefined)],
  ])('deletes local keys when reading the stored devices %s', async (_, read) => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    await startE2EE('u_alice');
    deviceRead.replace = read;
    await forgetCryptoStore();
    expect((await indexedDB.databases()).filter((d) => d.name?.startsWith('kymessages-crypto-'))).toEqual([]);
  });

  it.each(['upload', 'mailbox'])('signs back in as the same user while the old %s remains stalled', async (stalledPath) => {
    let stalledSignal: AbortSignal | null | undefined;
    let release = () => {};
    let first = true;
    let stalled = false;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const uploading = url === '/api/v1/keys/upload';
      const response = uploading
        ? json({ one_time_key_count: (JSON.parse(String(init?.body)) as { one_time_keys: unknown[] }).one_time_keys.length })
        : json({ messages: [] });
      if (first && (stalledPath === 'upload' ? uploading : url.startsWith('/api/v1/to-device?'))) {
        first = false;
        stalled = true;
        stalledSignal = init?.signal;
        return new Promise<Response>((resolve, reject) => {
          release = () => resolve(response);
          stalledSignal?.addEventListener('abort', () => reject(new DOMException('Stopped', 'AbortError')), { once: true });
        });
      }
      return response;
    }));
    const oldStart = startE2EE('u_alice').catch(() => undefined);
    await vi.waitFor(() => expect(stalled).toBe(true));
    await abandonDevice();
    let restartedId: string | undefined;
    const restarting = startE2EE('u_alice').then((e) => { restartedId = e.deviceId; });
    try {
      // Do not release the old response: stopping its entry must release the per-user lock.
      await vi.waitFor(() => expect(restartedId).toBeDefined());
      expect(stalledSignal?.aborted).toBe(true);
    } finally {
      release();
      await oldStart;
      await restarting;
    }
  });

  it('deletes local keys on revocation without waiting for a start-up stuck on the network', async () => {
    let releaseUpload: () => void = () => undefined;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        // The key upload hangs, as on a dead connection.
        return new Promise<Response>((resolve) => {
          releaseUpload = () => resolve(json({ one_time_key_count: req.one_time_keys.length }));
        });
      }
      if (url.startsWith('/api/v1/to-device')) return Promise.resolve(json({ messages: [] }));
      return Promise.resolve(json({ error: `unexpected ${url}` }, 404));
    }));
    const stores = async () => (await indexedDB.databases()).map((d) => d.name).filter((n) => n?.startsWith('kymessages-crypto-'));
    const starting = startE2EE('u_alice').catch((e: unknown) => e);
    await vi.waitFor(async () => expect(await stores()).toEqual(['kymessages-crypto-u_alice']));
    await vi.waitFor(() => expect(releaseUpload).not.toBe(undefined));
    // The session is revoked while the upload is still pending.
    await abandonDevice();
    expect(await stores()).toEqual([]);
    expect(pendingRetirements()).toHaveLength(1);
    releaseUpload();
    await starting;
    // The cancelled start-up never brings the store back.
    await new Promise((r) => setTimeout(r, 50));
    expect(await stores()).toEqual([]);
  });

  it('gives up retiring the device when start-up is stuck, so sign-out goes on', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      // The key upload never answers, as on a dead connection.
      if (url === '/api/v1/keys/upload') return new Promise<Response>(() => undefined);
      return Promise.resolve(json({ error: `unexpected ${url}` }, 404));
    }));
    void startE2EE('u_alice').catch(() => undefined);
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      const retiring = retireDevice().wait;
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      expect(await retiring).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('reopens waiting messages when another tab stores room keys', async () => {
    const heard = vi.fn();
    const off = onRoomKeys(heard);
    const before = keyGeneration();
    const otherTab = new BroadcastChannel('kymessages-room-keys');
    otherTab.postMessage(null);
    await vi.waitFor(() => expect(heard).toHaveBeenCalledTimes(1));
    expect(keyGeneration()).toBe(before + 1);
    otherTab.close();
    off();
  });

  it('marks a message whose open threw as worth trying again', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      return json({ messages: [] });
    }));
    const e = await startE2EE('u_alice');
    await vi.waitFor(async () => expect((await openMessage(parseMessage({ id: 'x', room_id: 'r1', sender_id: 'u_bob', encoding: 'plain_v1', body: 'p' }))).body).toBe('p'));
    // A local storage failure while opening: not a verdict on the message.
    vi.spyOn(e, 'decrypt').mockRejectedValue(new DOMException('transaction aborted', 'AbortError'));
    const m = parseMessage({
      id: 'm1', room_id: 'r1', sender_id: 'u_bob', encoding: 'e2ee_room_v1',
      body: '{"alg":"megolm.v1","sender_key":"k","device_id":"DEVICE0001","session_id":"s","ciphertext":"AAAA"}',
    });
    await vi.waitFor(async () => expect((await openMessage(m)).e2ee).toEqual({ kind: 'failed', reason: NOT_YET, gen: expect.any(Number) }));
    expect(retryable(NOT_YET)).toBe(true);
    expect(retryable(UNAVAILABLE)).toBe(true);
    expect(retryable('This message was moved into another room.')).toBe(false);
  });

  it('does not recreate keys after another tab deleted the store, until this tab signs out', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      return json({ messages: [] });
    }));
    const stores = async () => (await indexedDB.databases()).map((d) => d.name).filter((n) => n?.startsWith('kymessages-crypto-'));
    await startE2EE('u_alice');
    // Another tab signs out and deletes the store; this tab never hears why.
    await new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase('kymessages-crypto-u_alice');
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
    });
    await expect(startE2EE('u_alice')).rejects.toThrow('reset in another tab');
    expect(await stores()).toEqual([]);
    await forgetCryptoStore(); // this tab's own sign-out
    await startE2EE('u_alice');
    expect(await stores()).toEqual(['kymessages-crypto-u_alice']);
  });

  it('reports whether sign-out removed the device from the server', async () => {
    let deleteStatus = 500;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') {
        return deleteStatus === 204 ? new Response(null, { status: 204 }) : json({ error: 'x' }, deleteStatus);
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    await startE2EE('u_alice');
    expect(await retireDevice().wait).toBe(false); // a 5xx: the device is still listed
    deleteStatus = 404;
    expect(await retireDevice().wait).toBe(true); // already gone
    deleteStatus = 204;
    expect(await retireDevice().wait).toBe(true);
  });

  it.each(['before', 'after'])('replaces a late-retired device when logout fails %s deletion completes, preserving history', async (order) => {
    let finishDelete: (r: Response) => void = () => {};
    const deletion = new Promise<Response>((resolve) => { finishDelete = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') return deletion;
      return json({ messages: [] });
    }));
    const old = await startE2EE('u_alice');
    const store = await openCryptoStore('u_alice');
    await store.write([['in:sender:session', { kept: true }], ['seen:sender:session:0', 'm1'], ['pin:peer', 'key']]);
    store.close();
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    const retiring = retireDevice();
    try {
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      expect(await retiring.wait).toBe(false);
    } finally {
      vi.useRealTimers();
    }
    // App calls this on refused logout, whether deletion is still pending or already finished.
    if (order === 'after') {
      finishDelete(new Response(null, { status: 204 }));
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    const repairing = retiring.replaceIfRetired();
    finishDelete(new Response(null, { status: 204 }));
    await repairing;
    expect((await startE2EE('u_alice')).deviceId).not.toBe(old.deviceId);
    const after = await openCryptoStore('u_alice');
    try {
      expect(await after.get('in:sender:session')).toEqual({ kept: true });
      expect(await after.get('seen:sender:session:0')).toBe('m1');
      expect(await after.get('pin:peer')).toBe('key');
    } finally {
      after.close();
    }
  });

  it('does not recreate keys when a pending retirement finishes after session revocation', async () => {
    let finishDelete: (r: Response) => void = () => {};
    const deletion = new Promise<Response>((resolve) => { finishDelete = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') return json({ one_time_key_count: 50 });
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') return deletion;
      return json({ messages: [] });
    }));
    await startE2EE('u_alice');
    const retiring = retireDevice();
    const repairing = retiring.replaceIfRetired(); // refused logout, deletion still pending
    await abandonDevice(); // session revoked before that deletion finishes
    finishDelete(new Response(null, { status: 204 }));
    await repairing;
    expect((await indexedDB.databases()).filter((d) => d.name?.startsWith('kymessages-crypto-'))).toEqual([]);
  });

  it('keeps received room keys when it replaces a retired device after a refused sign-out', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    const old = await startE2EE('u_alice');
    // A room key this device received earlier, and a peer key it pinned.
    const store = await openCryptoStore('u_alice');
    await store.write([['in:senderkey:session1', { kept: true }], ['pin:u_bob\nDEV', { kept: true }]]);
    store.close();
    await replaceDevice();
    const fresh = await startE2EE('u_alice');
    expect(fresh.deviceId).not.toBe(old.deviceId);
    const after = await openCryptoStore('u_alice');
    try {
      expect(await after.get('in:senderkey:session1')).toEqual({ kept: true });
      expect(await after.get('pin:u_bob\nDEV')).toEqual({ kept: true });
    } finally {
      after.close();
    }
  });

  it('does not hold messages behind a device that is still starting', async () => {
    let release: ((r: Response) => void) | undefined;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) =>
      String(input) === '/api/v1/keys/upload'
        ? new Promise<Response>((resolve) => { release = resolve; }) // a stalled key upload
        : Promise.resolve(json({ messages: [] }))));
    const starting = startE2EE('u_alice');
    const m = parseMessage({
      id: 'm1', room_id: 'r1', sender_id: 'u_bob', encoding: 'e2ee_room_v1',
      body: '{"alg":"megolm.v1","sender_key":"k","device_id":"DEVICE0001","session_id":"s","ciphertext":"AAAA"}',
    });
    await vi.waitFor(() => expect(release).toBeDefined()); // the upload is in flight
    const reopened = vi.fn();
    const stop = onRoomKeys(reopened);
    expect((await openMessage(m)).e2ee).toEqual({ kind: 'failed', reason: UNAVAILABLE, gen: expect.any(Number) });
    stop();
    release!(json({ error: 'stop' }, 500));
    await starting.catch(() => undefined);
  });

  it('reopens what arrived during start-up only once the device is ready', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      return json({ messages: [] });
    }));
    const m = parseMessage({
      id: 'm1', room_id: 'r1', sender_id: 'u_bob', encoding: 'e2ee_room_v1',
      body: '{"alg":"megolm.v1","sender_key":"k","device_id":"DEVICE0001","session_id":"s","ciphertext":"AAAA"}',
    });
    const seen: string[] = [];
    const stop = onRoomKeys(() => void openMessage(m).then((o) => seen.push(o.e2ee?.kind === 'failed' ? o.e2ee.reason : o.e2ee!.kind)));
    await startE2EE('u_alice');
    await vi.waitFor(() => expect(seen.length).toBeGreaterThan(0));
    stop();
    // The retry ran against the ready device: no longer "unavailable" (no key here, so waiting).
    expect(seen[0]).toBe('waiting');
  });

  it('refuses text whose sealed form would exceed the server envelope limit, before sealing', async () => {
    // 10 KiB of control characters is under the 16 KiB text limit but escapes to 60 KiB of JSON.
    await expect(sealRoomMessage('r1', { type: 'text', body: '\u0001'.repeat(10 << 10) })).rejects.toThrow('Message is too long');
    await expect(sealRoomMessage('r1', { type: 'text', body: 'x'.repeat((16 << 10) + 1) })).rejects.toThrow('Message is too long');
  });
});

describe('retirement from the signed device list', () => {
  it('keeps a sign-out pending until the removal is signed, even once the server row is gone', async () => {
    const deleted: string[] = [];
    let listed = true; // the account's identity lists devices; this browser is not verified
    const s = 'A'.repeat(64);
    const master = () => ({
      version: 1, master_key: s, self_signature: s, device_list: { epoch: 1, device_ids: ['SOMEDEVICE01'], signature: s },
      backup_key: { public_key: s, signature: s }, recovery: { wrapped_master_key: s, wrapped_backup_key: s }, pins: { counter: 0, sealed: '' },
    });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as { one_time_keys: unknown[] };
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') {
        deleted.push(decodeURIComponent(url.slice('/api/v1/keys/devices/'.length)));
        return new Response(null, { status: 204 });
      }
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: listed ? master() : null });
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    const e = await startE2EE('u_alice');
    expect(await retireDevice().wait).toBe(true);
    expect(deleted).toEqual([e.deviceId]);
    expect(pendingRetirements()).toEqual([expect.objectContaining({ device_id: e.deviceId, deleted: true, delisted: false })]);
    await forgetCryptoStore();
    // Next sign-in, the identity no longer lists devices: nothing is left to sign away.
    listed = false;
    await startE2EE('u_alice');
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
  });

  // Earlier builds kept one list; another tab records its own device while this one retires.
  it('keeps each pending device apart, so a tab retiring some never drops another tab\'s', async () => {
    localStorage.setItem('kymessages-e2ee-retire', JSON.stringify([{ user_id: 'u_alice', device_id: 'OLDDEVICE001' }]));
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') return json({ one_time_key_count: 50 });
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') {
        deleted.push(decodeURIComponent(url.slice('/api/v1/keys/devices/'.length)));
        // Meanwhile another tab signs a different device out, which it records as pending.
        localStorage.setItem('kymessages-e2ee-retire:u_alice:OTHERTAB0001', JSON.stringify({ user_id: 'u_alice', device_id: 'OTHERTAB0001', deleted: false, delisted: false }));
        return new Response(null, { status: 204 });
      }
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ messages: [] });
    }));
    await startE2EE('u_alice');
    await vi.waitFor(() => expect(deleted).toEqual(['OLDDEVICE001']));
    await vi.waitFor(() => expect(pendingRetirements().map((d) => d.device_id)).toEqual(['OTHERTAB0001']));
    expect(localStorage.getItem('kymessages-e2ee-retire')).toBeNull();
  });

  it('settles a sign-out whose removal from the list lands after sign-out moved on', async () => {
    let releaseMaster: () => void = () => {};
    const masterRead = new Promise<void>((r) => { releaseMaster = r; });
    let hold = false;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') return json({ one_time_key_count: 50 });
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') return new Response(null, { status: 204 });
      if (url === '/api/v1/keys/master') {
        if (hold) await masterRead;
        return json({ tenant_id: 'default', master: null });
      }
      return json({ messages: [] });
    }));
    const e = await startE2EE('u_alice');
    hold = true; // the delist's identity read stalls past its bound
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    let retiring: ReturnType<typeof retireDevice>;
    try {
      retiring = retireDevice();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
    } finally {
      vi.useRealTimers();
    }
    expect(await retiring.wait).toBe(true);
    expect(pendingRetirements()).toEqual([expect.objectContaining({ device_id: e.deviceId, deleted: true, delisted: false })]);
    releaseMaster(); // the late removal confirms, and the entry goes
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
  });

  it('replaces a device a refused sign-out took off the list though its deletion failed', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') return json({ one_time_key_count: 50 });
      if (url.startsWith('/api/v1/keys/devices/') && init?.method === 'DELETE') return json({ error: 'try later' }, 503);
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      return json({ messages: [] });
    }));
    const old = await startE2EE('u_alice');
    const retiring = retireDevice();
    expect(await retiring.wait).toBe(false);
    // The logout is refused (or cancelled): the retiring device no longer lists itself, so it is
    // replaced by one that does, and the old one stays pending.
    await retiring.replaceIfRetired();
    expect((await startE2EE('u_alice')).deviceId).not.toBe(old.deviceId);
    expect(pendingRetirements()).toEqual(expect.arrayContaining([expect.objectContaining({ device_id: old.deviceId })]));
  });
});

describe('retrying encryption work', () => {
  it('says work is waiting after a failed mailbox read, and clears once a retry ran', async () => {
    let down = false;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') return json({ one_time_key_count: 50 });
      if (url === '/api/v1/keys/master') return json({ tenant_id: 'default', master: null });
      if (url.startsWith('/api/v1/to-device')) return down ? json({ error: 'try later' }, 503) : json({ messages: [] });
      return json({ error: `unexpected ${url}` }, 404);
    }));
    await startE2EE('u_alice');
    down = true;
    receiveRoomKeys();
    await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
    down = false;
    await retryEncryptionNow();
    expect(encryptionRetry().pending).toBe(false);
  });

  it('opens a message from before this device’s session again when keys arrive', () => {
    expect(retryable(EARLY)).toBe(true);
  });
});

// With fake timers: jumps to each next timer, pausing in real time for the async work between,
// until cond holds.
const realTimeout = globalThis.setTimeout;
async function until(cond: () => boolean): Promise<void> {
  for (let n = 0; n < 2000 && !cond(); n++) {
    await vi.advanceTimersToNextTimerAsync();
    await new Promise((r) => realTimeout(r, 5));
  }
  expect(cond()).toBe(true);
}

describe('Round 4: the retry pipeline over the real key routes', () => {
  it('awaits the backup it retries, stops after its schedule, and recovers by hand', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    let backup: 'down' | 'hold' | 'up' = 'up';
    let release = () => {};
    let puts = 0;
    const block: { fn?: Block } = { fn: (method, path) => {
      if (method !== 'PUT' || path !== '/api/v1/keys/backup') return undefined;
      puts++;
      if (backup === 'down') return json({ error: 'down' }, 503);
      if (backup === 'hold') return new Promise<undefined>((r) => { release = () => r(undefined); });
      return undefined;
    } };
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', block)));
    // Fake timers throughout, so the schedule's own timers are the ones advanced; vi.waitFor
    // advances them while it polls.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let spent = 0;
    try {
      await startE2EE('u_alice');
      await (await prepareIdentity()).commit();
      await vi.waitFor(() => expect(server.backups.get('u_alice')?.size ?? 0).toBe(0));
      backup = 'down';
      await sealRoomMessage('r1', { type: 'text', body: 'backed up later' });
      await vi.waitFor(() => expect(puts).toBe(1));
      expect(encryptionRetry()).toEqual({ pending: true, exhausted: false });
      // Five scheduled retries, each awaiting a drain that fails, then no more by itself.
      // Each retry fires once the previous one finished (real async work) and scheduled it.
      for (let i = 0; i < 5; i++) await until(() => puts === i + 2);
      await vi.waitFor(() => expect(encryptionRetry()).toEqual({ pending: true, exhausted: true }), { interval: 1 });
      spent = puts;
      await vi.advanceTimersByTimeAsync(120_000);
      expect(puts).toBe(spent);
      expect(server.backups.get('u_alice')?.size ?? 0).toBe(0);

      // By hand, while the server still fails: tried, and scheduled again.
      await retryEncryptionNow();
      expect(puts).toBe(spent + 1);
      expect(encryptionRetry()).toEqual({ pending: true, exhausted: false });

      // The server is back but slow: pending holds until the write itself finished, and a second
      // retry joins the running one.
      backup = 'hold';
      const run = retryEncryptionNow();
      expect(retryEncryptionNow()).toBe(run);
      await vi.waitFor(() => expect(puts).toBe(spent + 2), { interval: 1 });
      expect(encryptionRetry().pending).toBe(true);
      release();
      await run;
    } finally {
      vi.useRealTimers();
    }
    expect(puts).toBe(spent + 2);
    expect(encryptionRetry()).toEqual({ pending: false, exhausted: false });
    expect(server.backups.get('u_alice')?.size).toBe(1);
  }, 60_000);

  it('treats an unreachable or failing key server as unavailability, and a refusal as a verdict', async () => {
    const server = new FakeKeyServer();
    let mailbox: 'offline' | '429' | 'refused' | 'up' = 'up';
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (path !== '/api/v1/to-device' || method !== 'GET' || mailbox === 'up') return undefined;
      if (mailbox === 'offline') throw new TypeError('Failed to fetch');
      return mailbox === '429' ? json({ error: 'slow down' }, 429) : json({ error: 'bad request' }, 400);
    } })));
    await startE2EE('u_alice');
    for (const state of ['offline', '429'] as const) {
      mailbox = state;
      receiveRoomKeys();
      await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
      mailbox = 'up';
      await retryEncryptionNow();
      expect(encryptionRetry().pending).toBe(false);
    }
    mailbox = 'refused';
    receiveRoomKeys();
    await new Promise((r) => setTimeout(r, 50));
    expect(encryptionRetry().pending).toBe(false);
    // A closed screen's abort is not unavailability.
    expect(isTransient(new DOMException('closed', 'AbortError'))).toBe(false);
  });
});

describe('Round 4: retirement races', () => {
  it('retires pending devices once verified, even when the backup restore that follows fails', async () => {
    const server = new FakeKeyServer();
    let backupDown = false;
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'DELETE' && path.startsWith('/api/v1/keys/devices/')) deleted.push(decodeURIComponent(path.slice('/api/v1/keys/devices/'.length)));
      if (backupDown && method === 'GET' && path === '/api/v1/keys/backup') return json({ error: 'down' }, 503);
      return undefined;
    } })));
    const first = await startE2EE('u_alice');
    const p = await prepareIdentity();
    await p.commit();
    await forgetCryptoStore(); // a sign-out whose removal from the list did not land
    await startE2EE('u_alice');
    await vi.waitFor(() => expect(deleted).toContain(first.deviceId));
    expect(pendingRetirements()).toEqual([expect.objectContaining({ device_id: first.deviceId, deleted: true, delisted: false })]);
    backupDown = true;
    await expect(restoreIdentity(p.recoveryKey)).rejects.toThrow();
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
    expect(server.masters.get('u_alice')!.device_list!.device_ids).not.toContain(first.deviceId);
  });

  it('replaces a stored device whose retirement is pending instead of running it, and deletes only that one', async () => {
    const server = new FakeKeyServer();
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'DELETE' && path.startsWith('/api/v1/keys/devices/')) deleted.push(decodeURIComponent(path.slice('/api/v1/keys/devices/'.length)));
      return undefined;
    } })));
    const old = await startE2EE('u_alice');
    localStorage.setItem(`kymessages-e2ee-retire:u_alice:${old.deviceId}`, JSON.stringify({ user_id: 'u_alice', device_id: old.deviceId, deleted: false, delisted: false }));
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_bob')));
    await startE2EE('u_bob'); // closes alice's device, keeping its store
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'DELETE' && path.startsWith('/api/v1/keys/devices/')) deleted.push(decodeURIComponent(path.slice('/api/v1/keys/devices/'.length)));
      return undefined;
    } })));
    const fresh = await startE2EE('u_alice');
    expect(fresh.deviceId).not.toBe(old.deviceId);
    await vi.waitFor(() => expect(deleted).toEqual([old.deviceId]));
    expect(server.devices.get('u_alice')?.has(fresh.deviceId)).toBe(true);
  });

  it('replaces the touched device when a refused sign-out ends its bounded attempt, though the deletion hangs', async () => {
    const server = new FakeKeyServer();
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) =>
      method === 'DELETE' && path.startsWith('/api/v1/keys/devices/') ? new Promise<Response>(() => undefined) : undefined })));
    const old = await startE2EE('u_alice');
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    let repaired: Promise<void>;
    try {
      const retiring = retireDevice();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      expect(await retiring.wait).toBe(false);
      repaired = retiring.replaceIfRetired();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
    } finally {
      vi.useRealTimers();
    }
    await repaired;
    expect((await startE2EE('u_alice')).deviceId).not.toBe(old.deviceId);
    expect(pendingRetirements()).toEqual(expect.arrayContaining([expect.objectContaining({ device_id: old.deviceId })]));
  });

  it('does not record a fully retired device again when a clean sign-out wipes the store', async () => {
    const server = new FakeKeyServer();
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice')));
    await startE2EE('u_alice');
    expect(await retireDevice().wait).toBe(true);
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
    await forgetCryptoStore();
    expect(pendingRetirements()).toEqual([]);
  });
});

describe('Round 5: retry sessions and lifecycle', () => {
  const deferred = () => {
    let resolve: (r?: Response) => void = () => {};
    const promise = new Promise<Response | undefined>((r) => { resolve = r; });
    return { promise, resolve };
  };

  it('ignores a failure from a signed-out session: it neither schedules nor changes the next user\'s', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    let hold: ReturnType<typeof deferred> | undefined;
    const serveAlice = httpFake(server, 'u_alice', { fn: (method, path) => (method === 'PUT' && path === '/api/v1/keys/backup' && hold ? hold.promise : undefined) });
    // Alice's held write outlives her sign-out (it is not aborted), and then fails.
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => serveAlice(input, { ...init, signal: undefined })));
    await startE2EE('u_alice');
    await (await prepareIdentity()).commit();
    hold = deferred();
    await sealRoomMessage('r1', { type: 'text', body: 'x' });
    await new Promise((r) => setTimeout(r, 100));
    await forgetCryptoStore();
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_bob')));
    await startE2EE('u_bob');
    hold.resolve(json({ error: 'down' }, 503));
    await new Promise((r) => setTimeout(r, 100));
    expect(encryptionRetry()).toEqual({ pending: false, exhausted: false });
  });

  it('starts another user with a budget of their own, whatever the previous one left waiting', async () => {
    const server = new FakeKeyServer();
    let mailboxDown = true;
    const serveAlice = httpFake(server, 'u_alice', { fn: (method, path) => (method === 'GET' && path === '/api/v1/to-device' && mailboxDown ? json({ error: 'down' }, 503) : undefined) });
    vi.stubGlobal('fetch', vi.fn(serveAlice));
    await startE2EE('u_alice');
    receiveRoomKeys();
    await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
    // Another account in this browser, without a sign-out in between.
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_bob')));
    await startE2EE('u_bob');
    expect(encryptionRetry()).toEqual({ pending: false, exhausted: false });
    mailboxDown = false;
  });

  it('runs one more pass when a failure is reported while a retry runs', async () => {
    const server = new FakeKeyServer();
    let mailboxDown = false;
    let holdMaster: ReturnType<typeof deferred> | undefined;
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'GET' && path === '/api/v1/to-device' && mailboxDown) return json({ error: 'down' }, 503);
      if (method === 'GET' && path === '/api/v1/keys/master' && holdMaster) {
        const h = holdMaster;
        holdMaster = undefined;
        return h.promise;
      }
      return undefined;
    } })));
    await startE2EE('u_alice');
    await (await prepareIdentity()).commit();
    mailboxDown = true;
    receiveRoomKeys();
    await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
    mailboxDown = false;
    // The retry reads the mailbox, then waits (without the lock) on the identity...
    const hold = deferred();
    holdMaster = hold;
    const run = retryEncryptionNow();
    await vi.waitFor(() => expect(holdMaster).toBeUndefined());
    // ...while a mailbox wake fails.
    mailboxDown = true;
    receiveRoomKeys();
    await new Promise((r) => setTimeout(r, 100));
    mailboxDown = false;
    hold.resolve(undefined);
    await run;
    expect(encryptionRetry().pending).toBe(true); // that failure earned one more pass
    await retryEncryptionNow();
    expect(encryptionRetry()).toEqual({ pending: false, exhausted: false });
  });

  it('aborts its own-device check while it waits on the server, and frees the lock', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    let stall = false;
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) =>
      stall && method === 'POST' && path === '/api/v1/keys/query' ? new Promise<undefined>(() => undefined) : undefined })));
    const e = await startE2EE('u_alice');
    await (await prepareIdentity()).commit();
    stall = true;
    const ac = new AbortController();
    const check = ownDeviceVerified(e.deviceId, ac.signal);
    await new Promise((r) => setTimeout(r, 100));
    ac.abort(new DOMException('closed', 'AbortError'));
    await expect(check).rejects.toThrow('closed');
    stall = false;
    // The lock it held is free: a send (which takes it) goes through.
    await expect(sealRoomMessage('r1', { type: 'text', body: 'after' })).resolves.toMatch(/megolm/);
    expect(await ownDeviceVerified(e.deviceId)).toBe(true);
  });
});

describe('Round 5: bounded sign-out', () => {
  it('fences a refused sign-out that never reached a device: a slow start-up later keeps its device', async () => {
    const server = new FakeKeyServer();
    let release = () => {};
    let held = true;
    const deleted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'DELETE' && path.startsWith('/api/v1/keys/devices/')) deleted.push(path);
      if (method === 'POST' && path === '/api/v1/keys/upload' && held) return new Promise<undefined>((r) => { release = () => r(undefined); });
      return undefined;
    } })));
    const starting = startE2EE('u_alice');
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      const retiring = retireDevice();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      expect(await retiring.wait).toBe(false);
      const refused = retiring.replaceIfRetired();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      await refused;
    } finally {
      vi.useRealTimers();
    }
    held = false;
    release();
    const e = await starting;
    await new Promise((r) => setTimeout(r, 200));
    expect(deleted).toEqual([]);
    expect(pendingRetirements()).toEqual([]);
    expect(server.devices.get('u_alice')?.has(e.deviceId)).toBe(true);
  });

  it('settles a double sign-out once, and one whose deletion answer was lost, keeping the identity', async () => {
    const server = new FakeKeyServer();
    server.join('r1', 'u_alice');
    let lose = false;
    const serve = httpFake(server, 'u_alice');
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const r = await serve(input, init);
      // The deletion lands on the server, but its answer never arrives.
      if (lose && init?.method === 'DELETE') throw new TypeError('Failed to fetch');
      return r;
    }));
    await startE2EE('u_alice');
    // Twice at once: both finish, and nothing stays pending.
    expect(await Promise.all([retireDevice().wait, retireDevice().wait])).toEqual([true, true]);
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));

    await forgetCryptoStore();
    const old = await startE2EE('u_alice');
    await (await prepareIdentity()).commit();
    const store = await openCryptoStore('u_alice');
    await store.write([['in:sender:session', { kept: true }]]);
    store.close();
    lose = true;
    const retiring = retireDevice();
    expect(await retiring.wait).toBe(false); // the outcome is unknown
    lose = false;
    await retiring.replaceIfRetired();
    const fresh = await startE2EE('u_alice');
    expect(fresh.deviceId).not.toBe(old.deviceId);
    // The replacement keeps the identity (no recovery key needed) and the room keys.
    expect(await identityStatus()).toMatchObject({ state: 'verified' });
    const after = await openCryptoStore('u_alice');
    expect(await after.get('in:sender:session')).toEqual({ kept: true });
    after.close();
    // The next start learns the old device is gone (404) and settles it.
    await vi.waitFor(() => expect(pendingRetirements()).toEqual([]));
  });
});

describe('Round 6', () => {
  it('fences a refused sign-out at once, so a start-up finishing in what was its second wait keeps its device', async () => {
    const server = new FakeKeyServer();
    let release = () => {};
    let held = true;
    const touched: string[] = [];
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if ((method === 'DELETE' && path.startsWith('/api/v1/keys/devices/')) || path === '/api/v1/keys/devices/list/reserve') touched.push(`${method} ${path}`);
      if (method === 'POST' && path === '/api/v1/keys/upload' && held) return new Promise<undefined>((r) => { release = () => r(undefined); });
      return undefined;
    } })));
    const starting = startE2EE('u_alice');
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      const retiring = retireDevice();
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      expect(await retiring.wait).toBe(false);
      const refused = retiring.replaceIfRetired();
      // The start-up finishes right after the refusal, inside the window the refusal used to
      // wait, before that window ends.
      held = false;
      release();
      await starting;
      await new Promise((r) => setImmediate(r));
      await vi.advanceTimersByTimeAsync(RETIRE_MS);
      await refused;
    } finally {
      vi.useRealTimers();
    }
    const e = await starting;
    await new Promise((r) => setTimeout(r, 200));
    expect(touched).toEqual([]);
    expect(pendingRetirements()).toEqual([]);
    expect(server.devices.get('u_alice')?.has(e.deviceId)).toBe(true);
    expect((await startE2EE('u_alice')).deviceId).toBe(e.deviceId);
  });

  it('keeps a failure reported during a pass even when the pass ends in a verdict', async () => {
    const server = new FakeKeyServer();
    let mailboxDown = false;
    let holdMaster: { promise: Promise<undefined>; resolve: () => void } | undefined;
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'GET' && path === '/api/v1/to-device' && mailboxDown) return json({ error: 'down' }, 503);
      if (method === 'GET' && path === '/api/v1/keys/master' && holdMaster) {
        const h = holdMaster;
        holdMaster = undefined;
        return h.promise;
      }
      return undefined;
    } })));
    await startE2EE('u_alice');
    const p = await prepareIdentity();
    await p.commit();
    // Alice sees her device list at a newer epoch, which the server later rolls back.
    const m = server.masters.get('u_alice')!;
    const seed = pqc.recoveryUnwrap(pqc.recoveryParse(p.recoveryKey), 'master-key', TENANT, 'u_alice', m.recovery.wrapped_master_key);
    const older = structuredClone(m.device_list!);
    const ids = older.device_ids;
    m.device_list = { epoch: older.epoch + 1, device_ids: ids, signature: pqc.signDeviceList(seed, TENANT, 'u_alice', m.version, older.epoch + 1, ids) };
    await identityStatus();
    mailboxDown = true;
    receiveRoomKeys();
    await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
    mailboxDown = false;
    let resolve = () => {};
    holdMaster = { promise: new Promise<undefined>((r) => { resolve = () => r(undefined); }), resolve: () => resolve() };
    const run = retryEncryptionNow();
    await vi.waitFor(() => expect(holdMaster).toBeUndefined());
    mailboxDown = true;
    receiveRoomKeys(); // fails while the pass waits
    await new Promise((r) => setTimeout(r, 100));
    mailboxDown = false;
    m.device_list = older; // the pass then ends in a verdict: a rollback
    resolve();
    await run;
    expect(encryptionRetry().pending).toBe(true);
  });

  it('stops waiting for a starting device when its own-device check is aborted, leaving the start-up alone', async () => {
    const server = new FakeKeyServer();
    let release = () => {};
    let held = true;
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) =>
      method === 'POST' && path === '/api/v1/keys/upload' && held ? new Promise<undefined>((r) => { release = () => r(undefined); }) : undefined })));
    const starting = startE2EE('u_alice');
    await new Promise((r) => setTimeout(r, 50));
    const ac = new AbortController();
    const check = ownDeviceVerified('ANYDEVICE001', ac.signal);
    ac.abort(new DOMException('closed', 'AbortError'));
    await expect(check).rejects.toThrow('closed');
    held = false;
    release();
    expect((await starting).userId).toBe('u_alice');
  });
});

describe('Round 6: status checks share one run', () => {
  it('answers concurrent status requests from at most two checks, the last after every request', async () => {
    const server = new FakeKeyServer();
    let masters = 0;
    vi.stubGlobal('fetch', vi.fn(httpFake(server, 'u_alice', { fn: (method, path) => {
      if (method === 'GET' && path === '/api/v1/keys/master') masters++;
      return undefined;
    } })));
    await startE2EE('u_alice');
    await (await prepareIdentity()).commit();
    await new Promise((r) => setTimeout(r, 100));
    masters = 0;
    await identityStatus();
    const one = masters;
    expect(one).toBeGreaterThan(0);
    masters = 0;
    const all = await Promise.all(Array.from({ length: 5 }, () => identityStatus()));
    expect(all.every((s) => s.state === 'verified')).toBe(true);
    expect(masters).toBeLessThanOrEqual(2 * one);
  });
});
