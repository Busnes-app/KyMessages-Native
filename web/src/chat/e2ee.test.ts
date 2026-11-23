import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { abandonDevice, forgetCryptoStore, NOT_YET, onRoomKeys, openMessage, retireDevice, retryable, sealRoomMessage, startE2EE, UNAVAILABLE } from './e2ee';
import { parseMessage } from './types';

// Tests may replace the device read; everything else is the real store.
const deviceRead = vi.hoisted(() => ({ replace: undefined as undefined | (() => Promise<{ user_id: string; device_id: string }[]>) }));
vi.mock('../crypto/store', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/store')>();
  return { ...real, storedDevices: () => deviceRead.replace?.() ?? real.storedDevices() };
});

// jsdom cannot fetch the module by URL; load it from disk instead.
vi.mock('../crypto/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/index')>();
  return { ...real, loadCrypto: async () => real.loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm')) };
});

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(async () => {
  deviceRead.replace = undefined;
  await forgetCryptoStore();
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe('the signed-in device', () => {
  it('starts over as a new device when the server no longer knows it', async () => {
    const known = new Set<string>();
    const uploads: { device_id: string; device_keys?: unknown; one_time_keys: unknown[] }[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/keys/upload') {
        const req = JSON.parse(String(init?.body)) as (typeof uploads)[number];
        uploads.push(req);
        if (req.device_keys) known.add(req.device_id);
        if (!known.has(req.device_id)) return json({ error: 'Unknown device' }, 404);
        return json({ one_time_key_count: req.one_time_keys.length });
      }
      if (url.startsWith('/api/v1/to-device')) return json({ messages: [] });
      return json({ error: `unexpected ${url}` }, 404);
    }));

    const first = await startE2EE('u_alice');
    // Registered once, self-signed, then stocked with 50 one-time keys.
    expect(uploads[0].device_keys).toBeTruthy();
    expect(uploads.reduce((n, u) => n + u.one_time_keys.length, 0)).toBe(50);

    await startE2EE('u_bob'); // closes alice's device, keeping its store
    known.delete(first.deviceId); // removed from another session
    const again = await startE2EE('u_alice');
    expect(again.deviceId).not.toBe(first.deviceId);
    expect(again.curve25519).not.toBe(first.curve25519);
    expect(known.has(first.deviceId)).toBe(false);
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
      return json({ error: `unexpected ${url}` }, 404);
    }));
    const old = await startE2EE('u_alice');
    await abandonDevice(); // the session was revoked: nothing can be deleted yet
    expect(deleted).toEqual([]);
    const fresh = await startE2EE('u_alice');
    await vi.waitFor(() => expect(deleted).toEqual([old.deviceId]));
    expect(fresh.deviceId).not.toBe(old.deviceId);
    expect(localStorage.getItem('kymessages-e2ee-retire')).toBeNull();
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
      return json({ error: `unexpected ${url}` }, 404);
    }));
    await startE2EE('u_alice');
    deviceRead.replace = read;
    await forgetCryptoStore();
    expect((await indexedDB.databases()).filter((d) => d.name?.startsWith('kymessages-crypto-'))).toEqual([]);
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
    expect(JSON.parse(localStorage.getItem('kymessages-e2ee-retire') ?? '[]')).toHaveLength(1);
    releaseUpload();
    await starting;
    // The cancelled start-up never brings the store back.
    await new Promise((r) => setTimeout(r, 50));
    expect(await stores()).toEqual([]);
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
    await vi.waitFor(async () => expect((await openMessage(m)).e2ee).toEqual({ kind: 'failed', reason: NOT_YET }));
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
      return json({ error: `unexpected ${url}` }, 404);
    }));
    await startE2EE('u_alice');
    expect(await retireDevice()).toBe(false); // a 5xx: the device is still listed
    deleteStatus = 404;
    expect(await retireDevice()).toBe(true); // already gone
    deleteStatus = 204;
    expect(await retireDevice()).toBe(true);
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
    expect((await openMessage(m)).e2ee).toEqual({ kind: 'failed', reason: UNAVAILABLE });
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
