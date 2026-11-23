import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { abandonDevice, forgetCryptoStore, openMessage, retireDevice, startE2EE, UNAVAILABLE } from './e2ee';
import { parseMessage } from './types';

// jsdom cannot fetch the module by URL; load it from disk instead.
vi.mock('../crypto/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/index')>();
  return { ...real, loadCrypto: async () => real.loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm')) };
});

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(async () => {
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

  it('does not hold live messages behind a device that is still starting', async () => {
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
    const live = await openMessage(m, { wait: false });
    expect(live.e2ee).toEqual({ kind: 'failed', reason: UNAVAILABLE });
    release!(json({ error: 'stop' }, 500));
    await starting.catch(() => undefined);
  });
});
