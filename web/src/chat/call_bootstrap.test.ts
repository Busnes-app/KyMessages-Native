import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchBootstrap } from './client';
import type { CallState } from './types';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const state = (room: string): CallState => ({ call_id: `call_${room}`, room_id: room, mode: 'p2p_mesh', epoch: 2, sfu_sticky: false, peers: [] });
const bootstrap = (tenant: string) => ({
  user: { id: 'alice', username: 'alice', role: 'user' },
  tenant: { id: tenant, slug: tenant, display_name: 'Team' },
  rooms: ['one', 'two', 'three'].map((id) => ({ id, tenant_id: tenant, kind: 'channel', name: id,
    topic: '', is_private: false, last_seq: 0, created_by: 'alice', created_at: 1,
    role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all' })),
  active_calls: { two: state('two'), three: state('three') },
});

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('room-routed call bootstrap', () => {
  it('discovers another owner, removes ended calls and retains a snapshot on outage', async () => {
    const request = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') return json(bootstrap('hosted-org'));
      if (url === '/api/v1/rooms/one/calls/state') return json({ call: state('one') });
      if (url === '/api/v1/rooms/two/calls/state') return json({ call: null });
      return json({ error: 'owner unavailable' }, 503);
    });
    vi.stubGlobal('fetch', request);
    const result = await fetchBootstrap();
    expect(Object.keys(result.active_calls).sort()).toEqual(['one', 'three']);
    expect(result.active_calls.one.room_id).toBe('one');
    expect(request).toHaveBeenCalledTimes(4);
  });

  it('rejects a different room in a successful owner response', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => String(input) === '/api/v1/bootstrap'
      ? json(bootstrap('hosted-org')) : json({ call: state('unrelated-room') })));
    const result = await fetchBootstrap();
    expect(result.active_calls.one).toBeUndefined();
    expect(Object.keys(result.active_calls).sort()).toEqual(['three', 'two']);
  });

  it('retains the caller roster on owner failure, removes authoritative nulls and drops inaccessible rooms', async () => {
    const previous = { one: state('one'), two: state('two'), removed: state('removed') };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') return json({ ...bootstrap('hosted-org'), active_calls: {} });
      if (url === '/api/v1/rooms/one/calls/state') return json({ error: 'owner unavailable' }, 503);
      if (url === '/api/v1/rooms/two/calls/state') return json({ call: null });
      return json({ call: state('three') });
    }));
    const result = await fetchBootstrap(() => ({ calls: previous, revisions: {} }));
    expect(Object.keys(result.active_calls).sort()).toEqual(['one', 'three']);
    expect(result.active_calls.one).toEqual(previous.one);
    expect(Object.keys(previous).sort()).toEqual(['one', 'removed', 'two']);
  });

  it('keeps single-mode bootstrap at its existing one request', async () => {
    const request = vi.fn(async () => json(bootstrap('default')));
    vi.stubGlobal('fetch', request);
    expect(Object.keys((await fetchBootstrap()).active_calls).sort()).toEqual(['three', 'two']);
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('bounds a stalled owner with controlled time', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/api/v1/bootstrap') return json({ ...bootstrap('hosted-org'), active_calls: {} });
      return new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    }));
    let previous: Record<string, ReturnType<typeof state>> = { two: state('two'), three: state('three') };
    const pending = fetchBootstrap(() => ({ calls: previous, revisions: {} }));
    await vi.advanceTimersByTimeAsync(1_000);
    // A call ended locally while the other owner's request was still stalled.
    previous = { two: state('two') };
    await vi.advanceTimersByTimeAsync(1_000);
    const result = await pending;
    expect(Object.keys(result.active_calls)).toEqual(['two']);
  });
  it('does not restore a successful but outdated owner response after a live call ends', async () => {
    vi.useFakeTimers();
    let current: Record<string, CallState> = { one: state('one') };
    const revisions = { one: 0 };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') return json(bootstrap('hosted-org'));
      if (url === '/api/v1/rooms/one/calls/state') return json({ call: state('one') });
      return new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    }));
    const pending = fetchBootstrap(() => ({ calls: current, revisions }));
    await vi.advanceTimersByTimeAsync(1_000);
    current = {};
    revisions.one++;
    await vi.advanceTimersByTimeAsync(1_000);
    expect((await pending).active_calls.one).toBeUndefined();
  });

  it.each([false, true])('preserves a live update after an earlier owner read (ended=%s)', async (ended) => {
    vi.useFakeTimers();
    let current: Record<string, CallState> = {};
    const revisions = { one: 0 };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') return json(bootstrap('hosted-org'));
      if (url === '/api/v1/rooms/one/calls/state') return json({ call: ended ? state('one') : null });
      return new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    }));
    const pending = fetchBootstrap(() => ({ calls: current, revisions }));
    await vi.advanceTimersByTimeAsync(1_000);
    current = { one: { ...state('one'), epoch: 9 } };
    revisions.one++;
    if (ended) { current = {}; revisions.one++; }
    await vi.advanceTimersByTimeAsync(1_000);
    const calls = (await pending).active_calls;
    if (ended) expect(calls.one).toBeUndefined();
    else expect(calls.one.epoch).toBe(9);
  });

});
