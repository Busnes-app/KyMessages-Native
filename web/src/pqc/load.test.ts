import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadPQCFrom, pqc, pqcCall, PQCUnavailable, pqcRunning } from './index';

// Its own file: each test file gets fresh module state, and these tests start the module.
const wasm = readFileSync('src/pqc/pqc.wasm');
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('loading the post-quantum module', () => {
  it('says unavailable, never a data error, before it runs; recovers from a crashed, silent or late start', async () => {
    expect(() => pqcCall('hash', 'a')).toThrow(PQCUnavailable);
    const crashing = () => {
      const go = new globalThis.Go();
      go.run = () => Promise.reject(new Error('boom'));
      return go;
    };
    await expect(loadPQCFrom(wasm, crashing)).rejects.toThrow('boom');
    expect(pqcRunning()).toBe(false);

    const silent = () => {
      const go = new globalThis.Go();
      go.run = () => new Promise<void>(() => undefined); // never hands over, never exits
      return go;
    };
    await expect(loadPQCFrom(wasm, silent, 300)).rejects.toThrow('did not start');
    expect(pqcRunning()).toBe(false);

    // A start that finishes after it was given up on must not take over from a newer one.
    let late: (() => void) | undefined;
    const slow = () => {
      const go = new globalThis.Go();
      const run = go.run.bind(go);
      go.run = (inst) => new Promise<void>((resolve) => { late = () => void run(inst).then(resolve); });
      return go;
    };
    await expect(loadPQCFrom(wasm, slow, 200)).rejects.toThrow('did not start');
    await loadPQCFrom(wasm);
    const before = pqc.hash('a', 'bc');
    late?.();
    await wait(200);
    expect(pqcRunning()).toBe(true);
    expect(pqc.hash('a', 'bc')).toBe(before);
    expect(before).toBe('b534ce16ac9c8b36823f39a395ce8e0e3c7ad9605b82b5444f18cadacd217a5d');
  });
});
