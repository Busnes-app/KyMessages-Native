import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadPQCFrom, pqc } from './index';

// Its own file: each test file gets fresh globals, and these tests start the module themselves.
const wasm = readFileSync('src/pqc/pqc.wasm');

describe('loading the post-quantum module', () => {
  it('rejects a Go program that crashes or never starts, and loads cleanly on the next call', async () => {
    const crashing = () => {
      const go = new globalThis.Go();
      go.run = () => Promise.reject(new Error('boom'));
      return go;
    };
    await expect(loadPQCFrom(wasm, crashing)).rejects.toThrow('boom');
    const silent = () => {
      const go = new globalThis.Go();
      go.run = () => new Promise<void>(() => undefined); // never registers, never exits
      return go;
    };
    await expect(loadPQCFrom(wasm, silent, 300)).rejects.toThrow('did not start');
    expect(globalThis.kyPQCCall).toBeUndefined();

    await loadPQCFrom(wasm);
    expect(pqc.hash('a', 'bc')).toBe('b534ce16ac9c8b36823f39a395ce8e0e3c7ad9605b82b5444f18cadacd217a5d');
  });
});
