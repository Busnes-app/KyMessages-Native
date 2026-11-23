import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Account, loadCrypto } from './index';

afterEach(() => vi.unstubAllGlobals());

describe('loadCrypto', () => {
  it('retries after a failed load and is idempotent once it succeeds', async () => {
    const wasm = readFileSync('src/crypto/pkg/kycrypto_bg.wasm');
    let online = false;
    const fetchMock = vi.fn(async () => {
      if (!online) throw new TypeError('offline');
      return new Response(wasm, { headers: { 'Content-Type': 'application/wasm' } });
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(loadCrypto()).rejects.toThrow('offline');
    online = true;
    await loadCrypto();
    await loadCrypto();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(new Account().curve25519).toMatch(/^[A-Za-z0-9+/]{43}$/);
  });
});
