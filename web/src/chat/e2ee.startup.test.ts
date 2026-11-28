import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { afterEach, expect, it, vi } from 'vitest';
import { encryptionRetry, forgetCryptoStore, retryEncryptionNow, startE2EE } from './e2ee';
import { FakeKeyServer } from '../crypto/fakeKeyServer';
import { PQCUnavailable } from '../pqc/index';
import { httpFake } from './httpFake';

// Its own file: the post-quantum module must not have started yet, as on a first page load.
const pqcFetch = vi.hoisted(() => ({ fail: true, fetches: 0 }));
vi.mock('../crypto/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../crypto/index')>();
  return { ...real, loadCrypto: async () => real.loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm')) };
});
vi.mock('../pqc/index', async (importOriginal) => {
  const real = await importOriginal<typeof import('../pqc/index')>();
  // Read on every start, as loadPQC fetches on every start.
  return { ...real, loadPQC: () => real.loadPQCFrom(async () => {
    pqcFetch.fetches++;
    if (pqcFetch.fail) throw new TypeError('Failed to fetch');
    return readFileSync('src/pqc/pqc.wasm');
  }) };
});

afterEach(async () => {
  await forgetCryptoStore();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it('shows a device that could not start for availability as waiting, and starts it on retry', async () => {
  vi.stubGlobal('fetch', vi.fn(httpFake(new FakeKeyServer(), 'u_alice')));
  await expect(startE2EE('u_alice')).rejects.toBeInstanceOf(PQCUnavailable);
  await vi.waitFor(() => expect(encryptionRetry().pending).toBe(true));
  // Still failing: the retry fails too and stays scheduled, from the same session's budget.
  await retryEncryptionNow();
  expect(encryptionRetry()).toEqual({ pending: true, exhausted: false });
  pqcFetch.fail = false;
  await retryEncryptionNow();
  expect(encryptionRetry()).toEqual({ pending: false, exhausted: false });
  expect((await startE2EE('u_alice')).userId).toBe('u_alice');
  expect(pqcFetch.fetches).toBeGreaterThanOrEqual(3);
});
