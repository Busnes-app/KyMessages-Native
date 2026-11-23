import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { deleteCryptoStores, openCryptoStore } from './store';

afterEach(() => vi.restoreAllMocks());

const names = async () => (await indexedDB.databases()).map((d) => d.name).filter((n) => n?.startsWith('kymessages-crypto-'));

describe('crypto store deletion', () => {
  it("closes another tab's connection, tells its owner, and only then reports the store gone", async () => {
    const mine = await openCryptoStore('u-a');
    await mine.write([['secret', 'device private key pickle']]);
    const otherTab = await openCryptoStore('u-a');
    let dropped = false;
    otherTab.onClosed(() => {
      dropped = true;
    });
    mine.close();
    await deleteCryptoStores();
    expect(dropped).toBe(true);
    expect(await names()).toEqual([]);
    await expect(otherTab.get('secret')).rejects.toThrow();
  });

  it('reports failure while a connection without a handler holds the store, then finishes once it closes', async () => {
    const store = await openCryptoStore('u-b');
    await store.write([['secret', 'room keys']]);
    store.close();
    // An old tab that never closes on versionchange.
    const stuck = await new Promise<IDBDatabase>((resolve) => {
      const r = indexedDB.open('kymessages-crypto-u-b');
      r.onsuccess = () => resolve(r.result);
    });
    await expect(deleteCryptoStores()).rejects.toThrow('still open in another tab');
    expect(await names()).toEqual(['kymessages-crypto-u-b']);
    stuck.close();
    await expect.poll(names).toEqual([]);
  }, 15_000);

  it('rejects when the browser fails the delete, so sign-out can warn', async () => {
    const store = await openCryptoStore('u-c');
    await store.write([['secret', 'k']]);
    store.close();
    vi.spyOn(indexedDB, 'deleteDatabase').mockImplementation(() => {
      const r = {} as IDBOpenDBRequest;
      setTimeout(() => {
        Object.defineProperty(r, 'error', { value: new DOMException('disk failure', 'UnknownError') });
        r.onerror?.(new Event('error'));
      });
      return r;
    });
    await expect(deleteCryptoStores()).rejects.toThrow('disk failure');
  });

  it('rejects when the browser cannot list its databases', async () => {
    vi.spyOn(indexedDB, 'databases').mockRejectedValue(new DOMException('listing refused', 'UnknownError'));
    await expect(deleteCryptoStores()).rejects.toThrow('listing refused');
  });
});
