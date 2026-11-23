// The device's end-to-end encryption state in IndexedDB (docs/superpowers/specs/2026-11-22-e2ee-design.md
// §3, §4): the vodozemac Account, Olm and Megolm sessions, pinned device keys and the replay log.
// Every pickle is encrypted by vodozemac under a random 32-byte pickle key, and that key is stored
// only wrapped by a non-extractable AES-GCM key that never leaves this database. Signing out
// deletes the database.

const DB_PREFIX = 'kymessages-crypto-';
const KV = 'kv';

export interface CryptoStore {
  get<T>(key: string): Promise<T | undefined>;
  /** Every [key, value] whose key starts with prefix. */
  list<T>(prefix: string): Promise<[string, T][]>;
  /** Writes and deletes in one transaction. */
  write(puts: [string, unknown][], deletes?: string[]): Promise<void>;
  /** Stores value under key unless one is there; returns what is stored afterwards. */
  putIfAbsent<T>(key: string, value: T): Promise<T>;
  /** The 32-byte key vodozemac encrypts pickles under. */
  pickleKey(): Promise<Uint8Array>;
  close(): void;
  /** Calls fn once if another tab deletes this store and the connection is closed under us. */
  onClosed(fn: () => void): void;
}

// How long a delete waits for other tabs to let go before reporting failure.
const DELETE_TIMEOUT_MS = 5_000;

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

interface WrappedKey {
  iv: Uint8Array;
  ct: ArrayBuffer;
}

class IdbCryptoStore implements CryptoStore {
  private key?: Promise<Uint8Array>;
  private closedFns: (() => void)[] = [];

  constructor(private readonly db: IDBDatabase) {
    // Sign-out or a device reset in any tab deletes this database: let go at once so the delete
    // completes, and tell the owner, which drops this device instead of using a deleted one.
    db.onversionchange = () => {
      this.close();
      for (const fn of this.closedFns.splice(0)) fn();
    };
  }

  onClosed(fn: () => void): void {
    this.closedFns.push(fn);
  }

  async get<T>(key: string): Promise<T | undefined> {
    return (await req(this.db.transaction(KV).objectStore(KV).get(key))) as T | undefined;
  }

  async list<T>(prefix: string): Promise<[string, T][]> {
    const store = this.db.transaction(KV).objectStore(KV);
    const range = IDBKeyRange.bound(prefix, prefix + '￿');
    const [keys, values] = await Promise.all([req(store.getAllKeys(range)), req(store.getAll(range))]);
    return keys.map((k, i) => [String(k), values[i] as T]);
  }

  async write(puts: [string, unknown][], deletes: string[] = []): Promise<void> {
    if (puts.length === 0 && deletes.length === 0) return;
    const tx = this.db.transaction(KV, 'readwrite');
    const store = tx.objectStore(KV);
    for (const [k, v] of puts) store.put(v, k);
    for (const k of deletes) store.delete(k);
    await done(tx);
  }

  async putIfAbsent<T>(key: string, value: T): Promise<T> {
    const tx = this.db.transaction(KV, 'readwrite');
    const store = tx.objectStore(KV);
    const found = (await req(store.get(key))) as T | undefined;
    if (found === undefined) store.put(value, key);
    await done(tx);
    return found === undefined ? value : found;
  }

  pickleKey(): Promise<Uint8Array> {
    this.key ??= this.loadPickleKey().catch((e: unknown) => {
      this.key = undefined;
      throw e;
    });
    return this.key;
  }

  private async loadPickleKey(): Promise<Uint8Array> {
    const unwrap = async (wrap: CryptoKey, w: WrappedKey) =>
      new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: w.iv }, wrap, w.ct));
    const wrap = await this.get<CryptoKey>('meta:wrap');
    const wrapped = await this.get<WrappedKey>('meta:pickle_key');
    if (wrap instanceof CryptoKey && wrapped) return unwrap(wrap, wrapped);

    const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fresh, raw);
    // Another tab may have stored a key first; keep whichever is there.
    const tx = this.db.transaction(KV, 'readwrite');
    const store = tx.objectStore(KV);
    const racedWrap = (await req(store.get('meta:wrap'))) as CryptoKey | undefined;
    const racedKey = (await req(store.get('meta:pickle_key'))) as WrappedKey | undefined;
    if (!(racedWrap instanceof CryptoKey && racedKey)) {
      store.put(fresh, 'meta:wrap');
      store.put({ iv, ct } satisfies WrappedKey, 'meta:pickle_key');
    }
    await done(tx);
    return racedWrap instanceof CryptoKey && racedKey ? unwrap(racedWrap, racedKey) : raw;
  }

  close(): void {
    this.db.close();
  }
}

/** Opens (creating if needed) a user's crypto store in this browser. */
export async function openCryptoStore(userId: string): Promise<CryptoStore> {
  const r = indexedDB.open(DB_PREFIX + userId, 1);
  r.onupgradeneeded = () => {
    r.result.createObjectStore(KV);
  };
  return new IdbCryptoStore(await req(r));
}

// Resolves only once the database is gone. Other tabs close on versionchange; one that still
// holds it past the timeout (an old tab) makes this reject. The delete itself stays queued and
// completes when that connection closes.
function deleteDb(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.deleteDatabase(name);
    const timer = setTimeout(() => reject(new Error('The encryption store is still open in another tab')), DELETE_TIMEOUT_MS);
    r.onsuccess = () => {
      clearTimeout(timer);
      resolve();
    };
    r.onerror = () => {
      clearTimeout(timer);
      reject(r.error ?? new Error('Could not delete the encryption store'));
    };
  });
}

/** Deletes one user's crypto store in this browser. */
export function deleteCryptoStore(userId: string): Promise<void> {
  return typeof indexedDB === 'undefined' ? Promise.resolve() : deleteDb(DB_PREFIX + userId);
}

/** Deletes every KyMessages crypto store in this browser, for sign-out; rejects if any remains. */
export async function deleteCryptoStores(): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const dbs = await indexedDB.databases();
  const results = await Promise.allSettled(dbs.filter((d) => d.name?.startsWith(DB_PREFIX)).map((d) => deleteDb(d.name!)));
  const failed = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
  if (failed) throw failed.reason;
}
