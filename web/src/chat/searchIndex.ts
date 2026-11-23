// On-device message search (docs/superpowers/specs/2026-11-22-e2ee-design.md §6). The server
// cannot read encrypted rooms, so each browser keeps an index of the messages it has read, in
// SearchHitDB, with every entry encrypted at rest under a non-extractable AES-GCM key that never
// leaves this database. Signing out deletes the index.
import type { ChatMessage } from './types';

const STORE = 'messages';
const META = 'meta';
// The newest messages kept per device; older ones fall out of search.
export const MAX_INDEXED = 50_000;

interface Entry {
  id: string;
  room_id: string;
  created_at: number;
  iv: Uint8Array;
  ct: ArrayBuffer;
}

// The fields kept for a hit: enough to show it and jump to it.
export type SearchHit = Pick<ChatMessage, 'id' | 'room_id' | 'seq' | 'sender_id' | 'sender_name' | 'body' | 'created_at'>;

const dbName = (userId: string) => `kymessages-search-${userId}`;

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

function open(userId: string): Promise<IDBDatabase> {
  const r = indexedDB.open(dbName(userId), 1);
  r.onupgradeneeded = () => {
    const db = r.result;
    db.createObjectStore(META);
    db.createObjectStore(STORE, { keyPath: 'id' }).createIndex('created_at', 'created_at');
  };
  return req(r);
}

async function atRestKey(db: IDBDatabase): Promise<CryptoKey> {
  const found = await req(db.transaction(META).objectStore(META).get('key'));
  if (found instanceof CryptoKey) return found;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  // Another tab may have stored one first; keep whichever is there.
  const tx = db.transaction(META, 'readwrite');
  const meta = tx.objectStore(META);
  const raced = await req(meta.get('key'));
  if (raced instanceof CryptoKey) return raced;
  meta.put(key, 'key');
  await done(tx);
  return key;
}

export class SearchIndex {
  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {}

  static async open(userId: string): Promise<SearchIndex> {
    const db = await open(userId);
    return new SearchIndex(db, await atRestKey(db));
  }

  close(): void {
    this.db.close();
  }

  /** Indexes readable messages and drops deleted or empty ones. */
  async put(messages: ChatMessage[]): Promise<void> {
    const keep: Entry[] = [];
    const drop: string[] = [];
    for (const m of messages) {
      if (m.deleted_at || !m.body.trim() || m.encoding === 'system_v1' || m.delivery.kind !== 'synced') {
        if (m.deleted_at) drop.push(m.id);
        continue;
      }
      const plain: SearchHit = { id: m.id, room_id: m.room_id, seq: m.seq, sender_id: m.sender_id, sender_name: m.sender_name, body: m.body, created_at: m.created_at };
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(JSON.stringify(plain)));
      keep.push({ id: m.id, room_id: m.room_id, created_at: m.created_at, iv, ct });
    }
    if (keep.length === 0 && drop.length === 0) return;
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    for (const e of keep) store.put(e);
    for (const id of drop) store.delete(id);
    await done(tx);
    await this.prune();
  }

  private async prune(): Promise<void> {
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    let extra = (await req(store.count())) - MAX_INDEXED;
    if (extra > 0) {
      await new Promise<void>((resolve, reject) => {
        const cursor = store.index('created_at').openCursor();
        cursor.onerror = () => reject(cursor.error);
        cursor.onsuccess = () => {
          const c = cursor.result;
          if (!c || extra <= 0) return resolve();
          c.delete();
          extra--;
          c.continue();
        };
      });
    }
    await done(tx);
  }

  /** Newest first: messages whose text or sender contains every word of query. */
  async search(query: string, roomId?: string, limit = 50): Promise<SearchHit[]> {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return [];
    const entries = (await req(this.db.transaction(STORE).objectStore(STORE).index('created_at').getAll())) as Entry[];
    const hits: SearchHit[] = [];
    for (let i = entries.length - 1; i >= 0 && hits.length < limit; i--) {
      const e = entries[i];
      if (roomId && e.room_id !== roomId) continue;
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: e.iv }, this.key, e.ct);
      const m = JSON.parse(new TextDecoder().decode(plain)) as SearchHit;
      const text = `${m.body}\n${m.sender_name}`.toLowerCase();
      if (words.every((w) => text.includes(w))) hits.push(m);
    }
    return hits;
  }
}

/** Deletes a user's index, for sign-out. */
export function deleteSearchIndex(userId: string): Promise<void> {
  return new Promise((resolve) => {
    const r = indexedDB.deleteDatabase(dbName(userId));
    // A blocked delete (another tab still open) completes once that tab closes the database.
    r.onsuccess = r.onerror = r.onblocked = () => resolve();
  });
}

let current: Promise<SearchIndex> | undefined;
let currentUser = '';

/** The signed-in user's index, opened once. */
export function searchIndexFor(userId: string): Promise<SearchIndex> {
  if (!current || currentUser !== userId) {
    void current?.then((i) => i.close()).catch(() => undefined);
    currentUser = userId;
    current = SearchIndex.open(userId).catch((e: unknown) => {
      current = undefined;
      throw e;
    });
  }
  return current;
}

/** Closes the open index and deletes every KyMessages search index in this browser, for sign-out. */
export async function forgetSearchIndex(): Promise<void> {
  const open = current;
  current = undefined;
  currentUser = '';
  await open?.then((i) => i.close()).catch(() => undefined);
  if (typeof indexedDB === 'undefined') return;
  const dbs = await indexedDB.databases().catch(() => []);
  await Promise.all(
    dbs.filter((d) => d.name?.startsWith('kymessages-search-')).map((d) => deleteSearchIndex(d.name!.slice('kymessages-search-'.length))),
  );
}
