// On-device message search (docs/superpowers/specs/2026-11-22-e2ee-design.md §6). The server
// cannot read encrypted rooms, so each browser keeps an index of the messages it has read, in
// IndexedDB, with every entry encrypted at rest under a non-extractable AES-GCM key that never
// leaves this database. Signing out deletes the index in every tab.
import type { ChatMessage } from './types';

const STORE = 'messages';
const META = 'meta';
const PREFIX = 'kymessages-search-';
// The newest messages kept per device; older ones fall out of search.
export const MAX_INDEXED = 50_000;
// Entries read and decrypted per step of a search.
const PAGE = 200;
// How long sign-out waits for other tabs to let go of the index before reporting failure.
const DELETE_TIMEOUT_MS = 5_000;

interface Entry {
  id: string;
  room_id: string;
  created_at: number;
  iv: Uint8Array;
  ct: ArrayBuffer;
}

// The fields kept for a hit: enough to show it and jump to it.
export type SearchHit = Pick<ChatMessage, 'id' | 'room_id' | 'seq' | 'sender_id' | 'sender_name' | 'body' | 'created_at' | 'edited_at'>;

const dbName = (userId: string) => PREFIX + userId;

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
  const r = indexedDB.open(dbName(userId), 2);
  r.onupgradeneeded = (ev) => {
    const db = r.result;
    // Version 2 only adds indexes for paged, newest-first and per-room reads.
    if (ev.oldVersion < 1) {
      db.createObjectStore(META);
      db.createObjectStore(STORE, { keyPath: 'id' }).createIndex('created_at', 'created_at');
    }
    const store = r.transaction!.objectStore(STORE);
    store.createIndex('newest', ['created_at', 'id']);
    store.createIndex('room_newest', ['room_id', 'created_at', 'id']);
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
  private closed = false;

  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {
    // Sign-out in any tab deletes the database; let it go at once so the delete completes, and
    // refuse every later read from this connection.
    db.onversionchange = () => this.close();
  }

  static async open(userId: string): Promise<SearchIndex> {
    const db = await open(userId);
    return new SearchIndex(db, await atRestKey(db));
  }

  get isClosed(): boolean {
    return this.closed;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
    if (current && currentIndex === this) {
      current = undefined;
      currentIndex = undefined;
      currentUser = '';
    }
  }

  private live(): void {
    if (this.closed) throw new DOMException('The search index was closed', 'InvalidStateError');
  }

  /** Indexes readable messages and drops deleted or empty ones. */
  async put(messages: ChatMessage[]): Promise<void> {
    this.live();
    const keep: Entry[] = [];
    const drop: string[] = [];
    for (const m of messages) {
      if (m.deleted_at || !m.body.trim() || m.encoding === 'system_v1' || m.delivery.kind !== 'synced') {
        if (m.deleted_at) drop.push(m.id);
        continue;
      }
      const plain: SearchHit = { id: m.id, room_id: m.room_id, seq: m.seq, sender_id: m.sender_id, sender_name: m.sender_name, body: m.body, created_at: m.created_at, edited_at: m.edited_at };
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(JSON.stringify(plain)));
      keep.push({ id: m.id, room_id: m.room_id, created_at: m.created_at, iv, ct });
    }
    if (keep.length === 0 && drop.length === 0) return;
    this.live();
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    for (const e of keep) store.put(e);
    for (const id of drop) store.delete(id);
    await done(tx);
    await this.prune();
  }

  /** Drops entries, for messages deleted or edited while their room was not loaded here. */
  async remove(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    this.live();
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    for (const id of ids) store.delete(id);
    await done(tx);
  }

  private async prune(): Promise<void> {
    this.live();
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    let extra = (await req(store.count())) - MAX_INDEXED;
    if (extra > 0) {
      await new Promise<void>((resolve, reject) => {
        const cursor = store.index('newest').openCursor();
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

  /** Up to `count` entries strictly older than `before`, newest first, in one short transaction. */
  private page(roomId: string | undefined, before: IDBValidKey[] | undefined, count: number): Promise<Entry[]> {
    this.live();
    const index = this.db.transaction(STORE).objectStore(STORE).index(roomId ? 'room_newest' : 'newest');
    let range: IDBKeyRange | undefined;
    if (roomId) range = IDBKeyRange.bound([roomId], before ?? [roomId, []], false, !!before);
    else if (before) range = IDBKeyRange.upperBound(before, true);
    return new Promise((resolve, reject) => {
      const out: Entry[] = [];
      const cursor = index.openCursor(range, 'prev');
      cursor.onerror = () => reject(cursor.error);
      cursor.onsuccess = () => {
        const c = cursor.result;
        if (!c || out.length >= count) return resolve(out);
        out.push(c.value as Entry);
        c.continue();
      };
    });
  }

  /**
   * Newest first: messages whose text or sender contains every word of query. Reads a page at a
   * time, decrypts each page in parallel, and stops at `limit` hits or when `signal` aborts.
   */
  async search(query: string, roomId?: string, limit = 50, signal?: AbortSignal): Promise<SearchHit[]> {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return [];
    const hits: SearchHit[] = [];
    let before: IDBValidKey[] | undefined;
    for (;;) {
      signal?.throwIfAborted();
      const entries = await this.page(roomId, before, PAGE);
      if (entries.length === 0) return hits;
      const last = entries[entries.length - 1];
      before = roomId ? [roomId, last.created_at, last.id] : [last.created_at, last.id];
      const plain = await Promise.all(
        entries.map(async (e) => {
          const bytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: e.iv }, this.key, e.ct);
          return JSON.parse(new TextDecoder().decode(bytes)) as SearchHit;
        }),
      );
      for (const m of plain) {
        const text = `${m.body}\n${m.sender_name}`.toLowerCase();
        if (words.every((w) => text.includes(w)) && hits.push(m) >= limit) return hits;
      }
      if (entries.length < PAGE) return hits;
    }
  }
}

/** The server's word on a message: still readable by this user, deleted, or edited since. */
export interface MessageState {
  id: string;
  deleted: boolean;
  edited_at: number;
}

/**
 * Keeps only hits the server still vouches for: the reader can see the message, it is not
 * deleted, and it has not been edited since it was indexed. The rest leave the index. A message
 * changed while this browser was away is never shown from its old copy.
 */
export async function freshHits(index: SearchIndex, hits: SearchHit[], states: (ids: string[]) => Promise<MessageState[]>): Promise<SearchHit[]> {
  if (hits.length === 0) return hits;
  const live = new Map((await states(hits.map((h) => h.id))).map((s) => [s.id, s]));
  const stale: string[] = [];
  const fresh = hits.filter((h) => {
    const s = live.get(h.id);
    const ok = !!s && !s.deleted && (s.edited_at || 0) === (h.edited_at || 0);
    if (!ok) stale.push(h.id);
    return ok;
  });
  await index.remove(stale).catch(() => undefined);
  return fresh;
}

/**
 * Deletes a user's index. It resolves only once the database is gone; other tabs close their
 * connections on `versionchange`, and a tab that still holds it past the timeout makes it reject.
 */
export function deleteSearchIndex(userId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.deleteDatabase(dbName(userId));
    const timer = setTimeout(() => reject(new Error('The search index is still open in another tab')), DELETE_TIMEOUT_MS);
    r.onsuccess = () => {
      clearTimeout(timer);
      resolve();
    };
    r.onerror = () => {
      clearTimeout(timer);
      reject(r.error ?? new Error('Could not delete the search index'));
    };
  });
}

let current: Promise<SearchIndex> | undefined;
let currentIndex: SearchIndex | undefined;
let currentUser = '';

/** The signed-in user's index, opened once (and reopened after another tab deleted it). */
export function searchIndexFor(userId: string): Promise<SearchIndex> {
  if (!current || currentUser !== userId) {
    currentIndex?.close();
    currentUser = userId;
    const opening: Promise<SearchIndex> = SearchIndex.open(userId).then(
      (i) => {
        if (current === opening) currentIndex = i;
        return i;
      },
      (e: unknown) => {
        if (current === opening) current = undefined;
        throw e;
      },
    );
    current = opening;
  }
  return current;
}

/**
 * Closes the open index and deletes every KyMessages search index in this browser, for sign-out.
 * It rejects if any index could not be deleted, so the caller can tell the user.
 */
export async function forgetSearchIndex(): Promise<void> {
  const opening = current;
  current = undefined;
  currentIndex = undefined;
  currentUser = '';
  await opening?.then((i) => i.close()).catch(() => undefined);
  if (typeof indexedDB === 'undefined') return;
  const dbs = await indexedDB.databases();
  const results = await Promise.allSettled(
    dbs.filter((d) => d.name?.startsWith(PREFIX)).map((d) => deleteSearchIndex(d.name!.slice(PREFIX.length))),
  );
  const failed = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
  if (failed) throw failed.reason;
}

// Sign-out in one tab signs out the others, even one whose WebSocket missed the revocation.
const CHANNEL = 'kymessages-session';

export function announceSignOut(): void {
  if (typeof BroadcastChannel === 'undefined') return;
  const ch = new BroadcastChannel(CHANNEL);
  ch.postMessage('signed-out');
  ch.close();
}

/** Calls onSignOut when another tab signs out; returns the unsubscribe function. */
export function onSignOutElsewhere(onSignOut: () => void): () => void {
  if (typeof BroadcastChannel === 'undefined') return () => undefined;
  const ch = new BroadcastChannel(CHANNEL);
  ch.onmessage = (ev: MessageEvent) => {
    if (ev.data === 'signed-out') onSignOut();
  };
  return () => ch.close();
}
