import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { forgetSearchIndex, SearchIndex, searchIndexFor } from './searchIndex';
import type { ChatMessage } from './types';

const msg = (id: string, room: string, body: string, created: number, extra: Partial<ChatMessage> = {}): ChatMessage => ({
  id, tenant_id: 't', room_id: room, seq: created, sender_id: 'u1', sender_name: 'Ana Lima', encoding: 'plain_v1', body,
  created_at: created, reactions: [], attachments: [], delivery: { kind: 'synced' }, ...extra,
});

afterEach(async () => {
  await forgetSearchIndex();
});

describe('on-device search index', () => {
  it('finds every word, newest first, scoped to a room, and drops deleted messages', async () => {
    const index = await searchIndexFor('u-alice');
    await index.put([
      msg('m1', 'r1', 'Budget review on Friday', 1),
      msg('m2', 'r2', 'The budget sheet is ready', 2),
      msg('m3', 'r1', 'Lunch?', 3),
      msg('m4', 'r1', '', 4),
      msg('m5', 'r1', 'pending budget', 5, { delivery: { kind: 'sending' } as ChatMessage['delivery'] }),
    ]);
    expect((await index.search('budget')).map((h) => h.id)).toEqual(['m2', 'm1']);
    expect((await index.search('BUDGET friday')).map((h) => h.id)).toEqual(['m1']);
    expect((await index.search('budget', 'r2')).map((h) => h.id)).toEqual(['m2']);
    expect((await index.search('ana lima', 'r1')).map((h) => h.id)).toEqual(['m3', 'm1']);
    await index.put([msg('m1', 'r1', 'Budget review on Friday', 1, { deleted_at: 9 })]);
    expect((await index.search('friday')).map((h) => h.id)).toEqual([]);
  });

  it('stores only ciphertext at rest and keeps each user apart', async () => {
    const alice = await searchIndexFor('u-alice');
    await alice.put([msg('m1', 'r1', 'quarterly secret plan', 1)]);
    const raw = await new Promise<unknown[]>((resolve) => {
      const r = indexedDB.open('kymessages-search-u-alice');
      r.onsuccess = () => {
        const all = r.result.transaction('messages').objectStore('messages').getAll();
        all.onsuccess = () => {
          r.result.close();
          resolve(all.result);
        };
      };
    });
    expect(raw).toHaveLength(1);
    expect(JSON.stringify(raw)).not.toContain('quarterly');
    const bob = await SearchIndex.open('u-bob');
    expect(await bob.search('quarterly')).toEqual([]);
    bob.close();
  });

  it('is deleted for every user on sign-out', async () => {
    await (await searchIndexFor('u-alice')).put([msg('m1', 'r1', 'keep me private', 1)]);
    const bob = await SearchIndex.open('u-bob');
    await bob.put([msg('m2', 'r1', 'also private', 1)]);
    bob.close();
    await forgetSearchIndex();
    const names = (await indexedDB.databases()).map((d) => d.name);
    expect(names.filter((n) => n?.startsWith('kymessages-search-'))).toEqual([]);
    expect(await (await searchIndexFor('u-alice')).search('private')).toEqual([]);
  });

  it('pages newest first across many entries, scopes by room, and stops when aborted', async () => {
    const index = await searchIndexFor('u-alice');
    const many = Array.from({ length: 450 }, (_, i) => msg(`m${String(i).padStart(3, '0')}`, i % 2 ? 'r1' : 'r2', i === 0 ? 'note oldest' : `note ${i}`, 1000 + i));
    await index.put(many);
    const newest = await index.search('note', undefined, 5);
    expect(newest.map((h) => h.id)).toEqual(['m449', 'm448', 'm447', 'm446', 'm445']);
    // Room-scoped reads use the room index and still cross page boundaries.
    const r2 = await index.search('note', 'r2', 300);
    expect(r2).toHaveLength(225);
    expect(r2.every((h) => h.room_id === 'r2')).toBe(true);
    expect(r2[0].id).toBe('m448');
    expect(r2[224].id).toBe('m000');
    // The oldest entry is found even though every page before it misses.
    expect((await index.search('oldest')).map((h) => h.id)).toEqual(['m000']);
    const abort = new AbortController();
    abort.abort();
    await expect(index.search('note', undefined, 50, abort.signal)).rejects.toThrow();
  });

  it('closes another tab\'s connection on sign-out, which then refuses reads', async () => {
    const mine = await searchIndexFor('u-alice');
    await mine.put([msg('m1', 'r1', 'shared browser secret', 1)]);
    const otherTab = await SearchIndex.open('u-alice');
    expect((await otherTab.search('secret')).map((h) => h.id)).toEqual(['m1']);
    await forgetSearchIndex();
    expect(otherTab.isClosed).toBe(true);
    await expect(otherTab.search('secret')).rejects.toThrow();
    expect((await indexedDB.databases()).map((d) => d.name)).not.toContain('kymessages-search-u-alice');
  });

  it('reports failure when a tab holds the index open and will not let go', async () => {
    await (await searchIndexFor('u-alice')).put([msg('m1', 'r1', 'stuck', 1)]);
    // An old tab without a versionchange handler blocks the delete.
    const stuck = await new Promise<IDBDatabase>((resolve) => {
      const r = indexedDB.open('kymessages-search-u-alice');
      r.onsuccess = () => resolve(r.result);
    });
    await expect(forgetSearchIndex()).rejects.toThrow('still open in another tab');
    stuck.close();
  }, 15_000);
});
