import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { forgetSearchIndex, freshHits, type MessageState, SearchIndex, searchIndexFor } from './searchIndex';
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

  it('shows only hits the server still vouches for and drops the rest from the index', async () => {
    const index = await searchIndexFor('u-alice');
    await index.put([
      msg('kept', 'r1', 'quarterly plan', 1),
      msg('edited', 'r1', 'quarterly draft', 2, { edited_at: 5 }),
      msg('deleted', 'r1', 'quarterly secret', 3),
      msg('left', 'r2', 'quarterly gossip', 4),
    ]);
    const server: MessageState[] = [
      { id: 'kept', deleted: false, edited_at: 0 },
      { id: 'edited', deleted: false, edited_at: 9 }, // edited again while this browser was away
      { id: 'deleted', deleted: true, edited_at: 0 },
      // 'left': the reader left r2, so the server does not answer for it
    ];
    const asked: string[][] = [];
    const states = async (ids: string[]) => {
      asked.push(ids);
      return server.filter((s) => ids.includes(s.id));
    };
    const hits = await freshHits(index, await index.search('quarterly'), states);
    expect(hits.map((h) => h.id)).toEqual(['kept']);
    expect(asked).toEqual([['left', 'deleted', 'edited', 'kept']]);
    // The stale copies are gone from the device, not just hidden once.
    expect((await index.search('quarterly')).map((h) => h.id)).toEqual(['kept']);
    // If the server cannot be asked, nothing unverified is shown.
    await expect(freshHits(index, await index.search('quarterly'), async () => { throw new Error('offline'); })).rejects.toThrow('offline');
  });

  it('drops an earlier copy when a message stops being indexable without being deleted', async () => {
    const index = await searchIndexFor('u-alice');
    await index.put([msg('m1', 'r1', 'readable secret', 1), msg('m2', 'r1', 'another secret', 2), msg('m3', 'r1', 'third secret', 3)]);
    expect((await index.search('secret')).map((h) => h.id)).toEqual(['m3', 'm2', 'm1']);
    await index.put([
      msg('m1', 'r1', '', 1), // emptied, e.g. a decrypt that now fails
      msg('m2', 'r1', 'another secret', 2, { encoding: 'system_v1' }),
      msg('m3', 'r1', 'third secret', 3, { delivery: { kind: 'sending' } as ChatMessage['delivery'] }),
    ]);
    expect(await index.search('secret')).toEqual([]);
  });
});
