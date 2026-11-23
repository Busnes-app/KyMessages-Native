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
});
