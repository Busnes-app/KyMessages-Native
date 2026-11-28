import { describe, expect, it } from 'vitest';
import { applyReactionDelta, forgetDeleted, isGroupedWithPrevious, mergeMessageBatch, rememberDeleted, replaceMessageHistory, resolvePending, searchSignature, sortRooms, upsertMessage } from './state';
import { parseMessagesPage, parseWsEvent, type ChatMessage, type ChatRoomSummary } from './types';

function makeMsg(overrides: Partial<ChatMessage> = {}): ChatMessage {
  return {
    id: 'msg_1',
    tenant_id: 'default',
    room_id: 'rm_1',
    seq: 1,
    sender_id: 'u_alice',
    sender_name: 'Alice',
    encoding: 'plain_v1',
    body: 'hello',
    created_at: 1_700_000_000_000,
    reactions: [],
    attachments: [],
    delivery: { kind: 'synced' },
    ...overrides,
  };
}

describe('chat state helpers', () => {
  it('reconciles optimistic pending message on server confirmation without duplicates', () => {
    const pending = makeMsg({
      id: 'pending_k1',
      seq: Number.MAX_SAFE_INTEGER,
      body: 'ship it',
      delivery: { kind: 'sending', idempotencyKey: 'k1' },
    });
    const confirmed = makeMsg({ id: 'msg_42', seq: 42, body: 'ship it', ref: 'k1' });

    const next = upsertMessage([pending], confirmed);
    expect(next).toHaveLength(1);
    expect(next[0].id).toBe('msg_42');
    expect(next[0].delivery.kind).toBe('synced');
  });

  it('deduplicates when WS message.new arrives before REST resolves', () => {
    const pending = makeMsg({
      id: 'pending_k2',
      seq: Number.MAX_SAFE_INTEGER,
      body: 'race condition',
      delivery: { kind: 'sending', idempotencyKey: 'k2' },
    });
    const wsCopy = makeMsg({ id: 'msg_99', seq: 99, body: 'race condition', ref: 'k2' });

    const afterWs = upsertMessage([pending], wsCopy);
    expect(afterWs).toHaveLength(1);
    expect(afterWs[0].id).toBe('msg_99');

    const afterRest = upsertMessage(afterWs, wsCopy);
    expect(afterRest).toHaveLength(1);
    expect(afterRest[0].id).toBe('msg_99');
  });

  it('does not collide distinct attachment-only pending messages when WS arrives', () => {
    const attA = {
      id: 'att_a',
      tenant_id: 'default',
      room_id: 'rm_1',
      uploader_id: 'u_alice',
      filename: 'a.png',
      mime_type: 'image/png',
      size_bytes: 120,
      sha256_hex: 'aa',
      created_at: 1_700_000_000_000,
    };
    const attB = { ...attA, id: 'att_b', filename: 'b.png' };
    const pendingA = makeMsg({
      id: 'pending_a',
      seq: Number.MAX_SAFE_INTEGER,
      body: '',
      attachments: [attA],
      delivery: { kind: 'sending', idempotencyKey: 'ka' },
    });
    const pendingB = makeMsg({
      id: 'pending_b',
      seq: Number.MAX_SAFE_INTEGER,
      body: '',
      attachments: [attB],
      delivery: { kind: 'sending', idempotencyKey: 'kb' },
    });
    const wsB = makeMsg({ id: 'msg_101', seq: 101, body: '', attachments: [attB], ref: 'kb' });

    const next = upsertMessage([pendingA, pendingB], wsB);
    expect(next).toHaveLength(2);
    expect(next[0].id).toBe('msg_101');
    expect(next[1].id).toBe('pending_a');
  });

  it('applies reaction add/remove idempotently and removes empty buckets', () => {
    const base = [makeMsg({ id: 'msg_1' })];
    const added = applyReactionDelta(base, 'msg_1', 'u_alice', '👍', true);
    expect(added[0].reactions).toEqual([{ emoji: '👍', user_ids: ['u_alice'], count: 1 }]);

    const dupAdd = applyReactionDelta(added, 'msg_1', 'u_alice', '👍', true);
    expect(dupAdd[0].reactions[0].count).toBe(1);

    const addedBob = applyReactionDelta(dupAdd, 'msg_1', 'u_bob', '👍', true);
    expect(addedBob[0].reactions[0].count).toBe(2);

    const removedAlice = applyReactionDelta(addedBob, 'msg_1', 'u_alice', '👍', false);
    expect(removedAlice[0].reactions).toEqual([{ emoji: '👍', user_ids: ['u_bob'], count: 1 }]);

    const removedAll = applyReactionDelta(removedAlice, 'msg_1', 'u_bob', '👍', false);
    expect(removedAll[0].reactions).toEqual([]);
  });

  it('groups consecutive messages from the same sender within 5 minutes', () => {
    const m1 = makeMsg({ id: '1', seq: 1, created_at: 1_700_000_000_000 });
    const m2 = makeMsg({ id: '2', seq: 2, created_at: 1_700_000_120_000 });
    const m3 = makeMsg({ id: '3', seq: 3, created_at: 1_700_000_900_000 });
    const mReply = makeMsg({ id: '4', seq: 4, reply_to_id: '1', created_at: 1_700_000_130_000 });

    expect(isGroupedWithPrevious(m1, m2)).toBe(true);
    expect(isGroupedWithPrevious(m1, m3)).toBe(false);
    expect(isGroupedWithPrevious(m1, mReply)).toBe(false);
  });

  it('merges historical pages in strict seq order', () => {
    const newer = [makeMsg({ id: 'm3', seq: 3 }), makeMsg({ id: 'm4', seq: 4 })];
    const older = [makeMsg({ id: 'm1', seq: 1 }), makeMsg({ id: 'm2', seq: 2 }), makeMsg({ id: 'm3', seq: 3 })];
    expect(mergeMessageBatch(newer, older).map((m) => m.seq)).toEqual([1, 2, 3, 4]);
  });

  it('sorts unread rooms first and closed rooms last', () => {
    const base: Omit<ChatRoomSummary, 'id' | 'name' | 'unread_count' | 'closed_at'> = {
      tenant_id: 'default',
      kind: 'channel',
      topic: '',
      is_private: false,
      last_seq: 10,
      created_by: 'u1',
      created_at: 1,
      role: 'member',
      last_read_seq: 10,
      notify_mode: 'all',
    };
    const sorted = sortRooms([
      { ...base, id: '1', name: 'zebra', unread_count: 0 },
      { ...base, id: '2', name: 'closed', unread_count: 5, closed_at: 123 },
      { ...base, id: '3', name: 'alerts', unread_count: 2 },
    ]);
    expect(sorted.map((r) => r.name)).toEqual(['alerts', 'zebra', 'closed']);
  });

  it('parses slim Postgres NOTIFY refetch frames and standard WS events safely', () => {
    const slim = parseWsEvent({ t: 'message.new', room: 'rm_1', seq: 8, d: { refetch: true } });
    expect(slim).toEqual({ kind: 'message.new', roomId: 'rm_1', seq: 8, refetch: true });

    const revoked = parseWsEvent({ t: 'auth.revoked' });
    expect(revoked).toEqual({ kind: 'auth.revoked' });

    const invalid = parseWsEvent({ t: 'unknown.event' });
    expect(invalid).toBeNull();
  });
});

describe('encrypted files', () => {
  const base = { id: 'm1', tenant_id: 't', room_id: 'r', seq: 1, sender_id: 'u', sender_name: 'U', encoding: 'e2ee_room_v1' as const, body: '', created_at: 1, reactions: [], attachments: [], delivery: { kind: 'synced' as const } };
  const file = { attachment_id: 'att_f', name: 'q3.xlsx', thumb: { attachment_id: 'att_t' } } as NonNullable<ChatMessage['files']>[number];

  it('reindexes an attachment-only message once its key arrives and its files open', () => {
    const waiting: ChatMessage = { ...base, e2ee: { kind: 'waiting' } };
    const opened: ChatMessage = { ...base, e2ee: { kind: 'decrypted' }, files: [file] };
    expect(searchSignature(waiting)).not.toBe(searchSignature(opened));
    expect(searchSignature(opened)).not.toBe(searchSignature({ ...opened, files: [{ ...file, name: 'q4.xlsx' }] }));
  });

  it('matches an unsent copy to the server copy by the idempotency key it seals, not by its rows', () => {
    const optimistic: ChatMessage = { ...base, id: 'pending_k', seq: Number.MAX_SAFE_INTEGER, body: 'hi', e2ee: { kind: 'decrypted' }, files: [file], delivery: { kind: 'sending', idempotencyKey: 'k' } };
    const att = (id: string) => ({ id, tenant_id: 't', room_id: 'r', uploader_id: 'u', filename: 'encrypted.bin', mime_type: 'application/octet-stream', size_bytes: 1, sha256_hex: '', created_at: 1 });
    // The server dropped the thumbnail row: still the same message.
    const confirmed: ChatMessage = { ...base, id: 'm_real', seq: 5, body: 'hi', e2ee: { kind: 'decrypted' }, attachments: [att('att_f')], ref: 'k' };
    expect(upsertMessage([optimistic], confirmed).map((m) => m.id)).toEqual(['m_real']);
    // A send that failed after the server took it is replaced too, not shown twice.
    const failed: ChatMessage = { ...optimistic, delivery: { kind: 'failed', idempotencyKey: 'k', error: 'network' } };
    expect(upsertMessage([failed], confirmed).map((m) => m.id)).toEqual(['m_real']);
    // Another message with the same text and rows is not that send.
    expect(upsertMessage([optimistic], { ...confirmed, ref: 'other' }).map((m) => m.id)).toEqual(['m_real', 'pending_k']);
  });

  it('rejects wire IDs reserved for retryable local sends', () => {
    const id = 'pending_k';
    const row = { ...base, id, sender_id: 'other' };
    expect(() => parseMessagesPage({ messages: [row] })).toThrow('Server message uses a local send ID');
    expect(parseWsEvent({ t: 'message.new', room: base.room_id, d: row })).toBeNull();
    expect(parseWsEvent({ t: 'message.delete', room: base.room_id, d: { id } })).toBeNull();
  });

  it('carries a failed file send through a history jump and back to the latest slice', () => {
    const failed: ChatMessage = { ...base, id: 'pending_k', seq: Number.MAX_SAFE_INTEGER, body: 'caption', files: [file],
      delivery: { kind: 'failed', idempotencyKey: 'k', error: 'network' } };
    const history = replaceMessageHistory([{ ...base, id: 'm_latest' }, failed], [{ ...base, id: 'm_older' }]);
    expect(history).toEqual([{ ...base, id: 'm_older' }, failed]);
    expect(replaceMessageHistory(history, [{ ...base, id: 'm_latest' }])).toEqual([{ ...base, id: 'm_latest' }, failed]);
    expect(replaceMessageHistory(history, [{ ...base, id: 'm_sent', ref: 'k' }])).toEqual([{ ...base, id: 'm_sent', ref: 'k' }]);
  });

  it('keeps a deletion and the newest edit over late copies', () => {
    const live: ChatMessage = { ...base, body: 'v2', edited_at: 20, e2ee: { kind: 'decrypted' } };
    const tomb: ChatMessage = { ...base, body: '', deleted_at: 30 };
    // A late edit response or history page never revives a deleted message.
    expect(upsertMessage([tomb], live)[0].deleted_at).toBe(30);
    expect(mergeMessageBatch([tomb], [live])[0].deleted_at).toBe(30);
    // An older edit never replaces a newer one.
    expect(upsertMessage([live], { ...live, body: 'v1', edited_at: 10 })[0].body).toBe('v2');
    expect(mergeMessageBatch([live], [{ ...live, body: 'v1', edited_at: 10 }])[0].body).toBe('v2');
    // A deletion always lands.
    expect(upsertMessage([live], tomb)[0].deleted_at).toBe(30);
  });
});

describe('deletions and confirmations', () => {
  it('remembers fetched tombstones after a noncontiguous history replacement', () => {
    const stale = makeMsg({ id: 'm_fetched', body: 'deleted caption' });
    try {
      const fetched = mergeMessageBatch([], [{ ...stale, deleted_at: 20 }]);
      expect(fetched[0].body).toBe('');
      const replacement = mergeMessageBatch([], [makeMsg({ id: 'm_other' })]);
      expect(mergeMessageBatch(replacement, [stale]).find((m) => m.id === stale.id)).toMatchObject({ deleted_at: 20, body: '' });
    } finally {
      forgetDeleted();
    }
  });
  const base = { id: 'm1', tenant_id: 't', room_id: 'r', seq: 1, sender_id: 'u', sender_name: 'U', encoding: 'e2ee_room_v1' as const, body: 'hello', created_at: 1, reactions: [], attachments: [], delivery: { kind: 'synced' as const }, e2ee: { kind: 'decrypted' as const } };

  it('keeps a deletion that arrived before the message, through pages and responses', () => {
    rememberDeleted('m1', 40);
    try {
      expect(mergeMessageBatch([], [{ ...base, files: [] }])[0]).toMatchObject({ deleted_at: 40, body: '' });
      expect(upsertMessage([], base)[0]).toMatchObject({ deleted_at: 40, body: '' });
      expect(upsertMessage([], base)[0].files).toBeUndefined();
    } finally {
      forgetDeleted();
    }
    expect(upsertMessage([], base)[0].deleted_at).toBeUndefined();
  });

  it('resolves an unsent copy only with the sealed ref of its own send', () => {
    const pending: ChatMessage = { ...base, id: 'pending_k', seq: Number.MAX_SAFE_INTEGER, delivery: { kind: 'failed', idempotencyKey: 'k', error: 'x' } };
    // No ref (an unopened or untrusted answer), another sender, another ref: nothing resolved.
    expect(resolvePending([pending, { ...base }])).toHaveLength(2);
    expect(resolvePending([pending, { ...base, ref: 'k', sender_id: 'mallory' }])).toHaveLength(2);
    expect(resolvePending([pending, { ...base, ref: 'k', room_id: 'other' }])).toHaveLength(2);
    expect(resolvePending([pending, { ...base, ref: 'other' }])).toHaveLength(2);
    expect(resolvePending([pending, { ...base, ref: 'k' }]).map((m) => m.id)).toEqual(['m1']);
    // The same rule on a page of history.
    expect(mergeMessageBatch([pending], [{ ...base, ref: 'k' }]).map((m) => m.id)).toEqual(['m1']);
  });
});
