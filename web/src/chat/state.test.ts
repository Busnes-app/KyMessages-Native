import { describe, expect, it } from 'vitest';
import { applyReactionDelta, isGroupedWithPrevious, mergeMessageBatch, sortRooms, upsertMessage } from './state';
import { parseWsEvent, type ChatMessage, type ChatRoomSummary } from './types';

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
    const confirmed = makeMsg({ id: 'msg_42', seq: 42, body: 'ship it' });

    const next = upsertMessage([pending], confirmed, 'k1');
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
    const wsCopy = makeMsg({ id: 'msg_99', seq: 99, body: 'race condition' });

    const afterWs = upsertMessage([pending], wsCopy);
    expect(afterWs).toHaveLength(1);
    expect(afterWs[0].id).toBe('msg_99');

    const afterRest = upsertMessage(afterWs, wsCopy, 'k2');
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
    const wsB = makeMsg({ id: 'msg_101', seq: 101, body: '', attachments: [attB] });

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
