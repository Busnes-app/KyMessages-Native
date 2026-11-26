import type { ChatMessage, ChatReactionSummary, ChatRoomSummary } from './types';

/**
 * Which of two copies of one message to keep: a deletion always wins, and a copy older than the
 * one held (an earlier edit, a stale page or response) never replaces it.
 */
function keep(held: ChatMessage, incoming: ChatMessage): ChatMessage {
  if (held.deleted_at && !incoming.deleted_at) return held;
  if (!incoming.deleted_at && (held.edited_at ?? 0) > (incoming.edited_at ?? 0)) return held;
  return incoming;
}

/** What the on-device search index holds of a message: a change means it is indexed again. */
export function searchSignature(m: ChatMessage): string {
  const names = (m.files ?? []).map((f) => f.name).join('\u0001');
  return [m.body, m.edited_at ?? '', m.deleted_at ?? '', m.delivery.kind, m.e2ee?.kind ?? '', names].join('\u0000');
}

/** Insert or replace a server-confirmed message, reconciling any optimistic pending copy. */
export function upsertMessage(
  list: ChatMessage[],
  incoming: ChatMessage,
  reconcileClientKey?: string,
): ChatMessage[] {
  const withoutOptimistic = reconcileClientKey
    ? list.filter((m) => !(m.delivery.kind !== 'synced' && m.delivery.idempotencyKey === reconcileClientKey))
    : list;

  const idx = withoutOptimistic.findIndex((m) => m.id === incoming.id);
  let next: ChatMessage[];
  if (idx >= 0) {
    const held = withoutOptimistic[idx];
    next = [...withoutOptimistic];
    next[idx] = keep(held, incoming) === held ? held : { ...incoming, reactions: incoming.reactions.length > 0 ? incoming.reactions : held.reactions };
  } else {
    // The socket can confirm a send before (or instead of) its REST answer: the unsent copy with the
    // idempotency key the message seals as its `ref` is that message, sending or already failed.
    const dupIdx = withoutOptimistic.findIndex(
      (m) =>
        m.delivery.kind !== 'synced' &&
        m.sender_id === incoming.sender_id &&
        incoming.ref !== undefined &&
        m.delivery.idempotencyKey === incoming.ref,
    );
    if (dupIdx >= 0) {
      next = [...withoutOptimistic];
      next[dupIdx] = incoming;
    } else {
      next = [...withoutOptimistic, incoming];
    }
  }

  return sortMessages(next);
}

/** Merge a batch of historical or catch-up messages without duplicates. */
export function mergeMessageBatch(existing: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  if (incoming.length === 0) return existing;
  const byId = new Map<string, ChatMessage>();
  for (const m of existing) {
    byId.set(m.id, m);
  }
  for (const m of incoming) {
    const held = byId.get(m.id);
    byId.set(m.id, held ? keep(held, m) : m);
  }
  return sortMessages(Array.from(byId.values()));
}

function sortMessages(list: ChatMessage[]): ChatMessage[] {
  return [...list].sort((a, b) => {
    const aPending = a.delivery.kind !== 'synced';
    const bPending = b.delivery.kind !== 'synced';
    if (aPending !== bPending) return aPending ? 1 : -1;
    if (a.seq !== b.seq) return a.seq - b.seq;
    return a.created_at - b.created_at;
  });
}

/** Apply a reaction delta (add or remove) immutably to a message list. */
export function applyReactionDelta(
  list: ChatMessage[],
  messageId: string,
  userId: string,
  emoji: string,
  added: boolean,
): ChatMessage[] {
  return list.map((msg) => {
    if (msg.id !== messageId) return msg;
    const reactions = applyReactionToSummaries(msg.reactions, userId, emoji, added);
    return { ...msg, reactions };
  });
}

function applyReactionToSummaries(
  reactions: ChatReactionSummary[],
  userId: string,
  emoji: string,
  added: boolean,
): ChatReactionSummary[] {
  const existing = reactions.find((r) => r.emoji === emoji);
  if (added) {
    if (!existing) {
      return [...reactions, { emoji, user_ids: [userId], count: 1 }];
    }
    if (existing.user_ids.includes(userId)) {
      return reactions;
    }
    return reactions.map((r) =>
      r.emoji === emoji ? { ...r, user_ids: [...r.user_ids, userId], count: r.user_ids.length + 1 } : r,
    );
  }
  if (!existing) return reactions;
  const nextUsers = existing.user_ids.filter((id) => id !== userId);
  if (nextUsers.length === 0) {
    return reactions.filter((r) => r.emoji !== emoji);
  }
  return reactions.map((r) => (r.emoji === emoji ? { ...r, user_ids: nextUsers, count: nextUsers.length } : r));
}

/** Sort rooms cleanly: active rooms first, then by recent activity (`last_seq` / `created_at`) and name. */
export function sortRooms(rooms: ChatRoomSummary[]): ChatRoomSummary[] {
  return [...rooms].sort((a, b) => {
    const aClosed = Boolean(a.closed_at);
    const bClosed = Boolean(b.closed_at);
    if (aClosed !== bClosed) return aClosed ? 1 : -1;
    if (b.unread_count !== a.unread_count) return b.unread_count - a.unread_count;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}

/** Decide whether two consecutive messages belong to the same visual sender cluster (within 5 minutes). */
export function isGroupedWithPrevious(prev: ChatMessage | undefined, curr: ChatMessage): boolean {
  if (!prev) return false;
  if (prev.sender_id !== curr.sender_id) return false;
  if (curr.reply_to_id) return false;
  if (prev.deleted_at || curr.deleted_at) return false;
  return Math.abs(curr.created_at - prev.created_at) < 5 * 60 * 1000 && sameCalendarDay(prev.created_at, curr.created_at);
}

export function sameCalendarDay(aMs: number, bMs: number): boolean {
  const a = new Date(aMs);
  const b = new Date(bMs);
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

export function formatDayDivider(ms: number): string {
  const d = new Date(ms);
  const now = new Date();
  if (sameCalendarDay(ms, now.getTime())) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameCalendarDay(ms, yesterday.getTime())) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
}

export function initialsFor(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return '?';
  const parts = trimmed.split(/\s+/).filter(Boolean);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

/** Webhook posts choose their own sender_name, so they must never pass for a member. */
export function isWebhookSender(senderId: string): boolean {
  return senderId.startsWith('webhook:');
}

/** Meeting guests post as guest_ IDs; they have no encryption keys. */
export function isGuestSender(senderId: string): boolean {
  return senderId.startsWith('guest_');
}

/** Native bot accounts have bot_ user IDs; mark their posts and member rows distinctly. */
export function isBotSender(senderId: string): boolean {
  return senderId.startsWith('bot_');
}
