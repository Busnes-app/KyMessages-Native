import type { ChatMessage, ChatReactionSummary, ChatRoomSummary } from './types';

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
    next = [...withoutOptimistic];
    next[idx] = {
      ...incoming,
      reactions: incoming.reactions.length > 0 ? incoming.reactions : withoutOptimistic[idx].reactions,
    };
  } else {
    // Also drop any pending optimistic message from the same sender with identical body when WS races ahead of REST.
    const dupIdx = withoutOptimistic.findIndex(
      (m) => m.delivery.kind === 'sending' && m.sender_id === incoming.sender_id && m.body === incoming.body,
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
    byId.set(m.id, m);
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
