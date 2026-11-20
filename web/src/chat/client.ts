import { errorMessage, secureFetch } from '../api';
import { arr, bool, count, obj, str } from '../dto';
import {
  parseBootstrap,
  parseMessage,
  parseMessagesPage,
  parseRoom,
  parseRoomDetail,
  parseRoomSummary,
  parseUsersList,
  parseWebhook,
  parseWsEvent,
  type ChatBootstrap,
  type ChatDirectoryUser,
  type ChatMessage,
  type ChatMessagesPage,
  type ChatRoom,
  type ChatRoomDetail,
  type ChatRoomSummary,
  type ChatRoomWebhook,
  type WsServerEvent,
  type WsStatus,
} from './types';

async function apiJSON(input: string, init: RequestInit = {}, fallback = 'Request failed'): Promise<unknown> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await secureFetch(input, { credentials: 'same-origin', ...init, headers });
  if (!res.ok) {
    throw new Error(await errorMessage(res, fallback));
  }
  return res.json();
}

export async function fetchBootstrap(): Promise<ChatBootstrap> {
  return parseBootstrap(await apiJSON('/api/v1/bootstrap', {}, 'Could not load chat'));
}

export async function fetchDirectoryUsers(): Promise<ChatDirectoryUser[]> {
  return parseUsersList(await apiJSON('/api/v1/users', {}, 'Could not load teammates'));
}

export async function fetchRooms(): Promise<ChatRoomSummary[]> {
  const data = obj(await apiJSON('/api/v1/rooms', {}, 'Could not load rooms'));
  return arr(data.rooms ?? []).map(parseRoomSummary);
}

export async function createChannel(params: {
  name: string;
  topic: string;
  isPrivate: boolean;
  memberIds: string[];
}): Promise<ChatRoom> {
  const data = obj(
    await apiJSON(
      '/api/v1/rooms',
      {
        method: 'POST',
        body: JSON.stringify({
          kind: 'channel',
          name: params.name,
          topic: params.topic,
          is_private: params.isPrivate,
          member_ids: params.memberIds,
        }),
      },
      'Could not create channel',
    ),
  );
  return parseRoom(data.room);
}

export async function openDirectMessage(dmUserId: string): Promise<{ room: ChatRoom; created: boolean }> {
  const data = obj(
    await apiJSON(
      '/api/v1/rooms',
      {
        method: 'POST',
        body: JSON.stringify({ kind: 'dm', dm_user_id: dmUserId }),
      },
      'Could not open direct message',
    ),
  );
  return { room: parseRoom(data.room), created: bool(data.created) };
}

export async function fetchRoomDetail(roomId: string): Promise<ChatRoomDetail> {
  return parseRoomDetail(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}`, {}, 'Could not load room details'),
  );
}

export async function updateRoomInfo(roomId: string, params: { name: string; topic: string }): Promise<ChatRoom> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(params),
      },
      'Could not update room',
    ),
  );
  return parseRoom(data.room);
}

export async function addRoomMember(roomId: string, userId: string): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/members`,
    {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, role: 'member' }),
    },
    'Could not add member',
  );
}

export async function removeRoomMember(roomId: string, userId: string): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/members/${encodeURIComponent(userId)}`,
    { method: 'DELETE' },
    'Could not remove member',
  );
}

export async function fetchMessages(
  roomId: string,
  opts: { before?: number; after?: number; limit?: number } = {},
): Promise<ChatMessagesPage> {
  const qs = new URLSearchParams();
  if (opts.before && opts.before > 0) qs.set('before', String(opts.before));
  if (opts.after && opts.after > 0) qs.set('after', String(opts.after));
  if (opts.limit && opts.limit > 0) qs.set('limit', String(opts.limit));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return parseMessagesPage(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}/messages${suffix}`, {}, 'Could not load messages'),
  );
}

export async function sendMessage(params: {
  roomId: string;
  body: string;
  replyToId?: string;
  idempotencyKey: string;
}): Promise<ChatMessage> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(params.roomId)}/messages`,
      {
        method: 'POST',
        headers: { 'Idempotency-Key': params.idempotencyKey },
        body: JSON.stringify({
          body: params.body,
          reply_to_id: params.replyToId || undefined,
          idempotency_key: params.idempotencyKey,
        }),
      },
      'Could not send message',
    ),
  );
  return parseMessage(data.message);
}

export async function editMessage(roomId: string, messageId: string, body: string): Promise<ChatMessage> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/messages/${encodeURIComponent(messageId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ body }),
      },
      'Could not edit message',
    ),
  );
  return parseMessage(data.message);
}

export async function deleteMessage(roomId: string, messageId: string): Promise<ChatMessage> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/messages/${encodeURIComponent(messageId)}`,
      { method: 'DELETE' },
      'Could not delete message',
    ),
  );
  return parseMessage(data.message);
}

export async function setReaction(roomId: string, messageId: string, emoji: string, add: boolean): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/messages/${encodeURIComponent(messageId)}/reactions/${encodeURIComponent(emoji)}`,
    { method: add ? 'PUT' : 'DELETE' },
    'Could not update reaction',
  );
}

export async function markRoomRead(roomId: string, seq: number): Promise<number> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/read`,
      {
        method: 'POST',
        body: JSON.stringify({ seq }),
      },
      'Could not mark read',
    ),
  );
  return count(data.last_read_seq);
}

export async function searchMessages(query: string, roomId?: string): Promise<ChatMessage[]> {
  const qs = new URLSearchParams({ q: query, limit: '25' });
  if (roomId) qs.set('room_id', roomId);
  const data = obj(await apiJSON(`/api/v1/search?${qs.toString()}`, {}, 'Search failed'));
  return arr(data.messages ?? []).map(parseMessage);
}

export async function fetchRoomWebhooks(roomId: string): Promise<ChatRoomWebhook[]> {
  const data = obj(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}/webhooks`, {}, 'Could not load webhooks'),
  );
  return arr(data.webhooks ?? []).map(parseWebhook);
}

export async function createRoomWebhook(
  roomId: string,
  name: string,
): Promise<{ webhook: ChatRoomWebhook; token: string }> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/webhooks`,
      {
        method: 'POST',
        body: JSON.stringify({ name }),
      },
      'Could not create webhook',
    ),
  );
  return { webhook: parseWebhook(data.webhook), token: str(data.token, 256) };
}

export async function revokeRoomWebhook(roomId: string, webhookId: string): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/webhooks/${encodeURIComponent(webhookId)}`,
    { method: 'DELETE' },
    'Could not revoke webhook',
  );
}

export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `msg_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

export interface ChatSocketHandlers {
  onStatus: (status: WsStatus) => void;
  onEvent: (event: WsServerEvent) => void;
  onReconnect: () => void;
}

/** Single multiplexed WebSocket connection to /api/v1/ws with bounded exponential backoff. */
export class ChatSocket {
  private ws: WebSocket | null = null;
  private closed = false;
  private revoked = false;
  private attempt = 0;
  private hasConnectedOnce = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private lastTypingAt = new Map<string, number>();

  constructor(private readonly handlers: ChatSocketHandlers) {}

  connect(): void {
    if (this.closed || this.revoked) return;
    if (typeof WebSocket === 'undefined') {
      this.handlers.onStatus('offline');
      return;
    }

    this.handlers.onStatus(this.hasConnectedOnce ? 'reconnecting' : 'connecting');
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/api/v1/ws`;

    let socket: WebSocket;
    try {
      socket = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = socket;

    socket.onopen = () => {
      if (this.closed || this.ws !== socket) {
        socket.close();
        return;
      }
      const isReconnect = this.hasConnectedOnce;
      this.hasConnectedOnce = true;
      this.attempt = 0;
      this.handlers.onStatus('live');
      this.startPing();
      if (isReconnect) {
        this.handlers.onReconnect();
      }
    };

    socket.onmessage = (msg) => {
      if (typeof msg.data !== 'string') return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(msg.data);
      } catch {
        return;
      }
      const ev = parseWsEvent(parsed);
      if (!ev) return;
      if (ev.kind === 'auth.revoked') {
        this.revoked = true;
        this.handlers.onStatus('revoked');
      }
      this.handlers.onEvent(ev);
    };

    socket.onerror = () => {
      // Close event handles reconnect scheduling.
    };

    socket.onclose = () => {
      this.stopPing();
      if (this.ws === socket) {
        this.ws = null;
      }
      if (this.closed || this.revoked) return;
      this.scheduleReconnect();
    };
  }

  sendTyping(roomId: string, active: boolean): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    if (active) {
      const prev = this.lastTypingAt.get(roomId) ?? 0;
      if (now - prev < 2000) return;
      this.lastTypingAt.set(roomId, now);
    } else {
      this.lastTypingAt.delete(roomId);
    }
    try {
      this.ws.send(JSON.stringify({ t: 'typing', room: roomId, active }));
    } catch {
      // Ignore transient write errors while closing.
    }
  }

  close(): void {
    this.closed = true;
    this.stopPing();
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.close(1000, 'client_unmount');
      } catch {
        // Ignore close errors.
      }
      this.ws = null;
    }
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify({ t: 'ping' }));
        } catch {
          // Ignore.
        }
      }
    }, 25000);
  }

  private stopPing(): void {
    if (this.pingTimer !== null) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.closed || this.revoked) return;
    this.handlers.onStatus('reconnecting');
    const baseMs = Math.min(1000 * 2 ** this.attempt, 15000);
    const jitter = Math.floor(Math.random() * 400);
    this.attempt = Math.min(this.attempt + 1, 6);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, baseMs + jitter);
  }
}
