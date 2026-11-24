import { errorMessage, secureFetch } from '../api';
import { arr, bool, count, obj, opt, str } from '../dto';
import { openMessage, openMessages, sealRoomMessage } from './e2ee';
import type { MessageState } from './searchIndex';
import {
  parseAdminMediaPolicy,
  parseAttachment,
  parseBootstrap,
  parseCallJoinResponse,
  parseCallState,
  parseGuestMeetInfo,
  parseLobbyGuest,
  parseMessage,
  parseMessagesPage,
  parseRoom,
  parseRoomDetail,
  parseRoomSummary,
  parseUsersList,
  parseWsEvent,
  type AdminMediaPolicyResponse,
  type CallJoinResponse,
  type CallState,
  type ChatAttachment,
  type ChatBootstrap,
  type ChatDirectoryUser,
  type ChatMessage,
  type ChatMessagesPage,
  type ChatRoom,
  type ChatRoomDetail,
  type ChatRoomSummary,
  type GuestMeetInfo,
  type LobbyGuest,
  type MediaPolicyConfig,
  type NotifyMode,
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

export async function fetchBootstrap(previousCalls?: () => Readonly<Record<string, CallState>>): Promise<ChatBootstrap> {
  const boot = parseBootstrap(await apiJSON('/api/v1/bootstrap', {}, 'Could not load chat'));
  if (boot.tenant.id === 'default') return boot;
  // The global chat socket/HTTP may reach any pod. Only the room route can supply its
  // current call roster. Bound fanout and time so an unavailable owner cannot stall chat.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2_000);
  const rooms = boot.rooms.values();
  const results = new Map<string, CallState | null>();
  const readRooms = async () => {
    for (const room of rooms) {
      if (controller.signal.aborted) return;
      try {
        const reply = obj(await apiJSON(
          `/api/v1/rooms/${encodeURIComponent(room.id)}/calls/state`,
          { signal: controller.signal }, 'Could not load call state',
        ));
        if (reply.call === null) {
          results.set(room.id, null);
        } else {
          const state = parseCallState(reply.call);
          if (state.room_id !== room.id) throw new Error('Unexpected call room');
          results.set(room.id, state);
        }
      } catch {
        // Merge the caller's latest displayed snapshot after all room reads finish.
      }
    }
  };
  try {
    await Promise.all(Array.from({ length: 4 }, readRooms));
    const previous = previousCalls?.() ?? boot.active_calls;
    const calls: Record<string, CallState> = {};
    for (const room of boot.rooms) {
      const result = results.get(room.id);
      const state = result === undefined ? previous[room.id] : result;
      if (state) calls[room.id] = state;
    }
    return { ...boot, active_calls: calls };
  } finally {
    clearTimeout(timer);
  }
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
  const page = parseMessagesPage(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}/messages${suffix}`, {}, 'Could not load messages'),
  );
  return { ...page, messages: await openMessages(page.messages) };
}

export async function uploadAttachment(
  roomId: string,
  file: File,
  signal?: AbortSignal,
): Promise<ChatAttachment> {
  const form = new FormData();
  form.append('file', file, file.name);
  // Leave Content-Type unset so the browser supplies the multipart boundary; secureFetch adds X-CSRF-Token.
  const res = await secureFetch(`/api/v1/rooms/${encodeURIComponent(roomId)}/attachments`, {
    method: 'POST',
    credentials: 'same-origin',
    body: form,
    signal,
  });
  if (!res.ok) {
    throw new Error(await errorMessage(res, 'Could not upload file'));
  }
  const data = obj(await res.json());
  return parseAttachment(data.attachment);
}

// The caller's staged (unposted) uploads in a room, which still count against their quota.
export async function listStagedAttachments(roomId: string): Promise<ChatAttachment[]> {
  const data = obj(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}/attachments`, {}, 'Could not load staged files'),
  );
  return arr(data.attachments).map(parseAttachment);
}

export async function deleteAttachment(attachmentId: string): Promise<void> {
  const res = await secureFetch(`/api/v1/attachments/${encodeURIComponent(attachmentId)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(await errorMessage(res, 'Could not remove attachment'));
  }
}

export async function sendMessage(params: {
  roomId: string;
  body: string;
  replyToId?: string;
  attachmentIds?: string[];
  idempotencyKey: string;
}): Promise<ChatMessage> {
  const hasFiles = Boolean(params.attachmentIds && params.attachmentIds.length > 0);
  // Rooms are end-to-end encrypted: the text, its kind and its reply target travel sealed. The
  // server keeps reply_to_id as a pointer; files stay plaintext until E5.
  const envelope = await sealRoomMessage(params.roomId, {
    type: params.replyToId ? 'reply' : hasFiles ? 'attachment' : 'text',
    body: params.body,
    ...(params.replyToId ? { reply_to_id: params.replyToId } : {}),
  });
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(params.roomId)}/messages`,
      {
        method: 'POST',
        headers: { 'Idempotency-Key': params.idempotencyKey },
        body: JSON.stringify({
          body: envelope,
          encoding: 'e2ee_room_v1',
          reply_to_id: params.replyToId || undefined,
          attachment_ids:
            params.attachmentIds && params.attachmentIds.length > 0 ? params.attachmentIds : undefined,
          idempotency_key: params.idempotencyKey,
        }),
      },
      'Could not send message',
    ),
  );
  return openMessage(parseMessage(data.message));
}

export async function editMessage(roomId: string, messageId: string, body: string, replyToId?: string): Promise<ChatMessage> {
  // An edit is sealed too, names the message it replaces and keeps the reply it was.
  const envelope = await sealRoomMessage(roomId, {
    type: 'edit',
    body,
    message_id: messageId,
    ...(replyToId ? { reply_to_id: replyToId } : {}),
  });
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/messages/${encodeURIComponent(messageId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ body: envelope, encoding: 'e2ee_room_v1' }),
      },
      'Could not edit message',
    ),
  );
  return openMessage(parseMessage(data.message));
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

export async function updateRoomNotifyMode(roomId: string, notifyMode: NotifyMode): Promise<NotifyMode> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/notifications`,
      {
        method: 'PUT',
        body: JSON.stringify({ notify_mode: notifyMode }),
      },
      'Could not update notification preference',
    ),
  );
  const mode = str(data.notify_mode, 16);
  if (mode === 'all' || mode === 'mentions' || mode === 'mute') {
    return mode;
  }
  return notifyMode;
}

export async function registerPushSubscription(params: {
  endpoint: string;
  p256dh: string;
  auth: string;
}): Promise<void> {
  await apiJSON(
    '/api/v1/push/subscriptions',
    {
      method: 'POST',
      body: JSON.stringify({
        endpoint: params.endpoint,
        keys: { p256dh: params.p256dh, auth: params.auth },
      }),
    },
    'Could not register push notifications',
  );
}

export async function deletePushSubscription(endpoint: string): Promise<void> {
  await apiJSON(
    '/api/v1/push/subscriptions',
    {
      method: 'DELETE',
      body: JSON.stringify({ endpoint }),
    },
    'Could not disable push notifications',
  );
}





// ---------------------------------------------------------------------
// Hybrid P2P / SFU Calls, Meeting Waiting Rooms & Admin Media Policy
// ---------------------------------------------------------------------

export async function joinRoomCall(
  roomId: string,
  opts: { audio: boolean; video: boolean; screenShare?: boolean; protectIp?: boolean },
): Promise<CallJoinResponse> {
  return parseCallJoinResponse(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/calls/join`,
      {
        method: 'POST',
        body: JSON.stringify({
          audio: opts.audio,
          video: opts.video,
          screen_share: Boolean(opts.screenShare),
          protect_ip: Boolean(opts.protectIp),
        }),
      },
      'Could not join call',
    ),
  );
}

export async function leaveRoomCall(roomId: string): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/calls/leave`,
    { method: 'POST', body: '{}' },
    'Could not leave call',
  );
}

export async function escalateRoomCall(roomId: string, reason = 'user_requested'): Promise<CallState> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/calls/escalate`,
      { method: 'POST', body: JSON.stringify({ reason }) },
      'Could not escalate call to SFU',
    ),
  );
  return parseCallState(data.call);
}

export async function fetchRoomLobby(roomId: string): Promise<LobbyGuest[]> {
  const data = obj(
    await apiJSON(`/api/v1/rooms/${encodeURIComponent(roomId)}/lobby`, {}, 'Could not load waiting room'),
  );
  return arr(data.guests ?? []).map(parseLobbyGuest);
}

export async function decideRoomLobby(roomId: string, guestId: string, admit: boolean): Promise<void> {
  await apiJSON(
    `/api/v1/rooms/${encodeURIComponent(roomId)}/lobby/${encodeURIComponent(guestId)}/${admit ? 'admit' : 'deny'}`,
    { method: 'POST', body: '{}' },
    admit ? 'Could not admit guest' : 'Could not deny guest',
  );
}

export async function createInstantMeeting(params: {
  title: string;
  memberIds?: string[];
}): Promise<{ room: ChatRoom; guestUrl: string; guestPath: string }> {
  const data = obj(
    await apiJSON(
      '/api/v1/meetings',
      {
        method: 'POST',
        body: JSON.stringify({ title: params.title, member_ids: params.memberIds ?? [] }),
      },
      'Could not create meeting',
    ),
  );
  return {
    room: parseRoom(data.room),
    guestUrl: str(data.guest_url, 512),
    guestPath: str(data.guest_path, 512),
  };
}

export async function createRoomGuestLink(roomId: string): Promise<{ guestUrl: string; guestPath: string }> {
  const data = obj(
    await apiJSON(
      `/api/v1/rooms/${encodeURIComponent(roomId)}/meeting/guest-link`,
      { method: 'POST', body: '{}' },
      'Could not create guest invite link',
    ),
  );
  return {
    guestUrl: str(data.guest_url, 512),
    guestPath: str(data.guest_path, 512),
  };
}

export async function fetchAdminMediaPolicy(): Promise<AdminMediaPolicyResponse> {
  return parseAdminMediaPolicy(await apiJSON('/api/admin/media-policy', {}, 'Could not load media policy'));
}

export async function updateAdminMediaPolicy(policy: MediaPolicyConfig): Promise<MediaPolicyConfig> {
  const data = obj(
    await apiJSON(
      '/api/admin/media-policy',
      { method: 'PUT', body: JSON.stringify(policy) },
      'Could not save media policy',
    ),
  );
  const p = obj(data.policy);
  return {
    p2p_policy: p.p2p_policy === 'sfu_only' ? 'sfu_only' : 'hybrid',
    p2p_max_video: count(p.p2p_max_video),
    p2p_max_audio: count(p.p2p_max_audio),
    guest_force_sfu: bool(p.guest_force_sfu),
  };
}

// ---------------------------------------------------------------------
// Confined External Guest API (/api/meet/{token}...)
// ---------------------------------------------------------------------

async function guestJSON(input: string, init: RequestInit = {}, fallback = 'Request failed'): Promise<unknown> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await fetch(input, { credentials: 'same-origin', ...init, headers });
  if (!res.ok) {
    throw new Error(await errorMessage(res, fallback));
  }
  return res.json();
}

export async function fetchGuestMeetInfo(token: string): Promise<GuestMeetInfo> {
  return parseGuestMeetInfo(
    await guestJSON(`/api/meet/${encodeURIComponent(token)}`, {}, 'Could not load meeting'),
  );
}

export async function knockGuestMeet(
  token: string,
  displayName: string,
  captchaToken?: string,
): Promise<{ guestId: string; displayName: string; status: string; roomId: string; meetingTitle: string }> {
  const data = obj(
    await guestJSON(
      `/api/meet/${encodeURIComponent(token)}/knock`,
      {
        method: 'POST',
        body: JSON.stringify({ display_name: displayName, captcha_token: captchaToken }),
      },
      'Could not enter waiting room',
    ),
  );
  return {
    guestId: str(data.guest_id, 128),
    displayName: str(data.display_name, 255),
    status: str(data.status, 32),
    roomId: str(data.room_id, 128),
    meetingTitle: str(data.meeting_title, 255),
  };
}

export async function joinGuestCall(
  token: string,
  opts: { audio: boolean; video: boolean; screenShare?: boolean; protectIp?: boolean },
  roomId?: string,
): Promise<CallJoinResponse> {
  return parseCallJoinResponse(
    await guestJSON(
      roomId ? `/api/v1/rooms/${encodeURIComponent(roomId)}/calls/guest/${encodeURIComponent(token)}/join` : `/api/meet/${encodeURIComponent(token)}/call/join`,
      {
        method: 'POST',
        body: JSON.stringify({
          audio: opts.audio,
          video: opts.video,
          screen_share: Boolean(opts.screenShare),
          protect_ip: Boolean(opts.protectIp),
        }),
      },
      'Could not join meeting call',
    ),
  );
}

export async function leaveGuestCall(token: string, roomId?: string): Promise<void> {
  await guestJSON(
    roomId ? `/api/v1/rooms/${encodeURIComponent(roomId)}/calls/guest/${encodeURIComponent(token)}/leave` : `/api/meet/${encodeURIComponent(token)}/call/leave`,
    { method: 'POST', body: '{}' },
    'Could not leave meeting call',
  );
}

export async function fetchGuestMessages(token: string): Promise<ChatMessagesPage> {
  return parseMessagesPage(
    await guestJSON(`/api/meet/${encodeURIComponent(token)}/messages`, {}, 'Could not load meeting chat'),
  );
}

export async function sendGuestMessage(token: string, body: string): Promise<ChatMessage> {
  const data = obj(
    await guestJSON(
      `/api/meet/${encodeURIComponent(token)}/messages`,
      { method: 'POST', body: JSON.stringify({ body }) },
      'Could not send message',
    ),
  );
  return parseMessage(data.message);
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

/** Single multiplexed WebSocket connection to /api/v1/ws (or confined /api/meet/{token}/ws) with bounded exponential backoff. */
export class ChatSocket {
  private ws: WebSocket | null = null;
  private closed = false;
  private revoked = false;
  private attempt = 0;
  private hasConnectedOnce = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private lastTypingAt = new Map<string, number>();
  // Events are delivered in order, each message decrypted first.
  private inbound: Promise<void> = Promise.resolve();

  constructor(
    private readonly handlers: ChatSocketHandlers,
    private readonly wsPath = '/api/v1/ws',
  ) {}

  connect(): void {
    if (this.closed || this.revoked) return;
    if (typeof WebSocket === 'undefined') {
      this.handlers.onStatus('offline');
      return;
    }

    this.handlers.onStatus(this.hasConnectedOnce ? 'reconnecting' : 'connecting');
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}${this.wsPath}`;

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
      this.inbound = this.inbound
        .then(async () => {
          if ((ev.kind === 'message.new' || ev.kind === 'message.edit') && ev.message) {
            // openMessage never waits on a device still starting, so no event queues behind it.
            this.handlers.onEvent({ ...ev, message: await openMessage(ev.message) });
          } else {
            this.handlers.onEvent(ev);
          }
        })
        .catch(() => undefined);
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

  isOpen(): boolean {
    return !!this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  private sendRaw(frame: Record<string, unknown>): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    try {
      this.ws.send(JSON.stringify(frame));
      return true;
    } catch {
      // Ignore transient write errors while closing.
      return false;
    }
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
    this.sendRaw({ t: 'typing', room: roomId, active });
  }

  sendCallSignal(
    roomId: string,
    callId: string,
    toPeerId: string,
    kind: 'offer' | 'answer' | 'ice',
    data: unknown,
  ): void {
    this.sendRaw({
      t: 'call.signal',
      room: roomId,
      call_id: callId,
      to_peer_id: toPeerId,
      kind,
      data,
    });
  }

  sendCallMedia(
    roomId: string,
    callId: string,
    media: { audio: boolean; video: boolean; screenShare: boolean; protectIp: boolean },
  ): boolean {
    return this.sendRaw({
      t: 'call.media',
      room: roomId,
      call_id: callId,
      audio: media.audio,
      video: media.video,
      screen_share: media.screenShare,
      protect_ip: media.protectIp,
    });
  }

  sendCallMigrated(roomId: string, callId: string, epoch?: number): void {
    this.sendRaw({ t: 'call.migrated', room: roomId, call_id: callId, ...(epoch !== undefined ? { epoch } : {}) });
  }

  sendCallICEFailed(roomId: string, callId: string): void {
    this.sendRaw({ t: 'call.ice_failed', room: roomId, call_id: callId });
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
        this.sendRaw({ t: 'ping' });
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

/** Which of these messages the caller can still read, and their deleted and edit state (no text). */
export async function fetchMessageStates(ids: string[]): Promise<MessageState[]> {
  const data = obj(
    await apiJSON('/api/v1/messages/state', { method: 'POST', body: JSON.stringify({ ids }) }, 'Could not check search results'),
  );
  return arr(data.messages ?? []).map((v) => {
    const o = obj(v);
    return { id: str(o.id, 128), deleted: bool(o.deleted), edited_at: opt(o.edited_at, count) ?? 0 };
  });
}
