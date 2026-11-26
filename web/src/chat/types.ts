import type { MessageFiles } from '../crypto/attachments';
import { arr, bool, count, obj, oneOf, opt, str } from '../dto';

export type RoomKind = 'dm' | 'channel' | 'meeting';
export type RoomRole = 'owner' | 'admin' | 'member' | 'bot';
export type NotifyMode = 'all' | 'mentions' | 'mute';
export type MessageEncoding = 'plain_v1' | 'e2ee_room_v1' | 'system_v1';
export type WsStatus = 'connecting' | 'live' | 'reconnecting' | 'revoked' | 'offline';

export interface ChatPushConfig {
  available: boolean;
  vapid_public_key: string;
}

export interface ChatCurrentUser {
  id: string;
  username: string;
  display_name: string;
  role: string;
}

export interface ChatDirectoryUser {
  id: string;
  username: string;
  display_name: string;
  role?: string;
}

export interface ChatTenant {
  id: string;
  slug: string;
  display_name: string;
  plan: string;
  p2p_policy: string;
  p2p_max_video: number;
  p2p_max_audio: number;
  guest_force_sfu: boolean;
}

export interface ChatRoom {
  id: string;
  tenant_id: string;
  kind: RoomKind;
  name: string;
  topic: string;
  is_private: boolean;
  last_seq: number;
  closed_at?: number;
  created_by: string;
  created_at: number;
}

export interface ChatRoomSummary extends ChatRoom {
  role: RoomRole;
  last_read_seq: number;
  unread_count: number;
  notify_mode: string;
}

export interface ChatRoomMember {
  tenant_id: string;
  room_id: string;
  user_id: string;
  role: RoomRole;
  last_read_seq: number;
  notify_mode: string;
  joined_at: number;
}

export interface ChatReactionSummary {
  emoji: string;
  user_ids: string[];
  count: number;
}

export interface ChatAttachment {
  id: string;
  tenant_id: string;
  room_id: string;
  message_id?: string;
  uploader_id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  sha256_hex: string;
  created_at: number;
}

export interface ChatAttachmentLimits {
  available: boolean;
  max_upload_bytes: number;
  max_per_message: number;
}

export const DEFAULT_ATTACHMENT_LIMITS: ChatAttachmentLimits = {
  available: true,
  max_upload_bytes: 25 * 1024 * 1024,
  max_per_message: 10,
};

const INLINE_IMAGE_MIMES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);

export function isInlineImageAttachment(att: Pick<ChatAttachment, 'mime_type'>): boolean {
  return INLINE_IMAGE_MIMES.has(att.mime_type.toLowerCase());
}

export function attachmentUrl(id: string, inline = false): string {
  const base = `/api/v1/attachments/${encodeURIComponent(id)}`;
  return inline ? `${base}?inline=1` : base;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb >= 10 ? Math.round(kb) : kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb >= 10 ? Math.round(mb) : mb.toFixed(1)} MB`;
}

export type MessageDeliveryState =
  | { kind: 'synced' }
  | { kind: 'sending'; idempotencyKey: string }
  | { kind: 'failed'; idempotencyKey: string; error: string };

/**
 * What this device could do with an e2ee_room_v1 message: read it, not yet (its key has not
 * arrived), or never (with the reason shown in its place).
 */
// `gen` is the key generation (keyGeneration) the open saw, on waiting and on retryable failures:
// a newer one means keys arrived or the device started since, so the message is worth opening again.
export type E2EEState = { kind: 'decrypted' } | { kind: 'waiting'; gen?: number } | { kind: 'failed'; reason: string; gen?: number };

export interface ChatMessage {
  id: string;
  tenant_id: string;
  room_id: string;
  seq: number;
  sender_id: string;
  sender_name: string;
  reply_to_id?: string;
  encoding: MessageEncoding;
  body: string;
  edited_at?: number;
  deleted_at?: number;
  created_at: number;
  reactions: ChatReactionSummary[];
  attachments: ChatAttachment[];
  delivery: MessageDeliveryState;
  /** For e2ee_room_v1: the envelope as stored. `body` holds only decrypted text, never this. */
  envelope?: string;
  /** For an edited e2ee_room_v1 message with files: the envelope it was first sent in, which holds them. */
  original?: string;
  e2ee?: E2EEState;
  /** From the decrypted message only, never the server: its encrypted files (keys included). */
  files?: MessageFiles['files'];
  filesState?: MessageFiles['filesState'];
}

export type CallMode = 'p2p_mesh' | 'sfu_livekit';

export interface CallPeer {
  peer_id?: string;
  user_id: string;
  display_name: string;
  is_guest: boolean;
  audio: boolean;
  video: boolean;
  screen_share: boolean;
  protect_ip: boolean;
  joined_at: number;
}

export interface CallState {
  call_id: string;
  room_id: string;
  active?: boolean;
  mode: CallMode;
  epoch?: number;
  sfu_sticky: boolean;
  livekit_room?: string;
  ended?: boolean;
  peers: CallPeer[];
}

export interface CallJoinResponse {
 call_ws_path?: string;
  call_id: string;
  room_id: string;
  peer_id?: string;
  mode: CallMode;
  epoch?: number;
  sfu_sticky: boolean;
  ice_servers: RTCIceServer[];
  livekit_url?: string;
  livekit_token?: string;
  livekit_room?: string;
  peers: CallPeer[];
}

export interface CallMigratePayload {
  call_id: string;
  room_id: string;
  epoch?: number;
  target_mode: CallMode;
  peers?: CallPeer[];
  reason?: string;
  livekit_url?: string;
  livekit_token?: string;
  livekit_room?: string;
  ice_servers?: RTCIceServer[];
}

export interface CallSignalData {
  call_id: string;
  from: string;
  to: string;
  from_peer_id?: string;
  to_peer_id?: string;
  kind: 'offer' | 'answer' | 'ice';
  payload: unknown;
}

export interface LobbyGuest {
  guest_id: string;
  meeting_id: string;
  room_id: string;
  display_name: string;
  status: 'waiting' | 'admitted' | 'denied';
  knocked_at: number;
}

export interface MediaPolicyConfig {
  p2p_policy: 'hybrid' | 'sfu_only';
  p2p_max_video: number;
  p2p_max_audio: number;
  guest_force_sfu: boolean;
}

export interface AdminMediaPolicyResponse {
  policy: MediaPolicyConfig;
  rtc: {
    sfu_available: boolean;
    livekit_url: string;
    stun_urls: string[];
  };
  stats: {
    active_calls: number;
    p2p_calls: number;
    sfu_calls: number;
    active_peers: number;
    sfu_available: boolean;
  };
}

export interface GuestMeetInfo {
 call_room_id?: string;
  meeting_title: string;
  closed: boolean;
  in_window: boolean;
  pow_required: boolean;
  sfu_available: boolean;
  session?: {
    guest_id: string;
    display_name: string;
    status: 'waiting' | 'admitted' | 'denied';
    room_id: string;
  };
}

export interface ChatBootstrap {
  user: ChatCurrentUser;
  tenant: ChatTenant;
  rooms: ChatRoomSummary[];
  active_calls: Record<string, CallState>;
  rtc: {
    sfu_available: boolean;
    ice_servers: RTCIceServer[];
  };
  attachments: ChatAttachmentLimits;
  push: ChatPushConfig;
}

export interface ChatRoomDetail {
  room: ChatRoom;
  member: ChatRoomMember;
  members: ChatRoomMember[];
}

export interface ChatMessagesPage {
  messages: ChatMessage[];
  has_more: boolean;
}

export type WsServerEvent =
  | { kind: 'hello'; userId: string }
  | { kind: 'pong' }
  | { kind: 'message.new'; roomId: string; seq: number; message?: ChatMessage; refetch: boolean }
  | { kind: 'message.edit'; roomId: string; seq: number; message?: ChatMessage; refetch: boolean }
  | { kind: 'message.delete'; roomId: string; seq: number; messageId: string; deletedAt: number }
  | { kind: 'reaction.set'; roomId: string; messageId: string; userId: string; emoji: string; added: boolean }
  | { kind: 'room.member'; roomId: string; action: 'added' | 'removed' | 'role'; userId: string; role?: RoomRole }
  | { kind: 'room.updated'; roomId: string; room?: ChatRoom }
  | { kind: 'room.closed'; roomId: string }
  | { kind: 'typing'; roomId: string; userId: string; active: boolean }
  | { kind: 'read.sync'; roomId: string; lastReadSeq: number }
  | { kind: 'call.state'; roomId: string; state: CallState }
  | { kind: 'call.signal'; roomId: string; signal: CallSignalData }
  | { kind: 'call.migrate'; roomId: string; migrate: CallMigratePayload }
  | { kind: 'lobby.knock'; roomId: string; guest: LobbyGuest }
  | { kind: 'lobby.decision'; roomId: string; guestId: string; decision: 'admitted' | 'denied'; meetingId: string }
  | { kind: 'auth.revoked' }
  | { kind: 'to_device' };

const ROOM_KINDS: readonly RoomKind[] = ['dm', 'channel', 'meeting'];
const ROOM_ROLES: readonly RoomRole[] = ['owner', 'admin', 'member', 'bot'];
const ENCODINGS: readonly MessageEncoding[] = ['plain_v1', 'e2ee_room_v1', 'system_v1'];

function num(v: unknown): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Error('Invalid numeric field');
  return v;
}

export function parseDirectoryUser(v: unknown): ChatDirectoryUser {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    username: str(o.username, 255),
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? str(o.username, 255),
    role: opt(o.role, (s) => str(s, 32)),
  };
}

export function parseCurrentUser(v: unknown): ChatCurrentUser {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    username: str(o.username, 255),
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? '',
    role: opt(o.role, (s) => str(s, 32)) ?? 'user',
  };
}

export function parseTenant(v: unknown): ChatTenant {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    slug: opt(o.slug, (s) => str(s, 128)) ?? 'default',
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? 'KyMessages',
    plan: opt(o.plan, (s) => str(s, 64)) ?? 'self_hosted',
    p2p_policy: opt(o.p2p_policy, (s) => str(s, 32)) ?? 'hybrid',
    p2p_max_video: opt(o.p2p_max_video, count) ?? 2,
    p2p_max_audio: opt(o.p2p_max_audio, count) ?? 4,
    guest_force_sfu: opt(o.guest_force_sfu, bool) ?? true,
  };
}

export function parseRoom(v: unknown): ChatRoom {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    tenant_id: opt(o.tenant_id, (s) => str(s, 128)) ?? 'default',
    kind: oneOf(o.kind, ROOM_KINDS),
    name: opt(o.name, (s) => str(s, 255)) ?? '',
    topic: opt(o.topic, (s) => str(s, 1000)) ?? '',
    is_private: opt(o.is_private, bool) ?? false,
    last_seq: opt(o.last_seq, count) ?? 0,
    closed_at: opt(o.closed_at, num),
    created_by: opt(o.created_by, (s) => str(s, 128)) ?? '',
    created_at: opt(o.created_at, num) ?? 0,
  };
}

export function parseRoomSummary(v: unknown): ChatRoomSummary {
  const o = obj(v);
  return {
    ...parseRoom(o),
    role: opt(o.role, (r) => oneOf(r, ROOM_ROLES)) ?? 'member',
    last_read_seq: opt(o.last_read_seq, count) ?? 0,
    unread_count: opt(o.unread_count, count) ?? 0,
    notify_mode: opt(o.notify_mode, (s) => str(s, 32)) ?? 'all',
  };
}

export function parseRoomMember(v: unknown): ChatRoomMember {
  const o = obj(v);
  return {
    tenant_id: opt(o.tenant_id, (s) => str(s, 128)) ?? 'default',
    room_id: str(o.room_id, 128),
    user_id: str(o.user_id, 128),
    role: opt(o.role, (r) => oneOf(r, ROOM_ROLES)) ?? 'member',
    last_read_seq: opt(o.last_read_seq, count) ?? 0,
    notify_mode: opt(o.notify_mode, (s) => str(s, 32)) ?? 'all',
    joined_at: opt(o.joined_at, num) ?? 0,
  };
}

export function parseReactionSummary(v: unknown): ChatReactionSummary {
  const o = obj(v);
  const ids = opt(o.user_ids, (list) => arr(list).map((id) => str(id, 128))) ?? [];
  return {
    emoji: str(o.emoji, 32),
    user_ids: ids,
    count: opt(o.count, count) ?? ids.length,
  };
}

export function parseAttachment(v: unknown): ChatAttachment {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    tenant_id: opt(o.tenant_id, (s) => str(s, 128)) ?? 'default',
    room_id: str(o.room_id, 128),
    message_id: opt(o.message_id, (s) => str(s, 128)),
    uploader_id: opt(o.uploader_id, (s) => str(s, 128)) ?? '',
    filename: opt(o.filename, (s) => str(s, 255)) ?? 'file',
    mime_type: opt(o.mime_type, (s) => str(s, 128)) ?? 'application/octet-stream',
    size_bytes: opt(o.size_bytes, count) ?? 0,
    sha256_hex: opt(o.sha256_hex, (s) => str(s, 128)) ?? '',
    created_at: opt(o.created_at, num) ?? 0,
  };
}

export function parseMessage(v: unknown): ChatMessage {
  const o = obj(v);
  const encoding = opt(o.encoding, (e) => oneOf(e, ENCODINGS)) ?? 'plain_v1';
  const body = opt(o.body, (s) => str(s, 65536)) ?? '';
  // Ciphertext never sits in body, so nothing that shows or indexes body can leak it.
  const sealed = encoding === 'e2ee_room_v1' && !opt(o.deleted_at, num);
  return {
    id: str(o.id, 128),
    tenant_id: opt(o.tenant_id, (s) => str(s, 128)) ?? 'default',
    room_id: str(o.room_id, 128),
    seq: opt(o.seq, count) ?? 0,
    sender_id: str(o.sender_id, 128),
    sender_name: opt(o.sender_name, (s) => str(s, 255)) ?? '',
    reply_to_id: opt(o.reply_to_id, (s) => str(s, 128)),
    encoding,
    body: encoding === 'e2ee_room_v1' ? '' : body,
    ...(sealed ? { envelope: body, e2ee: { kind: 'waiting' } as E2EEState } : {}),
    ...(sealed && typeof o.original_body === 'string' && o.original_body ? { original: str(o.original_body, 65536) } : {}),
    edited_at: opt(o.edited_at, num),
    deleted_at: opt(o.deleted_at, num),
    created_at: opt(o.created_at, num) ?? Date.now(),
    reactions: opt(o.reactions, (list) => arr(list).map(parseReactionSummary)) ?? [],
    attachments: opt(o.attachments, (list) => arr(list).map(parseAttachment)) ?? [],
    delivery: { kind: 'synced' },
  };
}

const CALL_MODES: readonly CallMode[] = ['p2p_mesh', 'sfu_livekit'];

export function parseICEServers(v: unknown): RTCIceServer[] {
  if (!Array.isArray(v)) return [];
  const out: RTCIceServer[] = [];
  for (const item of v) {
    try {
      const o = obj(item);
      const urls = Array.isArray(o.urls)
        ? o.urls.filter((u): u is string => typeof u === 'string' && u.length > 0)
        : typeof o.urls === 'string' && o.urls.length > 0
          ? [o.urls]
          : [];
      if (urls.length > 0) {
        const srv: RTCIceServer = { urls };
        if (typeof o.username === 'string' && o.username) srv.username = o.username;
        if (typeof o.credential === 'string' && o.credential) srv.credential = o.credential;
        out.push(srv);
      }
    } catch {
      // Ignore malformed entry.
    }
  }
  return out;
}

export function parseCallPeer(v: unknown): CallPeer {
  const o = obj(v);
  return {
    peer_id: opt(o.peer_id, (s) => str(s, 128)),
    user_id: str(o.user_id, 128),
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? '',
    is_guest: opt(o.is_guest, bool) ?? false,
    audio: opt(o.audio, bool) ?? true,
    video: opt(o.video, bool) ?? false,
    screen_share: opt(o.screen_share, bool) ?? false,
    protect_ip: opt(o.protect_ip, bool) ?? false,
    joined_at: opt(o.joined_at, num) ?? 0,
  };
}

export function parseCallState(v: unknown): CallState {
  const o = obj(v);
  const active = opt(o.active, bool);
  const ended = opt(o.ended, bool) ?? (active === false ? true : undefined);
  return {
    call_id: str(o.call_id, 128),
    room_id: str(o.room_id, 128),
    active,
    mode: opt(o.mode, (m) => oneOf(m, CALL_MODES)) ?? 'p2p_mesh',
    epoch: opt(o.epoch, num),
    sfu_sticky: opt(o.sfu_sticky, bool) ?? false,
    livekit_room: opt(o.livekit_room, (s) => str(s, 256)),
    ended,
    peers: opt(o.peers, (list) => arr(list).map(parseCallPeer)) ?? [],
  };
}

export function parseCallJoinResponse(v: unknown): CallJoinResponse {
  const o = obj(v);
  const room = str(o.room_id,128);
  const path = opt(o.call_ws_path,(value)=>str(value,512));
  const prefix = `/api/v1/rooms/${encodeURIComponent(room)}/calls/`;
  if (path && path !== `${prefix}ws` && !(path.startsWith(`${prefix}guest/`) && /^guest\/[A-Za-z0-9_-]{16,128}\/ws$/.test(path.slice(prefix.length)))) {
    throw new Error('Invalid call socket path');
  }
  return {
 call_ws_path: path,
    call_id: str(o.call_id, 128),
    room_id: str(o.room_id, 128),
    peer_id: opt(o.peer_id, (s) => str(s, 128)),
    mode: oneOf(o.mode, CALL_MODES),
    epoch: opt(o.epoch, num),
    sfu_sticky: opt(o.sfu_sticky, bool) ?? false,
    ice_servers: parseICEServers(o.ice_servers),
    livekit_url: opt(o.livekit_url, (s) => str(s, 512)),
    livekit_token: opt(o.livekit_token, (s) => str(s, 4096)),
    livekit_room: opt(o.livekit_room, (s) => str(s, 256)),
    peers: opt(o.peers, (list) => arr(list).map(parseCallPeer)) ?? [],
  };
}

export function parseCallMigrate(v: unknown): CallMigratePayload {
  const o = obj(v);
  return {
    call_id: str(o.call_id, 128),
    room_id: str(o.room_id, 128),
    epoch: opt(o.epoch, num),
    target_mode: oneOf(o.target_mode, CALL_MODES),
    peers: o.peers !== undefined ? arr(o.peers).map(parseCallPeer) : undefined,
    reason: opt(o.reason, (s) => str(s, 128)),
    livekit_url: opt(o.livekit_url, (s) => str(s, 512)),
    livekit_token: opt(o.livekit_token, (s) => str(s, 4096)),
    livekit_room: opt(o.livekit_room, (s) => str(s, 256)),
    ice_servers: o.ice_servers !== undefined ? parseICEServers(o.ice_servers) : undefined,
  };
}

export function parseLobbyGuest(v: unknown): LobbyGuest {
  const o = obj(v);
  return {
    guest_id: str(o.guest_id, 128),
    meeting_id: opt(o.meeting_id, (s) => str(s, 128)) ?? '',
    room_id: opt(o.room_id, (s) => str(s, 128)) ?? '',
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? 'Guest',
    status: oneOf(o.status ?? 'waiting', ['waiting', 'admitted', 'denied'] as const),
    knocked_at: opt(o.knocked_at, num) ?? Date.now(),
  };
}

export function parseAdminMediaPolicy(v: unknown): AdminMediaPolicyResponse {
  const o = obj(v);
  const p = obj(o.policy);
  const r = obj(o.rtc);
  const st = obj(o.stats);
  return {
    policy: {
      p2p_policy: oneOf(p.p2p_policy, ['hybrid', 'sfu_only'] as const),
      p2p_max_video: count(p.p2p_max_video),
      p2p_max_audio: count(p.p2p_max_audio),
      guest_force_sfu: bool(p.guest_force_sfu),
    },
    rtc: {
      sfu_available: opt(r.sfu_available, bool) ?? false,
      livekit_url: opt(r.livekit_url, (s) => str(s, 512)) ?? '',
      stun_urls: opt(r.stun_urls, (list) => arr(list).map((s) => str(s, 512))) ?? [],
    },
    stats: {
      active_calls: opt(st.active_calls, count) ?? 0,
      p2p_calls: opt(st.p2p_calls, count) ?? 0,
      sfu_calls: opt(st.sfu_calls, count) ?? 0,
      active_peers: opt(st.active_peers, count) ?? 0,
      sfu_available: opt(st.sfu_available, bool) ?? false,
    },
  };
}

export function parseGuestMeetInfo(v: unknown): GuestMeetInfo {
  const o = obj(v);
  let session: GuestMeetInfo['session'];
  if (o.session && typeof o.session === 'object') {
    const s = obj(o.session);
    session = {
      guest_id: str(s.guest_id, 128),
      display_name: opt(s.display_name, (x) => str(x, 255)) ?? 'Guest',
      status: oneOf(s.status, ['waiting', 'admitted', 'denied'] as const),
      room_id: opt(s.room_id, (x) => str(x, 128)) ?? '',
    };
  }
  return {
 call_room_id: opt(o.call_room_id,(v)=>str(v,128)),
    meeting_title: opt(o.meeting_title, (s) => str(s, 255)) ?? 'Meeting',
    closed: opt(o.closed, bool) ?? false,
    in_window: opt(o.in_window, bool) ?? false,
    pow_required: opt(o.pow_required, bool) ?? false,
    sfu_available: opt(o.sfu_available, bool) ?? false,
    session,
  };
}

export function parseBootstrap(v: unknown): ChatBootstrap {
  const o = obj(v);
  const activeCalls: Record<string, CallState> = {};
  if (o.active_calls && typeof o.active_calls === 'object' && !Array.isArray(o.active_calls)) {
    for (const [rid, rawState] of Object.entries(o.active_calls as Record<string, unknown>)) {
      try {
        activeCalls[rid] = parseCallState(rawState);
      } catch {
        // Ignore malformed call state.
      }
    }
  }
  const rtcObj = o.rtc && typeof o.rtc === 'object' ? obj(o.rtc) : {};
  const attObj = o.attachments && typeof o.attachments === 'object' ? obj(o.attachments) : {};
  const pushObj = o.push && typeof o.push === 'object' ? obj(o.push) : {};
  return {
    user: parseCurrentUser(o.user),
    tenant: parseTenant(o.tenant),
    rooms: opt(o.rooms, (list) => arr(list).map(parseRoomSummary)) ?? [],
    active_calls: activeCalls,
    rtc: {
      sfu_available: opt(rtcObj.sfu_available, bool) ?? false,
      ice_servers: parseICEServers(rtcObj.ice_servers),
    },
    attachments: {
      available: opt(attObj.available, bool) ?? DEFAULT_ATTACHMENT_LIMITS.available,
      max_upload_bytes: opt(attObj.max_upload_bytes, count) ?? DEFAULT_ATTACHMENT_LIMITS.max_upload_bytes,
      max_per_message: opt(attObj.max_per_message, count) ?? DEFAULT_ATTACHMENT_LIMITS.max_per_message,
    },
    push: {
      available: opt(pushObj.available, bool) ?? false,
      vapid_public_key: opt(pushObj.vapid_public_key, (s) => str(s, 256)) ?? '',
    },
  };
}

export function parseUsersList(v: unknown): ChatDirectoryUser[] {
  const o = obj(v);
  return opt(o.users, (list) => arr(list).map(parseDirectoryUser)) ?? [];
}

export function parseRoomDetail(v: unknown): ChatRoomDetail {
  const o = obj(v);
  return {
    room: parseRoom(o.room),
    member: parseRoomMember(o.member),
    members: opt(o.members, (list) => arr(list).map(parseRoomMember)) ?? [],
  };
}

export function parseMessagesPage(v: unknown): ChatMessagesPage {
  const o = obj(v);
  return {
    messages: opt(o.messages, (list) => arr(list).map(parseMessage)) ?? [],
    has_more: opt(o.has_more, bool) ?? false,
  };
}

export function parseWsEvent(raw: unknown): WsServerEvent | null {
  try {
    const o = obj(raw);
    const t = str(o.t, 64);
    const roomId = opt(o.room, (s) => str(s, 128)) ?? '';
    const seq = opt(o.seq, count) ?? 0;
    const data = o.d;

    switch (t) {
      case 'hello': {
        const d = data !== undefined && data !== null ? obj(data) : {};
        return { kind: 'hello', userId: opt(d.user_id, (s) => str(s, 128)) ?? '' };
      }
      case 'pong':
        return { kind: 'pong' };
      case 'message.new':
      case 'message.edit': {
        if (!roomId) return null;
        if (data !== undefined && data !== null) {
          const d = obj(data);
          if (d.refetch === true) {
            return { kind: t, roomId, seq, refetch: true };
          }
          return { kind: t, roomId, seq, message: parseMessage(d), refetch: false };
        }
        return { kind: t, roomId, seq, refetch: true };
      }
      case 'message.delete': {
        if (!roomId) return null;
        const d = obj(data);
        return {
          kind: 'message.delete',
          roomId,
          seq,
          messageId: str(d.id, 128),
          deletedAt: opt(d.deleted_at, num) ?? Date.now(),
        };
      }
      case 'reaction.set': {
        if (!roomId) return null;
        const d = obj(data);
        return {
          kind: 'reaction.set',
          roomId,
          messageId: str(d.message_id, 128),
          userId: str(d.user_id, 128),
          emoji: str(d.emoji, 32),
          added: bool(d.added),
        };
      }
      case 'room.member': {
        if (!roomId) return null;
        const d = obj(data);
        const action = oneOf(d.action, ['added', 'removed', 'role'] as const);
        return {
          kind: 'room.member',
          roomId,
          action,
          userId: str(d.user_id, 128),
          role: opt(d.role, (r) => oneOf(r, ROOM_ROLES)),
        };
      }
      case 'room.updated': {
        if (!roomId) return null;
        return {
          kind: 'room.updated',
          roomId,
          room: data !== undefined && data !== null ? parseRoom(data) : undefined,
        };
      }
      case 'room.closed':
        return roomId ? { kind: 'room.closed', roomId } : null;
      case 'typing': {
        if (!roomId) return null;
        const d = obj(data);
        return {
          kind: 'typing',
          roomId,
          userId: str(d.user_id, 128),
          active: bool(d.active),
        };
      }
      case 'read.sync': {
        const d = obj(data);
        return {
          kind: 'read.sync',
          roomId: str(d.room_id, 128),
          lastReadSeq: count(d.last_read_seq),
        };
      }
      case 'call.state': {
        if (data === undefined || data === null) return null;
        const state = parseCallState(data);
        return { kind: 'call.state', roomId: roomId || state.room_id, state };
      }
      case 'call.signal': {
        if (data === undefined || data === null) return null;
        const d = obj(data);
        const sigKind = oneOf(d.kind, ['offer', 'answer', 'ice'] as const);
        const fromPeer = str(d.from_peer_id ?? d.from, 128);
        const toPeer = str(d.to_peer_id ?? d.to, 128);
        return {
          kind: 'call.signal',
          roomId: roomId || (opt(d.room_id, (s) => str(s, 128)) ?? ''),
          signal: {
            call_id: str(d.call_id, 128),
            from: fromPeer,
            to: toPeer,
            from_peer_id: fromPeer,
            to_peer_id: toPeer,
            kind: sigKind,
            payload: d.data !== undefined ? d.data : d.payload,
          },
        };
      }
      case 'call.migrate': {
        if (data === undefined || data === null) return null;
        const migrate = parseCallMigrate(data);
        return { kind: 'call.migrate', roomId: roomId || migrate.room_id, migrate };
      }
      case 'lobby.knock': {
        if (data === undefined || data === null) return null;
        const guest = parseLobbyGuest(data);
        return { kind: 'lobby.knock', roomId: roomId || guest.room_id, guest };
      }
      case 'lobby.decision': {
        if (data === undefined || data === null) return null;
        const d = obj(data);
        return {
          kind: 'lobby.decision',
          roomId: roomId || (opt(d.room_id, (s) => str(s, 128)) ?? ''),
          guestId: str(d.guest_id, 128),
          decision: oneOf(d.decision, ['admitted', 'denied'] as const),
          meetingId: opt(d.meeting_id, (s) => str(s, 128)) ?? '',
        };
      }
      case 'auth.revoked':
        return { kind: 'auth.revoked' };
      case 'to_device':
        return { kind: 'to_device' };
      default:
        return null;
    }
  } catch {
    return null;
  }
}
