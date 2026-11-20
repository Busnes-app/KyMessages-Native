import { arr, bool, count, obj, oneOf, opt, str } from '../dto';

export type RoomKind = 'dm' | 'channel' | 'meeting';
export type RoomRole = 'owner' | 'admin' | 'member' | 'bot';
export type MessageEncoding = 'plain_v1' | 'e2ee_room_v1' | 'system_v1';
export type WsStatus = 'connecting' | 'live' | 'reconnecting' | 'revoked' | 'offline';

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

export type MessageDeliveryState =
  | { kind: 'synced' }
  | { kind: 'sending'; idempotencyKey: string }
  | { kind: 'failed'; idempotencyKey: string; error: string };

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
  delivery: MessageDeliveryState;
}

export interface ChatRoomWebhook {
  id: string;
  room_id: string;
  name: string;
  direction: string;
  created_by: string;
  revoked_at?: number;
  created_at: number;
}

export interface ChatBootstrap {
  user: ChatCurrentUser;
  tenant: ChatTenant;
  rooms: ChatRoomSummary[];
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
  | { kind: 'room.member'; roomId: string; action: 'added' | 'removed'; userId: string; role?: RoomRole }
  | { kind: 'room.updated'; roomId: string; room?: ChatRoom }
  | { kind: 'room.closed'; roomId: string }
  | { kind: 'typing'; roomId: string; userId: string; active: boolean }
  | { kind: 'read.sync'; roomId: string; lastReadSeq: number }
  | { kind: 'auth.revoked' };

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

export function parseMessage(v: unknown): ChatMessage {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    tenant_id: opt(o.tenant_id, (s) => str(s, 128)) ?? 'default',
    room_id: str(o.room_id, 128),
    seq: opt(o.seq, count) ?? 0,
    sender_id: str(o.sender_id, 128),
    sender_name: opt(o.sender_name, (s) => str(s, 255)) ?? '',
    reply_to_id: opt(o.reply_to_id, (s) => str(s, 128)),
    encoding: opt(o.encoding, (e) => oneOf(e, ENCODINGS)) ?? 'plain_v1',
    body: opt(o.body, (s) => str(s, 32768)) ?? '',
    edited_at: opt(o.edited_at, num),
    deleted_at: opt(o.deleted_at, num),
    created_at: opt(o.created_at, num) ?? Date.now(),
    reactions: opt(o.reactions, (list) => arr(list).map(parseReactionSummary)) ?? [],
    delivery: { kind: 'synced' },
  };
}

export function parseWebhook(v: unknown): ChatRoomWebhook {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    room_id: str(o.room_id, 128),
    name: str(o.name, 255),
    direction: opt(o.direction, (s) => str(s, 32)) ?? 'incoming',
    created_by: opt(o.created_by, (s) => str(s, 128)) ?? '',
    revoked_at: opt(o.revoked_at, num),
    created_at: opt(o.created_at, num) ?? 0,
  };
}

export function parseBootstrap(v: unknown): ChatBootstrap {
  const o = obj(v);
  return {
    user: parseCurrentUser(o.user),
    tenant: parseTenant(o.tenant),
    rooms: opt(o.rooms, (list) => arr(list).map(parseRoomSummary)) ?? [],
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
        const action = oneOf(d.action, ['added', 'removed'] as const);
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
      case 'auth.revoked':
        return { kind: 'auth.revoked' };
      default:
        return null;
    }
  } catch {
    return null;
  }
}
