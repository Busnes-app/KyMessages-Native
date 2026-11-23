// A stand-in for chat/e2ee.ts in page tests, which run without the WebAssembly core: "sealing"
// base64-encodes the inner JSON under a session name, and a message opens once its session's key
// has "arrived". Use with vi.mock('../chat/e2ee', () => import('../chat/e2eeFake')).
import type { RoomInner } from '../crypto/engine';
import type { ChatMessage } from './types';

export const UNAVAILABLE = 'Encryption is not available in this browser yet.';
export const MAX_MESSAGE_BYTES = 16 << 10;
export const MAX_INNER_BYTES = 32 << 10;

const keys = new Set<string>(['s_own']);
const listeners = new Set<() => void>();

/** A stored envelope as another member's device would have written it. */
export function fakeEnvelope(inner: RoomInner, session = 's_own'): string {
  return JSON.stringify({ alg: 'megolm.v1', sender_key: 'k', device_id: 'DEVICE0001', session_id: session, ciphertext: btoa(JSON.stringify(inner)) });
}

/** Lets messages in session open, and wakes whoever waits for keys. */
export function deliverKey(session: string): void {
  keys.add(session);
  for (const fn of listeners) fn();
}

let unavailable = false;

/** Makes every encrypted message fail as if this browser's device had not started. */
export function setFakeUnavailable(v: boolean): void {
  unavailable = v;
}

export function resetFakeE2EE(): void {
  keys.clear();
  keys.add('s_own');
  unavailable = false;
}

export const startE2EE = async () => ({});
export const receiveRoomKeys = () => undefined;
export const roomMembershipChanged = () => undefined;
export const setMembershipLive = () => undefined;
export const retireDevice = async () => true;
export const abandonDevice = async () => undefined;
export const forgetCryptoStore = async () => undefined;
export const replaceDevice = async () => undefined;

export function onRoomKeys(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export async function sealRoomMessage(roomId: string, inner: Omit<RoomInner, 'room_id'>): Promise<string> {
  return fakeEnvelope({ ...inner, room_id: roomId });
}

export async function openMessage(m: ChatMessage): Promise<ChatMessage> {
  if (m.encoding !== 'e2ee_room_v1' || !m.envelope || m.deleted_at) return m;
  if (unavailable) return { ...m, body: '', e2ee: { kind: 'failed', reason: UNAVAILABLE } };
  const env = JSON.parse(m.envelope) as { session_id: string; ciphertext: string };
  if (!keys.has(env.session_id)) return { ...m, body: '', e2ee: { kind: 'waiting' } };
  const inner = JSON.parse(atob(env.ciphertext)) as RoomInner;
  if (inner.room_id !== m.room_id) return { ...m, body: '', e2ee: { kind: 'failed', reason: 'This message was encrypted for another room.' } };
  return { ...m, body: inner.body, reply_to_id: inner.reply_to_id, e2ee: { kind: 'decrypted' } };
}

export function openMessages(list: ChatMessage[]): Promise<ChatMessage[]> {
  return Promise.all(list.map(openMessage));
}
