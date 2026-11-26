// A stand-in for chat/e2ee.ts in page tests, which run without the WebAssembly core: "sealing"
// base64-encodes the inner JSON under a session name, and a message opens once its session's key
// has "arrived". Use with vi.mock('../chat/e2ee', () => import('../chat/e2eeFake')).
import type { RoomInner } from '../crypto/engine';
import type { ChatMessage } from './types';

export const UNAVAILABLE = 'Encryption is not available in this browser yet.';
export const NOT_YET = 'This message could not be opened yet.';
export const retryable = (reason: string) => reason === UNAVAILABLE || reason === NOT_YET;
export const MAX_MESSAGE_BYTES = 16 << 10;
export const MAX_INNER_BYTES = 32 << 10;

const keys = new Set<string>(['s_own']);
const listeners = new Set<() => void>();

/** A stored envelope as another member's device would have written it. */
export function fakeEnvelope(inner: RoomInner, session = 's_own'): string {
  return JSON.stringify({ alg: 'megolm.v1', sender_key: 'k', device_id: 'DEVICE0001', session_id: session, ciphertext: btoa(JSON.stringify(inner)) });
}

/** Lets messages in session open, and wakes whoever waits for keys. */
let keyGen = 0;
export const keyGeneration = () => keyGen;

export function deliverKey(session: string): void {
  keys.add(session);
  keyGen++;
  for (const fn of listeners) fn();
}

/** Stores a key without telling listeners, as when keys land between an open and its display. */
export function storeKeySilently(session: string): void {
  keys.add(session);
  keyGen++;
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
  fakeIdentity = { state: 'verified', fingerprint: 'f'.repeat(64) };
  fakeChanges = [];
}

export const startE2EE = async () => ({});
export const receiveRoomKeys = () => undefined;
export const roomMemberLeft = () => undefined;
export const retireDevice = () => ({
  wait: Promise.resolve(true),
  replaceIfRetired: async () => undefined,
});
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
  const out = openNow(m);
  // A held open has already read the key store, as a slow decrypt would have.
  if (held) {
    heldOpens++;
    await held;
  }
  return out;
}

function openNow(m: ChatMessage): ChatMessage {
  if (m.encoding !== 'e2ee_room_v1' || !m.envelope || m.deleted_at) return m;
  if (unavailable) return { ...m, body: '', e2ee: { kind: 'failed', reason: UNAVAILABLE, gen: keyGen } };
  const env = JSON.parse(m.envelope) as { session_id: string; ciphertext: string };
  if (!keys.has(env.session_id)) return { ...m, body: '', e2ee: { kind: 'waiting', gen: keyGen } };
  const inner = JSON.parse(atob(env.ciphertext)) as RoomInner;
  if (inner.room_id !== m.room_id) return { ...m, body: '', e2ee: { kind: 'failed', reason: 'This message was encrypted for another room.' } };
  return { ...m, body: inner.body, reply_to_id: inner.reply_to_id, e2ee: { kind: 'decrypted' } };
}

let held: Promise<void> | undefined;
let heldOpens = 0;
/** How many opens have paused on holdFakeOpens since it was last called. */
export const heldOpenCount = () => heldOpens;

/** Holds opens after they read the key store (as a slow decrypt would) until release is called. */
export function holdFakeOpens(): () => void {
  let release = () => undefined as void;
  held = new Promise((r) => (release = r));
  heldOpens = 0;
  return () => {
    held = undefined;
    release();
  };
}

export function openMessages(list: ChatMessage[]): Promise<ChatMessage[]> {
  return Promise.all(list.map(openMessage));
}

// Identity (E3): page tests see a verified device with no identity changes unless they say so.
let fakeIdentity: { state: 'none' } | { state: 'unverified'; fingerprint: string } | { state: 'verified'; fingerprint: string } = { state: 'verified', fingerprint: 'f'.repeat(64) };
let fakeChanges: { user_id: string; fingerprint: string; previous: string }[] = [];
const identityListeners = new Set<() => void>();
export function setFakeIdentity(s: typeof fakeIdentity, changes: typeof fakeChanges = []): void {
  fakeIdentity = s;
  fakeChanges = changes;
  for (const fn of identityListeners) fn();
}
export const identityStatus = async () => fakeIdentity;
export const identityChanges = async () => fakeChanges;
export const onIdentityChanged = (fn: () => void) => {
  identityListeners.add(fn);
  return () => identityListeners.delete(fn);
};
export async function acceptIdentity(userId: string): Promise<void> {
  fakeChanges = fakeChanges.filter((c) => c.user_id !== userId);
  for (const fn of identityListeners) fn();
}
export const prepareIdentity = async () => ({ recoveryKey: 'ABCD '.repeat(14).trim(), commit: async () => setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64) }) });
export const restoreIdentity = async () => 0;
export const offerVerification = async () => ({ text: 'x'.repeat(108), expiresAt: Date.now() + 180_000, poll: async () => undefined, approve: async () => undefined, cancel: async () => undefined });
export const joinVerification = async () => ({ code: '123456', finish: async () => 0, cancel: async () => undefined });
