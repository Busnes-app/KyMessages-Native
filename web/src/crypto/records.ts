import { PQCUnavailable } from '../pqc/index';

// Stored records the device engine (engine.ts) and its identity (identity.ts) share.

/** A room session this device can read, bound to the device that sent its key. */
export interface InboundRecord {
  pickle: string;
  room_id: string;
  sender_user: string;
  sender_device: string;
  sender_key: string;
  first_index: number;
  /** Set when the key came from the key backup rather than over Olm from its sender. */
  from_backup?: boolean;
  /** Set when the sending device was vouched for by its member's master key on arrival. */
  verified?: boolean;
}

// Room sessions and their replay log are keyed by the sender's verified curve25519 key as well
// as the session ID: a member who re-shares someone else's session as their own gets a separate
// entry, and can neither displace the real sender's key nor claim its message indexes.
export const inboundKey = (senderKey: string, sessionId: string) => `in:${senderKey}:${sessionId}`;
export const seenKey = (senderKey: string, sessionId: string, index: number) => `seen:${senderKey}:${sessionId}:${index}`;
/** A key-backup copy of a session that reaches earlier than the verified one this device holds:
 * used only for messages before that one's first index, and never as authenticated. */
export const backupCoverKey = (senderKey: string, sessionId: string) => `inb:${senderKey}:${sessionId}`;
/** A room session waiting to be sealed to the key backup; the value is its inbound key. */
export const backupQueueKey = (inbound: string) => `bq:${inbound}`;
/** A queued room session the backup refused for its caps: retried less often, shown as full. */
export const backupRefusedKey = (inbound: string) => `bqf:${inbound}`;

/** A failure worth retrying later (the network, the server), as opposed to bad data. */
export class Transient extends Error {}

/** Local storage (IndexedDB) failed or aborted the request: availability, not bad data. */
export class StorageUnavailable extends Transient {}

/** Waits ms, or until signal aborts (then rejects with its reason); leaves no listener behind. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const stop = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', stop);
      resolve();
    }, ms);
    signal?.addEventListener('abort', stop, { once: true });
  });
}

/**
 * Whether e is about availability (the network or server, the post-quantum module, local
 * storage) rather than a verdict on data: such failures keep their work for a retry. An abort
 * (a closed screen, a stopped device) is neither: nothing asked for that work any more.
 */
export function isTransient(e: unknown): boolean {
  return e instanceof Transient || e instanceof PQCUnavailable ||
    (e instanceof DOMException && e.name !== 'AbortError' && e.name !== 'TimeoutError');
}

/** The key server refused a write because the identity, pin set or backup version moved on.
 * retryInMs: when a device list reservation in the way lapses. */
export class Conflict extends Error {
  constructor(message?: string, readonly retryInMs?: number) {
    super(message);
  }
}

export function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function isStr(v: unknown, max = 65536): v is string {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}

export function parseJSON(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}
