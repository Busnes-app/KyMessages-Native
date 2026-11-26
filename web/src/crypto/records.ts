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
/** A room session waiting to be sealed to the key backup; the value is its inbound key. */
export const backupQueueKey = (inbound: string) => `bq:${inbound}`;

/** A failure worth retrying later (the network, the server), as opposed to bad data. */
export class Transient extends Error {}

/** The key server refused a write because the identity, pin set or backup version moved on. */
export class Conflict extends Error {}

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
