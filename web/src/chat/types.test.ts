import { describe, expect, it } from 'vitest';
import { parseMessage, parseWsEvent } from './types';

describe('message parsing', () => {
  it('keeps an envelope out of body, so nothing shows or indexes ciphertext', () => {
    const envelope = '{"alg":"megolm.v1","sender_key":"k","device_id":"D","session_id":"s","ciphertext":"AAAA"}';
    const m = parseMessage({ id: 'm1', room_id: 'r1', sender_id: 'u1', encoding: 'e2ee_room_v1', body: envelope });
    expect(m.body).toBe('');
    expect(m.envelope).toBe(envelope);
    expect(m.e2ee).toEqual({ kind: 'waiting' });
    const plain = parseMessage({ id: 'm2', room_id: 'r1', sender_id: 'u1', encoding: 'plain_v1', body: 'hi' });
    expect(plain.body).toBe('hi');
    expect(plain.e2ee).toBeUndefined();
    const deleted = parseMessage({ id: 'm3', room_id: 'r1', sender_id: 'u1', encoding: 'e2ee_room_v1', body: '', deleted_at: 5 });
    expect(deleted.e2ee).toBeUndefined();
  });

  it('reads the to_device wake', () => {
    expect(parseWsEvent({ t: 'to_device', d: { user_id: 'u1' } })).toEqual({ kind: 'to_device' });
  });
});
