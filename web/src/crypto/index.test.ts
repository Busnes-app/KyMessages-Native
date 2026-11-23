import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { Account, GroupSession, InboundGroupSession, loadCryptoSync, verifyEd25519 } from './index';

beforeAll(() => {
  // Vitest runs from web/; jsdom gives import.meta.url an http scheme.
  loadCryptoSync(readFileSync('src/crypto/pkg/kycrypto_bg.wasm'));
});

describe('crypto core bindings', () => {
  it('runs an Olm session and a Megolm room session from JavaScript', () => {
    const alice = new Account();
    const bob = new Account();
    bob.generateOneTimeKeys(1);
    const [otk] = Object.values(JSON.parse(bob.oneTimeKeys()) as Record<string, string>);
    bob.markKeysAsPublished();

    const toBob = alice.createOutboundSession(bob.curve25519, otk);
    const first = toBob.encrypt('room key');
    expect(first.type).toBe(0);
    const inbound = bob.createInboundSession(alice.curve25519, first.ciphertext);
    expect(inbound.plaintext).toBe('room key');
    expect(inbound.takeSession().sessionId).toBe(toBob.sessionId);

    const room = new GroupSession();
    const reader = new InboundGroupSession(room.sessionKey());
    const decrypted = reader.decrypt(room.encrypt('{"room_id":"rm_1","body":"hi"}'));
    expect(decrypted.plaintext).toBe('{"room_id":"rm_1","body":"hi"}');
    expect(() => new InboundGroupSession(new GroupSession().sessionKey()).decrypt(room.encrypt('x'))).toThrow();

    expect(verifyEd25519(alice.ed25519, 'msg', alice.sign('msg'))).toBe(true);
    expect(() => Account.fromPickle(alice.pickle(new Uint8Array(32)), new Uint8Array(32).fill(1))).toThrow();
  });
});
