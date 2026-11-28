import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { b64, loadPQCFrom, pqc, pqcCall, unb64 } from './index';

// The vectors internal/e2eeid's Go tests run natively (TestSharedVectors): the WebAssembly
// build must give the same bytes for every deterministic step.
interface Vector {
  name: string;
  call: string;
  args: string[];
  want?: unknown;
  error?: boolean;
}
const vectors = JSON.parse(readFileSync('../internal/e2eeid/testdata/vectors.json', 'utf8')) as Vector[];

beforeAll(async () => {
  await loadPQCFrom(readFileSync('src/pqc/pqc.wasm'));
});

describe('pqc.wasm', () => {
  it('agrees with the native Go build on every shared vector', () => {
    expect(vectors.length).toBeGreaterThan(20);
    for (const v of vectors) {
      if (v.error) {
        expect(() => pqcCall(v.call, ...v.args), v.name).toThrow();
      } else {
        expect(pqcCall(v.call, ...v.args), v.name).toEqual(v.want);
      }
    }
  });

  it('loads the shared pqwasm command alongside the product adapter', () => {
    const shared: unknown = Reflect.get(globalThis, 'pqwasm');
    if (typeof shared !== 'object' || shared === null || !('xwingGenerate' in shared)
      || typeof shared.xwingGenerate !== 'function') throw new Error('shared pqwasm did not start');
    const key: unknown = shared.xwingGenerate();
    if (typeof key !== 'object' || key === null || !('seed' in key) || !('publicKey' in key)
      || !(key.seed instanceof Uint8Array) || !(key.publicKey instanceof Uint8Array)) {
      throw new Error('invalid shared X-Wing key');
    }
    const raw = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/=+$/, '');
    expect(pqc.xwingPublic(raw(key.seed))).toBe(raw(key.publicKey));
  });

  it('signs with both halves and refuses either half alone', () => {
    const m = pqc.masterGenerate();
    const key = pqc.masterPublic(m.seed).key;
    expect(key).toBe(m.public_key);
    expect(atob(key.slice(0, 24))).toMatch(/^mldsa65\+ed25519\0/);
    const s = pqc.signDevice(m.seed, 't', 'u', 'DEVICE01', 'curve', 'ed');
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', s)).toBe(true);
    const other = pqc.signDevice(pqc.masterGenerate().seed, 't', 'u', 'DEVICE01', 'curve', 'ed');
    // Tag (16 bytes), ML-DSA-65 (3309), Ed25519 (64): splice in the other key's half.
    const bytes = (v: string) => Uint8Array.from(atob(v.padEnd(v.length + ((4 - (v.length % 4)) % 4), '=')), (c) => c.charCodeAt(0));
    const text = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/=+$/, '');
    const splice = (from: number, to: number) => {
      const out = bytes(s);
      out.set(bytes(other).subarray(from, to), from);
      return text(out);
    };
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', splice(16, 16 + 3309))).toBe(false);
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', splice(16 + 3309, 16 + 3309 + 64))).toBe(false);
    expect(pqc.verifyDevice(key, 't2', 'u', 'DEVICE01', 'curve', 'ed', s)).toBe(false);
  });

  it('round-trips the recovery key, the backup seal and the two-layer transfer', () => {
    const rk = pqc.recoveryGenerate();
    expect(rk.text).toMatch(/^([0-9A-HJKMNP-TV-Z]{4} ){13}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(pqc.recoveryParse(rk.text.toLowerCase())).toBe(rk.key);
    const m = pqc.masterGenerate();
    const x = pqc.xwingGenerate();
    const wrapped = pqc.recoveryWrap(rk.key, 'master-key', 't', 'u', m.seed);
    expect(pqc.recoveryUnwrap(rk.key, 'master-key', 't', 'u', wrapped)).toBe(m.seed);
    expect(() => pqc.recoveryUnwrap(rk.key, 'backup-key', 't', 'u', wrapped)).toThrow();

    const ref = { room_id: 'rm_1', sender_key: 'senderkey', session_id: 'sess', first_index: 4 };
    const sealed = pqc.backupSeal(x.public, m.seed, ref, b64('{"k":"é"}'));
    expect(unb64(pqc.backupOpen(x.seed, m.seed, ref, sealed))).toBe('{"k":"é"}');
    expect(() => pqc.backupOpen(x.seed, m.seed, { ...ref, room_id: 'rm_2' }, sealed)).toThrow();
    expect(() => pqc.backupOpen(x.seed, m.seed, { ...ref, first_index: 0 }, sealed)).toThrow();

    const eph = pqc.xwingGenerate();
    const qr = pqc.qrNew('QkJCQkJCQkJCQkJCQkJCQg', m.fingerprint);
    const parsed = pqc.qrParse(qr.text);
    expect(parsed).toEqual({ pairing_id: 'QkJCQkJCQkJCQkJCQkJCQg', secret: qr.secret, fingerprint: m.fingerprint });
    const code = pqc.comparisonCode(qr.secret, parsed.pairing_id, 'NEW_DEVICE', eph.public);
    expect(code).toMatch(/^\d{6}$/);
    // Another of the user's devices joining with the same key shows another code.
    expect(pqc.comparisonCode(qr.secret, parsed.pairing_id, 'OTHER_DEVICE', eph.public)).not.toBe(code);
    const t = pqc.transferSeal(eph.public, qr.secret, parsed.pairing_id, 'OLD_DEVICE', 'NEW_DEVICE', m.seed, x.seed);
    expect(pqc.transferOpen(eph.seed, parsed.secret, parsed.pairing_id, 'OLD_DEVICE', 'NEW_DEVICE', t)).toEqual({ master_seed: m.seed, backup_seed: x.seed });
    expect(() => pqc.transferOpen(eph.seed, rk.key, parsed.pairing_id, 'OLD_DEVICE', 'NEW_DEVICE', t)).toThrow();
  });

  it('reports a bad call as an error, not a crash', () => {
    expect(() => pqcCall('nope')).toThrow(/unknown call/);
    expect(() => pqcCall('masterPublic', '!!')).toThrow();
    expect(() => pqc.recoveryParse('not a key')).toThrow();
  });
});
