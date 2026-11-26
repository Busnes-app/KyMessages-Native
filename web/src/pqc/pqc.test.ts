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

  it('signs with both halves and refuses either half alone', () => {
    const m = pqc.masterGenerate();
    expect(m.alg).toBe('mldsa65+ed25519');
    const key = pqc.masterPublic(m.seed).key;
    const s = pqc.signDevice(m.seed, 't', 'u', 'DEVICE01', 'curve', 'ed');
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', s)).toBe(true);
    const other = pqc.signDevice(pqc.masterGenerate().seed, 't', 'u', 'DEVICE01', 'curve', 'ed');
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', { ...s, mldsa65: other.mldsa65 })).toBe(false);
    expect(pqc.verifyDevice(key, 't', 'u', 'DEVICE01', 'curve', 'ed', { ...s, ed25519: other.ed25519 })).toBe(false);
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

    const sealed = pqc.backupSeal(x.public, m.seed, 'rm_1', 'sess', b64('{"k":"é"}'));
    expect(unb64(pqc.backupOpen(x.seed, m.seed, 'rm_1', 'sess', sealed))).toBe('{"k":"é"}');
    expect(() => pqc.backupOpen(x.seed, m.seed, 'rm_2', 'sess', sealed)).toThrow();

    const eph = pqc.xwingGenerate();
    const qr = pqc.qrNew('QkJCQkJCQkJCQkJCQkJCQg', m.fingerprint);
    const parsed = pqc.qrParse(qr.text);
    expect(parsed).toEqual({ pairing_id: 'QkJCQkJCQkJCQkJCQkJCQg', secret: qr.secret, fingerprint: m.fingerprint });
    expect(pqc.comparisonCode(qr.secret, parsed.pairing_id, eph.public)).toMatch(/^\d{6}$/);
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
