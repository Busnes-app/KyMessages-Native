// The browser's post-quantum code: internal/e2eeid (X-Wing, ML-DSA-65 + Ed25519, the recovery
// key, the key backup seal and the QR transfer) compiled from Go to WebAssembly by
// web/pqc-wasm/build.sh, the same code the server runs. pqc.wasm and wasm_exec.js are build
// output; never edit them. Call loadPQC() before any export; it is idempotent.
//
// Keys, signatures and ciphertext are unpadded standard base64, pairing IDs and QR text are
// unpadded base64url, and fingerprints are lowercase hex.
import './wasm_exec.js';

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

declare global {
  // Defined by wasm_exec.js and by the Go program.
  var Go: new () => GoRuntime;
  var kyPQCCall: ((name: string, ...args: string[]) => { ok?: unknown; error?: string }) | undefined;
  var kyPQCReady: (() => void) | undefined;
}

let loading: Promise<void> | undefined;

async function start(source: () => Promise<WebAssembly.WebAssemblyInstantiatedSource>): Promise<void> {
  if (globalThis.kyPQCCall) return;
  const go = new globalThis.Go();
  const ready = new Promise<void>((resolve) => {
    globalThis.kyPQCReady = resolve;
  });
  const { instance } = await source.call(go);
  void go.run(instance);
  await ready;
}

// A failed load (offline start, a swapped asset) is retried by the next call.
export function loadPQC(): Promise<void> {
  loading ??= start(function (this: GoRuntime) {
    return WebAssembly.instantiateStreaming(fetch(new URL('./pqc.wasm', import.meta.url)), this.importObject);
  }).catch((e: unknown) => {
    loading = undefined;
    throw e;
  });
  return loading;
}

// Tests run in Node, where the module is read from disk.
export function loadPQCFrom(bytes: BufferSource): Promise<void> {
  loading ??= start(function (this: GoRuntime) {
    return WebAssembly.instantiate(bytes, this.importObject);
  });
  return loading;
}

/** Calls internal/e2eeid.Call by name; throws its error. */
export function pqcCall<T = unknown>(name: string, ...args: string[]): T {
  const call = globalThis.kyPQCCall;
  if (!call) throw new Error('The post-quantum module is not loaded');
  const r = call(name, ...args);
  if (r.error !== undefined) throw new Error(r.error);
  return r.ok as T;
}

export const HYBRID_ALG = 'mldsa65+ed25519';

/**
 * A hybridsig public key or signature on the wire: unpadded base64 of its tagged encoding
 * ("mldsa65+ed25519" 0x00 ‖ ML-DSA-65 half ‖ Ed25519 half), as ky-primitives hybridsig writes it.
 */
export type Hybrid = string;

export interface MasterKeyPair {
  seed: string;
  public_key: Hybrid;
  fingerprint: string;
}

export const pqc = {
  masterGenerate: () => pqcCall<MasterKeyPair>('masterGenerate'),
  masterPublic: (seed: string) => {
    const k = pqcCall<{ public_key: Hybrid; fingerprint: string }>('masterPublic', seed);
    return { key: k.public_key, fingerprint: k.fingerprint };
  },
  fingerprint: (k: Hybrid) => pqcCall<string>('fingerprint', k),
  signMaster: (seed: string, tenant: string, user: string) => pqcCall<Hybrid>('signMaster', seed, tenant, user),
  verifyMaster: (k: Hybrid, tenant: string, user: string, s: Hybrid) => pqcCall<boolean>('verifyMaster', k, tenant, user, s),
  signDevice: (seed: string, tenant: string, user: string, device: string, curve: string, ed: string) =>
    pqcCall<Hybrid>('signDevice', seed, tenant, user, device, curve, ed),
  verifyDevice: (k: Hybrid, tenant: string, user: string, device: string, curve: string, ed: string, s: Hybrid) =>
    pqcCall<boolean>('verifyDevice', k, tenant, user, device, curve, ed, s),
  signBackupKey: (seed: string, tenant: string, user: string, version: number, backupKey: string) =>
    pqcCall<Hybrid>('signBackupKey', seed, tenant, user, String(version), backupKey),
  verifyBackupKey: (k: Hybrid, tenant: string, user: string, version: number, backupKey: string, s: Hybrid) =>
    pqcCall<boolean>('verifyBackupKey', k, tenant, user, String(version), backupKey, s),
  xwingGenerate: () => pqcCall<{ seed: string; public: string }>('xwingGenerate'),
  xwingPublic: (seed: string) => pqcCall<string>('xwingPublic', seed),
  backupSeal: (backupKey: string, masterSeed: string, roomId: string, sessionId: string, plaintext: string) =>
    pqcCall<string>('backupSeal', backupKey, masterSeed, roomId, sessionId, plaintext),
  backupOpen: (backupSeed: string, masterSeed: string, roomId: string, sessionId: string, sealed: string) =>
    pqcCall<string>('backupOpen', backupSeed, masterSeed, roomId, sessionId, sealed),
  recoveryGenerate: () => pqcCall<{ key: string; text: string }>('recoveryGenerate'),
  recoveryParse: (text: string) => pqcCall<string>('recoveryParse', text),
  recoveryWrap: (key: string, purpose: 'master-key' | 'backup-key', tenant: string, user: string, seed: string) =>
    pqcCall<string>('recoveryWrap', key, purpose, tenant, user, seed),
  recoveryUnwrap: (key: string, purpose: 'master-key' | 'backup-key', tenant: string, user: string, wrapped: string) =>
    pqcCall<string>('recoveryUnwrap', key, purpose, tenant, user, wrapped),
  pinsSeal: (masterSeed: string, tenant: string, user: string, counter: number, plaintext: string) =>
    pqcCall<string>('pinsSeal', masterSeed, tenant, user, String(counter), plaintext),
  pinsOpen: (masterSeed: string, tenant: string, user: string, counter: number, sealed: string) =>
    pqcCall<string>('pinsOpen', masterSeed, tenant, user, String(counter), sealed),
  qrNew: (pairingId: string, fingerprint: string) => pqcCall<{ secret: string; text: string }>('qrNew', pairingId, fingerprint),
  qrParse: (text: string) => pqcCall<{ pairing_id: string; secret: string; fingerprint: string }>('qrParse', text.trim()),
  comparisonCode: (secret: string, pairingId: string, ephemeralKey: string) => pqcCall<string>('comparisonCode', secret, pairingId, ephemeralKey),
  transferSeal: (ephemeralKey: string, secret: string, pairingId: string, verifiedDevice: string, newDevice: string, masterSeed: string, backupSeed: string) =>
    pqcCall<string>('transferSeal', ephemeralKey, secret, pairingId, verifiedDevice, newDevice, masterSeed, backupSeed),
  transferOpen: (ephemeralSeed: string, secret: string, pairingId: string, verifiedDevice: string, newDevice: string, sealed: string) =>
    pqcCall<{ master_seed: string; backup_seed: string }>('transferOpen', ephemeralSeed, secret, pairingId, verifiedDevice, newDevice, sealed),
};

/** UTF-8 text to unpadded standard base64, and back. */
export function b64(text: string): string {
  let bin = '';
  for (const c of new TextEncoder().encode(text)) bin += String.fromCharCode(c);
  return btoa(bin).replace(/=+$/, '');
}

export function unb64(s: string): string {
  const bin = atob(s.padEnd(s.length + ((4 - (s.length % 4)) % 4), '='));
  return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}
