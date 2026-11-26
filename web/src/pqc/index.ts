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
  argv: string[];
  run(instance: WebAssembly.Instance): Promise<void>;
}

type PQCCall = (name: string, ...args: string[]) => { ok?: unknown; error?: string };

declare global {
  // Defined by wasm_exec.js; the Go program calls kyPQCReady with the generation it was started
  // with (its argv[1]) and its call function.
  var Go: new () => GoRuntime;
  var kyPQCReady: ((gen: string, call: PQCCall) => void) | undefined;
}

/**
 * The module is not running (not loaded yet, crashed, or exited): a failure of availability,
 * never a verdict on data. Callers keep their work for a retry; the module reloads meanwhile.
 */
export class PQCUnavailable extends Error {
  constructor() {
    super('The post-quantum module is not running');
  }
}

let loading: Promise<void> | undefined;
let live: PQCCall | undefined;
let generation = 0;
let reload: (() => Promise<void>) | undefined;

/** How long a start may take, from fetching the module to the Go program handing over its call. */
export const PQC_START_MS = 10_000;

type Source = (this: GoRuntime) => Promise<WebAssembly.WebAssemblyInstantiatedSource>;

// Starts the Go program and resolves once it handed over its call, all within startMs (fetch,
// compile and start). Each start has a generation, which the Go program is started with and
// hands back with its call: only the current one may install its call, and only its exit
// withdraws it, so a start given up on cannot replace a newer one when it finishes late, even
// though both reach the one global kyPQCReady.
async function start(source: Source, runtime: () => GoRuntime, startMs: number): Promise<void> {
  if (live) return;
  const gen = ++generation;
  const go = runtime();
  go.argv = ['js', String(gen)];
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('The post-quantum module did not start')), startMs);
  });
  const ready = new Promise<void>((resolve) => {
    globalThis.kyPQCReady = (from, call) => {
      if (from !== String(gen) || gen !== generation) return;
      live = call;
      resolve();
    };
  });
  try {
    const { instance } = await Promise.race([source.call(go), timeout]);
    const exited = go.run(instance).then(
      () => { throw new Error('The post-quantum module exited'); },
      (e: unknown) => { throw e instanceof Error ? e : new Error('The post-quantum module crashed'); },
    );
    void exited.catch(() => {
      if (gen !== generation) return;
      live = undefined;
      loading = undefined;
    });
    await Promise.race([ready, exited, timeout]);
  } catch (e) {
    if (gen === generation) {
      generation++; // a late hand-over from this start is ignored
      live = undefined;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function load(source: Source, runtime: () => GoRuntime = () => new globalThis.Go(), startMs = PQC_START_MS): Promise<void> {
  reload = () => load(source, runtime, startMs);
  loading ??= start(source, runtime, startMs).catch((e: unknown) => {
    loading = undefined;
    throw e;
  });
  return loading;
}

// A failed load (offline start, a swapped asset, a crashed module) is retried by the next call.
export function loadPQC(): Promise<void> {
  return load(function (this: GoRuntime) {
    return WebAssembly.instantiateStreaming(fetch(new URL('./pqc.wasm', import.meta.url)), this.importObject);
  });
}

// Tests run in Node, where the module is read from disk; a pending bytes, runtime and startMs let
// them fake a stalled fetch or a failing Go.
export function loadPQCFrom(bytes: BufferSource | Promise<BufferSource>, runtime?: () => GoRuntime, startMs?: number): Promise<void> {
  return load(async function (this: GoRuntime) {
    return WebAssembly.instantiate(await bytes, this.importObject);
  }, runtime, startMs);
}

/** Resolves once the module runs, loading it again if it stopped. */
export function ensurePQC(): Promise<void> {
  return live ? Promise.resolve() : reload ? reload() : Promise.reject(new PQCUnavailable());
}

/** Whether the module is running now. */
export const pqcRunning = () => live !== undefined;

/** Calls internal/e2eeid.Call by name; throws its error. */
// A missing or dead module throws PQCUnavailable and starts a reload; an {error} answer is the
// call's verdict on its arguments and throws a plain Error.
export function pqcCall<T = unknown>(name: string, ...args: string[]): T {
  const call = live;
  if (!call) {
    void ensurePQC().catch(() => undefined);
    throw new PQCUnavailable();
  }
  let r: ReturnType<PQCCall>;
  try {
    r = call(name, ...args);
  } catch {
    // The Go program is gone (wasm_exec throws once it exited): reload, and retry later.
    if (live === call) {
      live = undefined;
      loading = undefined;
    }
    void ensurePQC().catch(() => undefined);
    throw new PQCUnavailable();
  }
  if (r.error !== undefined) throw new Error(r.error);
  return r.ok as T;
}

export const HYBRID_ALG = 'mldsa65+ed25519';

/**
 * A hybridsig public key or signature on the wire: unpadded base64 of its tagged encoding
 * ("mldsa65+ed25519" 0x00 ‖ ML-DSA-65 half ‖ Ed25519 half), as ky-primitives hybridsig writes it.
 */
export type Hybrid = string;

/** What a key backup entry's seal binds: its room, sender key, session and first index. */
export interface BackupRef {
  room_id: string;
  sender_key: string;
  session_id: string;
  first_index: number;
}

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
  backupSeal: (backupKey: string, masterSeed: string, e: BackupRef, plaintext: string) =>
    pqcCall<string>('backupSeal', backupKey, masterSeed, e.room_id, e.sender_key, e.session_id, String(e.first_index), plaintext),
  backupOpen: (backupSeed: string, masterSeed: string, e: BackupRef, sealed: string) =>
    pqcCall<string>('backupOpen', backupSeed, masterSeed, e.room_id, e.sender_key, e.session_id, String(e.first_index), sealed),
  signDeviceList: (seed: string, tenant: string, user: string, version: number, epoch: number, deviceIds: string[]) =>
    pqcCall<Hybrid>('signDeviceList', seed, tenant, user, String(version), String(epoch), JSON.stringify(deviceIds)),
  verifyDeviceList: (k: Hybrid, tenant: string, user: string, version: number, epoch: number, deviceIds: string[], s: Hybrid) =>
    pqcCall<boolean>('verifyDeviceList', k, tenant, user, String(version), String(epoch), JSON.stringify(deviceIds), s),
  signPinsWrite: (seed: string, tenant: string, user: string, version: number, counter: number, sealed: string) =>
    pqcCall<Hybrid>('signPinsWrite', seed, tenant, user, String(version), String(counter), sealed),
  signBackupWrite: (seed: string, tenant: string, user: string, version: number, generation: number, entries: (BackupRef & { sealed: string })[]) =>
    pqcCall<Hybrid>('signBackupWrite', seed, tenant, user, String(version), String(generation), JSON.stringify(entries.map((e) => ({
      room_id: e.room_id, sender_key: e.sender_key, session_id: e.session_id, first_index: e.first_index, sealed: e.sealed,
    })))),
  verifyPinsWrite: (k: Hybrid, tenant: string, user: string, version: number, counter: number, sealed: string, sig: Hybrid) =>
    pqcCall<boolean>('verifyPinsWrite', k, tenant, user, String(version), String(counter), sealed, sig),
  verifyBackupWrite: (k: Hybrid, tenant: string, user: string, version: number, generation: number, entries: (BackupRef & { sealed: string })[], sig: Hybrid) =>
    pqcCall<boolean>('verifyBackupWrite', k, tenant, user, String(version), String(generation), JSON.stringify(entries.map((e) => ({
      room_id: e.room_id, sender_key: e.sender_key, session_id: e.session_id, first_index: e.first_index, sealed: e.sealed,
    }))), sig),
  /** Hex SHA-256 of the length-prefixed fields: a compact cache key. */
  hash: (...fields: string[]) => pqcCall<string>('hash', ...fields),
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
  /** The six digits both screens show; bound to the joining device and its ephemeral key. */
  comparisonCode: (secret: string, pairingId: string, newDevice: string, ephemeralKey: string) =>
    pqcCall<string>('comparisonCode', secret, pairingId, newDevice, ephemeralKey),
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
