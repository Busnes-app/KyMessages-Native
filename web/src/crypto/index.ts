// The end-to-end encryption core (web/crypto, vodozemac compiled to WebAssembly). Call
// loadCrypto() once before using any export; it is idempotent.
import init, { initSync } from './pkg/kycrypto.js';

export {
  Account,
  Session,
  GroupSession,
  InboundGroupSession,
  verifyEd25519,
} from './pkg/kycrypto.js';

let loading: Promise<unknown> | undefined;

export function loadCrypto(): Promise<unknown> {
  loading ??= init({ module_or_path: new URL('./pkg/kycrypto_bg.wasm', import.meta.url) });
  return loading;
}

// Tests run in Node, where the module is read from disk instead of fetched.
export function loadCryptoSync(bytes: BufferSource): void {
  initSync({ module: bytes });
}
