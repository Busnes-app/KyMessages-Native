/* tslint:disable */
/* eslint-disable */

/**
 * One device's long-term keys (vodozemac `Account`).
 */
export class Account {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Starts a session from a peer's first (pre-key, type 0) message and returns it with the
     * message's plaintext. Consumes the one-time key it used.
     */
    createInboundSession(identity_key: string, ciphertext: string): InboundSession;
    createOutboundSession(identity_key: string, one_time_key: string): Session;
    /**
     * The unpublished fallback key as JSON `{key_id: curve25519}` (empty once published).
     */
    fallbackKey(): string;
    static fromPickle(pickle: string, key: Uint8Array | number[]): Account;
    generateFallbackKey(): void;
    generateOneTimeKeys(count: number): void;
    markKeysAsPublished(): void;
    maxOneTimeKeys(): number;
    constructor();
    /**
     * Unpublished one-time keys as JSON `{key_id: curve25519}`.
     */
    oneTimeKeys(): string;
    pickle(key: Uint8Array | number[]): string;
    sign(message: string): string;
    readonly curve25519: string;
    readonly ed25519: string;
}

/**
 * A decrypted Megolm message and its ratchet index (for replay detection).
 */
export class DecryptedGroup {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly messageIndex: number;
    readonly plaintext: string;
}

/**
 * An encrypted Olm message: `type` 0 is a pre-key message, 1 a normal one.
 */
export class EncryptedOlm {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly ciphertext: string;
    readonly type: number;
}

/**
 * The sending half of a room's Megolm session.
 */
export class GroupSession {
    free(): void;
    [Symbol.dispose](): void;
    encrypt(plaintext: string): string;
    static fromPickle(pickle: string, key: Uint8Array | number[]): GroupSession;
    constructor();
    pickle(key: Uint8Array | number[]): string;
    /**
     * The key that lets a recipient decrypt from the current index on. Send it only over Olm.
     */
    sessionKey(): string;
    readonly messageIndex: number;
    readonly sessionId: string;
}

/**
 * The receiving half of a room's Megolm session.
 */
export class InboundGroupSession {
    free(): void;
    [Symbol.dispose](): void;
    decrypt(ciphertext: string): DecryptedGroup;
    /**
     * Exports the session from its first known index, for the key backup.
     */
    exportAtFirstKnownIndex(): string;
    static fromPickle(pickle: string, key: Uint8Array | number[]): InboundGroupSession;
    /**
     * From an unsigned export (the key backup); trust comes from the backup, not the key.
     */
    static import(exported_key: string): InboundGroupSession;
    /**
     * From a `GroupSession.sessionKey()` received over Olm (it is signed by the sender).
     */
    constructor(session_key: string);
    pickle(key: Uint8Array | number[]): string;
    readonly firstKnownIndex: number;
    readonly sessionId: string;
}

/**
 * The result of `Account.createInboundSession`.
 */
export class InboundSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The new session; can be taken once.
     */
    takeSession(): Session;
    readonly plaintext: string;
}

/**
 * A pairwise Olm session between two devices.
 */
export class Session {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    decrypt(message_type: number, ciphertext: string): string;
    encrypt(plaintext: string): EncryptedOlm;
    static fromPickle(pickle: string, key: Uint8Array | number[]): Session;
    pickle(key: Uint8Array | number[]): string;
    readonly sessionId: string;
}

/**
 * Verifies an Ed25519 signature over message by key.
 */
export function verifyEd25519(key: string, message: string, signature: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_account_free: (a: number, b: number) => void;
    readonly __wbg_decryptedgroup_free: (a: number, b: number) => void;
    readonly __wbg_encryptedolm_free: (a: number, b: number) => void;
    readonly __wbg_groupsession_free: (a: number, b: number) => void;
    readonly __wbg_inboundgroupsession_free: (a: number, b: number) => void;
    readonly __wbg_inboundsession_free: (a: number, b: number) => void;
    readonly __wbg_session_free: (a: number, b: number) => void;
    readonly account_createInboundSession: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly account_createOutboundSession: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly account_curve25519: (a: number) => [number, number];
    readonly account_ed25519: (a: number) => [number, number];
    readonly account_fallbackKey: (a: number) => [number, number];
    readonly account_fromPickle: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly account_generateFallbackKey: (a: number) => void;
    readonly account_generateOneTimeKeys: (a: number, b: number) => void;
    readonly account_markKeysAsPublished: (a: number) => void;
    readonly account_maxOneTimeKeys: (a: number) => number;
    readonly account_new: () => number;
    readonly account_oneTimeKeys: (a: number) => [number, number];
    readonly account_pickle: (a: number, b: number, c: number) => [number, number, number, number];
    readonly account_sign: (a: number, b: number, c: number) => [number, number];
    readonly decryptedgroup_messageIndex: (a: number) => number;
    readonly decryptedgroup_plaintext: (a: number) => [number, number];
    readonly encryptedolm_ciphertext: (a: number) => [number, number];
    readonly encryptedolm_type: (a: number) => number;
    readonly groupsession_encrypt: (a: number, b: number, c: number) => [number, number];
    readonly groupsession_fromPickle: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly groupsession_messageIndex: (a: number) => number;
    readonly groupsession_new: () => number;
    readonly groupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
    readonly groupsession_sessionId: (a: number) => [number, number];
    readonly groupsession_sessionKey: (a: number) => [number, number];
    readonly inboundgroupsession_decrypt: (a: number, b: number, c: number) => [number, number, number];
    readonly inboundgroupsession_exportAtFirstKnownIndex: (a: number) => [number, number];
    readonly inboundgroupsession_firstKnownIndex: (a: number) => number;
    readonly inboundgroupsession_fromPickle: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly inboundgroupsession_import: (a: number, b: number) => [number, number, number];
    readonly inboundgroupsession_new: (a: number, b: number) => [number, number, number];
    readonly inboundgroupsession_pickle: (a: number, b: number, c: number) => [number, number, number, number];
    readonly inboundgroupsession_sessionId: (a: number) => [number, number];
    readonly inboundsession_plaintext: (a: number) => [number, number];
    readonly inboundsession_takeSession: (a: number) => [number, number, number];
    readonly session_decrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly session_encrypt: (a: number, b: number, c: number) => [number, number, number];
    readonly session_fromPickle: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly session_pickle: (a: number, b: number, c: number) => [number, number, number, number];
    readonly session_sessionId: (a: number) => [number, number];
    readonly verifyEd25519: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
