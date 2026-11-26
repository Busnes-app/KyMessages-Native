// Client-side attachment encryption (E5, docs/superpowers/specs/2026-11-22-e2ee-design.md §5).
//
// A256GCM-STREAM, version 1. Every blob (a file, or its thumbnail) gets its own random 256-bit
// key and 7-byte nonce prefix. The plaintext is cut into chunk_size pieces, at least one (an empty
// file is one empty final chunk), and each is sealed with AES-256-GCM:
//   nonce = nonce_prefix || index (u32 BE) || final (0x00 or 0x01)
//   aad   = "kymessages.attachment.v1" || 0x00 || kind || index (u32 BE) || final
// so chunks cannot be reordered, duplicated, dropped or extended, and a thumbnail never opens as
// a file. The descriptor (key, sizes, SHA-256 of the whole ciphertext, name and type) travels only
// inside the encrypted room message; the server stores opaque ciphertext.

export const ATTACHMENT_ALG = 'A256GCM-STREAM';
export type BlobKind = 'file' | 'thumb';

export const CHUNK_SIZE = 64 << 10;
const MIN_CHUNK = 4 << 10;
const MAX_CHUNK = 4 << 20;
const TAG = 16;
// No server accepts a single upload over 100 MiB (config.MaxAllowedUploadBytes).
const MAX_CIPHERTEXT = 100 << 20;
// Every viewer fetches thumbnails as messages render, so a "thumbnail" may not be large.
export const MAX_THUMB_CIPHERTEXT = 1 << 20;
export const MAX_FILES = 10;
export const THUMB_MIMES: ReadonlySet<string> = new Set(['image/jpeg', 'image/png', 'image/webp']);
/** A thumbnail's longest side. */
export const THUMB_MAX_PX = 400;
const LABEL = new TextEncoder().encode('kymessages.attachment.v1');

/** How to fetch and open one encrypted blob. Sizes are bytes. */
export interface SealedBlob {
  attachment_id: string;
  v: 1;
  alg: typeof ATTACHMENT_ALG;
  /** Unpadded base64 of the 32-byte key. */
  key: string;
  /** Unpadded base64 of the 7-byte nonce prefix. */
  nonce_prefix: string;
  chunk_size: number;
  /** Lowercase hex SHA-256 of the whole ciphertext. */
  sha256: string;
  ciphertext_size: number;
  size: number;
}

export interface ThumbDescriptor extends SealedBlob {
  mime_type: string;
  width: number;
  height: number;
}

export interface FileDescriptor extends SealedBlob {
  name: string;
  mime_type: string;
  width?: number;
  height?: number;
  thumb?: ThumbDescriptor;
}

const chunkCount = (size: number, chunkSize: number) => Math.max(1, Math.ceil(size / chunkSize));

/** The ciphertext length of a plaintext of `size` bytes. */
export const ciphertextSize = (size: number, chunkSize = CHUNK_SIZE) => size + TAG * chunkCount(size, chunkSize);

// The chunk count a ciphertext of this length must hold, or undefined when no encryption of a
// `size`-byte plaintext has that length. Only full chunks precede the last, which is empty only
// when it is the only one.
function layout(ciphertextBytes: number, chunkSize: number, size: number): number | undefined {
  const full = chunkSize + TAG;
  const n = Math.max(1, Math.ceil(ciphertextBytes / full));
  const last = ciphertextBytes - (n - 1) * full;
  if (last < TAG || (n > 1 && last === TAG) || n > 0xffffffff) return undefined;
  return ciphertextBytes - TAG * n === size ? n : undefined;
}

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, '');
}

function unb64(s: string, length: number): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]+$/.test(s)) return undefined;
  let bin: string;
  try {
    bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  } catch {
    return undefined;
  }
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  // Canonical only: one key has one spelling.
  return out.length === length && b64(out) === s ? out : undefined;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

function chunkParams(prefix: Uint8Array, kind: BlobKind, index: number, final: boolean) {
  const flag = final ? 1 : 0;
  const iv = new Uint8Array(12);
  iv.set(prefix);
  new DataView(iv.buffer).setUint32(7, index);
  iv[11] = flag;
  const k = new TextEncoder().encode(kind);
  const additionalData = new Uint8Array(LABEL.length + 1 + k.length + 5);
  additionalData.set(LABEL);
  additionalData.set(k, LABEL.length + 1);
  new DataView(additionalData.buffer).setUint32(LABEL.length + 1 + k.length, index);
  additionalData[additionalData.length - 1] = flag;
  return { name: 'AES-GCM', iv, additionalData, tagLength: 128 } satisfies AesGcmParams;
}

/** Encrypts data under a fresh key and nonce prefix; nothing is ever reused across blobs. */
export async function encryptBlob(
  data: Blob,
  kind: BlobKind,
  chunkSize = CHUNK_SIZE,
): Promise<{ ciphertext: Uint8Array<ArrayBuffer>; sealed: Omit<SealedBlob, 'attachment_id'> }> {
  if (!Number.isInteger(chunkSize) || chunkSize < MIN_CHUNK || chunkSize > MAX_CHUNK) throw new Error('Invalid chunk size');
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const prefix = crypto.getRandomValues(new Uint8Array(7));
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const n = chunkCount(data.size, chunkSize);
  const ciphertext = new Uint8Array(ciphertextSize(data.size, chunkSize));
  for (let i = 0, off = 0; i < n; i++) {
    const plain = new Uint8Array(await data.slice(i * chunkSize, (i + 1) * chunkSize).arrayBuffer());
    const ct = new Uint8Array(await crypto.subtle.encrypt(chunkParams(prefix, kind, i, i === n - 1), key, plain));
    ciphertext.set(ct, off);
    off += ct.length;
  }
  return {
    ciphertext,
    sealed: {
      v: 1,
      alg: ATTACHMENT_ALG,
      key: b64(raw),
      nonce_prefix: b64(prefix),
      chunk_size: chunkSize,
      sha256: await sha256Hex(ciphertext),
      ciphertext_size: ciphertext.length,
      size: data.size,
    },
  };
}

export const DAMAGED = 'This file is damaged or was changed after it was sent.';

/** The descriptor if it is one this format opens as `kind`, within that kind's size limit. */
export function checkBlob(d: SealedBlob, kind: BlobKind): SealedBlob {
  const blob = parseBlob(d, kind === 'thumb' ? MAX_THUMB_CIPHERTEXT : MAX_CIPHERTEXT);
  if (!blob) throw new Error('This file uses an unsupported format.');
  return blob;
}

/**
 * Checks the ciphertext's length and SHA-256 against the descriptor, then opens every chunk.
 * Nothing is returned unless the whole blob is authentic.
 */
export async function decryptBlob(ciphertext: Uint8Array, d: SealedBlob, kind: BlobKind, signal?: AbortSignal): Promise<Uint8Array<ArrayBuffer>[]> {
  const blob = checkBlob(d, kind);
  if (ciphertext.length !== blob.ciphertext_size || (await sha256Hex(ciphertext)) !== blob.sha256) throw new Error(DAMAGED);
  const n = layout(blob.ciphertext_size, blob.chunk_size, blob.size)!;
  const key = await crypto.subtle.importKey('raw', unb64(blob.key, 32)!, 'AES-GCM', false, ['decrypt']);
  const prefix = unb64(blob.nonce_prefix, 7)!;
  const parts: Uint8Array<ArrayBuffer>[] = [];
  const full = blob.chunk_size + TAG;
  for (let i = 0; i < n; i++) {
    signal?.throwIfAborted();
    const chunk = ciphertext.subarray(i * full, Math.min((i + 1) * full, ciphertext.length));
    try {
      parts.push(new Uint8Array(await crypto.subtle.decrypt(chunkParams(prefix, kind, i, i === n - 1), key, chunk)));
    } catch {
      throw new Error(DAMAGED);
    }
  }
  return parts;
}

// --- Descriptors, as they arrive inside a decrypted room message ---

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * A file name safe to show and save: no control, format (bidirectional override), line or path
 * separator characters, never "." or "..", at most 255 code points.
 */
export function cleanName(name: string): string {
  const s = Array.from(name.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}/\\]/gu, '_').trim()).slice(0, 255).join('');
  return s === '' || s === '.' || s === '..' ? 'file' : s;
}

function parseBlob(v: unknown, maxCiphertext: number): SealedBlob | undefined {
  if (!isObj(v) || v.v !== 1 || v.alg !== ATTACHMENT_ALG) return undefined;
  const { attachment_id: id, key, nonce_prefix: prefix, chunk_size: chunk, sha256, ciphertext_size: ct, size } = v;
  if (typeof id !== 'string' || !ID_RE.test(id)) return undefined;
  if (typeof key !== 'string' || !unb64(key, 32) || typeof prefix !== 'string' || !unb64(prefix, 7)) return undefined;
  if (!isInt(chunk, MIN_CHUNK, MAX_CHUNK) || typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) return undefined;
  if (!isInt(ct, TAG, maxCiphertext) || !isInt(size, 0, maxCiphertext) || !layout(ct, chunk, size)) return undefined;
  return { attachment_id: id, v: 1, alg: ATTACHMENT_ALG, key, nonce_prefix: prefix, chunk_size: chunk, sha256, ciphertext_size: ct, size };
}

const mime = (v: unknown) => (typeof v === 'string' && MIME_RE.test(v.toLowerCase()) ? v.toLowerCase() : undefined);

/** A file's type as a descriptor may carry it. */
export const cleanMime = (type: string) => mime(type) ?? 'application/octet-stream';

function parseThumb(v: unknown): ThumbDescriptor | undefined {
  const blob = parseBlob(v, MAX_THUMB_CIPHERTEXT);
  if (!blob || !isObj(v)) return undefined;
  const type = mime(v.mime_type);
  if (!type || !THUMB_MIMES.has(type) || !isInt(v.width, 1, THUMB_MAX_PX) || !isInt(v.height, 1, THUMB_MAX_PX)) return undefined;
  return { ...blob, mime_type: type, width: v.width, height: v.height };
}

export function parseFileDescriptor(v: unknown): FileDescriptor | undefined {
  const blob = parseBlob(v, MAX_CIPHERTEXT);
  if (!blob || !isObj(v) || typeof v.name !== 'string' || v.name.length > 1024) return undefined;
  const type = mime(v.mime_type);
  if (!type) return undefined;
  if (v.width !== undefined && !isInt(v.width, 1, 65535)) return undefined;
  if (v.height !== undefined && !isInt(v.height, 1, 65535)) return undefined;
  const thumb = v.thumb === undefined ? undefined : parseThumb(v.thumb);
  if (v.thumb !== undefined && !thumb) return undefined;
  return {
    ...blob,
    name: cleanName(v.name),
    mime_type: type,
    ...(typeof v.width === 'number' ? { width: v.width } : {}),
    ...(typeof v.height === 'number' ? { height: v.height } : {}),
    ...(thumb ? { thumb } : {}),
  };
}

/** A file a message names; `missing` when the server did not attach its blob to the message. */
export type SealedFile = FileDescriptor & { missing?: true };

/**
 * The descriptors of a decrypted message's `files`, or undefined when they are malformed (the
 * message is then damaged). A file whose blob the server did not attach to this message is kept as
 * `missing`, never dropped, so a sender cannot point viewers at another message's upload and the
 * server cannot hide a file. A thumbnail the server did not attach is dropped (the file stays).
 */
export function openFiles(raw: unknown, attached: readonly { id: string }[]): SealedFile[] | undefined {
  if (!Array.isArray(raw) || raw.length > MAX_FILES) return undefined;
  const files: FileDescriptor[] = [];
  const ids = new Set<string>();
  for (const v of raw) {
    const f = parseFileDescriptor(v);
    if (!f) return undefined;
    for (const id of [f.attachment_id, f.thumb?.attachment_id]) {
      if (!id) continue;
      if (ids.has(id)) return undefined;
      ids.add(id);
    }
    files.push(f);
  }
  const have = new Set(attached.map((a) => a.id));
  return files.map((f) => {
    if (!have.has(f.attachment_id)) return { ...f, missing: true };
    const { thumb, ...rest } = f;
    return thumb && !have.has(thumb.attachment_id) ? rest : f;
  });
}

/**
 * What an edit says the message it edits holds: E5 files (the sender's message ID and how many),
 * or a message from before E5 and the plaintext uploads it had when first edited (`rows`, carried
 * unchanged by later edits). Read only from an envelope bound to the message (the message itself,
 * or its latest edit), never from the server's kept original.
 */
export type Provenance = { kind: 'e5'; ref: string; files: number } | { kind: 'legacy'; rows: string[] };
const REF_RE = /^[A-Za-z0-9_-]{8,128}$/;

// Undefined: malformed. `rows` absent: a legacy edit sealed before rows were named.
function parseProvenance(v: unknown): Provenance | { kind: 'legacy'; rows?: undefined } | undefined {
  if (!isObj(v)) return undefined;
  if (v.kind === 'legacy') {
    if (v.rows === undefined) return { kind: 'legacy' };
    const rows = v.rows;
    return Array.isArray(rows) && rows.length <= MAX_FILES && rows.every((r): r is string => typeof r === 'string' && ID_RE.test(r))
      ? { kind: 'legacy', rows }
      : undefined;
  }
  if (v.kind !== 'e5' || typeof v.ref !== 'string' || !REF_RE.test(v.ref) || !isInt(v.files, 0, MAX_FILES)) return undefined;
  return { kind: 'e5', ref: v.ref, files: v.files };
}

/** What a message's files are once opened. Only `plainIds` (or neither field) means plaintext uploads. */
export interface MessageFiles {
  files?: SealedFile[];
  /** Files exist but cannot be read here. `session`: the key that, when it arrives, may open them. */
  filesState?: { reason: string; gen?: number; session?: string; expected?: number };
  /**
   * The plaintext uploads (from before E5) an edit vouches for. Absent on an unedited message from
   * before E5, whose rows the server alone lists.
   */
  plainIds?: string[];
  /** What an edit of this message must carry; absent when it cannot be edited safely. */
  provenance?: Provenance;
  /** The sender's ID for the message (its idempotency key). */
  ref?: string;
}

/** An envelope opened as far as files care (crypto/engine.ts `Opened`). */
export type OpenedEnvelope =
  | { state: 'decrypted'; inner: Inner }
  | { state: 'waiting'; sessionId?: string }
  | { state: 'failed'; reason: string };
type Inner = { type: string; files?: unknown[]; ref?: string; original?: unknown };

export const FILES_WAITING = "Waiting for the key to this message's files.";
const FILES_GONE = "This message's files are not available.";
export const FILES_REPLACED = "This message's files were replaced or damaged, so they are not shown.";
const FILES_UNVERIFIED = "This message was edited by an older version, so its files cannot be verified.";

/**
 * Whether reading this message's files needs the server's kept original: only an E5 edit that
 * says there are files. A legacy or file-less edit never opens one, so an unrelated envelope the
 * server offers is never decrypted, nor its ratchet index claimed for this message.
 */
export function needsOriginal(inner: Inner): boolean {
  if (inner.type !== 'edit') return false;
  const prov = parseProvenance(inner.original);
  return prov?.kind === 'e5' && prov.files > 0;
}

/**
 * What the kept original of an edited message must be: the sender's first envelope of this very
 * message (same ID, same number of files). Checked before the original's ratchet index is claimed,
 * so a substitute never takes another message's place.
 */
export function expectOriginal(edit: Inner): (inner: Inner) => string | undefined {
  const prov = parseProvenance(edit.original);
  return (inner) =>
    prov?.kind === 'e5' && inner.type !== 'edit' && inner.ref === prov.ref && Array.isArray(inner.files) && inner.files.length === prov.files
      ? undefined
      : FILES_REPLACED;
}

/**
 * A message's files, or undefined when the message is damaged. A message sent since E5 carries
 * its files and its sender's ID (`ref`); an edit carries only text and `original`, never file keys.
 * An E5 edit's files come only from the server's kept first envelope, which must match. A legacy
 * edit names the plaintext uploads it vouches for. Anything missing, withheld, substituted or not
 * established reads as unavailable, never as fewer files.
 */
export function messageFiles(
  inner: Inner,
  original: OpenedEnvelope | undefined,
  attached: readonly { id: string }[],
  gen: number,
): MessageFiles | undefined {
  if (inner.type !== 'edit') {
    // From before E5: its rows are the server's word alone (docs §5). Only an envelope that says it
    // carried attachments lets a first edit name those rows; a text message's edit names none.
    if (inner.files === undefined) {
      const rows = inner.type === 'attachment' ? attached.map((a) => a.id).slice(0, MAX_FILES) : [];
      return { provenance: { kind: 'legacy', rows } };
    }
    if (typeof inner.ref !== 'string' || !REF_RE.test(inner.ref)) return undefined;
    const files = openFiles(inner.files, attached);
    return files && { files, ref: inner.ref, provenance: { kind: 'e5', ref: inner.ref, files: files.length } };
  }
  if (inner.original === undefined) {
    // Sealed before this format (a pre-E5 or older tab's edit): nothing vouches for its uploads.
    return attached.length > 0 ? { filesState: { reason: FILES_UNVERIFIED } } : { files: [] };
  }
  const prov = parseProvenance(inner.original);
  if (!prov) return undefined;
  if (prov.kind === 'legacy') {
    if (!prov.rows) return attached.length > 0 ? { filesState: { reason: FILES_UNVERIFIED } } : { files: [] };
    return { provenance: { kind: 'legacy', rows: prov.rows }, plainIds: prov.rows };
  }
  const base = { provenance: prov, ref: prov.ref };
  if (prov.files === 0) return { ...base, files: [] };
  const expected = prov.files;
  if (!original) return { ...base, filesState: { reason: FILES_GONE, expected } };
  if (original.state === 'waiting') return { ...base, filesState: { reason: FILES_WAITING, gen, session: original.sessionId, expected } };
  if (original.state === 'failed') return { ...base, filesState: { reason: original.reason, expected } };
  const files = expectOriginal(inner)(original.inner) ? undefined : openFiles(original.inner.files, attached);
  return files ? { ...base, files } : { ...base, filesState: { reason: FILES_REPLACED, expected } };
}

/** Every server attachment ID a descriptor list names (files and their thumbnails). */
export const sealedIds = (files: readonly FileDescriptor[]) =>
  files.flatMap((f) => (f.thumb ? [f.attachment_id, f.thumb.attachment_id] : [f.attachment_id]));

// --- Raster headers, read before any image is decoded (a small file can claim a huge canvas) ---

/** Image types shown inline (thumbnails, previews); GIF and anything else are only ever saved. */
export const PREVIEW_MIMES = THUMB_MIMES;

const SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

/**
 * The pixel size a still PNG, JPEG or WebP header declares, only when its signature is the type
 * `mime` names. Undefined for anything else: another or no signature, an animation (APNG `acTL`,
 * animated WebP), a header cut short or not found in `b`.
 */
export function rasterSize(b: Uint8Array, mime: string): { width: number; height: number } | undefined {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const is = (off: number, ...bytes: number[]) => off + bytes.length <= b.length && bytes.every((x, i) => b[off + i] === x);
  const ascii = (off: number, s: string) => is(off, ...Array.from(s, (c) => c.charCodeAt(0)));
  const size = (width: number, height: number) => (width > 0 && height > 0 ? { width, height } : undefined);
  const u24 = (off: number) => b[off] | (b[off + 1] << 8) | (b[off + 2] << 16);
  if (mime === 'image/png') {
    if (!is(0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) || !ascii(12, 'IHDR') || b.length < 24) return undefined;
    const declared = size(dv.getUint32(16), dv.getUint32(20));
    // An APNG announces itself (acTL) before its first image data (IDAT).
    for (let off = 8; off + 8 <= b.length; off += 12 + dv.getUint32(off)) {
      if (ascii(off + 4, 'acTL')) return undefined;
      if (ascii(off + 4, 'IDAT')) return declared;
    }
    return undefined;
  }
  if (mime === 'image/webp') {
    if (!ascii(0, 'RIFF') || !ascii(8, 'WEBP') || b.length < 30) return undefined;
    if (ascii(12, 'VP8 ') && is(23, 0x9d, 0x01, 0x2a)) return size(dv.getUint16(26, true) & 0x3fff, dv.getUint16(28, true) & 0x3fff);
    if (ascii(12, 'VP8L') && b[20] === 0x2f) {
      const bits = dv.getUint32(21, true);
      return size((bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1);
    }
    if (ascii(12, 'VP8X') && !(b[20] & 0x02)) return size(u24(24) + 1, u24(27) + 1);
    return undefined;
  }
  if (mime === 'image/jpeg' && is(0, 0xff, 0xd8, 0xff)) {
    for (let off = 2; off + 9 <= b.length; ) {
      if (b[off] !== 0xff) return undefined;
      const marker = b[off + 1];
      if (marker === 0xff) {
        off++;
      } else if (SOF.has(marker)) {
        return size(dv.getUint16(off + 7), dv.getUint16(off + 5));
      } else if (marker === 0xd9 || marker === 0xda) {
        return undefined;
      } else if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
        off += 2;
      } else {
        const len = dv.getUint16(off + 2);
        if (len < 2) return undefined;
        off += 2 + len;
      }
    }
  }
  return undefined;
}
