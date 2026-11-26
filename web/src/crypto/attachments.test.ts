import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ATTACHMENT_ALG,
  CHUNK_SIZE,
  MAX_THUMB_CIPHERTEXT,
  ciphertextSize,
  cleanName,
  decryptBlob,
  encryptBlob,
  FILES_WAITING,
  messageFiles,
  openFiles,
  parseFileDescriptor,
  type BlobKind,
  type SealedBlob,
} from './attachments';

const MIN = 4096;
const TAG = 16;

function bytes(n: number, seed = 1): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}

async function seal(data: Uint8Array, kind: BlobKind = 'file', chunk = MIN) {
  const { ciphertext, sealed } = await encryptBlob(new Blob([data]), kind, chunk);
  return { ciphertext, blob: { ...sealed, attachment_id: 'att_1' } as SealedBlob };
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

const join = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

// A ciphertext changed by `edit`, with its descriptor's hash and length updated to match, so
// only the per-chunk authentication can catch it.
async function forged(ct: Uint8Array, blob: SealedBlob, edit: (ct: Uint8Array) => Uint8Array, size = blob.size) {
  const out = edit(ct);
  return { ct: out, blob: { ...blob, ciphertext_size: out.length, sha256: await sha256Hex(out), size } };
}

// Pinned v1 vectors, computed outside this code (Python `cryptography` AESGCM) from the format's
// definition: key 00..1f, nonce prefix a0..a6, 4 KiB chunks. A change here is a format break.
describe('A256GCM-STREAM v1 vectors', () => {
  const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);
  const PREFIX = Uint8Array.from({ length: 7 }, (_, i) => 0xa0 + i);
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
  const vectors: [string, Uint8Array, BlobKind, string][] = [
    ['one final chunk', new TextEncoder().encode('kymessages E5\n'), 'file', '1c18247bcb7581a76616f86afa84b6456f84e4858733d855d93953ef10cf'],
    ['the same bytes as a thumbnail', new TextEncoder().encode('kymessages E5\n'), 'thumb', '1c18247bcb7581a76616f86afa84566008d177da68c400447c958cdd589e'],
    ['an empty file', new Uint8Array(0), 'file', 'fe8f4d8f2a70be445ccf44c61529c1a7'],
  ];

  function fixedRandom() {
    const spy = vi.spyOn(crypto, 'getRandomValues');
    spy.mockImplementationOnce(<T extends ArrayBufferView | null>(a: T) => ((a as unknown as Uint8Array).set(KEY), a));
    spy.mockImplementationOnce(<T extends ArrayBufferView | null>(a: T) => ((a as unknown as Uint8Array).set(PREFIX), a));
  }
  afterEach(() => vi.restoreAllMocks());

  it.each(vectors)('seals and opens %s exactly as pinned', async (_name, plain, kind, want) => {
    fixedRandom();
    const { ciphertext, sealed } = await encryptBlob(new Blob([plain]), kind, 4096);
    expect(hex(ciphertext)).toBe(want);
    expect(sealed).toMatchObject({ key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', nonce_prefix: 'oKGio6Slpg', chunk_size: 4096 });
    const opened = await decryptBlob(fromHex(want), { ...sealed, attachment_id: 'att_v' }, kind);
    expect(Array.from(join(opened))).toEqual(Array.from(plain));
  });

  it('seals two chunks, the last one final, as pinned', async () => {
    fixedRandom();
    const { ciphertext, sealed } = await encryptBlob(new Blob([new Uint8Array(4097).fill(0x61)]), 'file', 4096);
    expect(ciphertext.length).toBe(4129);
    expect(sealed.sha256).toBe('222d3b03c6732738bb7e1389041ff20fa82dbb3e3fa702c9d5cf801c0b6ead52');
    expect(hex(ciphertext.subarray(-17))).toBe('88e30951e758972e0158b775caafcf1920');
  });
});

describe('A256GCM-STREAM', () => {
  it.each([
    ['empty', 0],
    ['small', 10],
    ['one byte short of a chunk', MIN - 1],
    ['exactly one chunk', MIN],
    ['one byte past a chunk', MIN + 1],
    ['exactly three chunks', MIN * 3],
    ['several chunks', MIN * 3 + 123],
  ])('round-trips a %s file', async (_name, n) => {
    const data = bytes(n);
    const { ciphertext, blob } = await seal(data);
    const chunks = Math.max(1, Math.ceil(n / MIN));
    expect(ciphertext.length).toBe(n + TAG * chunks);
    expect(blob.ciphertext_size).toBe(ciphertext.length);
    expect(ciphertextSize(n, MIN)).toBe(ciphertext.length);
    expect(blob).toMatchObject({ v: 1, alg: ATTACHMENT_ALG, chunk_size: MIN, size: n, sha256: await sha256Hex(ciphertext) });
    const parts = await decryptBlob(ciphertext, blob, 'file');
    expect(parts.length).toBe(chunks);
    expect(join(parts)).toEqual(data);
  });

  it('uses the default 64 KiB chunks', async () => {
    const { sealed, ciphertext } = await encryptBlob(new Blob([bytes(CHUNK_SIZE + 1)]), 'file');
    expect(sealed.chunk_size).toBe(65536);
    expect(ciphertext.length).toBe(CHUNK_SIZE + 1 + 2 * TAG);
  });

  it('never reuses a key or nonce prefix, even for the same bytes', async () => {
    const data = bytes(100);
    const seen = await Promise.all(Array.from({ length: 8 }, () => seal(data)));
    expect(new Set(seen.map((s) => s.blob.key)).size).toBe(8);
    expect(new Set(seen.map((s) => s.blob.nonce_prefix)).size).toBe(8);
    expect(seen[0].blob.key).toMatch(/^[A-Za-z0-9+/]{43}$/);
    expect(seen[0].blob.nonce_prefix).toMatch(/^[A-Za-z0-9+/]{10}$/);
  });

  it('refuses a flipped bit anywhere, even with a matching hash', async () => {
    const { ciphertext, blob } = await seal(bytes(MIN * 2 + 5));
    for (const at of [0, MIN + TAG + 3, ciphertext.length - 1]) {
      const f = await forged(ciphertext, blob, (ct) => {
        const c = ct.slice();
        c[at] ^= 1;
        return c;
      });
      await expect(decryptBlob(f.ct, f.blob, 'file')).rejects.toThrow(/damaged/);
    }
  });

  it('refuses a ciphertext that does not match the descriptor hash or length', async () => {
    const { ciphertext, blob } = await seal(bytes(50));
    const flipped = ciphertext.slice();
    flipped[3] ^= 1;
    await expect(decryptBlob(flipped, blob, 'file')).rejects.toThrow(/damaged/);
    await expect(decryptBlob(ciphertext, { ...blob, sha256: '0'.repeat(64) }, 'file')).rejects.toThrow(/damaged/);
    await expect(decryptBlob(ciphertext.subarray(0, ciphertext.length - 1), blob, 'file')).rejects.toThrow(/damaged/);
  });

  it('refuses reordered, duplicated, truncated and extended chunks', async () => {
    const { ciphertext, blob } = await seal(bytes(MIN * 3));
    const full = MIN + TAG;
    const c = (i: number) => ciphertext.subarray(i * full, (i + 1) * full);
    const cases: [string, Uint8Array[], number][] = [
      ['reordered', [c(1), c(0), c(2)], MIN * 3],
      ['duplicated', [c(0), c(0), c(2)], MIN * 3],
      ['truncated to a non-final chunk', [c(0), c(1)], MIN * 2],
      ['final chunk dropped from the middle', [c(0), c(2)], MIN * 2],
      ['extended past the final chunk', [c(0), c(1), c(2), c(2)], MIN * 4],
    ];
    for (const [name, parts, size] of cases) {
      const f = await forged(ciphertext, blob, () => join(parts), size);
      await expect(decryptBlob(f.ct, f.blob, 'file'), name).rejects.toThrow(/damaged/);
    }
  });

  it('never opens a thumbnail as a file, or a file as a thumbnail', async () => {
    const thumb = await seal(bytes(200), 'thumb');
    await expect(decryptBlob(thumb.ciphertext, thumb.blob, 'file')).rejects.toThrow(/damaged/);
    const file = await seal(bytes(200), 'file');
    await expect(decryptBlob(file.ciphertext, file.blob, 'thumb')).rejects.toThrow(/damaged/);
    expect(join(await decryptBlob(thumb.ciphertext, thumb.blob, 'thumb'))).toEqual(bytes(200));
  });

  it('refuses the wrong key or nonce prefix', async () => {
    const a = await seal(bytes(64));
    const b = await seal(bytes(64));
    await expect(decryptBlob(a.ciphertext, { ...a.blob, key: b.blob.key }, 'file')).rejects.toThrow(/damaged/);
    await expect(decryptBlob(a.ciphertext, { ...a.blob, nonce_prefix: b.blob.nonce_prefix }, 'file')).rejects.toThrow(/damaged/);
  });

  it('refuses chunk sizes outside 4 KiB to 4 MiB and sizes that do not fit the layout', async () => {
    const { ciphertext, blob } = await seal(bytes(10));
    for (const chunk_size of [0, 1, 4095, (4 << 20) + 1, 2 ** 40, 4096.5, -4096]) {
      await expect(decryptBlob(ciphertext, { ...blob, chunk_size }, 'file')).rejects.toThrow(/unsupported/);
    }
    await expect(decryptBlob(ciphertext, { ...blob, size: 11 }, 'file')).rejects.toThrow(/unsupported/);
    await expect(decryptBlob(ciphertext, { ...blob, ciphertext_size: 2 ** 40 }, 'file')).rejects.toThrow(/unsupported/);
    await expect(encryptBlob(new Blob([]), 'file', 1)).rejects.toThrow(/chunk size/);
  });

  it('refuses another version or algorithm', async () => {
    const { ciphertext, blob } = await seal(bytes(10));
    await expect(decryptBlob(ciphertext, { ...blob, v: 2 as 1 }, 'file')).rejects.toThrow(/unsupported/);
    await expect(decryptBlob(ciphertext, { ...blob, alg: 'A256GCM' as typeof ATTACHMENT_ALG }, 'file')).rejects.toThrow(/unsupported/);
  });

  it('refuses an oversized thumbnail', async () => {
    const { ciphertext, blob } = await seal(bytes(MAX_THUMB_CIPHERTEXT), 'thumb', 1 << 20);
    await expect(decryptBlob(ciphertext, blob, 'thumb')).rejects.toThrow(/unsupported/);
  });
});

describe('descriptors', () => {
  const blob = (id: string): SealedBlob => ({
    attachment_id: id,
    v: 1,
    alg: ATTACHMENT_ALG,
    key: 'A'.repeat(43),
    nonce_prefix: 'A'.repeat(10),
    chunk_size: CHUNK_SIZE,
    sha256: 'a'.repeat(64),
    ciphertext_size: 26,
    size: 10,
  });
  const file = (id = 'att_f', extra: object = {}) => ({ ...blob(id), name: 'plan.pdf', mime_type: 'application/pdf', ...extra });
  const thumb = (id = 'att_t') => ({ ...blob(id), mime_type: 'image/jpeg', width: 40, height: 30 });

  it('keeps known fields and drops the rest', () => {
    expect(parseFileDescriptor({ ...file(), extra: 'x' })).toEqual(file());
  });

  it('refuses malformed keys, hashes and types', () => {
    for (const bad of [
      { key: 'A'.repeat(42) },
      { key: 'A'.repeat(43) + '=' },
      { key: 'A'.repeat(42) + 'B' }, // non-canonical trailing bits
      { nonce_prefix: 'A'.repeat(11) },
      { sha256: 'A'.repeat(64) },
      { attachment_id: '../att' },
      { mime_type: 'not a type' },
      { name: 7 },
      { width: 0 },
      { thumb: { ...thumb(), mime_type: 'image/svg+xml' } },
      { thumb: { ...thumb(), width: undefined } },
    ]) {
      expect(parseFileDescriptor({ ...file(), ...bad }), JSON.stringify(bad)).toBeUndefined();
    }
  });

  it('cleans control and bidirectional-override characters from names', () => {
    expect(cleanName('invoice‮fdp.exe')).toBe('invoice_fdp.exe');
    expect(cleanName('a\nb\u0000')).toBe('a_b_');
    expect(cleanName('   ')).toBe('file');
    expect(cleanName('..')).toBe('file');
    expect(cleanName('.')).toBe('file');
    expect(cleanName('../etc/passwd')).toBe('.._etc_passwd');
    expect(cleanName('a\\b\u2028c\u200bd')).toBe('a_b_c_d');
    // Cut by code point, never through a surrogate pair.
    const cut = cleanName('\u{1F600}'.repeat(300));
    expect(Array.from(cut)).toHaveLength(255);
    expect(cut.endsWith('\u{1F600}')).toBe(true);
  });

  it('marks files the server did not attach as missing instead of dropping them', () => {
    const files = [file('att_a', { thumb: thumb('att_at') }), file('att_b', { thumb: thumb('att_bt') }), file('att_c')];
    const out = openFiles(files, [{ id: 'att_a' }, { id: 'att_at' }, { id: 'att_b' }])!;
    expect(out.map((f) => [f.attachment_id, f.missing ?? false])).toEqual([['att_a', false], ['att_b', false], ['att_c', true]]);
    expect(out[0].thumb?.attachment_id).toBe('att_at');
    expect(out[1].thumb).toBeUndefined();
  });

  it('treats malformed or reused descriptors as a damaged message', () => {
    expect(openFiles([], [])).toEqual([]);
    expect(openFiles(undefined, [])).toBeUndefined();
    expect(openFiles('x', [])).toBeUndefined();
    expect(openFiles([file(), { bogus: true }], [])).toBeUndefined();
    expect(openFiles([file('att_a'), file('att_a')], [])).toBeUndefined();
    expect(openFiles([file('att_a', { thumb: thumb('att_a') })], [])).toBeUndefined();
    expect(openFiles(Array.from({ length: 11 }, (_, i) => file(`att_${i}`)), [])).toBeUndefined();
  });

  it('caps thumbnails at 400 px', () => {
    expect(parseFileDescriptor({ ...file(), thumb: { ...thumb(), width: 400, height: 400 } })?.thumb).toBeDefined();
    expect(parseFileDescriptor({ ...file(), thumb: { ...thumb(), width: 401 } })).toBeUndefined();
    expect(parseFileDescriptor({ ...file(), thumb: { ...thumb(), height: 30000 } })).toBeUndefined();
  });

  describe('a message\'s files', () => {
  const at = (...ids: string[]) => ids.map((id) => ({ id }));
  const sent = (files?: unknown[]) => ({ state: 'decrypted' as const, inner: { type: 'attachment', ...(files ? { files } : {}) } });

  it('comes from the message itself, and is absent only for a message from before E5', () => {
    expect(messageFiles({ type: 'attachment', files: [file('att_a')] }, undefined, at('att_a'), 0)?.files?.[0].attachment_id).toBe('att_a');
    expect(messageFiles({ type: 'text', files: [] }, undefined, at(), 0)).toEqual({ files: [] });
    expect(messageFiles({ type: 'text' }, undefined, at('att_old'), 0)).toEqual({});
    expect(messageFiles({ type: 'text', files: [{ bogus: 1 }] }, undefined, at(), 0)).toBeUndefined();
  });

  it('comes from the original envelope once edited, never from the edit', () => {
    const edit = { type: 'edit', files: [file('att_planted')] };
    expect(messageFiles(edit, sent([file('att_a')]), at('att_a'), 0)?.files?.map((f) => f.attachment_id)).toEqual(['att_a']);
    // An edit whose original is unreadable here (a member who joined later) has unavailable files.
    expect(messageFiles(edit, { state: 'failed', reason: 'sent before you joined' }, at('att_a'), 0)).toEqual({ filesState: { reason: 'sent before you joined' } });
    expect(messageFiles(edit, { state: 'waiting' }, at('att_a'), 7)).toEqual({ filesState: { reason: FILES_WAITING, gen: 7 } });
    // The server dropped the original of an E5 edit: its uploads are not vouched for.
    expect(messageFiles(edit, undefined, at('att_a'), 0)?.filesState).toBeDefined();
    expect(messageFiles(edit, undefined, at(), 0)).toEqual({ files: [] });
    // An edit sealed before E5 keeps its plaintext uploads, labelled as such.
    expect(messageFiles({ type: 'edit' }, undefined, at('att_old'), 0)).toEqual({});
    expect(messageFiles(edit, sent(), at('att_old'), 0)).toEqual({});
    // An "original" that is itself an edit is a substitution.
    expect(messageFiles(edit, { state: 'decrypted', inner: { type: 'edit', files: [] } }, at(), 0)).toBeUndefined();
  });
});
});
