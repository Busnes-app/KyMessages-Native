import { describe, expect, it } from 'vitest';
import {
  ATTACHMENT_ALG,
  CHUNK_SIZE,
  MAX_THUMB_CIPHERTEXT,
  ciphertextSize,
  cleanName,
  decryptBlob,
  encryptBlob,
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
  });

  it('keeps only blobs the server attached to the message', () => {
    const files = [file('att_a', { thumb: thumb('att_at') }), file('att_b', { thumb: thumb('att_bt') }), file('att_c')];
    const out = openFiles(files, [{ id: 'att_a' }, { id: 'att_at' }, { id: 'att_b' }])!;
    expect(out.map((f) => f.attachment_id)).toEqual(['att_a', 'att_b']);
    expect(out[0].thumb?.attachment_id).toBe('att_at');
    expect(out[1].thumb).toBeUndefined();
  });

  it('treats malformed or reused descriptors as a damaged message', () => {
    expect(openFiles(undefined, [])).toEqual([]);
    expect(openFiles('x', [])).toBeUndefined();
    expect(openFiles([file(), { bogus: true }], [])).toBeUndefined();
    expect(openFiles([file('att_a'), file('att_a')], [])).toBeUndefined();
    expect(openFiles([file('att_a', { thumb: thumb('att_a') })], [])).toBeUndefined();
    expect(openFiles(Array.from({ length: 11 }, (_, i) => file(`att_${i}`)), [])).toBeUndefined();
  });
});
