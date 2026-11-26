import { afterEach, describe, expect, it, vi } from 'vitest';
import { encryptBlob, type FileDescriptor } from '../crypto/attachments';
import { openSealed, saveSealed, uploadEncryptedFile } from './files';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function sealedFile(text = 'hello world') {
  const { ciphertext, sealed } = await encryptBlob(new Blob([text]), 'file');
  const file: FileDescriptor = { ...sealed, attachment_id: 'att_1', name: 'notes.txt', mime_type: 'text/plain' };
  return { ciphertext, file };
}

describe('downloads', () => {
  it('stops reading as soon as the server sends more than the descriptor allows', async () => {
    const { file } = await sealedFile();
    let pulls = 0;
    let cancelled = false;
    const endless = new ReadableStream<Uint8Array>({
      pull(c) {
        pulls++;
        c.enqueue(new Uint8Array(64 << 10));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(endless)));
    await expect(openSealed(file, 'file', 'text/plain')).rejects.toThrow(/damaged/);
    expect(pulls).toBeLessThanOrEqual(2);
    expect(cancelled).toBe(true);
  });

  it('refuses a short reply and a descriptor over its kind limit, before fetching', async () => {
    const { ciphertext, file } = await sealedFile();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext.slice(0, -1))));
    await expect(openSealed(file, 'file', 'text/plain')).rejects.toThrow(/damaged/);
    const fetched = vi.fn();
    vi.stubGlobal('fetch', fetched);
    await expect(openSealed({ ...file, ciphertext_size: (1 << 20) + 16, size: 1 << 20 }, 'thumb', 'image/png')).rejects.toThrow(/unsupported/);
    expect(fetched).not.toHaveBeenCalled();
  });
});

describe('saving', () => {
  it('makes no decrypted copy when the caller leaves during the download', async () => {
    const { ciphertext, file } = await sealedFile();
    let respond!: (r: Response) => void;
    let sawSignal: AbortSignal | undefined;
    vi.stubGlobal('fetch', vi.fn((_url: string, init?: RequestInit) => {
      sawSignal = init?.signal ?? undefined;
      return new Promise<Response>((r) => (respond = r));
    }));
    const made = vi.spyOn(URL, 'createObjectURL');
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const ctrl = new AbortController();
    const saving = saveSealed(file, ctrl.signal);
    await vi.waitFor(() => expect(sawSignal?.aborted).toBe(false));
    ctrl.abort();
    expect(sawSignal?.aborted).toBe(true);
    respond(new Response(ciphertext));
    await expect(saving).rejects.toThrow();
    expect(made).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it('releases the decrypted copy a moment after the caller leaves, not 30 seconds later', async () => {
    const { ciphertext, file } = await sealedFile();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext)));
    const made: Blob[] = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      made.push(b as Blob);
      return 'blob:saved';
    });
    const revoke = vi.spyOn(URL, 'revokeObjectURL');
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const ctrl = new AbortController();
    await saveSealed(file, ctrl.signal);
    expect(made[0].type).toBe('application/octet-stream');
    vi.useFakeTimers();
    try {
      ctrl.abort();
      // Firefox reads the URL after the click returns: a short grace, then it is gone.
      expect(revoke).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1_000);
      expect(revoke).toHaveBeenCalledWith('blob:saved');
    } finally {
      vi.useRealTimers();
    }
  });

  it('gives up on a download that stalls', async () => {
    const { file } = await sealedFile();
    vi.useFakeTimers();
    try {
      vi.stubGlobal('fetch', vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
      })));
      const opening = openSealed(file, 'file', 'text/plain');
      const failed = expect(opening).rejects.toThrow(/stalled/);
      await vi.advanceTimersByTimeAsync(30_000);
      await failed;
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses a reply whose declared length is not the ciphertext length', async () => {
    const { ciphertext, file } = await sealedFile();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext, { headers: { 'Content-Length': String(ciphertext.length + 1) } })));
    await expect(openSealed(file, 'file', 'text/plain')).rejects.toThrow(/damaged/);
  });
});

describe('uploading', () => {
  const png = (width: number, height: number) => {
    const b = new Uint8Array(64);
    b.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
    new DataView(b.buffer).setUint32(16, width);
    new DataView(b.buffer).setUint32(20, height);
    return new File([b], 'photo.png', { type: 'image/png' });
  };
  const uploaded = (id: string) =>
    new Response(JSON.stringify({ attachment: { id, room_id: 'r1', filename: 'encrypted.bin' } }), { status: 201 });

  function stubCanvas() {
    const bitmap = vi.fn(async () => ({ width: 800, height: 600, close: () => undefined }));
    vi.stubGlobal('createImageBitmap', bitmap);
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({ drawImage: () => undefined } as unknown as CanvasRenderingContext2D);
    vi.spyOn(HTMLCanvasElement.prototype, 'toBlob').mockImplementation((cb) => cb(new Blob([new Uint8Array(100)], { type: 'image/webp' })));
    return bitmap;
  }

  it('sends the file without a preview when only its thumbnail upload fails', async () => {
    stubCanvas();
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`);
      if (init?.method === 'DELETE') return new Response(null, { status: 204 });
      return calls.filter((c) => c.startsWith('POST')).length === 1 ? uploaded('att_file') : new Response('{"error":"full"}', { status: 507 });
    }));
    const desc = await uploadEncryptedFile('r1', png(800, 600));
    expect(desc.attachment_id).toBe('att_file');
    expect(desc).toMatchObject({ width: 800, height: 600 });
    expect(desc.thumb).toBeUndefined();
    expect(calls.filter((c) => c.startsWith('DELETE'))).toEqual([]);
  });

  it('never decodes an image whose header declares more pixels than allowed', async () => {
    const bitmap = stubCanvas();
    vi.stubGlobal('fetch', vi.fn(async () => uploaded('att_file')));
    const desc = await uploadEncryptedFile('r1', png(100_000, 100_000));
    expect(bitmap).not.toHaveBeenCalled();
    expect(desc.thumb).toBeUndefined();
  });

  it('encrypts and uploads at most two files at a time', async () => {
    let inFlight = 0;
    let most = 0;
    let n = 0;
    const pending: (() => void)[] = [];
    vi.stubGlobal('fetch', vi.fn(() => {
      inFlight++;
      most = Math.max(most, inFlight);
      return new Promise<Response>((resolve) => pending.push(() => {
        inFlight--;
        resolve(uploaded(`att_${++n}`));
      }));
    }));
    const all = Promise.all([1, 2, 3, 4].map((i) => uploadEncryptedFile('r1', new File([`file ${i}`], `f${i}.txt`))));
    await vi.waitFor(() => expect(pending.length).toBe(2));
    await new Promise((r) => setTimeout(r, 50));
    expect(pending.length).toBe(2); // the other two wait their turn
    for (let done = 0; done < 4; done++) {
      await vi.waitFor(() => expect(pending.length).toBeGreaterThan(0));
      pending.shift()!();
    }
    expect((await all).map((d) => d.attachment_id).sort()).toEqual(['att_1', 'att_2', 'att_3', 'att_4']);
    expect(most).toBe(2);
  });
});
