import { afterEach, describe, expect, it, vi } from 'vitest';
import { encryptBlob, type FileDescriptor } from '../crypto/attachments';
import { openSealed, saveSealed } from './files';

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
    await vi.waitFor(() => expect(sawSignal).toBe(ctrl.signal));
    ctrl.abort();
    respond(new Response(ciphertext));
    await expect(saving).rejects.toThrow();
    expect(made).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it('revokes the decrypted copy at once when the caller leaves after saving began', async () => {
    const { ciphertext, file } = await sealedFile();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext)));
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:saved');
    const revoke = vi.spyOn(URL, 'revokeObjectURL');
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const ctrl = new AbortController();
    await saveSealed(file, ctrl.signal);
    expect(revoke).not.toHaveBeenCalled();
    ctrl.abort();
    expect(revoke).toHaveBeenCalledWith('blob:saved');
  });
});
