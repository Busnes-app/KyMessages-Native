// Encrypted attachments (E5): a file and its thumbnail are encrypted on this device
// (crypto/attachments.ts) before upload, and what is downloaded is verified and opened here. The
// server only ever receives opaque ciphertext named encrypted.bin.
import { errorMessage, secureFetch } from '../api';
import { obj } from '../dto';
import {
  DAMAGED,
  MAX_THUMB_CIPHERTEXT,
  THUMB_MAX_PX,
  THUMB_MIMES,
  checkBlob,
  ciphertextSize,
  cleanMime,
  cleanName,
  decryptBlob,
  encryptBlob,
  rasterSize,
  sealedIds,
  type BlobKind,
  type FileDescriptor,
  type SealedBlob,
} from '../crypto/attachments';
import { deleteAttachment } from './client';
import { attachmentUrl, isInlineImageAttachment, parseAttachment, type ChatAttachment } from './types';

// The most pixels this tab decodes for a thumbnail or a preview: a small file can declare a huge
// canvas (a decompression bomb), so headers are read before anything is decoded.
export const MAX_DECODE_PIXELS = 50_000_000;
// Where a raster header sits: a JPEG's frame header can follow up to 64 KiB of EXIF.
const HEADER_BYTES = 256 << 10;
// A download that sends nothing for this long is given up.
const STALL_MS = 30_000;

/** Runs at most `n` tasks at once, in call order. */
function limiter(n: number) {
  let running = 0;
  const queue: (() => void)[] = [];
  return async <T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> => {
    if (running >= n) await new Promise<void>((resolve) => queue.push(resolve));
    running++;
    try {
      signal?.throwIfAborted();
      return await task();
    } finally {
      running--;
      queue.shift()?.();
    }
  };
}
// A batch of files is encrypted and uploaded two at a time, each held in memory once.
const uploads = limiter(2);
// Thumbnails decrypt a few at a time, however many are on screen.
const thumbs = limiter(4);

interface Thumbnail {
  blob: Blob;
  width: number;
  height: number;
  thumbWidth: number;
  thumbHeight: number;
}

// A bounded re-encode of a browser-decodable image; re-encoding also drops its metadata (EXIF,
// location). Undefined when the browser cannot make one: the file is still sent, without a preview.
async function makeThumbnail(file: Blob): Promise<Thumbnail | undefined> {
  if (!isInlineImageAttachment({ mime_type: file.type }) || typeof createImageBitmap !== 'function') return undefined;
  try {
    const declared = rasterSize(new Uint8Array(await file.slice(0, HEADER_BYTES).arrayBuffer()));
    if (!declared || declared.width * declared.height > MAX_DECODE_PIXELS) return undefined;
    const bmp = await createImageBitmap(file);
    const { width, height } = bmp;
    const scale = Math.min(1, THUMB_MAX_PX / Math.max(width, height));
    const thumbWidth = Math.max(1, Math.round(width * scale));
    const thumbHeight = Math.max(1, Math.round(height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = thumbWidth;
    canvas.height = thumbHeight;
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.drawImage(bmp, 0, 0, thumbWidth, thumbHeight);
    bmp.close();
    if (!ctx) return undefined;
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/webp', 0.8));
    if (!blob || !THUMB_MIMES.has(blob.type) || ciphertextSize(blob.size) > MAX_THUMB_CIPHERTEXT) return undefined;
    return { blob, width, height, thumbWidth, thumbHeight };
  } catch {
    return undefined;
  }
}

async function uploadCiphertext(roomId: string, ciphertext: Uint8Array<ArrayBuffer>, signal?: AbortSignal): Promise<ChatAttachment> {
  const form = new FormData();
  form.append('file', new Blob([ciphertext], { type: 'application/octet-stream' }), 'encrypted.bin');
  const res = await secureFetch(`/api/v1/rooms/${encodeURIComponent(roomId)}/attachments?encrypted=1`, {
    method: 'POST',
    credentials: 'same-origin',
    body: form,
    signal,
  });
  if (!res.ok) throw new Error(await errorMessage(res, 'Could not upload file'));
  return parseAttachment(obj(await res.json()).attachment);
}

/**
 * Encrypts and uploads a file, and its thumbnail when it is an image, each under its own new key.
 * There is no plaintext path. A failed file upload removes whatever was uploaded; a failed
 * thumbnail only loses the preview.
 */
export function uploadEncryptedFile(roomId: string, file: File, signal?: AbortSignal): Promise<FileDescriptor> {
  return uploads(async () => {
    const thumb = await makeThumbnail(file);
    const sealed = await encryptBlob(file, 'file');
    const desc: FileDescriptor = {
      ...sealed.sealed,
      attachment_id: '',
      name: cleanName(file.name),
      mime_type: cleanMime(file.type),
      ...(thumb ? { width: thumb.width, height: thumb.height } : {}),
    };
    signal?.throwIfAborted(); // removed or left while encrypting: upload nothing
    try {
      desc.attachment_id = (await uploadCiphertext(roomId, sealed.ciphertext, signal)).id;
    } catch (e) {
      discardUploads([desc]);
      throw e;
    }
    if (!thumb) return desc;
    try {
      const sealedThumb = await encryptBlob(thumb.blob, 'thumb');
      const att = await uploadCiphertext(roomId, sealedThumb.ciphertext, signal);
      desc.thumb = { ...sealedThumb.sealed, attachment_id: att.id, mime_type: thumb.blob.type, width: thumb.thumbWidth, height: thumb.thumbHeight };
    } catch (e) {
      if (signal?.aborted) {
        discardUploads([desc]);
        throw e;
      }
    }
    return desc;
  }, signal);
}

/** Best-effort removal of uploads never posted; the server's sweep expires any left behind. */
export function discardUploads(files: readonly FileDescriptor[]): void {
  for (const id of sealedIds(files)) if (id) void deleteAttachment(id).catch(() => undefined);
}

// Reads exactly `size` bytes: a declared length that differs, or any byte past `size`, ends the
// download, so a reply is never buffered beyond what the descriptor allows.
async function readExactly(res: Response, size: number, stalled: () => void): Promise<Uint8Array<ArrayBuffer>> {
  const declared = res.headers.get('Content-Length');
  if (declared !== null && !res.headers.get('Content-Encoding') && Number(declared) !== size) {
    void res.body?.cancel();
    throw new Error(DAMAGED);
  }
  const reader = res.body?.getReader();
  if (!reader) throw new Error(DAMAGED);
  const parts: Uint8Array[] = [];
  let got = 0;
  for (;;) {
    stalled();
    const { done, value } = await reader.read();
    if (done) break;
    got += value.length;
    if (got > size) {
      void reader.cancel();
      throw new Error(DAMAGED);
    }
    parts.push(value);
  }
  if (got !== size) throw new Error(DAMAGED);
  const out = new Uint8Array(size);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** What an image must declare before it may be decoded: an exact size, or at most a pixel budget. */
export interface ImageCheck {
  width?: number;
  height?: number;
  maxPixels: number;
}

async function checkImage(plain: Blob, want: ImageCheck): Promise<void> {
  const got = rasterSize(new Uint8Array(await plain.slice(0, HEADER_BYTES).arrayBuffer()));
  if (!got || got.width * got.height > want.maxPixels) throw new Error('This image is too large to preview.');
  if ((want.width !== undefined && got.width !== want.width) || (want.height !== undefined && got.height !== want.height)) {
    throw new Error('This image is not the size its message says.');
  }
}

/**
 * Downloads a blob and opens it; nothing is returned unless all of it is authentic, and an image
 * to be shown (`image`) is refused unless its header declares an acceptable size.
 */
export async function openSealed(
  blob: SealedBlob,
  kind: BlobKind,
  type: string,
  signal?: AbortSignal,
  image?: ImageCheck,
): Promise<Blob> {
  const { ciphertext_size } = checkBlob(blob, kind);
  const stall = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stalled = () => {
    clearTimeout(timer);
    timer = setTimeout(() => stall.abort(new Error('The download stalled.')), STALL_MS);
  };
  const done = signal ? AbortSignal.any([signal, stall.signal]) : stall.signal;
  try {
    stalled();
    const res = await fetch(attachmentUrl(blob.attachment_id), { credentials: 'same-origin', cache: 'no-store', signal: done });
    if (!res.ok) throw new Error(res.status === 404 ? 'This file is no longer available.' : 'Could not download this file.');
    const plain = new Blob(await decryptBlob(await readExactly(res, ciphertext_size, stalled), blob, kind), { type });
    if (image) await checkImage(plain, image);
    return plain;
  } finally {
    clearTimeout(timer);
  }
}

/** A thumbnail, decrypted a few at a time and only if it declares exactly its descriptor's size. */
export function openThumb(thumb: NonNullable<FileDescriptor['thumb']>, signal?: AbortSignal): Promise<Blob> {
  const check = { width: thumb.width, height: thumb.height, maxPixels: THUMB_MAX_PX * THUMB_MAX_PX };
  return thumbs(() => openSealed(thumb, 'thumb', thumb.mime_type, signal, check), signal);
}

// Long enough for the browser to start saving; the decrypted copy is then released.
const SAVE_URL_MS = 30_000;
// After the caller leaves, a save already handed to the browser keeps its copy this long, so the
// download is not cut off (Firefox reads the blob: URL after the click returns).
const LEAVE_GRACE_MS = 1_000;

/**
 * Saves decrypted bytes under a name. They are always saved untyped: a blob: URL belongs to this
 * origin, so a typed one (HTML, SVG) opened in a tab would run as this app. Aborting `signal`
 * (the caller left: another room, sign-out) releases the copy shortly after.
 */
export function saveBlob(plain: Blob, name: string, signal?: AbortSignal): void {
  signal?.throwIfAborted();
  const url = URL.createObjectURL(plain.slice(0, plain.size, 'application/octet-stream'));
  const revoke = () => URL.revokeObjectURL(url);
  signal?.addEventListener('abort', () => setTimeout(revoke, LEAVE_GRACE_MS), { once: true });
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(revoke, SAVE_URL_MS);
}

/** Decrypts a file and saves it under its name; aborting stops the download first. */
export async function saveSealed(file: FileDescriptor, signal?: AbortSignal): Promise<void> {
  saveBlob(await openSealed(file, 'file', 'application/octet-stream', signal), file.name, signal);
}
