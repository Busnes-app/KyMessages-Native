// Encrypted attachments (E5): a file and its thumbnail are encrypted on this device
// (crypto/attachments.ts) before upload, and what is downloaded is verified and opened here. The
// server only ever receives opaque ciphertext named encrypted.bin.
import { errorMessage, secureFetch } from '../api';
import { obj } from '../dto';
import {
  DAMAGED,
  MAX_THUMB_CIPHERTEXT,
  PREVIEW_MIMES,
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
import { attachmentUrl, parseAttachment, type ChatAttachment } from './types';

// The most pixels this tab decodes for a thumbnail or a preview: a small file can declare a huge
// canvas (a decompression bomb), so headers are read before anything is decoded.
export const MAX_DECODE_PIXELS = 50_000_000;
// Where a raster header sits: a JPEG's frame header can follow up to 64 KiB of EXIF.
const HEADER_BYTES = 256 << 10;
// A download that sends nothing for this long, or is not done by its deadline (30 s plus the
// time to fetch it at 64 KiB/s), is given up.
const STALL_MS = 30_000;
const deadlineMs = (bytes: number) => 30_000 + Math.ceil(bytes / 64);

/**
 * Runs at most `n` tasks at once, in call order. A finished task hands its slot straight to the
 * next waiter, so nothing can slip in between; a waiter whose signal aborts leaves the queue at once.
 */
export function limiter(n: number) {
  let running = 0;
  const queue: { start: () => void }[] = [];
  const release = () => {
    const next = queue.shift();
    if (next) next.start();
    else running--;
  };
  return async <T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> => {
    signal?.throwIfAborted();
    if (running < n) {
      running++;
    } else {
      await new Promise<void>((resolve, reject) => {
        const waiter = {
          // A caller that left while its slot was being handed over passes the slot straight on.
          start: () => {
            signal?.removeEventListener('abort', leave);
            if (signal?.aborted) {
              release();
              reject(signal.reason);
            } else {
              resolve();
            }
          },
        };
        const leave = () => {
          queue.splice(queue.indexOf(waiter), 1);
          reject(signal?.reason);
        };
        queue.push(waiter);
        signal?.addEventListener('abort', leave, { once: true });
      });
    }
    try {
      signal?.throwIfAborted();
      return await task();
    } finally {
      release();
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
  if (!PREVIEW_MIMES.has(file.type) || typeof createImageBitmap !== 'function') return undefined;
  try {
    const declared = rasterSize(new Uint8Array(await file.slice(0, HEADER_BYTES).arrayBuffer()), file.type);
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
 * Encrypts and uploads a file, and its thumbnail when it is a still image, each under its own new
 * key. There is no plaintext path. `onPreview` gets the bounded re-encoded thumbnail, the only
 * form of the image the composer shows. A failed file upload removes whatever was uploaded; a
 * failed thumbnail only loses the preview.
 */
export function uploadEncryptedFile(
  roomId: string,
  file: File,
  signal?: AbortSignal,
  onPreview?: (thumb: Blob) => void,
): Promise<FileDescriptor> {
  return uploads(async () => {
    const thumb = await makeThumbnail(file);
    if (thumb && !signal?.aborted) onPreview?.(thumb.blob);
    const sealed = await encryptBlob(file, 'file', undefined, signal);
    const desc: FileDescriptor = {
      ...sealed.sealed,
      attachment_id: '',
      name: cleanName(file.name),
      mime_type: cleanMime(file.type),
      ...(thumb ? { width: thumb.width, height: thumb.height } : {}),
    };
    desc.attachment_id = (await uploadCiphertext(roomId, sealed.ciphertext, signal)).id;
    if (!thumb) return desc;
    try {
      const sealedThumb = await encryptBlob(thumb.blob, 'thumb', undefined, signal);
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

// Reads exactly `size` bytes into one buffer of that size: a declared length that differs, or any
// byte past `size`, ends the download, so a reply is never buffered beyond what the descriptor allows.
async function readExactly(res: Response, size: number, progress: () => void, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  if (signal.aborted) {
    void res.body?.cancel();
    signal.throwIfAborted();
  }
  const declared = res.headers.get('Content-Length');
  if (declared !== null && !res.headers.get('Content-Encoding') && Number(declared) !== size) {
    void res.body?.cancel();
    throw new Error(DAMAGED);
  }
  const reader = res.body?.getReader();
  if (!reader) throw new Error(DAMAGED);
  // Giving up (a stall, the deadline, the caller leaving) ends the read too, not just the request.
  const stop = () => void reader.cancel(signal.reason).catch(() => undefined);
  signal.addEventListener('abort', stop, { once: true });
  try {
    const out = new Uint8Array(size);
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (got + value.length > size) {
        void reader.cancel();
        throw new Error(DAMAGED);
      }
      out.set(value, got);
      got += value.length;
      progress();
    }
    signal.throwIfAborted();
    if (got !== size) throw new Error(DAMAGED);
    return out;
  } finally {
    signal.removeEventListener('abort', stop);
  }
}

/** What an image must declare before it may be decoded: its type, and an exact size or a pixel budget. */
export interface ImageCheck {
  mime: string;
  width?: number;
  height?: number;
  maxPixels: number;
}

async function checkImage(plain: Blob, want: ImageCheck): Promise<void> {
  const got = rasterSize(new Uint8Array(await plain.slice(0, HEADER_BYTES).arrayBuffer()), want.mime);
  if (!got) throw new Error('This image cannot be previewed. Download it instead.');
  if (got.width * got.height > want.maxPixels) throw new Error('This image is too large to preview.');
  if ((want.width !== undefined && got.width !== want.width) || (want.height !== undefined && got.height !== want.height)) {
    throw new Error('This image is not the size its message says.');
  }
}

/**
 * Downloads a blob and opens it; nothing is returned unless all of it is authentic, and an image
 * to be shown (`image`) is refused unless its header declares an acceptable still image.
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
  const late = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const progress = () => {
    clearTimeout(timer);
    timer = setTimeout(() => stall.abort(new Error('The download stalled.')), STALL_MS);
  };
  const deadline = setTimeout(() => late.abort(new Error('The download took too long.')), deadlineMs(ciphertext_size));
  const done = AbortSignal.any(signal ? [signal, stall.signal, late.signal] : [stall.signal, late.signal]);
  try {
    progress();
    const res = await fetch(attachmentUrl(blob.attachment_id), { credentials: 'same-origin', cache: 'no-store', signal: done });
    if (!res.ok) throw new Error(res.status === 404 ? 'This file is no longer available.' : 'Could not download this file.');
    // The deadline and the caller bound decryption too: nothing decrypted is returned after either.
    const ciphertext = await readExactly(res, ciphertext_size, progress, done);
    clearTimeout(timer);
    const plain = new Blob(await decryptBlob(ciphertext, blob, kind, done), { type });
    if (image) await checkImage(plain, image);
    done.throwIfAborted();
    return plain;
  } finally {
    clearTimeout(timer);
    clearTimeout(deadline);
  }
}

/** A thumbnail, decrypted a few at a time and only if it declares exactly its descriptor's size. */
export function openThumb(thumb: NonNullable<FileDescriptor['thumb']>, signal?: AbortSignal): Promise<Blob> {
  const check = { mime: thumb.mime_type, width: thumb.width, height: thumb.height, maxPixels: THUMB_MAX_PX * THUMB_MAX_PX };
  return thumbs(() => openSealed(thumb, 'thumb', thumb.mime_type, signal, check), signal);
}

// Long enough for the browser to start saving; the decrypted copy is then released.
const SAVE_URL_MS = 30_000;
// After the caller leaves, a save already handed to the browser keeps its copy this long, so the
// download is not cut off (Firefox reads the blob: URL after the click returns).
const LEAVE_GRACE_MS = 1_000;

/**
 * Saves decrypted bytes under a name. They are always saved untyped: a blob: URL belongs to this
 * origin, so a typed one (HTML, SVG) opened in a tab would run as this app. The copy is released
 * after SAVE_URL_MS, or shortly after `signal` aborts (the caller left: another room, sign-out);
 * `onRetired` runs then, with nothing of the save left behind.
 */
export function saveBlob(plain: Blob, name: string, signal?: AbortSignal, onRetired?: () => void): void {
  signal?.throwIfAborted();
  const url = URL.createObjectURL(plain.slice(0, plain.size, 'application/octet-stream'));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  let timer = setTimeout(retire, SAVE_URL_MS);
  function leave() {
    clearTimeout(timer);
    timer = setTimeout(retire, LEAVE_GRACE_MS);
  }
  function retire() {
    signal?.removeEventListener('abort', leave);
    URL.revokeObjectURL(url);
    onRetired?.();
  }
  signal?.addEventListener('abort', leave, { once: true });
}

/** Decrypts a file and saves it under its name; aborting stops the download first. */
export async function saveSealed(file: FileDescriptor, signal?: AbortSignal, onRetired?: () => void): Promise<void> {
  saveBlob(await openSealed(file, 'file', 'application/octet-stream', signal), file.name, signal, onRetired);
}
