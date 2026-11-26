// Encrypted attachments (E5): a file and its thumbnail are encrypted on this device
// (crypto/attachments.ts) before upload, and what is downloaded is verified and opened here. The
// server only ever receives opaque ciphertext named encrypted.bin.
import { errorMessage, secureFetch } from '../api';
import { obj } from '../dto';
import {
  MAX_THUMB_CIPHERTEXT,
  THUMB_MIMES,
  ciphertextSize,
  cleanMime,
  cleanName,
  decryptBlob,
  encryptBlob,
  sealedIds,
  type BlobKind,
  type FileDescriptor,
  type SealedBlob,
} from '../crypto/attachments';
import { deleteAttachment } from './client';
import { attachmentUrl, isInlineImageAttachment, parseAttachment, type ChatAttachment } from './types';

const THUMB_MAX_PX = 400;

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
 * There is no plaintext path. A failure removes whatever was already uploaded.
 */
export async function uploadEncryptedFile(roomId: string, file: File, signal?: AbortSignal): Promise<FileDescriptor> {
  const thumb = await makeThumbnail(file);
  const sealed = await encryptBlob(file, 'file');
  const sealedThumb = thumb && (await encryptBlob(thumb.blob, 'thumb'));
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
    if (thumb && sealedThumb) {
      const att = await uploadCiphertext(roomId, sealedThumb.ciphertext, signal);
      desc.thumb = { ...sealedThumb.sealed, attachment_id: att.id, mime_type: thumb.blob.type, width: thumb.thumbWidth, height: thumb.thumbHeight };
    }
    return desc;
  } catch (e) {
    discardUploads([desc]);
    throw e;
  }
}

/** Best-effort removal of uploads never posted; the server's sweep expires any left behind. */
export function discardUploads(files: readonly FileDescriptor[]): void {
  for (const id of sealedIds(files)) if (id) void deleteAttachment(id).catch(() => undefined);
}

/** Downloads a blob and opens it; nothing is returned unless all of it is authentic. */
export async function openSealed(blob: SealedBlob, kind: BlobKind, type: string, signal?: AbortSignal): Promise<Blob> {
  const res = await fetch(attachmentUrl(blob.attachment_id), { credentials: 'same-origin', cache: 'no-store', signal });
  if (!res.ok) throw new Error(res.status === 404 ? 'This file is no longer available.' : 'Could not download this file.');
  return new Blob(await decryptBlob(new Uint8Array(await res.arrayBuffer()), blob, kind), { type });
}

// Long enough for the browser to start saving; the decrypted copy is then released.
const SAVE_URL_MS = 30_000;

/** Decrypts a file and saves it under its name. */
export async function saveSealed(file: FileDescriptor, signal?: AbortSignal): Promise<void> {
  // Always untyped: a blob: URL belongs to this origin, so a typed one (HTML, SVG) opened in a tab
  // would run as this app.
  const url = URL.createObjectURL(await openSealed(file, 'file', 'application/octet-stream', signal));
  const a = document.createElement('a');
  a.href = url;
  a.download = file.name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), SAVE_URL_MS);
}
