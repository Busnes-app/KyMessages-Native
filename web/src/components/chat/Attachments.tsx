import React, { useEffect, useRef, useState } from 'react';
import { Download, FileText, Loader2, X } from 'lucide-react';
import type { FileDescriptor, SealedBlob } from '../../crypto/attachments';
import { MAX_DECODE_PIXELS, openSealed, openThumb, saveBlob, saveSealed } from '../../chat/files';
import { formatBytes, isInlineImageAttachment } from '../../chat/types';

// Everything that identifies a blob's bytes; the descriptor object itself changes each render.
const blobKey = (b: SealedBlob | undefined) =>
  b && [b.attachment_id, b.key, b.nonce_prefix, b.sha256, b.ciphertext_size, b.chunk_size, b.size].join('\u0000');

/**
 * A decrypted blob and its blob: URL while the caller is mounted and `open` is set. Leaving
 * (another room, sign-out, a closed preview) aborts the download and revokes the URL, releasing
 * the plaintext.
 */
export function useSealedUrl(
  blob: SealedBlob | undefined,
  open: ((signal: AbortSignal) => Promise<Blob>) | undefined,
): { url?: string; plain?: Blob; error?: string } {
  const [state, setState] = useState<{ url?: string; plain?: Blob; error?: string }>({});
  const id = open ? blobKey(blob) : undefined;
  const openRef = useRef(open);
  openRef.current = open;
  useEffect(() => {
    const run = openRef.current;
    if (!id || !run) return;
    const ctrl = new AbortController();
    let url: string | undefined;
    setState({});
    run(ctrl.signal).then(
      (plain) => {
        if (ctrl.signal.aborted) return;
        url = URL.createObjectURL(plain);
        setState({ url, plain });
      },
      (e: unknown) => {
        if (!ctrl.signal.aborted) setState({ error: e instanceof Error ? e.message : 'Could not open this file.' });
      },
    );
    return () => {
      ctrl.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [id]);
  return state;
}

/** Whether an element has come near the viewport (always, where IntersectionObserver is missing). */
function useNearViewport(ref: React.RefObject<Element | null>): boolean {
  const [near, setNear] = useState(typeof IntersectionObserver === 'undefined');
  useEffect(() => {
    const el = ref.current;
    if (near || !el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) setNear(true);
    }, { rootMargin: '200px' });
    io.observe(el);
    return () => io.disconnect();
  }, [near, ref]);
  return near;
}

/** Only raster types render inline; anything else (SVG, HTML) is only ever saved. */
export const previewable = (f: FileDescriptor) => isInlineImageAttachment(f);

function SaveButton({ file, plain, className, children }: { file: FileDescriptor; plain?: Blob; className: string; children: React.ReactNode }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // Every save this button started belongs to it: leaving aborts them and releases their plaintext.
  const saves = useRef(new Set<AbortController>());
  useEffect(() => {
    const live = saves.current;
    return () => {
      for (const c of live) c.abort();
    };
  }, []);
  return (
    <button
      type="button"
      className={className}
      disabled={busy}
      title={error || `Download ${file.name}`}
      aria-label={`Download ${file.name}`}
      onClick={() => {
        const ctrl = new AbortController();
        saves.current.add(ctrl);
        setBusy(true);
        setError('');
        (plain ? (async () => saveBlob(plain, file.name, ctrl.signal))() : saveSealed(file, ctrl.signal))
          .catch((e: unknown) => {
            if (!ctrl.signal.aborted) setError(e instanceof Error ? e.message : 'Could not download this file.');
          })
          .finally(() => {
            if (!ctrl.signal.aborted) setBusy(false);
          });
      }}
    >
      {children}
      {error && <span className="chat-att-error" role="alert">{error}</span>}
    </button>
  );
}

function SealedImage({ file, onPreview }: { file: FileDescriptor & { thumb: NonNullable<FileDescriptor['thumb']> }; onPreview?: (f: FileDescriptor) => void }) {
  const card = useRef<HTMLDivElement>(null);
  const near = useNearViewport(card);
  const { url, error } = useSealedUrl(file.thumb, near ? (signal) => openThumb(file.thumb, signal) : undefined);
  return (
    <div className="chat-att-image-card" ref={card}>
      <button type="button" className="chat-att-image-btn" aria-label={`Preview ${file.name}`} onClick={() => onPreview?.(file)}>
        {url ? (
          <img src={url} alt={file.name} className="chat-att-image" width={file.thumb.width} height={file.thumb.height} />
        ) : (
          <span className="chat-att-image-pending">{error ?? <Loader2 size={16} className="ky-spin" aria-label="Decrypting" />}</span>
        )}
      </button>
      <div className="chat-att-image-bar">
        <span className="chat-att-name" title={file.name}>{file.name}</span>
        <span className="chat-att-size">{formatBytes(file.size)}</span>
        <SaveButton file={file} className="chat-att-dl-icon">
          <Download size={13} aria-hidden="true" />
        </SaveButton>
      </div>
    </div>
  );
}

/** A message's end-to-end encrypted files: thumbnails decrypt as they render, files on demand. */
export function SealedFiles({ files, onPreview }: { files: readonly FileDescriptor[]; onPreview?: (f: FileDescriptor) => void }) {
  return (
    <div className="chat-attachments" aria-label="Attachments">
      {files.map((f) =>
        f.thumb && previewable(f) ? (
          <SealedImage key={f.attachment_id} file={{ ...f, thumb: f.thumb }} onPreview={onPreview} />
        ) : (
          <SaveButton key={f.attachment_id} file={f} className="chat-att-file">
            <span className="chat-att-file-icon" aria-hidden="true">
              <FileText size={16} />
            </span>
            <span className="chat-att-file-meta">
              <span className="chat-att-name" title={f.name}>{f.name}</span>
              <span className="chat-att-size">{formatBytes(f.size)}</span>
            </span>
            <Download size={14} className="chat-att-file-dl" aria-hidden="true" />
          </SaveButton>
        ),
      )}
    </div>
  );
}

interface LightboxProps {
  name: string;
  size: number;
  src?: string;
  error?: string;
  download: React.ReactNode;
  onClose: () => void;
}

export function Lightbox({ name, size, src, error, download, onClose }: LightboxProps) {
  return (
    <div className="chat-lightbox-backdrop" role="dialog" aria-modal="true" aria-label={`Image preview: ${name}`} onClick={onClose}>
      <div className="chat-lightbox-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="chat-lightbox-header">
          <div className="chat-lightbox-title">
            <strong>{name}</strong>
            <span>{formatBytes(size)}</span>
          </div>
          <div className="chat-lightbox-actions">
            {download}
            <button type="button" className="chat-icon-btn" aria-label="Close image preview" onClick={onClose}>
              <X size={16} />
            </button>
          </div>
        </div>
        <div className="chat-lightbox-body">
          {src ? (
            <img src={src} alt={name} className="chat-lightbox-img" />
          ) : (
            <p className="chat-att-image-pending">{error ?? 'Decrypting…'}</p>
          )}
        </div>
      </div>
    </div>
  );
}

/** The full image of an encrypted file, decrypted while the preview is open. */
export function SealedLightbox({ file, onClose }: { file: FileDescriptor; onClose: () => void }) {
  const { url, plain, error } = useSealedUrl(file, (signal) => openSealed(file, 'file', file.mime_type, signal, { maxPixels: MAX_DECODE_PIXELS }));
  return (
    <Lightbox
      name={file.name}
      size={file.size}
      src={url}
      error={error}
      onClose={onClose}
      download={
        <SaveButton file={file} plain={plain} className="btn-secondary chat-lightbox-dl">
          <Download size={14} aria-hidden="true" />
          <span>Download</span>
        </SaveButton>
      }
    />
  );
}
