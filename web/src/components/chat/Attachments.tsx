import React, { useEffect, useRef, useState } from 'react';
import { Download, FileText, Loader2, X } from 'lucide-react';
import { PREVIEW_MIMES, type FileDescriptor, type SealedBlob } from '../../crypto/attachments';
import { MAX_DECODE_PIXELS, openSealed, openThumb, saveBlob, saveSealed } from '../../chat/files';
import { formatBytes } from '../../chat/types';

// Everything that decides what a blob opens to: its bytes' identity, and how it is checked.
const identity = (b: SealedBlob, ...how: (string | number | undefined)[]) =>
  [b.attachment_id, b.key, b.nonce_prefix, b.sha256, b.ciphertext_size, b.chunk_size, b.size, ...how].join('\u0000');

/**
 * A decrypted blob and its blob: URL while the caller is mounted and `id` is set. Leaving
 * (another room, sign-out, a closed preview, a thumbnail scrolled away unfinished) or a new `id`
 * aborts the download and revokes the URL, releasing the plaintext.
 */
export function useSealedUrl(
  id: string | undefined,
  open: (signal: AbortSignal) => Promise<Blob>,
): { url?: string; plain?: Blob; error?: string } {
  const [state, setState] = useState<{ url?: string; plain?: Blob; error?: string }>({});
  const openRef = useRef(open);
  openRef.current = open;
  useEffect(() => {
    if (!id) return;
    const ctrl = new AbortController();
    let url: string | undefined;
    setState({});
    openRef.current(ctrl.signal).then(
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

/** Whether an element is near the viewport now (always, where IntersectionObserver is missing). */
function useNearViewport(ref: React.RefObject<Element | null>): boolean {
  const [near, setNear] = useState(typeof IntersectionObserver === 'undefined');
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') return;
    const io = new IntersectionObserver((entries) => setNear(entries.some((e) => e.isIntersecting)), { rootMargin: '200px' });
    io.observe(el);
    return () => io.disconnect();
  }, [ref]);
  return near;
}

/** Only still PNG, JPEG and WebP render inline; anything else (GIF, SVG, HTML) is only ever saved. */
export const previewable = (f: FileDescriptor) => PREVIEW_MIMES.has(f.mime_type);

interface SaveButtonProps {
  file: FileDescriptor;
  /** The preview's decrypted bytes, saved instead of a second download. */
  plain?: Blob;
  /** The preview is still decrypting: wait for its bytes rather than fetch them twice. */
  pending?: boolean;
  className: string;
  children: React.ReactNode;
}

function SaveButton({ file, plain, pending, className, children }: SaveButtonProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // The saves still holding a decrypted copy: leaving aborts them; each leaves the set once retired.
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
      disabled={busy || pending}
      title={error || `Download ${file.name}`}
      aria-label={`Download ${file.name}`}
      onClick={() => {
        const ctrl = new AbortController();
        const retired = () => saves.current.delete(ctrl);
        saves.current.add(ctrl);
        setBusy(true);
        setError('');
        (plain ? (async () => saveBlob(plain, file.name, ctrl.signal, retired))() : saveSealed(file, ctrl.signal, retired))
          .catch((e: unknown) => {
            retired();
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
  const [shown, setShown] = useState(false);
  const { thumb } = file;
  // Decrypts while near the viewport; leaving it before the thumbnail is ready cancels the work.
  const { url, error } = useSealedUrl(near || shown ? identity(thumb, thumb.mime_type, thumb.width, thumb.height) : undefined, (signal) => openThumb(thumb, signal));
  useEffect(() => {
    if (url) setShown(true);
  }, [url]);
  return (
    <div className="chat-att-image-card" ref={card}>
      <button type="button" className="chat-att-image-btn" aria-label={`Preview ${file.name}`} onClick={() => onPreview?.(file)}>
        {url ? (
          <img src={url} alt={file.name} className="chat-att-image" width={thumb.width} height={thumb.height} />
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

/** A message's end-to-end encrypted files: thumbnails decrypt near the viewport, files on demand. */
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
  const check = { mime: file.mime_type, maxPixels: MAX_DECODE_PIXELS };
  const { url, plain, error } = useSealedUrl(identity(file, file.mime_type, check.maxPixels), (signal) => openSealed(file, 'file', file.mime_type, signal, check));
  return (
    <Lightbox
      name={file.name}
      size={file.size}
      src={url}
      error={error}
      onClose={onClose}
      download={
        <SaveButton file={file} plain={plain} pending={!plain && !error} className="btn-secondary chat-lightbox-dl">
          <Download size={14} aria-hidden="true" />
          <span>Download</span>
        </SaveButton>
      }
    />
  );
}
