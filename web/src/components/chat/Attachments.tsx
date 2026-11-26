import React, { useEffect, useRef, useState } from 'react';
import { Download, FileText, Loader2, X } from 'lucide-react';
import type { BlobKind, FileDescriptor, SealedBlob } from '../../crypto/attachments';
import { openSealed, saveSealed } from '../../chat/files';
import { formatBytes, isInlineImageAttachment } from '../../chat/types';

/**
 * A blob: URL for a decrypted blob while the caller is mounted. Leaving (another room, sign-out,
 * a closed preview) aborts the download and revokes the URL, releasing the plaintext.
 */
export function useSealedUrl(blob: SealedBlob | undefined, kind: BlobKind, type: string): { url?: string; error?: string } {
  const [state, setState] = useState<{ url?: string; error?: string }>({});
  const id = blob?.attachment_id;
  const key = blob?.key;
  useEffect(() => {
    if (!blob) return;
    const ctrl = new AbortController();
    let url: string | undefined;
    setState({});
    openSealed(blob, kind, type, ctrl.signal).then(
      (b) => {
        if (ctrl.signal.aborted) return;
        url = URL.createObjectURL(b);
        setState({ url });
      },
      (e: unknown) => {
        if (!ctrl.signal.aborted) setState({ error: e instanceof Error ? e.message : 'Could not open this file.' });
      },
    );
    return () => {
      ctrl.abort();
      if (url) URL.revokeObjectURL(url);
    };
    // A blob is identified by its attachment and key; the descriptor object itself changes each render.
  }, [id, key, kind, type]);
  return state;
}

/** Only raster types render inline; anything else (SVG, HTML) is only ever saved. */
export const previewable = (f: FileDescriptor) => isInlineImageAttachment(f);

function SaveButton({ file, className, children }: { file: FileDescriptor; className: string; children: React.ReactNode }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // The save in flight belongs to this button: leaving aborts it and releases its plaintext.
  const save = useRef<AbortController | null>(null);
  useEffect(() => () => save.current?.abort(), []);
  return (
    <button
      type="button"
      className={className}
      disabled={busy}
      title={error || `Download ${file.name}`}
      aria-label={`Download ${file.name}`}
      onClick={() => {
        const ctrl = new AbortController();
        save.current = ctrl;
        setBusy(true);
        setError('');
        saveSealed(file, ctrl.signal)
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
  const { url, error } = useSealedUrl(file.thumb, 'thumb', file.thumb.mime_type);
  return (
    <div className="chat-att-image-card">
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
  const { url, error } = useSealedUrl(file, 'file', file.mime_type);
  return (
    <Lightbox
      name={file.name}
      size={file.size}
      src={url}
      error={error}
      onClose={onClose}
      download={
        <SaveButton file={file} className="btn-secondary chat-lightbox-dl">
          <Download size={14} aria-hidden="true" />
          <span>Download</span>
        </SaveButton>
      }
    />
  );
}
