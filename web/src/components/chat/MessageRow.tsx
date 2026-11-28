import React, { useEffect, useRef, useState } from 'react';
import { CornerUpLeft, Download, FileText, MoreHorizontal, Pencil, RefreshCw, Trash2, X } from 'lucide-react';
import {
  attachmentUrl,
  formatBytes,
  isInlineImageAttachment,
  type ChatAttachment,
  type ChatMessage,
} from '../../chat/types';
import { formatTime, initialsFor, isBotSender, isGuestSender, isWebhookSender } from '../../chat/state';
import { sealedIds, type FileDescriptor, type Provenance, type SealedFile } from '../../crypto/attachments';
import { SealedFiles } from './Attachments';

const WAITING_TEXT = "Waiting for this message's key";

/** Why a message is not end-to-end encrypted, or nothing when it is (or is a system event). */
export function plaintextLabel(msg: ChatMessage): string | null {
  if (msg.encoding !== 'plain_v1') return null;
  if (isBotSender(msg.sender_id)) return 'Not encrypted (bot)';
  if (isGuestSender(msg.sender_id)) return 'Not encrypted (guest)';
  if (isWebhookSender(msg.sender_id)) return 'Not encrypted (webhook)';
  return 'Sent before encryption';
}

/** "Attachment: <name>" or "<n> attachments", naming encrypted files by their decrypted names. */
export function attachmentSummary(msg: ChatMessage): string {
  const names = [...(msg.files ?? []).map((f) => f.name), ...attachmentView(msg).plain.map((a) => a.filename)];
  if (names.length === 1) return `Attachment: ${names[0]}`;
  return names.length > 1 ? `${names.length} attachments` : '';
}

interface AttachmentView {
  /** Encrypted files the message names and the server attached. */
  sealed: SealedFile[];
  /** Encrypted files the message names but the server did not attach. */
  missing: SealedFile[];
  /** Files this message has that cannot be read here (how many, when the message says), and why. */
  unreadable?: { reason: string; expected?: number };
  /** Uploads the server attached that the message does not name: never offered. */
  unnamed: number;
  /** Uploads of a message from before E5 (or a bot): plaintext, labelled as such. */
  plain: ChatAttachment[];
}

/**
 * What an edit of this message must seal, or undefined when no safe edit exists. Taken from the
 * message's own (or latest edit's) envelope. A message the relay calls plaintext names no uploads
 * on its own say: with uploads it is not offered for editing, without it edits as legacy.
 */
export function editProvenance(msg: ChatMessage): Provenance | undefined {
  if (msg.encoding === 'plain_v1') return msg.attachments.length > 0 ? undefined : { kind: 'legacy', rows: [] };
  return msg.provenance;
}

/**
 * How a message's uploads may be shown. Only a message without a sealed file list (sent before E5,
 * or plaintext) has plaintext uploads; an encrypted message not opened yet shows none, and one that
 * names its files never shows an upload it does not name.
 */
export function attachmentView(msg: ChatMessage): AttachmentView {
  const view: AttachmentView = { sealed: [], missing: [], unnamed: 0, plain: [] };
  if (msg.encoding === 'e2ee_room_v1' && msg.e2ee?.kind !== 'decrypted') return view;
  if (msg.files) {
    const named = new Set(sealedIds(msg.files));
    view.sealed = msg.files.filter((f) => !f.missing);
    view.missing = msg.files.filter((f) => f.missing);
    view.unnamed = msg.attachments.filter((a) => !named.has(a.id)).length;
  } else if (msg.filesState) {
    // Shown even when the server lists no rows: their absence is no evidence there are none.
    view.unreadable = { reason: msg.filesState.reason, expected: msg.filesState.expected };
  } else if (msg.plainIds) {
    // A legacy edit vouches for these plaintext rows only: others are hidden, missing ones said.
    const vouched = new Set(msg.plainIds);
    view.plain = msg.attachments.filter((a) => vouched.has(a.id));
    view.unnamed = msg.attachments.length - view.plain.length;
    const missing = msg.plainIds.length - view.plain.length;
    if (missing > 0) view.unreadable = { reason: "This message's files are not available.", expected: missing };
  } else {
    view.plain = msg.attachments;
  }
  return view;
}

/** A bot's message from a device its owner vouched for (E4): decrypted and authenticated. */
const botVerified = (msg: ChatMessage) => msg.e2ee?.kind === 'decrypted' && !msg.e2ee.trust;

/** Why a decrypted message's sender is not vouched for, or nothing when it is. */
export function trustLabel(msg: ChatMessage): string | null {
  if (msg.e2ee?.kind !== 'decrypted' || !msg.e2ee.trust) return null;
  return msg.e2ee.trust === 'backup'
    ? 'Restored from your key backup: the sender’s device could not be checked'
    : 'Sent from a device its owner has not verified';
}

function messagePreviewText(msg: ChatMessage): string {
  if (msg.e2ee?.kind === 'waiting') return WAITING_TEXT;
  if (msg.e2ee?.kind === 'failed') return 'Message could not be decrypted';
  return msg.body || attachmentSummary(msg);
}

const QUICK_REACTIONS = ['👍', '❤️', '🎉', '👀'] as const;

const INLINE_TOKEN_RE = /(`[^`\n]+`|https?:\/\/[^\s<>()]+(?:\([^\s<>()]*\)[^\s<>()]*)*)/g;

function trimTrailingUrlPunct(raw: string): { url: string; trailing: string } {
  let url = raw;
  let trailing = '';
  while (/[.,!?;:]$/.test(url)) {
    trailing = url.slice(-1) + trailing;
    url = url.slice(0, -1);
  }
  return { url, trailing };
}

function renderFormattedBody(text: string): React.ReactNode {
  if (!text) return null;
  const nodes: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  INLINE_TOKEN_RE.lastIndex = 0;
  while ((match = INLINE_TOKEN_RE.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith('`') && token.endsWith('`') && token.length > 2) {
      nodes.push(
        <code key={`code-${match.index}`} className="chat-inline-code">
          {token.slice(1, -1)}
        </code>,
      );
    } else if (/^https?:\/\//i.test(token)) {
      const { url, trailing } = trimTrailingUrlPunct(token);
      nodes.push(
        <a
          key={`link-${match.index}`}
          href={url}
          className="chat-inline-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          {url}
        </a>,
      );
      if (trailing) nodes.push(trailing);
    } else {
      nodes.push(token);
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }
  return nodes;
}

interface MessageRowProps {
  message: ChatMessage;
  grouped: boolean;
  currentUserId: string;
  canModerate: boolean;
  replyTarget?: ChatMessage;
  highlighted?: boolean;
  editTrigger?: number;
  onEditTriggerConsumed?: () => void;
  onEditEnd?: () => void;
  onReply: (message: ChatMessage) => void;
  onJumpToMessage?: (seq: number) => void;
  onPreviewImage?: (attachment: ChatAttachment) => void;
  onPreviewFile?: (file: FileDescriptor) => void;
  onToggleReaction: (messageId: string, emoji: string, currentlyReacted: boolean) => void;
  onEdit: (messageId: string, newBody: string) => Promise<void>;
  onDelete: (messageId: string) => Promise<void>;
  onRetryFailed: (message: ChatMessage) => void;
  onDismissFailed: (idempotencyKey: string) => void;
}

export const MessageRow: React.FC<MessageRowProps> = ({
  message,
  grouped,
  currentUserId,
  canModerate,
  replyTarget,
  highlighted = false,
  editTrigger = 0,
  onEditTriggerConsumed,
  onEditEnd,
  onReply,
  onJumpToMessage,
  onPreviewImage,
  onPreviewFile,
  onToggleReaction,
  onEdit,
  onDelete,
  onRetryFailed,
  onDismissFailed,
}) => {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(message.body);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [actionsPinned, setActionsPinned] = useState(false);
  const [actionError, setActionError] = useState('');
  const lastHandledTriggerRef = useRef(0);
  const bodyRef = useRef(message.body);
  bodyRef.current = message.body;

  const isDeleted = Boolean(message.deleted_at);
  const isSynced = message.delivery.kind === 'synced';
  const isOwn = message.sender_id === currentUserId;
  // A message this device cannot read cannot be edited from it.
  const sealedShut = message.e2ee !== undefined && message.e2ee.kind !== 'decrypted';
  // No edit is offered where none could say what the message's files are.
  const canEdit = isSynced && !isDeleted && isOwn && !sealedShut && editProvenance(message) !== undefined;
  const plainNote = plaintextLabel(message);
  const files = attachmentView(message);
  const sealedFiles = files.sealed;
  const plainFiles = files.plain;
  const shownFiles = sealedFiles.length + files.missing.length + (files.unreadable ? 1 : 0) + plainFiles.length;
  const trustNote = trustLabel(message);
  const canDelete = isSynced && !isDeleted && (isOwn || canModerate);
  const authorLabel = message.sender_name || 'Unknown';

  useEffect(() => {
    if (editTrigger > 0 && editTrigger !== lastHandledTriggerRef.current && canEdit) {
      lastHandledTriggerRef.current = editTrigger;
      setDraft(bodyRef.current);
      setActionError('');
      setEditing(true);
      onEditTriggerConsumed?.();
    }
  }, [editTrigger, canEdit, onEditTriggerConsumed]);

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed || trimmed === message.body) {
      setActionError('');
      setEditing(false);
      onEditEnd?.();
      return;
    }
    setSaving(true);
    setActionError('');
    try {
      await onEdit(message.id, trimmed);
      setEditing(false);
      onEditEnd?.();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Could not save edit');
    } finally {
      setSaving(false);
    }
  };

  return (
    <article
      className={`chat-msg${grouped ? ' grouped' : ''}${message.delivery.kind === 'sending' ? ' sending' : ''}${highlighted ? ' is-highlighted' : ''}`}
      data-seq={message.seq}
      data-msg-id={message.id}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && (confirmDelete || actionsPinned)) {
          e.stopPropagation();
          setConfirmDelete(false);
          setActionsPinned(false);
        }
      }}
    >
      <div>
        {grouped ? (
          <div className="chat-msg-gutter-time">{formatTime(message.created_at)}</div>
        ) : (
          <div className="chat-msg-avatar" aria-hidden="true">
            {initialsFor(authorLabel)}
          </div>
        )}
      </div>

      <div className="chat-msg-content">
        {!grouped && (
          <div className="chat-msg-meta">
            <span className="chat-msg-author">{authorLabel}</span>
            {isWebhookSender(message.sender_id) && <span className="chat-msg-badge">Webhook</span>}
            {isBotSender(message.sender_id) && (
              <span className="chat-msg-badge" title={botVerified(message) ? 'Sent from a device the bot’s owner vouched for' : undefined}>
                {botVerified(message) ? 'Bot, verified by its owner' : 'Bot'}
              </span>
            )}
            <time className="chat-msg-time" dateTime={new Date(message.created_at).toISOString()}>
              {formatTime(message.created_at)}
            </time>
            {message.edited_at && !isDeleted && <span className="chat-msg-edited">(edited)</span>}
            {message.delivery.kind === 'sending' && <span className="chat-msg-edited">Sending…</span>}
          </div>
        )}

        {message.reply_to_id && !isDeleted && (
          replyTarget && onJumpToMessage ? (
            <button
              type="button"
              className="chat-reply-quote is-clickable"
              onClick={() => onJumpToMessage(replyTarget.seq)}
              title="Jump to original message"
            >
              <CornerUpLeft size={12} aria-hidden="true" style={{ flexShrink: 0 }} />
              <strong>
                {replyTarget.sender_name || 'Message'}
                {isWebhookSender(replyTarget.sender_id) && ' (webhook)'}
                {isBotSender(replyTarget.sender_id) && ' (bot)'}
              </strong>
              <span>{replyTarget.deleted_at ? 'Original message deleted' : messagePreviewText(replyTarget)}</span>
            </button>
          ) : (
            <div className="chat-reply-quote">
              <CornerUpLeft size={12} aria-hidden="true" style={{ flexShrink: 0 }} />
              <strong>
                {replyTarget ? replyTarget.sender_name || 'Message' : 'Reply'}
                {replyTarget && isWebhookSender(replyTarget.sender_id) && ' (webhook)'}
                {replyTarget && isBotSender(replyTarget.sender_id) && ' (bot)'}
              </strong>
              <span>
                {replyTarget
                  ? replyTarget.deleted_at
                    ? 'Original message deleted'
                    : messagePreviewText(replyTarget)
                  : 'Referenced earlier message'}
              </span>
            </div>
          )
        )}

        {isDeleted ? (
          <p className="chat-msg-deleted">Message deleted</p>
        ) : editing ? (
          <form className="chat-edit-form" onSubmit={handleSaveEdit}>
            <textarea
              rows={2}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.nativeEvent.isComposing || e.keyCode === 229) return;
                if (e.key === 'Escape') {
                  e.stopPropagation();
                  setActionError('');
                  setEditing(false);
                  setDraft(message.body);
                  onEditEnd?.();
                } else if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void handleSaveEdit(e);
                }
              }}
              aria-label="Edit message"
              autoFocus
            />
            <div className="chat-edit-actions">
              <button type="submit" disabled={saving || !draft.trim()}>
                {saving ? 'Saving…' : 'Save'}
              </button>
              <button
                type="button"
                className="btn-secondary"
                disabled={saving}
                onClick={() => {
                  setActionError('');
                  setEditing(false);
                  setDraft(message.body);
                  onEditEnd?.();
                }}
              >
                Cancel
              </button>
              <span>Enter to save · Esc to cancel</span>
            </div>
          </form>
        ) : (
          <>
            {message.e2ee?.kind === 'waiting' ? (
              <p className="chat-msg-locked">{WAITING_TEXT}</p>
            ) : message.e2ee?.kind === 'failed' ? (
              <p className="chat-msg-locked is-error">Can't decrypt this message. {message.e2ee.reason}</p>
            ) : (
              (message.body || shownFiles === 0) && (
                <div className="chat-msg-body">
                  {renderFormattedBody(message.body)}
                  {grouped && message.edited_at && <span className="chat-msg-edited"> (edited)</span>}
                </div>
              )
            )}
            {plainNote && <p className="chat-msg-e2ee-note">{plainNote}</p>}
            {trustNote && <p className="chat-msg-e2ee-note is-unverified" data-testid="trust-note">{trustNote}</p>}

            {sealedFiles.length > 0 && <SealedFiles files={sealedFiles} onPreview={onPreviewFile} />}
            {files.missing.length > 0 && (
              <div className="chat-attachments" aria-label="Unavailable attachments">
                {files.missing.map((f) => (
                  <div key={f.attachment_id} className="chat-att-file is-unavailable">
                    <span className="chat-att-file-icon" aria-hidden="true">
                      <FileText size={16} />
                    </span>
                    <span className="chat-att-file-meta">
                      <span className="chat-att-name" title={f.name}>{f.name}</span>
                      <span className="chat-att-size">Attachment unavailable</span>
                    </span>
                  </div>
                ))}
              </div>
            )}
            {files.unreadable && (
              <p className="chat-msg-e2ee-note">
                {files.unreadable.expected === 1
                  ? 'Attachment unavailable.'
                  : files.unreadable.expected
                    ? `${files.unreadable.expected} attachments unavailable.`
                    : 'Attachments unavailable.'}{' '}
                {files.unreadable.reason}
              </p>
            )}
            {files.unnamed > 0 && (
              <p className="chat-msg-e2ee-note is-error" role="note">
                {files.unnamed === 1 ? 'An attachment' : `${files.unnamed} attachments`} this message does not include
                {files.unnamed === 1 ? ' was' : ' were'} hidden: the server may have added {files.unnamed === 1 ? 'it' : 'them'}.
              </p>
            )}
            {plainFiles.length > 0 && (
              <p className="chat-msg-e2ee-note">{plainFiles.length === 1 ? 'File not encrypted' : 'Files not encrypted'}</p>
            )}
            {plainFiles.length > 0 && (
              <div className="chat-attachments" aria-label="Unencrypted attachments">
                {plainFiles.map((att) =>
                  isInlineImageAttachment(att) ? (
                    <div key={att.id} className="chat-att-image-card">
                      <button
                        type="button"
                        className="chat-att-image-btn"
                        aria-label={`Preview ${att.filename}`}
                        onClick={() => onPreviewImage?.(att)}
                      >
                        <img
                          src={attachmentUrl(att.id, true)}
                          alt={att.filename}
                          className="chat-att-image"
                          loading="lazy"
                        />
                      </button>
                      <div className="chat-att-image-bar">
                        <span className="chat-att-name" title={att.filename}>
                          {att.filename}
                        </span>
                        <span className="chat-att-size">{formatBytes(att.size_bytes)}</span>
                        <a
                          href={attachmentUrl(att.id)}
                          download={att.filename}
                          className="chat-att-dl-icon"
                          title={`Download ${att.filename}`}
                          aria-label={`Download ${att.filename}`}
                        >
                          <Download size={13} aria-hidden="true" />
                        </a>
                      </div>
                    </div>
                  ) : (
                    <a
                      key={att.id}
                      href={attachmentUrl(att.id)}
                      download={att.filename}
                      className="chat-att-file"
                    >
                      <span className="chat-att-file-icon" aria-hidden="true">
                        <FileText size={16} />
                      </span>
                      <span className="chat-att-file-meta">
                        <span className="chat-att-name" title={att.filename}>
                          {att.filename}
                        </span>
                        <span className="chat-att-size">{formatBytes(att.size_bytes)}</span>
                      </span>
                      <Download size={14} className="chat-att-file-dl" aria-hidden="true" />
                    </a>
                  ),
                )}
              </div>
            )}
          </>
        )}

        {actionError && (
          <div className="chat-msg-failed" role="alert">
            <span>{actionError}</span>
          </div>
        )}

        {message.delivery.kind === 'failed' && (
          <div className="chat-msg-failed" role="alert">
            <span>Failed to send: {message.delivery.error}</span>
            <button type="button" className="btn-secondary" onClick={() => onRetryFailed(message)}>
              <RefreshCw size={12} />
              Retry
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                if (message.delivery.kind === 'failed') {
                  onDismissFailed(message.delivery.idempotencyKey);
                }
              }}
            >
              Dismiss
            </button>
          </div>
        )}

        {!isDeleted && message.reactions.length > 0 && (
          <div className="chat-reactions">
            {message.reactions.map((rx) => {
              const reacted = rx.user_ids.includes(currentUserId);
              return (
                <button
                  key={rx.emoji}
                  type="button"
                  className={`chat-reaction-pill${reacted ? ' reacted' : ''}`}
                  aria-pressed={reacted}
                  aria-label={`${rx.emoji} ${rx.count}`}
                  onClick={() => onToggleReaction(message.id, rx.emoji, reacted)}
                >
                  <span>{rx.emoji}</span>
                  <span>{rx.count}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {isSynced && !isDeleted && !editing && (
        <>
          <button
            type="button"
            className="chat-msg-more-btn"
            aria-label="Message actions"
            aria-expanded={actionsPinned}
            onClick={() => setActionsPinned((v) => !v)}
          >
            <MoreHorizontal size={14} aria-hidden="true" />
          </button>

          <div
            className={`chat-msg-actions${confirmDelete || actionsPinned ? ' is-pinned' : ''}`}
            role="toolbar"
            aria-label="Message actions"
          >
            {QUICK_REACTIONS.map((emoji) => {
              const existing = message.reactions.find((r) => r.emoji === emoji);
              const reacted = Boolean(existing?.user_ids.includes(currentUserId));
              return (
                <button
                  key={emoji}
                  type="button"
                  className={`chat-action-btn${reacted ? ' is-reacted' : ''}`}
                  title={reacted ? `Remove ${emoji}` : `React ${emoji}`}
                  aria-label={`React with ${emoji}`}
                  aria-pressed={reacted}
                  onClick={() => {
                    onToggleReaction(message.id, emoji, reacted);
                    setActionsPinned(false);
                  }}
                >
                  {emoji}
                </button>
              );
            })}
            <button
              type="button"
              className="chat-action-btn"
              title="Reply"
              aria-label="Reply"
              onClick={() => {
                setActionsPinned(false);
                onReply(message);
              }}
            >
              <CornerUpLeft size={14} aria-hidden="true" />
            </button>
            {canEdit && (
              <button
                type="button"
                className="chat-action-btn"
                title="Edit"
                aria-label="Edit message"
                onClick={() => {
                  setActionsPinned(false);
                  setDraft(message.body);
                  setEditing(true);
                }}
              >
                <Pencil size={14} aria-hidden="true" />
              </button>
            )}
            {canDelete && !confirmDelete && (
              <button
                type="button"
                className="chat-action-btn danger"
                title="Delete"
                aria-label="Delete message"
                onClick={() => setConfirmDelete(true)}
              >
                <Trash2 size={14} aria-hidden="true" />
              </button>
            )}
            {canDelete && confirmDelete && (
              <>
                <button
                  type="button"
                  className="chat-action-btn danger"
                  aria-label="Confirm delete message"
                  onClick={() => {
                    setConfirmDelete(false);
                    setActionsPinned(false);
                    setActionError('');
                    void onDelete(message.id).catch((err: unknown) => {
                      setActionError(err instanceof Error ? err.message : 'Could not delete message');
                    });
                  }}
                >
                  Delete?
                </button>
                <button
                  type="button"
                  className="chat-action-btn"
                  aria-label="Cancel delete"
                  onClick={() => {
                    setConfirmDelete(false);
                    setActionsPinned(false);
                  }}
                >
                  <X size={13} aria-hidden="true" />
                </button>
              </>
            )}
          </div>
        </>
      )}
    </article>
  );
};
