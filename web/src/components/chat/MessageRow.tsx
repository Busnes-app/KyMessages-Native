import React, { useState } from 'react';
import { CornerUpLeft, Pencil, RefreshCw, Trash2, X } from 'lucide-react';
import type { ChatMessage } from '../../chat/types';
import { formatTime, initialsFor } from '../../chat/state';

const QUICK_REACTIONS = ['👍', '❤️', '🎉', '👀'] as const;

interface MessageRowProps {
  message: ChatMessage;
  grouped: boolean;
  currentUserId: string;
  canModerate: boolean;
  replyTarget?: ChatMessage;
  onReply: (message: ChatMessage) => void;
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
  onReply,
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

  const isDeleted = Boolean(message.deleted_at);
  const isSynced = message.delivery.kind === 'synced';
  const isOwn = message.sender_id === currentUserId;
  const canEdit = isSynced && !isDeleted && isOwn;
  const canDelete = isSynced && !isDeleted && (isOwn || canModerate);
  const authorLabel = message.sender_name || 'Unknown';

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed || trimmed === message.body) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await onEdit(message.id, trimmed);
      setEditing(false);
    } finally {
      setSaving(false);
    }
  };

  return (
    <article
      className={`chat-msg${grouped ? ' grouped' : ''}${message.delivery.kind === 'sending' ? ' sending' : ''}`}
      data-seq={message.seq}
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
            <time className="chat-msg-time" dateTime={new Date(message.created_at).toISOString()}>
              {formatTime(message.created_at)}
            </time>
            {message.edited_at && !isDeleted && <span className="chat-msg-edited">(edited)</span>}
            {message.delivery.kind === 'sending' && <span className="chat-msg-edited">Sending…</span>}
          </div>
        )}

        {message.reply_to_id && !isDeleted && (
          <div className="chat-reply-quote">
            <CornerUpLeft size={12} aria-hidden="true" style={{ flexShrink: 0 }} />
            <strong>{replyTarget ? replyTarget.sender_name || 'Message' : 'Reply'}</strong>
            <span>
              {replyTarget
                ? replyTarget.deleted_at
                  ? 'Original message deleted'
                  : replyTarget.body
                : 'Referenced message'}
            </span>
          </div>
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
                if (e.key === 'Escape') {
                  setEditing(false);
                  setDraft(message.body);
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
                  setEditing(false);
                  setDraft(message.body);
                }}
              >
                Cancel
              </button>
              <span>Enter to save · Esc to cancel</span>
            </div>
          </form>
        ) : (
          <div className="chat-msg-body">
            {message.body}
            {grouped && message.edited_at && <span className="chat-msg-edited"> (edited)</span>}
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
        <div className="chat-msg-actions" role="toolbar" aria-label="Message actions">
          {QUICK_REACTIONS.map((emoji) => {
            const existing = message.reactions.find((r) => r.emoji === emoji);
            const reacted = Boolean(existing?.user_ids.includes(currentUserId));
            return (
              <button
                key={emoji}
                type="button"
                className="chat-action-btn"
                title={`React ${emoji}`}
                aria-label={`React with ${emoji}`}
                onClick={() => onToggleReaction(message.id, emoji, reacted)}
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
            onClick={() => onReply(message)}
          >
            <CornerUpLeft size={14} />
          </button>
          {canEdit && (
            <button
              type="button"
              className="chat-action-btn"
              title="Edit"
              aria-label="Edit message"
              onClick={() => {
                setDraft(message.body);
                setEditing(true);
              }}
            >
              <Pencil size={14} />
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
              <Trash2 size={14} />
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
                  void onDelete(message.id);
                }}
              >
                Delete?
              </button>
              <button
                type="button"
                className="chat-action-btn"
                aria-label="Cancel delete"
                onClick={() => setConfirmDelete(false)}
              >
                <X size={13} />
              </button>
            </>
          )}
        </div>
      )}
    </article>
  );
};
