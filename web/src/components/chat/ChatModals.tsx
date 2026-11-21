import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Hash, Lock, MessageSquare, Search, Video, X } from 'lucide-react';
import type { ChatDirectoryUser, ChatMessage, ChatRoomSummary } from '../../chat/types';
import { searchMessages } from '../../chat/client';
import { formatTime, isWebhookSender } from '../../chat/state';

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function useModalFocus(dialogRef: React.RefObject<HTMLElement | null>, onClose: () => void) {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const root = dialogRef.current;
      if (!root) return;
      const focusables = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first || !root.contains(document.activeElement)) {
          e.preventDefault();
          last.focus();
        }
      } else if (document.activeElement === last || !root.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => {
      window.removeEventListener('keydown', onKeyDown, true);
      if (previous && typeof previous.focus === 'function' && previous.isConnected) {
        previous.focus();
      }
    };
  }, [dialogRef]);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function highlightQuery(text: string, query: string): React.ReactNode {
  const terms = query
    .trim()
    .split(/\s+/)
    .filter((t) => t.length >= 2);
  if (terms.length === 0) return text;
  const re = new RegExp(`(${terms.map(escapeRegExp).join('|')})`, 'gi');
  const parts = text.split(re);
  if (parts.length === 1) return text;
  const lowerTerms = new Set(terms.map((t) => t.toLowerCase()));
  return parts.map((part, idx) =>
    lowerTerms.has(part.toLowerCase()) ? (
      <mark key={idx} className="chat-search-mark">
        {part}
      </mark>
    ) : (
      part
    ),
  );
}

interface CreateChannelModalProps {
  directory: ChatDirectoryUser[];
  currentUserId: string;
  onClose: () => void;
  onCreate: (params: { name: string; topic: string; isPrivate: boolean; memberIds: string[] }) => Promise<void>;
}

export const CreateChannelModal: React.FC<CreateChannelModalProps> = ({
  directory,
  currentUserId,
  onClose,
  onCreate,
}) => {
  const dialogRef = useRef<HTMLFormElement | null>(null);
  useModalFocus(dialogRef, onClose);

  const [name, setName] = useState('');
  const [topic, setTopic] = useState('');
  const [isPrivate, setIsPrivate] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const others = directory.filter((u) => u.id !== currentUserId);

  const toggleMember = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = name.trim();
    if (!cleanName) return;
    setBusy(true);
    setErr('');
    try {
      await onCreate({ name: cleanName, topic: topic.trim(), isPrivate, memberIds: selectedIds });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not create channel');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-channel-title"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <form ref={dialogRef} className="chat-modal-card" onSubmit={handleSubmit}>
        <div className="chat-modal-head">
          <h3 id="new-channel-title">Create channel</h3>
          <button type="button" className="chat-icon-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="chat-modal-body chat-scroll">
          {err && (
            <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.82rem' }}>
              {err}
            </div>
          )}
          <div className="chat-field">
            <label htmlFor="ch-name">Channel name</label>
            <input
              id="ch-name"
              placeholder="engineering"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              required
              autoFocus
            />
          </div>
          <div className="chat-field">
            <label htmlFor="ch-topic">Topic (optional)</label>
            <input
              id="ch-topic"
              placeholder="Release coordination and architecture notes"
              value={topic}
              onChange={(e) => setTopic(e.target.value)}
              maxLength={500}
            />
          </div>
          <label className="chat-checkbox-row">
            <input type="checkbox" checked={isPrivate} onChange={(e) => setIsPrivate(e.target.checked)} />
            <span>Private channel (invite only)</span>
          </label>

          {others.length > 0 && (
            <div className="chat-field">
              <label>Add teammates</label>
              <div className="chat-picker-list chat-scroll">
                {others.map((u) => (
                  <label key={u.id} className="chat-checkbox-row" style={{ padding: '0.32rem 0.45rem' }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(u.id)}
                      onChange={() => toggleMember(u.id)}
                    />
                    <span>
                      {u.display_name}{' '}
                      <span style={{ color: 'var(--ink)', fontSize: '0.78rem' }}>@{u.username}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="chat-modal-foot">
          <button type="button" className="btn-secondary" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" disabled={busy || !name.trim()}>
            {busy ? 'Creating…' : 'Create channel'}
          </button>
        </div>
      </form>
    </div>
  );
};

interface StartDMModalProps {
  directory: ChatDirectoryUser[];
  currentUserId: string;
  onClose: () => void;
  onSelectUser: (userId: string) => Promise<void>;
}

export const StartDMModal: React.FC<StartDMModalProps> = ({
  directory,
  currentUserId,
  onClose,
  onSelectUser,
}) => {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useModalFocus(dialogRef, onClose);

  const [filter, setFilter] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState('');

  const q = filter.trim().toLowerCase();
  const candidates = useMemo(
    () =>
      directory.filter((u) => {
        if (u.id === currentUserId) return false;
        if (!q) return true;
        return u.display_name.toLowerCase().includes(q) || u.username.toLowerCase().includes(q);
      }),
    [directory, currentUserId, q],
  );

  useEffect(() => {
    setActiveIdx(0);
  }, [q]);

  const handlePick = async (userId: string) => {
    setBusyId(userId);
    setErr('');
    try {
      await onSelectUser(userId);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not start direct message');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-dm-title"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && busyId === null) onClose();
      }}
    >
      <div ref={dialogRef} className="chat-modal-card">
        <div className="chat-modal-head">
          <h3 id="new-dm-title">New direct message</h3>
          <button type="button" className="chat-icon-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="chat-modal-body chat-scroll">
          {err && (
            <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.82rem' }}>
              {err}
            </div>
          )}
          <input
            aria-label="Filter teammates"
            placeholder="Search by name or username…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => {
              if (candidates.length === 0 || busyId !== null) return;
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIdx((i) => (i + 1) % candidates.length);
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => (i - 1 + candidates.length) % candidates.length);
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const target = candidates[activeIdx] ?? candidates[0];
                if (target) void handlePick(target.id);
              }
            }}
            autoFocus
          />
          <div className="chat-picker-list chat-scroll" role="listbox" aria-label="Teammates">
            {candidates.length === 0 ? (
              <p style={{ fontSize: '0.82rem', color: 'var(--ink)', padding: '0.6rem' }}>
                {directory.length <= 1 ? 'No other active accounts yet.' : 'No matching teammates.'}
              </p>
            ) : (
              candidates.map((u, idx) => (
                <button
                  key={u.id}
                  type="button"
                  role="option"
                  aria-selected={idx === activeIdx}
                  className={`chat-picker-item${idx === activeIdx ? ' is-active' : ''}`}
                  disabled={busyId !== null}
                  onMouseEnter={() => setActiveIdx(idx)}
                  onClick={() => void handlePick(u.id)}
                >
                  <span>{u.display_name}</span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--ink)' }}>
                    {busyId === u.id ? 'Opening…' : `@${u.username}`}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

interface SearchModalProps {
  rooms: ChatRoomSummary[];
  activeRoomId: string | null;
  onClose: () => void;
  onSelectHit: (roomId: string, seq?: number) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({ rooms, activeRoomId, onClose, onSelectHit }) => {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useModalFocus(dialogRef, onClose);

  const [query, setQuery] = useState('');
  const [scopeCurrent, setScopeCurrent] = useState(false);
  const [hits, setHits] = useState<ChatMessage[]>([]);
  const [activeIdx, setActiveIdx] = useState(0);
  const [searching, setSearching] = useState(false);
  const [err, setErr] = useState('');

  const roomById = useMemo(() => new Map(rooms.map((r) => [r.id, r])), [rooms]);

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setHits([]);
      setErr('');
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearching(true);
    setHits([]);
    setActiveIdx(0);
    setErr('');
    const timer = setTimeout(() => {
      void searchMessages(trimmed, scopeCurrent && activeRoomId ? activeRoomId : undefined)
        .then((res) => {
          if (!cancelled) {
            setHits(res);
            setActiveIdx(0);
          }
        })
        .catch((e) => {
          if (!cancelled) setErr(e instanceof Error ? e.message : 'Search failed');
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 220);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query, scopeCurrent, activeRoomId]);

  const selectHit = (hit: ChatMessage) => {
    onSelectHit(hit.room_id, hit.seq);
    onClose();
  };

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="chat-search-title"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div ref={dialogRef} className="chat-modal-card">
        <div className="chat-modal-head">
          <h3 id="chat-search-title" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
            <Search size={16} aria-hidden="true" />
            Search messages
          </h3>
          <button type="button" className="chat-icon-btn" onClick={onClose} aria-label="Close search">
            <X size={16} />
          </button>
        </div>
        <div className="chat-modal-body chat-scroll">
          <input
            aria-label="Search messages"
            placeholder="Search across your joined rooms…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (hits.length === 0) return;
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIdx((i) => (i + 1) % hits.length);
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIdx((i) => (i - 1 + hits.length) % hits.length);
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const target = hits[activeIdx] ?? hits[0];
                if (target) selectHit(target);
              }
            }}
            autoFocus
          />

          {activeRoomId && (
            <label className="chat-checkbox-row" style={{ fontSize: '0.8rem' }}>
              <input
                type="checkbox"
                checked={scopeCurrent}
                onChange={(e) => setScopeCurrent(e.target.checked)}
              />
              <span>Only in {roomById.get(activeRoomId)?.name || 'current room'}</span>
            </label>
          )}

          {err && (
            <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.82rem' }}>
              {err}
            </div>
          )}

          {searching ? (
            <p style={{ fontSize: '0.82rem', color: 'var(--ink)' }}>Searching…</p>
          ) : query.trim() && hits.length === 0 ? (
            <p style={{ fontSize: '0.82rem', color: 'var(--ink)' }}>No matching messages found.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }} role="listbox" aria-label="Search results">
              {hits.map((hit, idx) => {
                const room = roomById.get(hit.room_id);
                return (
                  <button
                    key={hit.id}
                    type="button"
                    role="option"
                    aria-selected={idx === activeIdx}
                    className={`chat-search-hit${idx === activeIdx ? ' is-active' : ''}`}
                    onMouseEnter={() => setActiveIdx(idx)}
                    onClick={() => selectHit(hit)}
                  >
                    <div className="chat-search-hit-meta">
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontWeight: 600 }}>
                        {room?.kind === 'meeting' ? (
                          <Video size={11} aria-hidden="true" />
                        ) : room?.kind === 'dm' ? (
                          <MessageSquare size={11} aria-hidden="true" />
                        ) : room?.is_private ? (
                          <Lock size={11} aria-hidden="true" />
                        ) : (
                          <Hash size={11} aria-hidden="true" />
                        )}
                        {room?.name || 'Room'}
                      </span>
                      <span>·</span>
                      <span>{hit.sender_name || 'Member'}</span>
                      {isWebhookSender(hit.sender_id) && <span className="chat-msg-badge">Webhook</span>}
                      <span>·</span>
                      <span>{formatTime(hit.created_at)}</span>
                    </div>
                    <div className="chat-search-hit-body">{highlightQuery(hit.body, query)}</div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
