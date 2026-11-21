import React, { useEffect, useState } from 'react';
import { Hash, Search, X } from 'lucide-react';
import type { ChatDirectoryUser, ChatMessage, ChatRoomSummary } from '../../chat/types';
import { searchMessages } from '../../chat/client';
import { formatTime, isWebhookSender } from '../../chat/state';

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
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="new-channel-title">
      <form className="chat-modal-card" onSubmit={handleSubmit}>
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
  const [filter, setFilter] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState('');

  const q = filter.trim().toLowerCase();
  const candidates = directory.filter((u) => {
    if (u.id === currentUserId) return false;
    if (!q) return true;
    return u.display_name.toLowerCase().includes(q) || u.username.toLowerCase().includes(q);
  });

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
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="new-dm-title">
      <div className="chat-modal-card">
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
            autoFocus
          />
          <div className="chat-picker-list chat-scroll">
            {candidates.length === 0 ? (
              <p style={{ fontSize: '0.82rem', color: 'var(--ink)', padding: '0.6rem' }}>
                {directory.length <= 1 ? 'No other active accounts yet.' : 'No matching teammates.'}
              </p>
            ) : (
              candidates.map((u) => (
                <button
                  key={u.id}
                  type="button"
                  className="chat-picker-item"
                  disabled={busyId !== null}
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
  onSelectHit: (roomId: string) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({ rooms, activeRoomId, onClose, onSelectHit }) => {
  const [query, setQuery] = useState('');
  const [scopeCurrent, setScopeCurrent] = useState(false);
  const [hits, setHits] = useState<ChatMessage[]>([]);
  const [searching, setSearching] = useState(false);
  const [err, setErr] = useState('');

  const roomById = new Map(rooms.map((r) => [r.id, r]));

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setHits([]);
      setErr('');
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      setSearching(true);
      setErr('');
      void searchMessages(trimmed, scopeCurrent && activeRoomId ? activeRoomId : undefined)
        .then((res) => {
          if (!cancelled) setHits(res);
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

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="chat-search-title">
      <div className="chat-modal-card">
        <div className="chat-modal-head">
          <h3 id="chat-search-title" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
            <Search size={16} />
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
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              {hits.map((hit) => {
                const room = roomById.get(hit.room_id);
                return (
                  <button
                    key={hit.id}
                    type="button"
                    className="chat-search-hit"
                    onClick={() => {
                      onSelectHit(hit.room_id);
                      onClose();
                    }}
                  >
                    <div className="chat-search-hit-meta">
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontWeight: 600 }}>
                        <Hash size={11} />
                        {room?.name || 'Room'}
                      </span>
                      <span>·</span>
                      <span>{hit.sender_name || 'Member'}</span>
                      {isWebhookSender(hit.sender_id) && <span className="chat-msg-badge">Webhook</span>}
                      <span>·</span>
                      <span>{formatTime(hit.created_at)}</span>
                    </div>
                    <div className="chat-search-hit-body">{hit.body}</div>
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
