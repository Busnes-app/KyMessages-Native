import React, { useMemo, useRef, useState, useEffect } from 'react';
import { Autocomplete } from '@base-ui/react/autocomplete';
import { Combobox } from '@base-ui/react/combobox';
import { Dialog } from '@base-ui/react/dialog';
import { Hash, Lock, MessageSquare, Search, Video, X } from 'lucide-react';
import type { ChatDirectoryUser, ChatMessage, ChatRoomSummary } from '../../chat/types';
import { searchMessages } from '../../chat/client';
import { formatTime, isBotSender, isWebhookSender } from '../../chat/state';

interface ChatDialogProps {
  title: React.ReactNode;
  titleStyle?: React.CSSProperties;
  closeLabel?: string;
  onClose: () => void;
  // While busy, a press outside the card does not close it; Escape and Close still do.
  busy?: boolean;
  onSubmit?: (e: React.FormEvent<HTMLFormElement>) => void;
  // The body and footer, below the titled header.
  children: React.ReactNode;
}

// ChatDialog is a chat modal on Base UI's Dialog, portalled to body: focus moves in (an
// autoFocus field that already holds it keeps it, otherwise the first control), Tab stays
// inside, Escape, Close and a press on the backdrop close it, focus returns to the opener
// and the page behind does not scroll.
function ChatDialog({ title, titleStyle, closeLabel = 'Close', onClose, busy = false, onSubmit, children }: ChatDialogProps) {
  const popup = useRef<HTMLDivElement | null>(null);
  // The opener, read before an autoFocus field takes focus: Base UI notes the element focused
  // when its popup mounts, which by then is that field, gone once the dialog closes.
  const [opener] = useState(() => document.activeElement);
  return (
    <Dialog.Root
      open
      disablePointerDismissal={busy}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="modal-backdrop" />
        <Dialog.Popup
          ref={popup}
          className="chat-modal-card chat-dialog"
          initialFocus={() =>
            popup.current?.contains(document.activeElement) ? (document.activeElement as HTMLElement) : true
          }
          finalFocus={() => (opener instanceof HTMLElement && opener !== document.body && opener.isConnected ? opener : true)}
          render={onSubmit ? <form onSubmit={onSubmit} /> : undefined}
        >
          <div className="chat-modal-head">
            <Dialog.Title render={<h3 style={titleStyle} />}>{title}</Dialog.Title>
            <button type="button" className="chat-icon-btn" onClick={onClose} aria-label={closeLabel}>
              <X size={16} />
            </button>
          </div>
          {children}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// matchesUser is the teammate pickers' filter: display name or username, case-insensitive.
function matchesUser(u: ChatDirectoryUser, q: string): boolean {
  return !q || u.display_name.toLowerCase().includes(q) || u.username.toLowerCase().includes(q);
}

// Only typing changes a picker's query: Base UI also reports highlight, Escape and item presses.
function typed(reason: string): boolean {
  return reason === 'input-change' || reason === 'input-clear';
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
  const [name, setName] = useState('');
  const [topic, setTopic] = useState('');
  const [isPrivate, setIsPrivate] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const [memberQuery, setMemberQuery] = useState('');

  const others = directory.filter((u) => u.id !== currentUserId);
  const byId = new Map(others.map((u) => [u.id, u]));
  const mq = memberQuery.trim().toLowerCase();
  const shownIds = others.filter((u) => matchesUser(u, mq)).map((u) => u.id);

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
    <ChatDialog title="Create channel" onClose={onClose} busy={busy} onSubmit={handleSubmit}>
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
            <label htmlFor="ch-members">Add teammates</label>
            {/* Base UI's multi-select Combobox: arrows move through the teammates from the
                box, Enter or a click toggles one, and the box narrows the list. */}
            <Combobox.Root
              multiple
              inline
              open
              items={shownIds}
              filter={null}
              itemToStringLabel={(id: string) => byId.get(id)?.display_name ?? id}
              value={selectedIds}
              onValueChange={(ids) => setSelectedIds(ids)}
              inputValue={memberQuery}
              onInputValueChange={(v, d) => {
                if (typed(d.reason)) setMemberQuery(v);
              }}
            >
              {/* Enter here toggles the highlighted teammate (Base UI handles it on the box
                  first) and never submits the form, even with nothing highlighted. */}
              <div
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.nativeEvent.isComposing) e.preventDefault();
                }}
              >
                <Combobox.Input id="ch-members" placeholder="Search by name or username…" disabled={busy} />
              </div>
              <Combobox.List className="chat-picker-list chat-scroll" aria-label="Teammates">
                {shownIds.length === 0 ? (
                  <p style={{ fontSize: '0.82rem', color: 'var(--ink)', padding: '0.6rem' }}>No matching teammates.</p>
                ) : (
                  shownIds.map((id) => {
                    const u = byId.get(id)!;
                    return (
                      <Combobox.Item key={id} value={id} className="chat-checkbox-row chat-member-option" disabled={busy}>
                        {/* The native box keeps the old look; the option carries the state. */}
                        <input type="checkbox" checked={selectedIds.includes(id)} readOnly tabIndex={-1} aria-hidden="true" />
                        <span>
                          {u.display_name}{' '}
                          <span style={{ color: 'var(--ink)', fontSize: '0.78rem' }}>@{u.username}</span>
                        </span>
                      </Combobox.Item>
                    );
                  })
                )}
              </Combobox.List>
            </Combobox.Root>
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
    </ChatDialog>
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
  const candidates = useMemo(
    () =>
      directory.filter((u) => u.id !== currentUserId && matchesUser(u, q)),
    [directory, currentUserId, q],
  );

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
    <ChatDialog title="New direct message" onClose={onClose} busy={busyId !== null}>
      <div className="chat-modal-body chat-scroll">
        {err && (
          <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.82rem' }}>
            {err}
          </div>
        )}
        {/* Base UI's Autocomplete: arrows move through the teammates from the box and Enter
            opens the highlighted one (the first until the arrows or the pointer move it). */}
        <Autocomplete.Root
          inline
          open
          autoHighlight="always"
          keepHighlight
          items={candidates}
          filter={null}
          itemToStringValue={(u: ChatDirectoryUser) => u.display_name}
          value={filter}
          onValueChange={(v, d) => {
            if (typed(d.reason)) setFilter(v);
          }}
        >
          <Autocomplete.Input aria-label="Filter teammates" placeholder="Search by name or username…" autoFocus />
          <Autocomplete.List className="chat-picker-list chat-scroll" aria-label="Teammates">
            {candidates.length === 0 ? (
              <p style={{ fontSize: '0.82rem', color: 'var(--ink)', padding: '0.6rem' }}>
                {directory.length <= 1 ? 'No other active accounts yet.' : 'No matching teammates.'}
              </p>
            ) : (
              candidates.map((u) => (
                <Autocomplete.Item
                  key={u.id}
                  value={u}
                  className="chat-picker-item"
                  disabled={busyId !== null}
                  onClick={() => void handlePick(u.id)}
                >
                  <span>{u.display_name}</span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--ink)' }}>
                    {busyId === u.id ? 'Opening…' : `@${u.username}`}
                  </span>
                </Autocomplete.Item>
              ))
            )}
          </Autocomplete.List>
        </Autocomplete.Root>
      </div>
    </ChatDialog>
  );
};

interface SearchModalProps {
  rooms: ChatRoomSummary[];
  activeRoomId: string | null;
  onClose: () => void;
  onSelectHit: (roomId: string, seq?: number) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({ rooms, activeRoomId, onClose, onSelectHit }) => {
  const [query, setQuery] = useState('');
  const [scopeCurrent, setScopeCurrent] = useState(false);
  const [hits, setHits] = useState<ChatMessage[]>([]);
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
    setErr('');
    const timer = setTimeout(() => {
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

  const selectHit = (hit: ChatMessage) => {
    onSelectHit(hit.room_id, hit.seq);
    onClose();
  };

  return (
    <ChatDialog
      title={
        <>
          <Search size={16} aria-hidden="true" />
          Search messages
        </>
      }
      titleStyle={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}
      closeLabel="Close search"
      onClose={onClose}
    >
      <div className="chat-modal-body chat-scroll">
        {/* Base UI's Autocomplete: arrows move through the results from the box and Enter
            opens the highlighted one (the first until the arrows or the pointer move it). */}
        <Autocomplete.Root
          inline
          open
          autoHighlight="always"
          keepHighlight
          items={hits}
          filter={null}
          itemToStringValue={(hit: ChatMessage) => hit.body}
          value={query}
          onValueChange={(v, d) => {
            if (typed(d.reason)) setQuery(v);
          }}
        >
          <Autocomplete.Input aria-label="Search messages" placeholder="Search across your joined rooms…" autoFocus />

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
            <Autocomplete.List
              style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}
              aria-label="Search results"
            >
              {hits.map((hit) => {
                const room = roomById.get(hit.room_id);
                return (
                  <Autocomplete.Item key={hit.id} value={hit} className="chat-search-hit" onClick={() => selectHit(hit)}>
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
                      {isBotSender(hit.sender_id) && <span className="chat-msg-badge">Bot</span>}
                      <span>·</span>
                      <span>{formatTime(hit.created_at)}</span>
                    </div>
                    <div className="chat-search-hit-body">{highlightQuery(hit.body, query)}</div>
                  </Autocomplete.Item>
                );
              })}
            </Autocomplete.List>
          )}
        </Autocomplete.Root>
      </div>
    </ChatDialog>
  );
};
