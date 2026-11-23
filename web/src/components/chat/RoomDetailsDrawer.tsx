import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AtSign,
  Bell,
  BellOff,
  Check,
  Copy,
  ExternalLink,
  Hash,
  Info,
  Link2,
  Lock,
  LogOut,
  MessageSquare,
  PanelRightClose,
  Search,
  UserMinus,
  UserPlus,
  Users,
  Video,
  X,
} from 'lucide-react';
import type {
  ChatDirectoryUser,
  ChatMessage,
  ChatRoomDetail,
  LobbyGuest,
  NotifyMode,
} from '../../chat/types';
import {
  addRoomMember,
  removeRoomMember,
  updateRoomInfo,
  updateRoomNotifyMode,
} from '../../chat/client';
import { formatTime, initialsFor, isBotSender } from '../../chat/state';

export type DrawerTab = 'about' | 'members' | 'shared';
const DRAWER_TABS: DrawerTab[] = ['about', 'members', 'shared'];

interface SharedLinkItem {
  url: string;
  host: string;
  senderName: string;
  createdAt: number;
  messageId: string;
}

const URL_RE = /https?:\/\/[^\s<>()[\]"']+/gi;

function extractSharedLinks(messages: ChatMessage[]): SharedLinkItem[] {
  const seen = new Set<string>();
  const items: SharedLinkItem[] = [];
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.deleted_at || !msg.body) continue;
    const matches = msg.body.match(URL_RE);
    if (!matches) continue;
    for (const raw of matches) {
      const cleaned = raw.replace(/[.,!?;:]+$/, '');
      if (seen.has(cleaned)) continue;
      try {
        const parsed = new URL(cleaned);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
        seen.add(cleaned);
        items.push({
          url: cleaned,
          host: parsed.hostname.replace(/^www\./, ''),
          senderName: msg.sender_name || 'Teammate',
          createdAt: msg.created_at,
          messageId: msg.id,
        });
      } catch {
        // Ignore malformed URLs.
      }
    }
  }
  return items;
}

function formatCreatedDate(ms: number): string {
  if (!ms) return '';
  return new Date(ms).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
}

interface RoomDetailsDrawerProps {
  detail: ChatRoomDetail | null;
  loading: boolean;
  currentUserId: string;
  isGlobalAdmin: boolean;
  directory: ChatDirectoryUser[];
  messages: ChatMessage[];
  lobbyGuests?: LobbyGuest[];
  requestedTab?: { tab: DrawerTab; seq: number } | null;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onLeftRoom: (roomId: string) => void;
  onOpenSearch: () => void;
  onStartDM: (userId: string) => Promise<void>;
  onDecideLobby?: (guestId: string, admit: boolean) => Promise<void>;
  onAdmitAllLobby?: () => Promise<void>;
  onCreateGuestLink?: () => Promise<string>;
  onNotifyModeChanged?: (roomId: string, mode: NotifyMode) => void;
}

export const RoomDetailsDrawer: React.FC<RoomDetailsDrawerProps> = ({
  detail,
  loading,
  currentUserId,
  isGlobalAdmin,
  directory,
  messages,
  lobbyGuests = [],
  requestedTab = null,
  onClose,
  onRefresh,
  onLeftRoom,
  onOpenSearch,
  onStartDM,
  onDecideLobby,
  onAdmitAllLobby,
  onCreateGuestLink,
  onNotifyModeChanged,
}) => {
  const [tab, setTab] = useState<DrawerTab>('about');
  const [name, setName] = useState('');
  const [topic, setTopic] = useState('');
  const [savingInfo, setSavingInfo] = useState(false);
  const [notifyMode, setNotifyMode] = useState<NotifyMode>('all');
  const [savingNotify, setSavingNotify] = useState(false);
  const [memberFilter, setMemberFilter] = useState('');
  const [addUserId, setAddUserId] = useState('');
  const [busyAction, setBusyAction] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [guestLink, setGuestLink] = useState('');
  const [copiedGuestLink, setCopiedGuestLink] = useState(false);
  const [confirmLeave, setConfirmLeave] = useState(false);
  const [confirmRemoveId, setConfirmRemoveId] = useState<string | null>(null);
  const [decidingGuestIds, setDecidingGuestIds] = useState<Record<string, boolean>>({});
  const [admittingAll, setAdmittingAll] = useState(false);
  const [err, setErr] = useState('');

  const tabRefs = useRef<Record<DrawerTab, HTMLButtonElement | null>>({
    about: null,
    members: null,
    shared: null,
  });

  const room = detail?.room;
  const memberRole = detail?.member.role ?? 'member';
  const canModerate = isGlobalAdmin || memberRole === 'owner' || memberRole === 'admin';
  const isDM = room?.kind === 'dm';
  const isMeeting = room?.kind === 'meeting';

  useEffect(() => {
    if (requestedTab) {
      setTab(requestedTab.tab);
    }
  }, [requestedTab]);

  useEffect(() => {
    setGuestLink('');
    setCopiedGuestLink(false);
    setConfirmLeave(false);
    setConfirmRemoveId(null);
    setDecidingGuestIds({});
    setMemberFilter('');
    setErr('');
  }, [room?.id]);

  useEffect(() => {
    if (!room) return;
    setName(room.name);
    setTopic(room.topic);
  }, [room?.id, room?.name, room?.topic]);

  useEffect(() => {
    const raw = detail?.member.notify_mode;
    if (raw === 'mentions' || raw === 'mute' || raw === 'all') {
      setNotifyMode(raw);
    } else {
      setNotifyMode('all');
    }
  }, [room?.id, detail?.member.notify_mode]);

  const userLookup = useMemo(() => new Map(directory.map((u) => [u.id, u])), [directory]);
  const memberIdSet = useMemo(() => new Set((detail?.members ?? []).map((m) => m.user_id)), [detail?.members]);
  const addableUsers = useMemo(
    () => directory.filter((u) => !memberIdSet.has(u.id)),
    [directory, memberIdSet],
  );
  const sharedLinks = useMemo(() => extractSharedLinks(messages), [messages]);
  const visibleMembers = useMemo(() => {
    const members = detail?.members ?? [];
    const q = memberFilter.trim().toLowerCase();
    if (!q) return members;
    return members.filter((m) => {
      const dirUser = userLookup.get(m.user_id);
      const display = (dirUser?.display_name || '').toLowerCase();
      const uname = (dirUser?.username || '').toLowerCase();
      return display.includes(q) || uname.includes(q) || m.role.toLowerCase().includes(q);
    });
  }, [detail?.members, memberFilter, userLookup]);

  const handleSaveInfo = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!room || !name.trim()) return;
    setSavingInfo(true);
    setErr('');
    try {
      await updateRoomInfo(room.id, { name: name.trim(), topic: topic.trim() });
      await onRefresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not update room');
    } finally {
      setSavingInfo(false);
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!room || !addUserId) return;
    setBusyAction(true);
    setErr('');
    try {
      await addRoomMember(room.id, addUserId);
      setAddUserId('');
      await onRefresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not add member');
    } finally {
      setBusyAction(false);
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!room) return;
    setBusyAction(true);
    setErr('');
    try {
      await removeRoomMember(room.id, userId);
      setConfirmLeave(false);
      setConfirmRemoveId(null);
      if (userId === currentUserId) {
        onLeftRoom(room.id);
      } else {
        await onRefresh();
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not remove member');
    } finally {
      setBusyAction(false);
    }
  };

  const handleMessageMember = async (userId: string) => {
    setBusyAction(true);
    setErr('');
    try {
      await onStartDM(userId);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not open direct message');
    } finally {
      setBusyAction(false);
    }
  };

  const handleLobbyDecision = async (guestId: string, admit: boolean) => {
    if (!onDecideLobby || decidingGuestIds[guestId]) return;
    setDecidingGuestIds((prev) => ({ ...prev, [guestId]: true }));
    try {
      await onDecideLobby(guestId, admit);
    } finally {
      setDecidingGuestIds((prev) => {
        const copy = { ...prev };
        delete copy[guestId];
        return copy;
      });
    }
  };

  const handleAdmitAll = async () => {
    if (!onAdmitAllLobby || admittingAll) return;
    setAdmittingAll(true);
    try {
      await onAdmitAllLobby();
    } finally {
      setAdmittingAll(false);
    }
  };

  const copyRoomLink = async () => {
    if (!room) return;
    const link = `${window.location.origin}/?room=${encodeURIComponent(room.id)}`;
    try {
      await navigator.clipboard.writeText(link);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  const handleTabKeyDown = (e: React.KeyboardEvent, current: DrawerTab) => {
    const idx = DRAWER_TABS.indexOf(current);
    let nextIdx = -1;
    if (e.key === 'ArrowRight') nextIdx = (idx + 1) % DRAWER_TABS.length;
    else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + DRAWER_TABS.length) % DRAWER_TABS.length;
    else if (e.key === 'Home') nextIdx = 0;
    else if (e.key === 'End') nextIdx = DRAWER_TABS.length - 1;
    if (nextIdx >= 0) {
      e.preventDefault();
      const nextTab = DRAWER_TABS[nextIdx];
      setTab(nextTab);
      tabRefs.current[nextTab]?.focus();
    }
  };

  const sharedBadgeCount = sharedLinks.length;

  return (
    <aside className="chat-drawer" aria-label="Room panel">
      <div className="chat-drawer-head">
        <h3>{isDM ? 'Conversation' : isMeeting ? 'Meeting details' : 'Room details'}</h3>
        <button
          type="button"
          className="chat-icon-btn"
          onClick={onClose}
          title="Collapse room panel"
          aria-label="Collapse room panel"
        >
          <PanelRightClose size={16} />
        </button>
      </div>

      <div className="chat-drawer-tabs" role="tablist" aria-label="Room sections">
        <button
          ref={(el) => {
            tabRefs.current.about = el;
          }}
          id="drawer-tab-about"
          type="button"
          role="tab"
          aria-selected={tab === 'about'}
          aria-controls="drawer-panel-about"
          tabIndex={tab === 'about' ? 0 : -1}
          className={tab === 'about' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('about')}
          onKeyDown={(e) => handleTabKeyDown(e, 'about')}
        >
          <Info size={14} aria-hidden="true" />
          <span>About</span>
          {lobbyGuests.length > 0 && <span className="chat-tab-count">{lobbyGuests.length}</span>}
        </button>
        <button
          ref={(el) => {
            tabRefs.current.members = el;
          }}
          id="drawer-tab-members"
          type="button"
          role="tab"
          aria-selected={tab === 'members'}
          aria-controls="drawer-panel-members"
          tabIndex={tab === 'members' ? 0 : -1}
          className={tab === 'members' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('members')}
          onKeyDown={(e) => handleTabKeyDown(e, 'members')}
        >
          <Users size={14} aria-hidden="true" />
          <span>Members</span>
          {detail && <span className="chat-tab-count">{detail.members.length}</span>}
        </button>
        <button
          ref={(el) => {
            tabRefs.current.shared = el;
          }}
          id="drawer-tab-shared"
          type="button"
          role="tab"
          aria-selected={tab === 'shared'}
          aria-controls="drawer-panel-shared"
          tabIndex={tab === 'shared' ? 0 : -1}
          className={tab === 'shared' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('shared')}
          onKeyDown={(e) => handleTabKeyDown(e, 'shared')}
        >
          <Link2 size={14} aria-hidden="true" />
          <span>Shared</span>
          {sharedBadgeCount > 0 && <span className="chat-tab-count">{sharedBadgeCount}</span>}
        </button>
      </div>

      <div className="chat-drawer-body chat-scroll">
        {err && (
          <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.8rem' }}>
            {err}
          </div>
        )}

        {loading || !room ? (
          <p className="chat-drawer-muted">Loading room details…</p>
        ) : (
          <>
            {tab === 'about' && (
              <div id="drawer-panel-about" role="tabpanel" aria-labelledby="drawer-tab-about" className="chat-drawer-panel">
                <div className="chat-room-summary">
                  <div className="chat-room-summary-head">
                    <span className="chat-room-summary-badge" aria-hidden="true">
                      {isDM ? (
                        initialsFor(room.name || 'DM')
                      ) : isMeeting ? (
                        <Video size={16} />
                      ) : room.is_private ? (
                        <Lock size={16} />
                      ) : (
                        <Hash size={16} />
                      )}
                    </span>
                    <div className="chat-room-summary-copy">
                      <div className="chat-room-summary-name">{room.name || 'Direct message'}</div>
                      <div className="chat-room-summary-kind">
                        {isDM
                          ? 'Direct message'
                          : isMeeting
                            ? 'Meeting room'
                            : room.is_private
                              ? 'Private channel'
                              : 'Public channel'}
                      </div>
                    </div>
                  </div>
                  {room.topic && <p className="chat-room-summary-topic">{room.topic}</p>}
                  <dl className="chat-room-facts">
                    <div>
                      <dt>Members</dt>
                      <dd>{detail.members.length}</dd>
                    </div>
                    <div>
                      <dt>Messages</dt>
                      <dd>{room.last_seq}</dd>
                    </div>
                    <div>
                      <dt>Created</dt>
                      <dd>{formatCreatedDate(room.created_at)}</dd>
                    </div>
                  </dl>
                </div>

                <div className="chat-quick-actions">
                  <button type="button" className="chat-quick-btn" onClick={onOpenSearch}>
                    <Search size={14} aria-hidden="true" />
                    <span>Search</span>
                  </button>
                  <button type="button" className="chat-quick-btn" onClick={() => void copyRoomLink()}>
                    {copiedLink ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
                    <span>{copiedLink ? 'Copied' : 'Copy link'}</span>
                  </button>
                  {!isDM && onCreateGuestLink && (
                    <button
                      type="button"
                      className="chat-quick-btn"
                      disabled={busyAction}
                      onClick={() => {
                        setBusyAction(true);
                        setErr('');
                        void onCreateGuestLink()
                          .then(async (url) => {
                            setGuestLink(url);
                            try {
                              await navigator.clipboard.writeText(url);
                              setCopiedGuestLink(true);
                              setTimeout(() => setCopiedGuestLink(false), 1800);
                            } catch {
                              // Clipboard unavailable; URL is still displayed below.
                            }
                          })
                          .catch((e) => setErr(e instanceof Error ? e.message : 'Could not create guest link'))
                          .finally(() => setBusyAction(false));
                      }}
                    >
                      {copiedGuestLink ? <Check size={14} aria-hidden="true" /> : <Link2 size={14} aria-hidden="true" />}
                      <span>{copiedGuestLink ? 'Copied!' : 'Guest link'}</span>
                    </button>
                  )}
                  {!isDM && !confirmLeave && (
                    <button
                      type="button"
                      className="chat-quick-btn danger"
                      disabled={busyAction}
                      onClick={() => setConfirmLeave(true)}
                    >
                      <LogOut size={14} aria-hidden="true" />
                      <span>Leave</span>
                    </button>
                  )}
                </div>

                {!isDM && confirmLeave && (
                  <div className="chat-confirm-bar" role="alert">
                    <span>Leave {room.name || 'this room'}?</span>
                    <div className="chat-confirm-bar-actions">
                      <button
                        type="button"
                        className="ky-lobby-btn is-deny"
                        disabled={busyAction}
                        onClick={() => void handleRemoveMember(currentUserId)}
                      >
                        Leave room
                      </button>
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={busyAction}
                        onClick={() => setConfirmLeave(false)}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                <section className="chat-drawer-section" aria-label="Room notifications">
                  <div className="chat-drawer-section-head">
                    <h4>Notifications</h4>
                  </div>
                  <div className="chat-notify-segment" role="radiogroup" aria-label="Notification preference">
                    {(
                      [
                        { value: 'all', label: 'All', icon: Bell },
                        { value: 'mentions', label: 'Mentions', icon: AtSign },
                        { value: 'mute', label: 'Mute', icon: BellOff },
                      ] as const
                    ).map(({ value, label, icon: Icon }) => {
                      const active = notifyMode === value;
                      return (
                        <button
                          key={value}
                          type="button"
                          role="radio"
                          aria-checked={active}
                          disabled={savingNotify}
                          className={`chat-notify-option${active ? ' active' : ''}`}
                          onClick={() => {
                            if (active || savingNotify) return;
                            const prevMode = notifyMode;
                            setNotifyMode(value);
                            setSavingNotify(true);
                            setErr('');
                            void updateRoomNotifyMode(room.id, value)
                              .then((saved) => {
                                setNotifyMode(saved);
                                onNotifyModeChanged?.(room.id, saved);
                              })
                              .catch((e) => {
                                setNotifyMode(prevMode);
                                setErr(
                                  e instanceof Error ? e.message : 'Could not update notification preference',
                                );
                              })
                              .finally(() => setSavingNotify(false));
                          }}
                        >
                          <Icon size={13} aria-hidden="true" />
                          <span>{label}</span>
                        </button>
                      );
                    })}
                  </div>
                </section>

                {guestLink && (
                  <section className="chat-drawer-section">
                    <div className="chat-drawer-section-head">
                      <h4>External guest invite link</h4>
                    </div>
                    <div className="ky-guest-link-box">
                      <input
                        type="text"
                        readOnly
                        aria-label="External guest invite link"
                        value={guestLink}
                        onFocus={(e) => e.currentTarget.select()}
                      />
                      <button
                        type="button"
                        className="chat-icon-btn"
                        title="Copy guest link"
                        aria-label="Copy guest link"
                        onClick={() => {
                          void navigator.clipboard.writeText(guestLink).then(() => {
                            setCopiedGuestLink(true);
                            setTimeout(() => setCopiedGuestLink(false), 1800);
                          }).catch(() => undefined);
                        }}
                      >
                        {copiedGuestLink ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    </div>
                  </section>
                )}

                {lobbyGuests.length > 0 && onDecideLobby && (
                  <section className="chat-drawer-section">
                    <div className="chat-drawer-section-head">
                      <h4>Waiting room ({lobbyGuests.length})</h4>
                      {lobbyGuests.length > 1 && onAdmitAllLobby && (
                        <button
                          type="button"
                          className="chat-drawer-link-btn"
                          disabled={admittingAll}
                          onClick={() => void handleAdmitAll()}
                        >
                          {admittingAll ? 'Admitting…' : 'Admit all'}
                        </button>
                      )}
                    </div>
                    <div className="ky-lobby-list">
                      {lobbyGuests.map((g) => {
                        const deciding = Boolean(decidingGuestIds[g.guest_id]) || admittingAll;
                        return (
                          <div key={g.guest_id} className="ky-lobby-row">
                            <span className="ky-lobby-name">{g.display_name}</span>
                            <div className="ky-lobby-actions">
                              <button
                                type="button"
                                className="ky-lobby-btn is-admit"
                                disabled={deciding}
                                onClick={() => void handleLobbyDecision(g.guest_id, true)}
                              >
                                Admit
                              </button>
                              <button
                                type="button"
                                className="ky-lobby-btn is-deny"
                                disabled={deciding}
                                onClick={() => void handleLobbyDecision(g.guest_id, false)}
                              >
                                Deny
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </section>
                )}

                {sharedLinks.length > 0 && (
                  <section className="chat-drawer-section">
                    <div className="chat-drawer-section-head">
                      <h4>Recent links</h4>
                      <button
                        type="button"
                        className="chat-drawer-link-btn"
                        onClick={() => setTab('shared')}
                      >
                        See all ({sharedLinks.length})
                      </button>
                    </div>
                    <div className="chat-shared-list">
                      {sharedLinks.slice(0, 3).map((item) => (
                        <a
                          key={item.url}
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="chat-shared-link"
                        >
                          <div className="chat-shared-link-copy">
                            <span className="chat-shared-link-host">{item.host}</span>
                            <span className="chat-shared-link-url">{item.url}</span>
                          </div>
                          <ExternalLink size={13} aria-hidden="true" />
                        </a>
                      ))}
                    </div>
                  </section>
                )}

                {!isDM && canModerate && (
                  <form className="chat-drawer-section" onSubmit={handleSaveInfo}>
                    <h4>{isMeeting ? 'Meeting settings' : 'Channel settings'}</h4>
                    <div className="chat-field">
                      <label htmlFor="drawer-room-name">Name</label>
                      <input
                        id="drawer-room-name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        maxLength={100}
                        required
                      />
                    </div>
                    <div className="chat-field">
                      <label htmlFor="drawer-room-topic">Topic</label>
                      <input
                        id="drawer-room-topic"
                        value={topic}
                        onChange={(e) => setTopic(e.target.value)}
                        placeholder="What is this room about?"
                        maxLength={500}
                      />
                    </div>
                    <button type="submit" disabled={savingInfo || !name.trim()} style={{ alignSelf: 'flex-start' }}>
                      {savingInfo ? 'Saving…' : 'Save changes'}
                    </button>
                  </form>
                )}
              </div>
            )}

            {tab === 'members' && (
              <div id="drawer-panel-members" role="tabpanel" aria-labelledby="drawer-tab-members" className="chat-drawer-panel">
                <section className="chat-drawer-section">
                  {detail.members.length > 3 && (
                    <input
                      type="search"
                      aria-label="Filter members"
                      placeholder="Filter people…"
                      value={memberFilter}
                      onChange={(e) => setMemberFilter(e.target.value)}
                      className="chat-drawer-filter"
                    />
                  )}

                  {!isDM && canModerate && addableUsers.length > 0 && (
                    <form onSubmit={handleAddMember} className="chat-drawer-inline-form">
                      <select
                        aria-label="Add member to channel"
                        value={addUserId}
                        onChange={(e) => setAddUserId(e.target.value)}
                      >
                        <option value="">Add teammate…</option>
                        {addableUsers.map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.display_name} (@{u.username}){u.role === 'bot' || isBotSender(u.id) ? ' · Bot' : ''}
                          </option>
                        ))}
                      </select>
                      <button
                        type="submit"
                        className="btn-secondary"
                        disabled={busyAction || !addUserId}
                        aria-label="Add selected member"
                      >
                        <UserPlus size={15} />
                      </button>
                    </form>
                  )}

                  <div>
                    {visibleMembers.length === 0 ? (
                      <p className="chat-drawer-muted">No matching members.</p>
                    ) : (
                      visibleMembers.map((m) => {
                        const dirUser = userLookup.get(m.user_id);
                        const label = dirUser?.display_name || dirUser?.username || m.user_id;
                        const isSelf = m.user_id === currentUserId;
                        const isBot = m.role === 'bot' || dirUser?.role === 'bot' || isBotSender(m.user_id);
                        const canRemove = !isDM && (isSelf || (canModerate && m.role !== 'owner'));
                        const confirming = confirmRemoveId === m.user_id;
                        return (
                          <div key={m.user_id} className="chat-member-row">
                            <span className="chat-member-avatar" aria-hidden="true">
                              {initialsFor(label)}
                            </span>
                            <div className="chat-member-copy">
                              <div className="chat-member-name">
                                {label}
                                {isSelf ? ' (you)' : ''}
                                {isBot && <span className="chat-msg-badge" style={{ marginLeft: '6px' }}>Bot</span>}
                              </div>
                              <div className="chat-member-role">
                                {dirUser?.username ? `@${dirUser.username} · ` : ''}
                                {m.role}
                              </div>
                            </div>
                            <div className="chat-member-actions">
                              {!isSelf && !confirming && (
                                <button
                                  type="button"
                                  className="chat-icon-btn"
                                  disabled={busyAction}
                                  title={`Message ${label}`}
                                  aria-label={`Message ${label}`}
                                  onClick={() => void handleMessageMember(m.user_id)}
                                >
                                  <MessageSquare size={14} />
                                </button>
                              )}
                              {canRemove && !confirming && (
                                <button
                                  type="button"
                                  className="chat-icon-btn"
                                  disabled={busyAction}
                                  title={isSelf ? 'Leave room' : `Remove ${label}`}
                                  aria-label={isSelf ? 'Leave room' : `Remove ${label}`}
                                  onClick={() => setConfirmRemoveId(m.user_id)}
                                >
                                  <UserMinus size={14} />
                                </button>
                              )}
                              {canRemove && confirming && (
                                <>
                                  <button
                                    type="button"
                                    className="ky-lobby-btn is-deny"
                                    disabled={busyAction}
                                    onClick={() => void handleRemoveMember(m.user_id)}
                                  >
                                    {isSelf ? 'Leave?' : 'Remove?'}
                                  </button>
                                  <button
                                    type="button"
                                    className="chat-icon-btn"
                                    aria-label="Cancel"
                                    onClick={() => setConfirmRemoveId(null)}
                                  >
                                    <X size={13} />
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </section>
              </div>
            )}

            {tab === 'shared' && (
              <div id="drawer-panel-shared" role="tabpanel" aria-labelledby="drawer-tab-shared" className="chat-drawer-panel">
                <section className="chat-drawer-section">
                  <h4>Shared links ({sharedLinks.length})</h4>
                  {sharedLinks.length === 0 ? (
                    <p className="chat-drawer-muted">
                      Links posted in this {isDM ? 'conversation' : 'room'} appear here automatically.
                    </p>
                  ) : (
                    <div className="chat-shared-list">
                      {sharedLinks.map((item) => (
                        <a
                          key={item.url}
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="chat-shared-link"
                        >
                          <div className="chat-shared-link-copy">
                            <span className="chat-shared-link-host">{item.host}</span>
                            <span className="chat-shared-link-url">{item.url}</span>
                            <span className="chat-shared-link-meta">
                              {item.senderName} · {formatTime(item.createdAt)}
                            </span>
                          </div>
                          <ExternalLink size={13} aria-hidden="true" />
                        </a>
                      ))}
                    </div>
                  )}
                </section>

              </div>
            )}
          </>
        )}
      </div>
    </aside>
  );
};
