import React, { useEffect, useMemo, useState } from 'react';
import {
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
  Trash2,
  UserMinus,
  UserPlus,
  Users,
  Webhook,
} from 'lucide-react';
import type {
  ChatDirectoryUser,
  ChatMessage,
  ChatRoomDetail,
  ChatRoomWebhook,
} from '../../chat/types';
import {
  addRoomMember,
  createRoomWebhook,
  fetchRoomWebhooks,
  removeRoomMember,
  revokeRoomWebhook,
  updateRoomInfo,
} from '../../chat/client';
import { formatTime, initialsFor } from '../../chat/state';

type DrawerTab = 'about' | 'members' | 'shared';

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
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onLeftRoom: (roomId: string) => void;
  onOpenSearch: () => void;
  onStartDM: (userId: string) => Promise<void>;
}

export const RoomDetailsDrawer: React.FC<RoomDetailsDrawerProps> = ({
  detail,
  loading,
  currentUserId,
  isGlobalAdmin,
  directory,
  messages,
  onClose,
  onRefresh,
  onLeftRoom,
  onOpenSearch,
  onStartDM,
}) => {
  const [tab, setTab] = useState<DrawerTab>('about');
  const [name, setName] = useState('');
  const [topic, setTopic] = useState('');
  const [savingInfo, setSavingInfo] = useState(false);
  const [memberFilter, setMemberFilter] = useState('');
  const [addUserId, setAddUserId] = useState('');
  const [busyAction, setBusyAction] = useState(false);
  const [webhooks, setWebhooks] = useState<ChatRoomWebhook[]>([]);
  const [webhookName, setWebhookName] = useState('');
  const [createdToken, setCreatedToken] = useState<{ id: string; token: string } | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [err, setErr] = useState('');

  const room = detail?.room;
  const memberRole = detail?.member.role ?? 'member';
  const canModerate = isGlobalAdmin || memberRole === 'owner' || memberRole === 'admin';
  const isDM = room?.kind === 'dm';

  useEffect(() => {
    if (!room) return;
    setName(room.name);
    setTopic(room.topic);
    setErr('');
    setCreatedToken(null);
    setMemberFilter('');
  }, [room?.id, room?.name, room?.topic]);

  useEffect(() => {
    if (!room || !canModerate || isDM) {
      setWebhooks([]);
      return;
    }
    let cancelled = false;
    void fetchRoomWebhooks(room.id)
      .then((list) => {
        if (!cancelled) setWebhooks(list);
      })
      .catch(() => {
        // Non-moderators or transient errors stay quiet here.
      });
    return () => {
      cancelled = true;
    };
  }, [room?.id, canModerate, isDM]);

  const userLookup = useMemo(() => new Map(directory.map((u) => [u.id, u])), [directory]);
  const memberIdSet = useMemo(() => new Set((detail?.members ?? []).map((m) => m.user_id)), [detail?.members]);
  const addableUsers = useMemo(
    () => directory.filter((u) => !memberIdSet.has(u.id)),
    [directory, memberIdSet],
  );
  const sharedLinks = useMemo(() => extractSharedLinks(messages), [messages]);
  const activeWebhookCount = useMemo(
    () => webhooks.filter((w) => !w.revoked_at).length,
    [webhooks],
  );
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

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!room || !webhookName.trim()) return;
    setBusyAction(true);
    setErr('');
    try {
      const created = await createRoomWebhook(room.id, webhookName.trim());
      setWebhookName('');
      setCreatedToken({ id: created.webhook.id, token: created.token });
      setWebhooks((prev) => [created.webhook, ...prev]);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not create webhook');
    } finally {
      setBusyAction(false);
    }
  };

  const handleRevokeWebhook = async (webhookId: string) => {
    if (!room) return;
    setBusyAction(true);
    setErr('');
    try {
      await revokeRoomWebhook(room.id, webhookId);
      setWebhooks((prev) => prev.map((w) => (w.id === webhookId ? { ...w, revoked_at: Date.now() } : w)));
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not revoke webhook');
    } finally {
      setBusyAction(false);
    }
  };

  const copyCurl = async () => {
    if (!createdToken) return;
    const cmd = `curl -X POST ${window.location.origin}/api/v1/webhooks/in/${createdToken.id} \\\n  -H "Authorization: Bearer ${createdToken.token}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"text":"Hello from webhook"}'`;
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 1800);
    } catch {
      // Clipboard unavailable.
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

  const sharedBadgeCount = sharedLinks.length + (canModerate && !isDM ? activeWebhookCount : 0);

  return (
    <aside className="chat-drawer" aria-label="Room panel">
      <div className="chat-drawer-head">
        <h3>{isDM ? 'Conversation' : 'Room details'}</h3>
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
          type="button"
          role="tab"
          aria-selected={tab === 'about'}
          className={tab === 'about' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('about')}
        >
          <Info size={14} aria-hidden="true" />
          <span>About</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'members'}
          className={tab === 'members' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('members')}
        >
          <Users size={14} aria-hidden="true" />
          <span>Members</span>
          {detail && <span className="chat-tab-count">{detail.members.length}</span>}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'shared'}
          className={tab === 'shared' ? 'chat-drawer-tab active' : 'chat-drawer-tab'}
          onClick={() => setTab('shared')}
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
              <>
                <div className="chat-room-summary">
                  <div className="chat-room-summary-head">
                    <span className="chat-room-summary-badge" aria-hidden="true">
                      {isDM ? (
                        initialsFor(room.name || 'DM')
                      ) : room.is_private ? (
                        <Lock size={16} />
                      ) : (
                        <Hash size={16} />
                      )}
                    </span>
                    <div className="chat-room-summary-copy">
                      <div className="chat-room-summary-name">{room.name || 'Direct message'}</div>
                      <div className="chat-room-summary-kind">
                        {isDM ? 'Direct message' : room.is_private ? 'Private channel' : 'Public channel'}
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
                  {!isDM && (
                    <button
                      type="button"
                      className="chat-quick-btn danger"
                      disabled={busyAction}
                      onClick={() => void handleRemoveMember(currentUserId)}
                    >
                      <LogOut size={14} aria-hidden="true" />
                      <span>Leave</span>
                    </button>
                  )}
                </div>

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
                    <h4>Channel settings</h4>
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
                        placeholder="What is this channel about?"
                        maxLength={500}
                      />
                    </div>
                    <button type="submit" disabled={savingInfo || !name.trim()} style={{ alignSelf: 'flex-start' }}>
                      {savingInfo ? 'Saving…' : 'Save changes'}
                    </button>
                  </form>
                )}
              </>
            )}

            {tab === 'members' && (
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
                          {u.display_name} (@{u.username})
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
                      const canRemove = !isDM && (isSelf || (canModerate && m.role !== 'owner'));
                      return (
                        <div key={m.user_id} className="chat-member-row">
                          <span className="chat-member-avatar" aria-hidden="true">
                            {initialsFor(label)}
                          </span>
                          <div className="chat-member-copy">
                            <div className="chat-member-name">
                              {label}
                              {isSelf ? ' (you)' : ''}
                            </div>
                            <div className="chat-member-role">
                              {dirUser?.username ? `@${dirUser.username} · ` : ''}
                              {m.role}
                            </div>
                          </div>
                          <div className="chat-member-actions">
                            {!isSelf && (
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
                            {canRemove && (
                              <button
                                type="button"
                                className="chat-icon-btn"
                                disabled={busyAction}
                                title={isSelf ? 'Leave channel' : `Remove ${label}`}
                                aria-label={isSelf ? 'Leave channel' : `Remove ${label}`}
                                onClick={() => void handleRemoveMember(m.user_id)}
                              >
                                <UserMinus size={14} />
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </section>
            )}

            {tab === 'shared' && (
              <>
                <section className="chat-drawer-section">
                  <h4>Shared links ({sharedLinks.length})</h4>
                  {sharedLinks.length === 0 ? (
                    <p className="chat-drawer-muted">
                      Links posted in this {isDM ? 'conversation' : 'channel'} appear here automatically.
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

                {!isDM && canModerate && (
                  <section className="chat-drawer-section">
                    <h4>
                      <Webhook size={13} style={{ display: 'inline', verticalAlign: '-2px', marginRight: 5 }} />
                      Incoming webhooks
                    </h4>
                    <form onSubmit={handleCreateWebhook} className="chat-drawer-inline-form">
                      <input
                        aria-label="New webhook name"
                        placeholder="CI Deploy Bot"
                        value={webhookName}
                        onChange={(e) => setWebhookName(e.target.value)}
                        maxLength={100}
                      />
                      <button
                        type="submit"
                        className="btn-secondary"
                        disabled={busyAction || !webhookName.trim()}
                      >
                        Add
                      </button>
                    </form>

                    {createdToken && (
                      <div className="chat-webhook-secret" role="status">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <strong>Token shown once</strong>
                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => void copyCurl()}
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem' }}
                          >
                            {copiedCurl ? <Check size={12} /> : <Copy size={12} />}
                            {copiedCurl ? 'Copied' : 'Copy curl'}
                          </button>
                        </div>
                        <pre>{`POST /api/v1/webhooks/in/${createdToken.id}\nAuthorization: Bearer ${createdToken.token}`}</pre>
                      </div>
                    )}

                    {webhooks.length === 0 ? (
                      <p className="chat-drawer-muted">No incoming webhooks yet.</p>
                    ) : (
                      <div>
                        {webhooks.map((wh) => (
                          <div key={wh.id} className="chat-member-row">
                            <div className="chat-member-copy">
                              <div className="chat-member-name">{wh.name}</div>
                              <div className="chat-member-role">
                                {wh.revoked_at ? 'Revoked' : 'Active · Bearer auth'}
                              </div>
                            </div>
                            {!wh.revoked_at && (
                              <button
                                type="button"
                                className="chat-icon-btn"
                                disabled={busyAction}
                                title={`Revoke ${wh.name}`}
                                aria-label={`Revoke ${wh.name}`}
                                onClick={() => void handleRevokeWebhook(wh.id)}
                              >
                                <Trash2 size={14} />
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                )}
              </>
            )}
          </>
        )}
      </div>
    </aside>
  );
};
