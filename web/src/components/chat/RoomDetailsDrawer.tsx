import React, { useEffect, useState } from 'react';
import { Check, Copy, Trash2, UserMinus, UserPlus, Webhook, X } from 'lucide-react';
import type {
  ChatDirectoryUser,
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

interface RoomDetailsDrawerProps {
  detail: ChatRoomDetail | null;
  loading: boolean;
  currentUserId: string;
  isGlobalAdmin: boolean;
  directory: ChatDirectoryUser[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onLeftRoom: (roomId: string) => void;
}

export const RoomDetailsDrawer: React.FC<RoomDetailsDrawerProps> = ({
  detail,
  loading,
  currentUserId,
  isGlobalAdmin,
  directory,
  onClose,
  onRefresh,
  onLeftRoom,
}) => {
  const [name, setName] = useState('');
  const [topic, setTopic] = useState('');
  const [savingInfo, setSavingInfo] = useState(false);
  const [addUserId, setAddUserId] = useState('');
  const [busyAction, setBusyAction] = useState(false);
  const [webhooks, setWebhooks] = useState<ChatRoomWebhook[]>([]);
  const [webhookName, setWebhookName] = useState('');
  const [createdToken, setCreatedToken] = useState<{ id: string; token: string } | null>(null);
  const [copied, setCopied] = useState(false);
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

  const userLookup = new Map(directory.map((u) => [u.id, u]));
  const memberIdSet = new Set((detail?.members ?? []).map((m) => m.user_id));
  const addableUsers = directory.filter((u) => !memberIdSet.has(u.id));

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
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  return (
    <aside className="chat-drawer" aria-label="Room details">
      <div className="chat-drawer-head">
        <h3>Room details</h3>
        <button type="button" className="chat-icon-btn" onClick={onClose} aria-label="Close room details">
          <X size={16} />
        </button>
      </div>

      <div className="chat-drawer-body chat-scroll">
        {err && (
          <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.8rem' }}>
            {err}
          </div>
        )}

        {loading || !room ? (
          <p style={{ fontSize: '0.84rem', color: 'var(--ink)' }}>Loading room details…</p>
        ) : (
          <>
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

            <section className="chat-drawer-section">
              <h4>Members ({detail.members.length})</h4>
              <div>
                {detail.members.map((m) => {
                  const dirUser = userLookup.get(m.user_id);
                  const label = dirUser?.display_name || dirUser?.username || m.user_id;
                  const canRemove = !isDM && (m.user_id === currentUserId || (canModerate && m.role !== 'owner'));
                  return (
                    <div key={m.user_id} className="chat-member-row">
                      <div className="chat-member-copy">
                        <div className="chat-member-name">
                          {label}
                          {m.user_id === currentUserId ? ' (you)' : ''}
                        </div>
                        <div className="chat-member-role">{m.role}</div>
                      </div>
                      {canRemove && (
                        <button
                          type="button"
                          className="chat-icon-btn"
                          disabled={busyAction}
                          title={m.user_id === currentUserId ? 'Leave channel' : `Remove ${label}`}
                          aria-label={m.user_id === currentUserId ? 'Leave channel' : `Remove ${label}`}
                          onClick={() => void handleRemoveMember(m.user_id)}
                        >
                          <UserMinus size={14} />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>

              {!isDM && canModerate && addableUsers.length > 0 && (
                <form onSubmit={handleAddMember} style={{ display: 'flex', gap: '0.45rem', marginTop: '0.35rem' }}>
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
                    style={{ padding: '0.45rem 0.65rem', flexShrink: 0 }}
                    aria-label="Add selected member"
                  >
                    <UserPlus size={15} />
                  </button>
                </form>
              )}
            </section>

            {!isDM && canModerate && (
              <section className="chat-drawer-section">
                <h4>
                  <Webhook size={13} style={{ display: 'inline', verticalAlign: '-2px', marginRight: 5 }} />
                  Incoming webhooks
                </h4>
                <form onSubmit={handleCreateWebhook} style={{ display: 'flex', gap: '0.45rem' }}>
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
                    style={{ flexShrink: 0, padding: '0.45rem 0.7rem' }}
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
                        {copied ? <Check size={12} /> : <Copy size={12} />}
                        {copied ? 'Copied' : 'Copy curl'}
                      </button>
                    </div>
                    <pre>{`POST /api/v1/webhooks/in/${createdToken.id}\nAuthorization: Bearer ${createdToken.token}`}</pre>
                  </div>
                )}

                {webhooks.length === 0 ? (
                  <p style={{ fontSize: '0.78rem', color: 'var(--ink)' }}>No incoming webhooks yet.</p>
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
      </div>
    </aside>
  );
};
