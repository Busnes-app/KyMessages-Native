import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertCircle,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  Download,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  ShieldOff,
  Trash2,
  X,
  XCircle,
} from 'lucide-react';
import { adminFetch, errorMessage } from '../api';
import { arr, count, iso, obj, oneOf, opt, str } from '../dto';

export type TokenState = 'active' | 'revoked' | 'expired';

export interface AgentOwner {
  id: string;
  username: string;
  display_name: string;
  status: string;
}

export interface AgentRow {
  id: string;
  user_id: string;
  username: string;
  display_name: string;
  owner: AgentOwner;
  token_state: TokenState;
  last_used_at: string | null;
  created_at: string;
}

export interface AgentListResponse {
  agents: AgentRow[];
  owners: AgentOwner[];
  idle_days: number;
}

export interface AgentTokenReveal {
  agent: AgentRow;
  token: string;
  configs: Record<string, string>;
}

const TOKEN_STATES = ['active', 'revoked', 'expired'] as const;
const NAME_RE = /^agent-[a-z0-9][a-z0-9_-]{0,57}$/;

function parseOwner(v: unknown): AgentOwner {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    username: opt(o.username, (s) => str(s, 128)) ?? '',
    display_name: opt(o.display_name, (s) => str(s, 255)) ?? '',
    status: opt(o.status, (s) => str(s, 32)) ?? 'unknown',
  };
}

function parseAgent(v: unknown): AgentRow {
  const o = obj(v);
  return {
    id: str(o.id, 128),
    user_id: str(o.user_id, 128),
    username: str(o.username, 128),
    display_name: str(o.display_name, 255),
    owner: parseOwner(o.owner),
    token_state: oneOf(o.token_state, TOKEN_STATES),
    last_used_at: opt(o.last_used_at, iso) ?? null,
    created_at: iso(o.created_at),
  };
}

export function parseAgentList(v: unknown): AgentListResponse {
  const o = obj(v);
  return {
    agents: arr(o.agents).map(parseAgent),
    owners: arr(o.owners).map(parseOwner),
    idle_days: opt(o.idle_days, count) ?? 90,
  };
}

export function parseAgentTokenReveal(v: unknown): AgentTokenReveal {
  const o = obj(v);
  const rawConfigs = obj(o.configs);
  const configs: Record<string, string> = {};
  for (const [k, val] of Object.entries(rawConfigs)) {
    configs[k] = str(val, 16384);
  }
  return {
    agent: parseAgent(o.agent),
    token: str(o.token, 512),
    configs,
  };
}

function formatWhen(raw: string | null): string {
  if (!raw) return 'Never';
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? raw : d.toLocaleString();
}

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

const RUNTIME_LABELS: Record<string, string> = {
  openclaw: 'OpenClaw',
  hermes: 'Hermes',
};

const STATE_BADGE: Record<TokenState, { label: string; className: string }> = {
  active: { label: 'Active', className: 'badge badge-success' },
  revoked: { label: 'Revoked', className: 'badge badge-danger' },
  expired: { label: 'Expired', className: 'badge dr-badge-muted' },
};

export const Agents: React.FC = () => {
  const [data, setData] = useState<AgentListResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string>('');

  const [name, setName] = useState<string>('agent-');
  const [displayName, setDisplayName] = useState<string>('');
  const [ownerId, setOwnerId] = useState<string>('');
  const [creating, setCreating] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string>('');
  const [actionNotice, setActionNotice] = useState<string>('');

  const [busyId, setBusyId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<AgentTokenReveal | null>(null);
  const [selectedRuntime, setSelectedRuntime] = useState<string>('openclaw');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const res = await fetch('/api/admin/agents', { cache: 'no-store' });
      if (!res.ok) throw new Error(await errorMessage(res, 'Could not load bots and agents'));
      const parsed = parseAgentList(await res.json());
      setData(parsed);
      setOwnerId((prev) => (prev && parsed.owners.some((o) => o.id === prev) ? prev : parsed.owners[0]?.id ?? ''));
    } catch (err) {
      setLoadError(errorText(err, 'Could not load bots and agents'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const sortedOwners = useMemo(
    () =>
      [...(data?.owners ?? [])].sort((a, b) =>
        (a.display_name || a.username).localeCompare(b.display_name || b.username, undefined, { sensitivity: 'base' }),
      ),
    [data?.owners],
  );

  const copyText = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1800);
    } catch {
      // Clipboard unavailable in this context.
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!NAME_RE.test(trimmedName)) {
      setActionError('Name must start with "agent-" followed by lowercase letters, digits, hyphens, or underscores.');
      return;
    }
    if (!ownerId) {
      setActionError('Choose an active user to own this bot.');
      return;
    }
    setCreating(true);
    setActionError('');
    setActionNotice('');
    try {
      const res = await adminFetch('/api/admin/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: trimmedName,
          display_name: displayName.trim() || undefined,
          owner: ownerId,
        }),
      });
      if (!res.ok) throw new Error(await errorMessage(res, 'Could not create bot'));
      const created = parseAgentTokenReveal(await res.json());
      setRevealed(created);
      const runtimes = Object.keys(created.configs);
      if (runtimes.length > 0 && !runtimes.includes(selectedRuntime)) {
        setSelectedRuntime(runtimes[0]);
      }
      setName('agent-');
      setDisplayName('');
      setActionNotice(`Created ${created.agent.username}. Copy the token below now — it will not be shown again.`);
      await load();
    } catch (err) {
      setActionError(errorText(err, 'Could not create bot'));
    } finally {
      setCreating(false);
    }
  };

  const handleRotate = async (agent: AgentRow) => {
    const label = agent.token_state === 'active' ? 'Rotate' : 'Reissue';
    if (
      agent.token_state === 'active' &&
      !window.confirm(`Rotate token for ${agent.username}?\n\nThe current token and any active WebSocket session will be disconnected immediately.`)
    ) {
      return;
    }
    setBusyId(agent.id);
    setActionError('');
    setActionNotice('');
    try {
      const res = await adminFetch(`/api/admin/agents/${encodeURIComponent(agent.id)}/rotate`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(await errorMessage(res, `Could not ${label.toLowerCase()} token`));
      const rotated = parseAgentTokenReveal(await res.json());
      setRevealed(rotated);
      setActionNotice(`Issued a new token for ${rotated.agent.username}. Copy it below now.`);
      await load();
    } catch (err) {
      setActionError(errorText(err, `Could not ${label.toLowerCase()} token`));
    } finally {
      setBusyId(null);
    }
  };

  const handleRevoke = async (agent: AgentRow) => {
    setBusyId(agent.id);
    setActionError('');
    setActionNotice('');
    try {
      const res = await adminFetch(`/api/admin/agents/${encodeURIComponent(agent.id)}/revoke`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(await errorMessage(res, 'Could not revoke token'));
      if (revealed?.agent.id === agent.id) setRevealed(null);
      setActionNotice(`Revoked ${agent.username}. Existing connections were cut immediately.`);
      await load();
    } catch (err) {
      setActionError(errorText(err, 'Could not revoke token'));
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (agent: AgentRow) => {
    if (
      !window.confirm(
        `Delete ${agent.username}?\n\nIts token will be revoked immediately and the bot account disabled. Messages it already sent stay in room history.`,
      )
    ) {
      return;
    }
    setBusyId(agent.id);
    setActionError('');
    setActionNotice('');
    try {
      const res = await adminFetch(`/api/admin/agents/${encodeURIComponent(agent.id)}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error(await errorMessage(res, 'Could not delete bot'));
      if (revealed?.agent.id === agent.id) setRevealed(null);
      setActionNotice(`Deleted ${agent.username}.`);
      await load();
    } catch (err) {
      setActionError(errorText(err, 'Could not delete bot'));
    } finally {
      setBusyId(null);
    }
  };

  const agents = data?.agents ?? [];
  const idleDays = data?.idle_days ?? 90;
  const runtimeKeys = revealed ? Object.keys(revealed.configs) : [];
  const activeRuntime = runtimeKeys.includes(selectedRuntime) ? selectedRuntime : runtimeKeys[0] ?? '';

  return (
    <div className="dr-page">
      <div className="dr-header">
        <h1>Bots &amp; Agents</h1>
        <div className="dr-actions">
          <a
            href="/api/admin/agents/skill"
            download="kymessages-agent-skill.zip"
            className="btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', textDecoration: 'none' }}
          >
            <Download size={14} aria-hidden="true" />
            <span>Download skill (.zip)</span>
          </a>
          <button type="button" className="btn-secondary" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <p className="dr-hint">
        Create native bot accounts that connect over HTTPS and WebSockets with a bearer token. Invite a bot into any channel
        from Room Details &rarr; Members. Tokens expire automatically after {idleDays} days without use, or immediately if the
        owning user is deactivated.
      </p>

      {loadError && (
        <div className="dr-alert dr-alert-error" role="alert">
          <XCircle size={16} aria-hidden="true" />
          <span>{loadError}</span>
        </div>
      )}
      {actionError && (
        <div className="dr-alert dr-alert-error" role="alert">
          <XCircle size={16} aria-hidden="true" />
          <span>{actionError}</span>
        </div>
      )}
      {actionNotice && (
        <div className="dr-alert dr-alert-success" role="status">
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>{actionNotice}</span>
        </div>
      )}

      {revealed && (
        <section className="panel dr-section" aria-label="New bot token">
          <div className="panel-header">
            <h3 style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
              <KeyRound size={16} aria-hidden="true" />
              <span>Token for {revealed.agent.username}</span>
            </h3>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setRevealed(null)}
              aria-label="Dismiss token"
            >
              <X size={14} aria-hidden="true" />
              <span>Dismiss</span>
            </button>
          </div>
          <div className="dr-alert dr-alert-warn" role="status">
            <AlertCircle size={16} aria-hidden="true" />
            <span>Copy this token now. KyMessages stores only its hash and cannot display it again.</span>
          </div>
          <div className="dr-row" style={{ alignItems: 'center' }}>
            <code
              className="dr-mono"
              style={{
                flex: 1,
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid var(--line)',
                background: 'var(--bg-subtle, var(--surface))',
                wordBreak: 'break-all',
              }}
            >
              {revealed.token}
            </code>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void copyText('token', revealed.token)}
            >
              {copiedKey === 'token' ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
              <span>{copiedKey === 'token' ? 'Copied' : 'Copy token'}</span>
            </button>
          </div>

          {runtimeKeys.length > 0 && (
            <div style={{ marginTop: '14px' }}>
              <div className="dr-actions" style={{ marginBottom: '8px' }}>
                {runtimeKeys.map((rt) => (
                  <button
                    key={rt}
                    type="button"
                    className={activeRuntime === rt ? '' : 'btn-secondary'}
                    onClick={() => setSelectedRuntime(rt)}
                  >
                    {RUNTIME_LABELS[rt] ?? rt}
                  </button>
                ))}
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => void copyText(`cfg-${activeRuntime}`, revealed.configs[activeRuntime] ?? '')}
                >
                  {copiedKey === `cfg-${activeRuntime}` ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
                  <span>{copiedKey === `cfg-${activeRuntime}` ? 'Copied' : 'Copy snippet'}</span>
                </button>
              </div>
              <pre
                className="dr-mono"
                style={{
                  margin: 0,
                  padding: '12px',
                  borderRadius: '6px',
                  border: '1px solid var(--line)',
                  background: 'var(--bg-subtle, var(--surface))',
                  overflowX: 'auto',
                  fontSize: '12px',
                }}
              >
                {revealed.configs[activeRuntime]}
              </pre>
            </div>
          )}
        </section>
      )}

      <section className="panel dr-section" aria-label="Create bot">
        <div className="panel-header">
          <h3>Create bot</h3>
        </div>
        <form onSubmit={handleCreate} className="dr-row" style={{ flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <label className="dr-field" style={{ flex: '1 1 200px' }}>
            <span>Username</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="agent-triage"
              required
              maxLength={64}
              autoComplete="off"
            />
          </label>
          <label className="dr-field" style={{ flex: '1 1 200px' }}>
            <span>Display name (optional)</span>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Triage Bot"
              maxLength={100}
              autoComplete="off"
            />
          </label>
          <label className="dr-field" style={{ flex: '1 1 200px' }}>
            <span>Owner</span>
            <select value={ownerId} onChange={(e) => setOwnerId(e.target.value)} required>
              {sortedOwners.length === 0 ? (
                <option value="">No active owners</option>
              ) : (
                sortedOwners.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.display_name || o.username} (@{o.username})
                  </option>
                ))
              )}
            </select>
          </label>
          <button type="submit" disabled={creating || sortedOwners.length === 0}>
            {creating ? <Loader2 size={14} className="animate-spin" aria-hidden="true" /> : <Plus size={14} aria-hidden="true" />}
            <span>{creating ? 'Creating…' : 'Create bot'}</span>
          </button>
        </form>
        <p className="dr-hint">
          Bot usernames must start with <code>agent-</code> and use lowercase letters, digits, hyphens, or underscores.
        </p>
      </section>

      <section className="panel dr-section" aria-label="Configured bots">
        <div className="panel-header">
          <h3>Configured bots ({agents.length})</h3>
        </div>
        {loading && !data ? (
          <p className="dr-hint">Loading…</p>
        ) : agents.length === 0 ? (
          <p className="dr-hint">No bots configured yet. Create one above to mint a bearer token.</p>
        ) : (
          <table className="console-table">
            <thead>
              <tr>
                <th>Bot</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Last active</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const badge = STATE_BADGE[a.token_state];
                const isBusy = busyId === a.id;
                const ownerInactive = a.owner.status !== 'active';
                return (
                  <tr key={a.id}>
                    <td>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
                        <Bot size={14} aria-hidden="true" />
                        <span>{a.display_name}</span>
                      </div>
                      <div className="dr-hint dr-mono">@{a.username}</div>
                    </td>
                    <td>
                      <div>{a.owner.display_name || a.owner.username || a.owner.id}</div>
                      {ownerInactive && <span className="badge badge-danger">Owner {a.owner.status}</span>}
                    </td>
                    <td>
                      <span className={badge.className}>{badge.label}</span>
                    </td>
                    <td className="dr-mono">{formatWhen(a.last_used_at)}</td>
                    <td>
                      <div className="dr-actions">
                        <button
                          type="button"
                          className="btn-secondary"
                          disabled={isBusy || ownerInactive}
                          onClick={() => void handleRotate(a)}
                        >
                          <KeyRound size={13} aria-hidden="true" />
                          <span>{a.token_state === 'active' ? 'Rotate' : 'Reissue'}</span>
                        </button>
                        {a.token_state === 'active' && (
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={isBusy}
                            onClick={() => void handleRevoke(a)}
                          >
                            <ShieldOff size={13} aria-hidden="true" />
                            <span>Revoke</span>
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn-secondary"
                          disabled={isBusy}
                          onClick={() => void handleDelete(a)}
                          aria-label={`Delete ${a.username}`}
                        >
                          <Trash2 size={13} aria-hidden="true" />
                          <span>Delete</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
};
