import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Agents, type AgentRow } from './Agents';

const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

const OWNER = { id: 'usr_alice', username: 'alice', display_name: 'Alice', status: 'active' };
const AGENT: AgentRow = {
  id: '00000000-0000-0000-0000-000000000001',
  user_id: 'bot_1',
  username: 'agent-triage',
  display_name: 'Triage Bot',
  owner: OWNER,
  token_state: 'active',
  last_used_at: '2026-10-01T12:00:00Z',
  created_at: '2026-09-01T12:00:00Z',
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('Agents', () => {
  it('lists configured bots, creates a new bot, reveals token and config snippets, revokes and deletes', async () => {
    let agents: AgentRow[] = [AGENT];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (url === '/api/admin/agents' && method === 'GET') {
        return json({ agents, owners: [OWNER], idle_days: 90 });
      }
      if (url === '/api/admin/agents' && method === 'POST') {
        const body = JSON.parse(String(init?.body ?? '{}')) as { name: string; display_name?: string; owner: string };
        const created: AgentRow = {
          id: '00000000-0000-0000-0000-000000000002',
          user_id: 'bot_2',
          username: body.name,
          display_name: body.display_name || body.name,
          owner: OWNER,
          token_state: 'active',
          last_used_at: null,
          created_at: '2026-10-02T12:00:00Z',
        };
        agents = [created, ...agents];
        return json({
          agent: created,
          token: 'kybot_secret_once',
          configs: {
            openclaw: '{"token":"kybot_secret_once"}',
            hermes: 'KYMESSAGES_TOKEN=kybot_secret_once',
          },
        });
      }
      if (url === `/api/admin/agents/${AGENT.id}/revoke` && method === 'POST') {
        agents = agents.map((a) => (a.id === AGENT.id ? { ...a, token_state: 'revoked' } : a));
        return json({ outcome: 'revoked' });
      }
      if (url === `/api/admin/agents/${AGENT.id}` && method === 'DELETE') {
        agents = agents.filter((a) => a.id !== AGENT.id);
        return json({ outcome: 'deleted' });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    render(<Agents />);

    expect(await screen.findByText('Triage Bot')).toBeTruthy();
    expect(screen.getByRole('link', { name: /Download skill/i }).getAttribute('href')).toBe('/api/admin/agents/skill');

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'agent-ops' } });
    fireEvent.change(screen.getByLabelText('Display name (optional)'), { target: { value: 'Ops Bot' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create bot' }));

    expect(await screen.findByText('kybot_secret_once')).toBeTruthy();
    expect(screen.getByText('{"token":"kybot_secret_once"}')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Hermes' }));
    expect(screen.getByText('KYMESSAGES_TOKEN=kybot_secret_once')).toBeTruthy();

    fireEvent.click(screen.getAllByRole('button', { name: 'Revoke' })[1]);
    await waitFor(() => expect(screen.getByText('Revoked')).toBeTruthy());

    fireEvent.click(screen.getByRole('button', { name: 'Delete agent-triage' }));
    await waitFor(() => expect(screen.queryByText('Triage Bot')).toBeNull());
  });

  it('refuses a malformed server response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ agents: [{ ...AGENT, token_state: 'bogus' }], owners: [OWNER] })),
    );
    render(<Agents />);
    expect((await screen.findByRole('alert')).textContent).toContain('Invalid');
  });
});
