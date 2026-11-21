import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { Dashboard } from './Dashboard';

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const up = (name: string) => ({ name, status: 'up', version: '', pinned: '', mismatch: false, source: '', error: '' });
function serve(routes: Record<string, Response>) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const key = Object.keys(routes).find((k) => String(input).startsWith(k));
    if (!key) throw new Error(`unexpected ${String(input)}`);
    return routes[key].clone();
  }));
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('shows service health, active members and the last backup, each linking to its page', async () => {
  serve({
    '/api/admin/health': json({ components: [up('kymessages'), up('database')] }),
    '/api/v1/users': json({ users: [{ id: 'u1' }, { id: 'u2' }, { id: 'u3' }] }),
    '/api/backup/status': json({ last_run: { outcome: 'success', trigger: 'scheduled', recorded_at: '2026-10-02T03:00:00Z', capsule_id: 'c1' } }),
  });
  const onNavigate = vi.fn();
  render(<Dashboard settings={{ app_name: 'KyMessages' }} user={{ username: 'root' }} onNavigate={onNavigate} />);
  expect(await screen.findByText('2 of 2 components up')).toBeTruthy();
  expect(await screen.findByText('3 active members')).toBeTruthy();
  expect(await screen.findByText(/^Last backup: Succeeded/)).toBeTruthy();
  fireEvent.click(within(screen.getByRole('region', { name: 'Workspace directory' })).getByRole('button'));
  expect(onNavigate).toHaveBeenCalledWith('scim');
  fireEvent.click(within(screen.getByRole('region', { name: 'Service health' })).getByRole('button'));
  expect(onNavigate).toHaveBeenCalledWith('health');
});

it('shows errors cleanly when a source fails', async () => {
  serve({
    '/api/admin/health': json({ error: 'boom' }, 500),
    '/api/v1/users': json({ users: [{ id: 'u1' }] }),
    '/api/backup/status': json({}),
  });
  render(<Dashboard settings={null} user={null} onNavigate={() => {}} />);
  expect(await screen.findByText('Unavailable: HTTP 500')).toBeTruthy();
  expect(await screen.findByText('1 active member')).toBeTruthy();
  expect(await screen.findByText('Last backup: none recorded')).toBeTruthy();
});
