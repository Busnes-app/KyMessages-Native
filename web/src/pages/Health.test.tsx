import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { Health } from './Health';

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const NET = { peer_ip: '10.0.0.1', client_ip: '203.0.113.9', forwarded_trusted: true, forwarded_proto: 'https', app_url_https: true, host_matches: true, trusted_proxies_narrow: true };
const c = (name: string, extra: Record<string, unknown> = {}) => ({ name, status: 'up', version: '', pinned: '', mismatch: false, source: '', error: '', ...extra });
const REPORT = { components: [
  c('kymessages', { version: '0.1.0-dev', pinned: '0.1.0-dev', source: 'https://github.com/Busnes-app/KyMessages-Native/tree/v0.1.0' }),
  c('database'),
  c('livekit'),
  c('postgres', { status: 'down', version: '17.5', pinned: '17.6', mismatch: true, source: 'javascript:alert(1)', error: 'dial tcp: lookup postgres: no such host' }),
] };
function serve(health: Response) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => (String(input) === '/api/admin/health' ? health.clone() : json(NET))));
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('shows each component, its pin, its source and the network check', async () => {
  serve(json(REPORT));
  render(<Health />);
  const list = await screen.findByRole('region', { name: 'Components' });
  expect(within(list).getAllByText('Up')).toHaveLength(3);
  expect(within(list).getByText('LiveKit SFU')).toBeTruthy();
  expect(within(list).getByText('Down')).toBeTruthy();
  expect(within(list).getByRole('link', { name: /Source for 0\.1\.0-dev/ }).getAttribute('href')).toBe('https://github.com/Busnes-app/KyMessages-Native/tree/v0.1.0');
  expect(within(list).getByText(/Compose pins 17\.6/)).toBeTruthy();
  expect(within(list).queryByRole('link', { name: /Source for 17\.5/ })).toBeNull();
  expect(within(list).getByText('dial tcp: lookup postgres: no such host')).toBeTruthy();
  expect(await screen.findByRole('heading', { name: 'Network path' })).toBeTruthy();
});

it('refuses a malformed report', async () => {
  serve(json({ components: [c('kymessages', { status: 'sideways' })] }));
  render(<Health />);
  expect((await screen.findByRole('alert')).textContent).toContain('Invalid response from the server');
});

it('drops an https source outside the upstream repos and shows odd versions as text', async () => {
  serve(json({ components: [c('kymessages', { version: '<b>x</b>', source: 'https://evil.example/Busnes-app/KyMessages-Native/tree/v1' })] }));
  render(<Health />);
  expect(await screen.findByText('<b>x</b>')).toBeTruthy();
  expect(screen.queryByRole('link')).toBeNull();
});
