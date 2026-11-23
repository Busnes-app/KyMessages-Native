import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { browserPushEndpoint, unsubscribeBrowserPush } from './chat/push';

vi.mock('./chat/e2ee', () => import('./chat/e2eeFake'));
vi.mock('./chat/push', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./chat/push')>()),
  browserPushEndpoint: vi.fn(async () => 'https://push.example/ep'),
  unsubscribeBrowserPush: vi.fn(async () => {}),
}));

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const member = { username: 'bob', display_name: 'Bob', role: 'user', must_change_password: false };

function stubServer(logout: () => Promise<Response>, me: unknown = { authenticated: true, user: member }) {
  vi.stubGlobal('WebSocket', class { close() {} send() {} });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/api/auth/me') return json(me);
    if (url === '/api/settings') return json({ app_name: 'KyMessages', chat_url: '' });
    if (url === '/api/v1/bootstrap') {
      return json({
        user: { id: 'u_bob', username: 'bob', display_name: 'Bob', role: 'user' },
        tenant: { id: 'default', slug: 'default', display_name: 'KyMessages', plan: 'self_hosted' },
        rooms: [],
      });
    }
    if (url === '/api/v1/users') return json({ users: [{ id: 'u_bob', username: 'bob', display_name: 'Bob' }] });
    if (url === '/api/auth/logout') return logout();
    return json({ error: 'not stubbed' }, 404);
  }));
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.mocked(unsubscribeBrowserPush).mockClear(); });

it('stays signed in and says so when the server refuses sign-out', async () => {
  stubServer(async () => json({ error: 'Invalid CSRF token' }, 403));
  render(<App />);
  fireEvent.click((await screen.findAllByRole('button', { name: 'Sign out' }))[0]);
  expect((await screen.findByRole('alert')).textContent).toContain('You are still signed in: Invalid CSRF token');
  expect(screen.getByText('Bob')).toBeTruthy();
});

it('stays signed in when sign-out cannot reach the server', async () => {
  stubServer(async () => { throw new TypeError('Failed to fetch'); });
  render(<App />);
  fireEvent.click((await screen.findAllByRole('button', { name: 'Sign out' }))[0]);
  expect((await screen.findByRole('alert')).textContent).toContain('You are still signed in');
  expect(screen.getByText('Bob')).toBeTruthy();
});

it('returns to sign-in only after the server confirms sign-out', async () => {
  stubServer(async () => json({ logged_out: true }));
  render(<App />);
  fireEvent.click((await screen.findAllByRole('button', { name: 'Sign out' }))[0]);
  expect(await screen.findByLabelText('Username')).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
});

it('shows an error for a malformed session instead of a blank page', async () => {
  stubServer(async () => json({}), { authenticated: true, user: { username: 42 } });
  render(<App />);
  expect((await screen.findByRole('alert')).textContent).toContain('Could not load the console: Invalid response from the server');
  await waitFor(() => expect(screen.getByLabelText('Username')).toBeTruthy());
});

it('catches a render failure in a page and keeps a message on screen', () => {
  const Broken = () => { throw new Error('boom'); };
  vi.spyOn(console, 'error').mockImplementation(() => {});
  render(<ErrorBoundary><Broken /></ErrorBoundary>);
  expect(screen.getByRole('alert').textContent).toContain('This page failed to load: boom');
  vi.restoreAllMocks();
});

it('opens preferences via the bottom settings gear and omits Pair Device', async () => {
  stubServer(async () => json({ logged_out: true }));
  render(<App />);
  const gear = await screen.findByRole('button', { name: 'Settings' });
  expect(screen.queryByRole('button', { name: /pair device/i })).toBeNull();
  fireEvent.click(gear);
  expect(await screen.findByRole('heading', { name: 'Preferences' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: /back to chat/i }));
  expect(await screen.findByRole('button', { name: 'Settings' })).toBeTruthy();
});

it('drops the push subscription with the session when signing out from Settings', async () => {
  let sent: unknown;
  stubServer(async () => json({ logged_out: true }));
  const stubbed = vi.mocked(fetch).getMockImplementation()!;
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    if (String(input) === '/api/auth/logout') sent = JSON.parse(String(init?.body));
    return stubbed(input, init);
  });
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Settings' }));
  await screen.findByRole('heading', { name: 'Preferences' });
  fireEvent.click(screen.getAllByRole('button', { name: 'Sign out' })[0]);
  expect(await screen.findByLabelText('Username')).toBeTruthy();
  expect(sent).toEqual({ push_endpoint: 'https://push.example/ep' });
  expect(browserPushEndpoint).toHaveBeenCalled();
  expect(unsubscribeBrowserPush).toHaveBeenCalledTimes(1);
});

it('keeps push on when the server refuses sign-out', async () => {
  stubServer(async () => json({ error: 'Invalid CSRF token' }, 403));
  render(<App />);
  fireEvent.click((await screen.findAllByRole('button', { name: 'Sign out' }))[0]);
  await screen.findByRole('alert');
  expect(unsubscribeBrowserPush).not.toHaveBeenCalled();
});

it('opens Chat on the room a notification click names, from another page', async () => {
  const listeners: Array<(ev: MessageEvent) => void> = [];
  vi.stubGlobal('navigator', Object.assign(Object.create(navigator), {
    serviceWorker: {
      addEventListener: (_: string, fn: (ev: MessageEvent) => void) => listeners.push(fn),
      removeEventListener: () => {},
    },
  }));
  stubServer(async () => json({ logged_out: true }));
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Settings' }));
  await screen.findByRole('heading', { name: 'Preferences' });
  for (const fn of listeners) fn(new MessageEvent('message', { data: { type: 'kymessages.navigate', roomId: 'rm 1' } }));
  expect(await screen.findByRole('button', { name: 'Settings' })).toBeTruthy();
  expect(screen.queryByRole('heading', { name: 'Preferences' })).toBeNull();
  expect(window.location.hash).toBe('#room=rm%201');
});

it('clears the room hash when Chat gives way to Settings', async () => {
  stubServer(async () => json({ logged_out: true }));
  render(<App />);
  const gear = await screen.findByRole('button', { name: 'Settings' });
  window.history.replaceState(null, '', '/#room=rm_seen');
  fireEvent.click(gear);
  await screen.findByRole('heading', { name: 'Preferences' });
  expect(window.location.hash).toBe('');
});
