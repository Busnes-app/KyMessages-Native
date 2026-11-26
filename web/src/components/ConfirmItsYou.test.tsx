import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ConfirmItsYou } from './ConfirmItsYou';
import { adminFetch } from '../api';

// A captcha that hands out one token per round, as the real widget solves one challenge each.
vi.mock('./CaptchaWidget', async () => {
  const { useEffect, useRef } = await import('react');
  return {
    CaptchaWidget: ({ onToken, round }: { onToken: (t: string) => void; round: number }) => {
      const cb = useRef(onToken);
      cb.current = onToken;
      useEffect(() => {
        cb.current('');
        // Solved a moment later, as a real challenge is.
        const timer = setTimeout(() => cb.current(`captcha-${round}`), 20);
        return () => clearTimeout(timer);
      }, [round]);
      return null;
    },
  };
});

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const STEP_UP = { error: "Confirm it's you: this change needs a sign-in from the last 10 minutes", code: 'reauthentication_required', reauth_url: '/api/sso/kyidentity/login?fresh=1' };
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

/** Waits until the captcha handed over its token (the button is enabled), then signs in. */
async function signInReady(dialog: HTMLElement) {
  const button = within(dialog).getByRole('button', { name: 'Sign in again' });
  await waitFor(() => expect(button).toHaveProperty('disabled', false));
  fireEvent.click(button);
}

/** fetch answers each path from its queue, repeating the last answer. */
function answers(byPath: Record<string, Response[]>) {
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    const q = byPath[url];
    return (q.length > 1 ? q.shift() : q[0])!.clone();
  }));
  return calls;
}

it('without a mounted prompt, returns the refusal', async () => {
  answers({ '/x': [json(STEP_UP, 403)] });
  expect((await adminFetch('/x', { method: 'POST' })).status).toBe(403);
});

it('passes through a 403 that is not a step-up', async () => {
  answers({ '/x': [json({ error: 'Administrator role required' }, 403)] });
  render(<ConfirmItsYou />);
  expect((await adminFetch('/x', { method: 'POST' })).status).toBe(403);
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('retries the request once the admin has signed in again', async () => {
  const calls = answers({ '/x': [json(STEP_UP, 403), json({ ok: true })] });
  render(<ConfirmItsYou />);
  const pending = adminFetch('/x', { method: 'POST' });
  const dialog = await screen.findByRole('dialog', { name: "Confirm it's you" });
  const link = within(dialog).getByRole('link', { name: 'Sign in to KyIdentity again' });
  expect(link.getAttribute('href')).toBe('/api/sso/kyidentity/login?fresh=1');
  expect(link.getAttribute('target')).toBe('_blank');
  expect(link.getAttribute('rel')).toBe('noopener noreferrer');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Retry' }));
  expect((await pending).status).toBe(200);
  expect(calls).toEqual(['/x', '/x']);
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('returns the refusal when the admin cancels', async () => {
  answers({ '/x': [json(STEP_UP, 403)] });
  render(<ConfirmItsYou />);
  const pending = adminFetch('/x', { method: 'POST' });
  fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
  expect((await pending).status).toBe(403);
});

it('offers no link for a reauth_url off the suite sign-in route', async () => {
  answers({ '/x': [json({ ...STEP_UP, reauth_url: 'https://evil.example/' }, 403)] });
  render(<ConfirmItsYou />);
  void adminFetch('/x', { method: 'POST' });
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).queryByRole('link')).toBeNull();
  expect(dialog.textContent).toContain('sign out and sign in again');
});

it('answers concurrent refusals with one prompt', async () => {
  answers({ '/a': [json(STEP_UP, 403), json({ ok: 1 })], '/b': [json(STEP_UP, 403), json({ ok: 2 })] });
  render(<ConfirmItsYou />);
  const a = adminFetch('/a', { method: 'POST' });
  const b = adminFetch('/b', { method: 'POST' });
  await screen.findByRole('dialog');
  // Both refusals are mocked and parse within a few ticks; 50 ms lets the second join the open prompt.
  await new Promise((r) => setTimeout(r, 50));
  expect(screen.getAllByRole('dialog')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect((await a).status).toBe(200);
  expect((await b).status).toBe(200);
});

it('never leaves a refusal hanging when the answer lands while it is joining', async () => {
  answers({ '/a': [json(STEP_UP, 403)], '/b': [json(STEP_UP, 403)] });
  render(<ConfirmItsYou />);
  const a = adminFetch('/a', { method: 'POST' });
  await screen.findByRole('dialog');
  const b = adminFetch('/b', { method: 'POST' });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect((await a).status).toBe(403);
  // b either joined the answer or opened its own prompt; cancelling that settles it too.
  const settled = await Promise.race([b, screen.findByRole('dialog').then((d) => { fireEvent.click(within(d).getByRole('button', { name: 'Cancel' })); return b; })]);
  expect(settled.status).toBe(403);
});

// A local account signs in again in place (password, then TOTP), never by signing out, which
// would delete this browser's encryption keys in every tab.
it('signs a local account in again in place, through TOTP, then retries', async () => {
  const LOCAL = { error: STEP_UP.error, code: STEP_UP.code };
  const calls = answers({
    '/x': [json(LOCAL, 403), json({ ok: true })],
    '/api/auth/pow-challenge': [json({ error: 'off' }, 404)],
    '/api/auth/login': [json({ mfa_required: true, mfa_token: 'mfa-1' })],
    '/api/auth/mfa/totp': [json({ authenticated: true, user: { username: 'alice', role: 'user' } })],
  });
  render(<ConfirmItsYou username="alice" />);
  const pending = adminFetch('/x', { method: 'PUT' });
  const dialog = await screen.findByRole('dialog', { name: "Confirm it's you" });
  expect(within(dialog).queryByText(/sign out/)).toBeNull();
  fireEvent.change(within(dialog).getByLabelText('Password for @alice'), { target: { value: 'pw' } });
  await signInReady(dialog);
  fireEvent.change(await within(dialog).findByLabelText(/Authentication code/), { target: { value: '123456' } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Verify' }));
  expect((await pending).status).toBe(200);
  expect(calls.filter((c) => !c.includes('pow-challenge'))).toEqual(['/x', '/api/auth/login', '/api/auth/mfa/totp', '/x']);
});

it('goes back to the password when a refused code spent its challenge, and then succeeds', async () => {
  const LOCAL = { error: STEP_UP.error, code: STEP_UP.code };
  answers({
    '/x': [json(LOCAL, 403), json({ ok: true })],
    '/api/auth/pow-challenge': [json({ error: 'off' }, 404)],
    '/api/auth/login': [json({ mfa_required: true, mfa_token: 'mfa-1' }), json({ mfa_required: true, mfa_token: 'mfa-2' })],
    '/api/auth/mfa/totp': [json({ error: 'Invalid code' }, 401), json({ authenticated: true, user: { username: 'alice', role: 'user' } })],
  });
  render(<ConfirmItsYou username="alice" />);
  const pending = adminFetch('/x', { method: 'PUT' });
  const dialog = await screen.findByRole('dialog', { name: "Confirm it's you" });
  const signIn = async () => {
    fireEvent.change(await within(dialog).findByLabelText('Password for @alice'), { target: { value: 'pw' } });
    await signInReady(dialog);
    fireEvent.change(await within(dialog).findByLabelText(/Authentication code/), { target: { value: '123456' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify' }));
  };
  await signIn();
  expect((await within(dialog).findByRole('alert')).textContent).toMatch(/Enter your password again/);
  await signIn();
  expect((await pending).status).toBe(200);
});

it('never sends a captcha token again that a login spent, also after a refused code', async () => {
  const LOCAL = { error: STEP_UP.error, code: STEP_UP.code };
  const tokens: unknown[] = [];
  const replies: Record<string, Response[]> = {
    '/x': [json(LOCAL, 403), json({ ok: true })],
    '/api/auth/login': [json({ mfa_required: true, mfa_token: 'mfa-1' }), json({ mfa_required: true, mfa_token: 'mfa-2' })],
    '/api/auth/mfa/totp': [json({ error: 'Invalid code' }, 401), json({ authenticated: true, user: { username: 'alice', role: 'user' } })],
  };
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/api/auth/login') tokens.push((JSON.parse(String(init?.body)) as { captcha_token?: string }).captcha_token);
    const q = replies[url];
    return (q.length > 1 ? q.shift() : q[0])!.clone();
  }));
  render(<ConfirmItsYou username="alice" />);
  const pending = adminFetch('/x', { method: 'PUT' });
  const dialog = await screen.findByRole('dialog', { name: "Confirm it's you" });
  // No sign-in while the challenge is still being solved.
  expect(within(dialog).getByRole('button', { name: 'Sign in again' })).toHaveProperty('disabled', true);
  for (let i = 0; i < 2; i++) {
    fireEvent.change(await within(dialog).findByLabelText('Password for @alice'), { target: { value: 'pw' } });
    await signInReady(dialog);
    fireEvent.change(await within(dialog).findByLabelText(/Authentication code/), { target: { value: '123456' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify' }));
  }
  expect((await pending).status).toBe(200);
  expect(tokens).toHaveLength(2);
  expect(tokens[0]).toBeTruthy();
  expect(tokens[1]).toBeTruthy();
  expect(tokens[1]).not.toBe(tokens[0]);
});
