import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CaptchaWidget } from './CaptchaWidget';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const hex = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))).map((b) => b.toString(16).padStart(2, '0')).join('');

it('re-solves a failed challenge, and starts every round without a token', async () => {
  const challenge = { algorithm: 'SHA-256', salt: 'salt', challenge: await hex('salt3'), maxnumber: 5, expires_at: Math.floor(Date.now() / 1000) + 600, signature: 'sig' };
  let fail = true;
  vi.stubGlobal('fetch', vi.fn(async () => (fail ? new Response('{}', { status: 500 }) : new Response(JSON.stringify(challenge), { status: 200 }))));
  const tokens: string[] = [];
  const { rerender } = render(<CaptchaWidget onToken={(t) => tokens.push(t)} round={0} />);
  const again = await screen.findByRole('button', { name: 'Try again' });
  fail = false;
  fireEvent.click(again);
  await waitFor(() => expect(tokens.at(-1)).toMatch(/./));
  expect(JSON.parse(atob(tokens.at(-1)!)).number).toBe(3);
  // The next round: the spent token is cleared at once, before the new one is solved.
  const solved = tokens.length;
  rerender(<CaptchaWidget onToken={(t) => tokens.push(t)} round={1} />);
  await waitFor(() => expect(tokens.length).toBeGreaterThan(solved));
  expect(tokens[solved]).toBe('');
});
