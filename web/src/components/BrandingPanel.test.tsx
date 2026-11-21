import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BrandingPanel, parseBranding } from './BrandingPanel';

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const SHA = 'a'.repeat(64);
const STATE = {
  name: 'KyMessages',
  stored_name: '',
  default_name: 'KyMessages',
  logo: { custom: false, sha256: '', size: 0 },
};

function serve(route: (url: string, init?: RequestInit) => Response | undefined) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const res = route(url, init);
    if (!res) throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`);
    return res;
  }));
  return calls;
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('parseBranding', () => {
  it('parses branding payload and refuses a malformed logo field', () => {
    expect(parseBranding(STATE)).toEqual(STATE);
    expect(() => parseBranding({ ...STATE, logo: { custom: 'yes', sha256: '', size: 0 } })).toThrow();
  });
});

describe('BrandingPanel', () => {
  it('saves a name and tells the shell to re-read the settings', async () => {
    const onChanged = vi.fn();
    const calls = serve((url, init) => {
      if (url === '/api/admin/branding') return json(STATE);
      if (url === '/api/admin/branding/name' && init?.method === 'PUT') return json({ ...STATE, name: 'Acme', stored_name: 'Acme' });
      return undefined;
    });
    render(<BrandingPanel onChanged={onChanged} />);
    fireEvent.change(await screen.findByLabelText('Product name'), { target: { value: 'Acme' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save name' }));
    expect(await screen.findByText(/^Name saved/)).toBeTruthy();
    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(calls.find((c) => c.init?.method === 'PUT')?.init?.body).toBe(JSON.stringify({ name: 'Acme' }));
    expect(screen.getByRole('button', { name: 'Use default (KyMessages)' })).toBeTruthy();
  });

  it('resets the name to the default', async () => {
    const calls = serve((url, init) => {
      if (url === '/api/admin/branding') return json({ ...STATE, name: 'Acme', stored_name: 'Acme' });
      if (init?.method === 'PUT') return json(STATE);
      return undefined;
    });
    render(<BrandingPanel onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Use default (KyMessages)' }));
    await waitFor(() => expect(calls.find((c) => c.init?.method === 'PUT')?.init?.body).toBe(JSON.stringify({ name: '' })));
    expect(await screen.findByText('Name reset to KyMessages.')).toBeTruthy();
  });

  it('uploads a PNG and previews it by its digest, never through a blob URL', async () => {
    const calls = serve((url, init) => {
      if (url === '/api/admin/branding') return json(STATE);
      if (url === '/api/admin/branding/logo' && init?.method === 'PUT') return json({ ...STATE, logo: { custom: true, sha256: SHA, size: 1234 } });
      if (url === '/api/admin/branding/logo' && init?.method === 'DELETE') return json(STATE);
      return undefined;
    });
    render(<BrandingPanel onChanged={() => {}} />);
    expect((await screen.findByAltText('Current logo')).getAttribute('src')).toBe('/app-icon.png?v=default');
    const file = new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], 'logo.png', { type: 'image/png' });
    fireEvent.change(screen.getByLabelText(/^Logo/), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: 'Upload logo' }));
    await waitFor(() => expect(screen.getByAltText('Current logo').getAttribute('src')).toBe(`/app-icon.png?v=${SHA}`));
    const put = calls.find((c) => c.init?.method === 'PUT');
    expect(new Headers(put?.init?.headers).get('Content-Type')).toBe('image/png');
    expect(put?.init?.body).toBe(file);
    fireEvent.click(screen.getByRole('button', { name: 'Reset logo' }));
    await waitFor(() => expect(screen.getByAltText('Current logo').getAttribute('src')).toBe('/app-icon.png?v=default'));
  });

  it('refuses a file over 1 MiB without sending it', async () => {
    const calls = serve((url) => (url === '/api/admin/branding' ? json(STATE) : undefined));
    render(<BrandingPanel onChanged={() => {}} />);
    const big = new File([new Uint8Array((1 << 20) + 1)], 'big.png', { type: 'image/png' });
    fireEvent.change(await screen.findByLabelText(/^Logo/), { target: { files: [big] } });
    fireEvent.click(screen.getByRole('button', { name: 'Upload logo' }));
    expect(await screen.findByText('The logo must be at most 1 MiB.')).toBeTruthy();
    expect(calls.filter((c) => c.init?.method === 'PUT')).toHaveLength(0);
  });
});
