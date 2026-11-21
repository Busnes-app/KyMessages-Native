import React, { useCallback, useEffect, useState } from 'react';
import { Type } from 'lucide-react';
import { adminFetch, errorMessage } from '../api';
import { bool, count, obj, str } from '../dto';

export interface Branding {
  name: string;
  stored_name: string;
  default_name: string;
  logo: { custom: boolean; sha256: string; size: number };
}

export const MAX_LOGO_BYTES = 1 << 20;

export function parseBranding(v: unknown): Branding {
  const b = obj(v);
  const logo = obj(b.logo);
  return {
    name: str(b.name, 256),
    stored_name: str(b.stored_name, 256),
    default_name: str(b.default_name, 256),
    logo: { custom: bool(logo.custom), sha256: str(logo.sha256, 64), size: count(logo.size) },
  };
}

export const BrandingPanel: React.FC<{ onChanged: () => void }> = ({ onChanged }) => {
  const [state, setState] = useState<Branding | null>(null);
  const [name, setName] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const apply = useCallback((b: Branding) => {
    setState(b);
    setName(b.stored_name);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/admin/branding', { signal: controller.signal, cache: 'no-store' })
      .then(async (res) => {
        if (!res.ok) throw new Error(await errorMessage(res, 'Could not load branding'));
        apply(parseBranding(await res.json()));
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : 'Could not load branding');
      });
    return () => controller.abort();
  }, [apply]);

  const change = async (path: string, init: RequestInit, done: string) => {
    setBusy(true);
    setMessage('');
    setError('');
    try {
      const res = await adminFetch(path, init);
      if (!res.ok) throw new Error(await errorMessage(res, 'The change was refused'));
      apply(parseBranding(await res.json()));
      setMessage(done);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The change was refused');
    } finally {
      setBusy(false);
    }
  };
  const saveName = (value: string, done: string) =>
    void change('/api/admin/branding/name', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: value }) }, done);
  const upload = () => {
    if (!file) return;
    if (file.size > MAX_LOGO_BYTES) {
      setMessage('');
      setError('The logo must be at most 1 MiB.');
      return;
    }
    void change('/api/admin/branding/logo', { method: 'PUT', headers: { 'Content-Type': 'image/png' }, body: file }, 'Logo saved. It shows on the next page load.');
  };

  return (
    <section className="panel dr-section" aria-label="Branding">
      <div className="panel-header">
        <h3><Type size={16} /> Branding</h3>
      </div>
      <p className="dr-hint">
        The workspace name and logo shown in KyMessages and its sign-in page. Changes require a sign-in from the last 10 minutes.
      </p>
      {state && (
        <>
          <form className="dr-row" onSubmit={(e) => { e.preventDefault(); saveName(name, 'Name saved.'); }}>
            <label className="dr-field">
              <span>Product name</span>
              <input value={name} placeholder={state.default_name} autoComplete="off" onChange={(e) => setName(e.target.value)} />
            </label>
            <button type="submit" disabled={busy}>Save name</button>
            <button type="button" className="btn-secondary" disabled={busy || !state.stored_name}
              onClick={() => saveName('', `Name reset to ${state.default_name}.`)}>
              Use default ({state.default_name})
            </button>
          </form>
          <div className="dr-row">
            {/* By digest: the CSP allows no object URLs. */}
            <img src={`/app-icon.png?v=${state.logo.custom ? state.logo.sha256 : 'default'}`} width={56} height={56} alt="Current logo" />
            <label className="dr-field">
              <span>Logo (PNG, at most 1 MiB and 1024×1024)</span>
              <input type="file" accept="image/png" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <button type="button" disabled={busy || !file} onClick={upload}>Upload logo</button>
            <button type="button" className="btn-secondary" disabled={busy || !state.logo.custom}
              onClick={() => void change('/api/admin/branding/logo', { method: 'DELETE' }, 'Logo reset to the KyMessages stamp.')}>
              Reset logo
            </button>
          </div>
        </>
      )}
      {message && <div className="dr-alert dr-alert-success" role="status">{message}</div>}
      {error && <div className="dr-alert dr-alert-error" role="alert">{error}</div>}
    </section>
  );
};
