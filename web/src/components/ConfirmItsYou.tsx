import { useEffect, useRef, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { onReauthRequired, secureFetch, type Reauth } from '../api';
import { CaptchaWidget } from './CaptchaWidget';

/**
 * Signs a local account in again here, with its password (and TOTP or a recovery code when it
 * has one), so the session is fresh without signing out: signing out would delete this
 * browser's encryption keys in every tab.
 */
function SignInAgain({ username, onDone }: { username: string; onDone: () => void }) {
  const [password, setPassword] = useState('');
  const [mfa, setMfa] = useState<string>('');
  const [code, setCode] = useState('');
  const [captcha, setCaptcha] = useState('');
  // While a challenge is being solved, signing in would send no token or a spent one.
  const [solving, setSolving] = useState(true);
  const [round, setRound] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const post = async (path: string, body: unknown) => {
    const res = await secureFetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = (await res.json().catch(() => ({}))) as { error?: string; mfa_required?: boolean; mfa_token?: string; authenticated?: boolean };
    if (!res.ok) throw new Error(data.error || 'Sign-in failed');
    return data;
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      const data = mfa
        ? await post(/^\d{6}$/.test(code.trim()) ? '/api/auth/mfa/totp' : '/api/auth/mfa/recovery-code', { mfa_token: mfa, code: code.trim() })
        : await post('/api/auth/login', { username, password, captcha_token: captcha || undefined });
      if (data.mfa_required && data.mfa_token) setMfa(data.mfa_token);
      else if (data.authenticated) onDone();
    } catch (x) {
      setErr(x instanceof Error ? x.message : 'Sign-in failed');
      // A refused code may have spent its challenge: start again from the password, rather
      // than leave a code box that can never succeed.
      if (mfa) {
        setMfa('');
        setCode('');
        setErr(`${x instanceof Error ? x.message : 'The code was not accepted'}. Enter your password again.`);
      }
    } finally {
      setBusy(false);
      // A captcha token is spent by the login that carried it, including one whose code step
      // then failed: the password step always gets a fresh challenge.
      setCaptcha('');
      setRound((r) => r + 1);
    }
  };
  return (
    <form onSubmit={submit} style={{ display: 'grid', gap: '8px', marginBottom: '16px' }}>
      {err && <div className="dr-alert dr-alert-error" role="alert">{err}</div>}
      {mfa ? (
        <label>Authentication code or recovery code
          <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
        </label>
      ) : (
        <>
          <label>Password for @{username}
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
          </label>
          <CaptchaWidget onToken={setCaptcha} round={round} onStatus={(s) => setSolving(s === 'working')} />
        </>
      )}
      <button type="submit" disabled={busy || (!mfa && solving)}>{busy ? 'Checking…' : mfa ? 'Verify' : 'Sign in again'}</button>
    </form>
  );
}

/** The console's one step-up prompt, mounted once and opened by adminFetch. Refusals that
 * arrive while it is open wait on the same answer; resolvers live in a ref so an answer
 * given before a queued refusal has rendered still settles it. */
export function ConfirmItsYou({ username }: { username?: string } = {}) {
  const [pending, setPending] = useState<Reauth | null>(null);
  const resolvers = useRef<((retry: boolean) => void)[]>([]);
  const dialog = useRef<HTMLDialogElement>(null);
  const settle = (retry: boolean) => resolvers.current.splice(0).forEach((resolve) => resolve(retry));
  useEffect(() => {
    const off = onReauthRequired((r) => new Promise<boolean>((resolve) => {
      resolvers.current.push(resolve);
      setPending((p) => p ?? r);
    }));
    return () => { off(); settle(false); };
  }, []);
  useEffect(() => {
    if (pending && !dialog.current?.open) dialog.current?.showModal();
  }, [pending]);
  const answer = (retry: boolean) => {
    settle(retry);
    dialog.current?.close();
    setPending(null);
  };
  if (!pending) return null;
  return (
    <dialog ref={dialog} className="modal-window" aria-labelledby="confirm-title"
      onClose={() => answer(false)}
      onCancel={(e) => { e.preventDefault(); answer(false); }}>
      <h3 id="confirm-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '18px', marginBottom: '12px' }}>
        <ShieldCheck size={20} style={{ color: 'var(--accent)' }} />
        {"Confirm it's you"}
      </h3>
      <p style={{ color: 'var(--ink)', fontSize: '14px', marginBottom: '12px' }}>{pending.message}</p>
      {pending.url ? (
        <p style={{ fontSize: '14px', marginBottom: '16px' }}>
          <a href={pending.url} target="_blank" rel="noopener noreferrer">Sign in to KyIdentity again</a>
          {' '}in the new tab, then come back here and retry.
        </p>
      ) : username ? (
        <SignInAgain username={username} onDone={() => answer(true)} />
      ) : (
        <p style={{ fontSize: '14px', marginBottom: '16px' }}>
          In another tab, sign out and sign in again, then come back here and retry.
        </p>
      )}
      <div className="dr-actions" style={{ justifyContent: 'flex-end' }}>
        <button type="button" className="btn-secondary" onClick={() => answer(false)}>Cancel</button>
        <button type="button" onClick={() => answer(true)}>Retry</button>
      </div>
    </dialog>
  );
}
