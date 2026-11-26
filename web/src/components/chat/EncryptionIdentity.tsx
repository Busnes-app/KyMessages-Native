// The E3 identity screens (docs/superpowers/specs/2026-11-22-e2ee-design.md §3): the first
// device's recovery key, verifying a new device (another device's code or the recovery key),
// showing a code to verify another device, and the blocking warning when a member's identity
// changed. All crypto runs in chat/e2ee.ts; nothing here sees a key.
import React, { useCallback, useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  acceptIdentity, identityChanges, identityStatus, joinVerification, offerVerification, onIdentityChanged, prepareIdentity, restoreIdentity,
} from '../../chat/e2ee';
import { formatFingerprint, type IdentityChange, type IdentityStatus, type PairingJoin, type PairingOffer } from '../../crypto/identity';
import { ChatDialog } from './ChatModals';

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

function Alert({ text }: { text: string }) {
  return text ? <div className="dr-alert dr-alert-error" role="alert" style={{ padding: '0.5rem 0.65rem', fontSize: '0.82rem' }}>{text}</div> : null;
}

/** A copy button that says so when the browser refuses. */
function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error('no clipboard');
      await navigator.clipboard.writeText(text);
      setState('copied');
    } catch {
      setState('failed');
    }
  };
  return (
    <>
      <button type="button" className="btn-secondary" onClick={() => void copy()}>{state === 'copied' ? 'Copied' : label}</button>
      {state === 'failed' && <span role="alert">Copying failed. Select the text and copy it, or write it down.</span>}
    </>
  );
}

/** The first device: shows the recovery key once and uploads the identity only after "saved it". */
export function SetUpEncryption({ reset = false, onDone, onClose }: { reset?: boolean; onDone: () => void; onClose: () => void }) {
  const [prepared, setPrepared] = useState<{ recoveryKey: string; commit(): Promise<void> }>();
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  useEffect(() => {
    let live = true;
    prepareIdentity(reset).then((p) => live && setPrepared(p), (e: unknown) => live && setErr(errText(e, 'Encryption could not start.')));
    // The key leaves memory with the screen.
    return () => { live = false; setPrepared(undefined); };
  }, [reset]);
  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!prepared || !saved) return;
    setBusy(true);
    setErr('');
    try {
      // A step-up refusal opens "Confirm it's you" and retries this same identity.
      await prepared.commit();
      onDone();
    } catch (x) {
      setErr(errText(x, 'The encryption identity could not be saved.'));
      setBusy(false);
    }
  };
  return (
    <ChatDialog title={reset ? 'Reset your encryption identity' : 'Save your recovery key'} onClose={onClose} busy={busy} onSubmit={submit}>
      <div className="chat-modal-body chat-scroll">
        <Alert text={err} />
        <p>
          {reset
            ? 'A new identity replaces the old one. Everyone you share rooms with will see that your identity changed, and history you cannot restore stays unreadable.'
            : 'Your messages are end-to-end encrypted. This recovery key is the only way to read them on a new device if you have no other signed-in device. KyMessages cannot recover it for you.'}
        </p>
        {prepared ? (
          <>
            <code className="e2ee-recovery-key" aria-label="Recovery key" data-testid="recovery-key">{prepared.recoveryKey}</code>
            <CopyButton text={prepared.recoveryKey} />
          </>
        ) : !err && <p>Generating keys…</p>}
        <label className="chat-checkbox-row">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} disabled={!prepared || busy} />
          I saved my recovery key somewhere safe
        </label>
      </div>
      <div className="chat-modal-foot">
        <button type="button" className="btn-secondary" onClick={onClose} disabled={busy}>Not now</button>
        <button type="submit" disabled={!prepared || !saved || busy}>{busy ? 'Saving…' : 'Continue'}</button>
      </div>
    </ChatDialog>
  );
}

/**
 * A new device: verify with another device's code, or with the recovery key. With a code, the
 * user confirms the six digits match the other screen before this device takes any keys.
 */
export function VerifyThisDevice({ fingerprint, onDone, onClose, onReset }: { fingerprint: string; onDone: (restored: number) => void; onClose: () => void; onReset: () => void }) {
  const [mode, setMode] = useState<'device' | 'recovery'>('device');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [join, setJoin] = useState<PairingJoin>();
  const [waiting, setWaiting] = useState(false);
  const abort = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => abort.current?.abort(), []);
  const switchMode = (m: 'device' | 'recovery') => {
    setMode(m);
    setText(''); // a pasted recovery key never lingers in the other field
    setErr('');
  };

  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErr('');
    setBusy(true);
    try {
      if (mode === 'recovery') {
        const n = await restoreIdentity(text);
        setText('');
        onDone(n);
        return;
      }
      setJoin(await joinVerification(text));
      setText('');
    } catch (x) {
      setErr(errText(x, 'This device could not be verified.'));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async () => {
    if (!join) return;
    setWaiting(true);
    abort.current = new AbortController();
    try {
      onDone(await join.finish(abort.current.signal));
    } catch (x) {
      if (abort.current?.signal.aborted) return;
      setErr(errText(x, 'This device could not be verified.'));
      setJoin(undefined);
      setWaiting(false);
    }
  };
  const close = () => {
    abort.current?.abort();
    void join?.cancel().catch(() => undefined);
    setText('');
    onClose();
  };
  return (
    <ChatDialog title="Verify this device" onClose={close} busy={busy || waiting} onSubmit={join ? undefined : submit}>
      <div className="chat-modal-body chat-scroll">
        <Alert text={err} />
        <p>Until this device is verified, it receives nothing sent to you and shares its own messages with no one. Your identity: <code>{formatFingerprint(fingerprint)}</code></p>
        {join ? (
          <div role="status">
            <p>Your other device shows a code. Does it match this one exactly?</p>
            <p className="e2ee-code" data-testid="comparison-code">{join.code}</p>
            {waiting && <p>Waiting for your other device to approve…</p>}
          </div>
        ) : (
          <>
            <div className="chat-field" role="radiogroup" aria-label="How to verify">
              <label className="chat-checkbox-row"><input type="radio" checked={mode === 'device'} onChange={() => switchMode('device')} /> Use a code from my other device</label>
              <label className="chat-checkbox-row"><input type="radio" checked={mode === 'recovery'} onChange={() => switchMode('recovery')} /> Use my recovery key</label>
            </div>
            <div className="chat-field">
              <label htmlFor="e2ee-verify-text">{mode === 'device' ? 'Verification code (the shield button, “Verify a device”, on a signed-in device)' : 'Recovery key'}</label>
              <textarea id="e2ee-verify-text" value={text} onChange={(e) => setText(e.target.value)} rows={3} autoFocus spellCheck={false} autoComplete="off" />
            </div>
            <button type="button" className="btn-link" onClick={onReset} disabled={busy}>I lost my recovery key and every other device</button>
          </>
        )}
      </div>
      <div className="chat-modal-foot">
        <button type="button" className="btn-secondary" onClick={close}>{join ? 'They do not match' : 'Not now'}</button>
        {join
          ? <button type="button" onClick={() => void confirm()} disabled={waiting}>{waiting ? 'Waiting…' : 'The codes match'}</button>
          : <button type="submit" disabled={busy || !text.trim()}>{busy ? 'Checking…' : 'Verify'}</button>}
      </div>
    </ChatDialog>
  );
}

/** On a verified device: the code to verify a new one, then its comparison code to approve. */
export function VerifyAnotherDevice({ onClose }: { onClose: () => void }) {
  const [offer, setOffer] = useState<PairingOffer>();
  const [qr, setQr] = useState('');
  const [joined, setJoined] = useState<{ code: string; device: string }>();
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const offerRef = useRef<PairingOffer | undefined>(undefined);
  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    void (async () => {
      try {
        const o = await offerVerification();
        if (!live) return void o.cancel().catch(() => undefined);
        // The server's lifetime, counted on this clock: the two clocks may disagree.
        const deadline = Date.now() + o.expiresInMs;
        offerRef.current = o;
        setOffer(o);
        // The copyable code works without the picture.
        setQr(await QRCode.toDataURL(o.text, { margin: 1, width: 220 }).catch(() => ''));
        const poll = async () => {
          if (!live) return;
          if (Date.now() >= deadline) return setErr('The code expired. Close this and start again.');
          try {
            const j = await o.poll();
            if (j) return live && setJoined(j);
          } catch {
            return live && setErr('The code expired or was used. Close this and start again.');
          }
          timer = setTimeout(() => void poll(), 1500);
        };
        void poll();
      } catch (e) {
        if (live) setErr(errText(e, 'Verification could not start.'));
      }
    })();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, []);
  const close = () => {
    if (!done) void offerRef.current?.cancel().catch(() => undefined);
    onClose();
  };
  const approve = async () => {
    setBusy(true);
    try {
      await offer!.approve();
      setDone(true);
    } catch (e) {
      setErr(errText(e, 'The keys could not be sent.'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <ChatDialog title="Verify a device" onClose={close} busy={busy}>
      <div className="chat-modal-body chat-scroll">
        <Alert text={err} />
        {done ? (
          <p role="status"><ShieldCheck size={16} aria-hidden="true" /> The new device is verified.</p>
        ) : joined ? (
          <div role="status">
            <p>Does the new device show this code?</p>
            <p className="e2ee-code" data-testid="comparison-code">{joined.code}</p>
            <p>Approve only if it matches exactly. Approving gives that device your encryption keys.</p>
          </div>
        ) : offer ? (
          <>
            <p>On the new device, choose “Use a code from my other device” and scan or paste this code. It works once, for a few minutes.</p>
            {qr && <img src={qr} alt="Verification QR code" width={220} height={220} />}
            <code className="e2ee-recovery-key" data-testid="verification-code">{offer.text}</code>
            <CopyButton text={offer.text} label="Copy code" />
          </>
        ) : !err && <p>Starting…</p>}
      </div>
      <div className="chat-modal-foot">
        <button type="button" className="btn-secondary" onClick={close} disabled={busy}>{done ? 'Close' : joined ? 'It does not match' : 'Cancel'}</button>
        {joined && !done && <button type="button" onClick={() => void approve()} disabled={busy}>{busy ? 'Sending…' : 'The codes match'}</button>}
      </div>
    </ChatDialog>
  );
}

export type GateState = { state: 'loading' } | { state: 'error'; message: string } | IdentityStatus;

/** This device's identity status, kept current once encryption is ready. */
export function useIdentityStatus(ready: boolean): [GateState, () => void] {
  const [gate, setGate] = useState<GateState>({ state: 'loading' });
  const refresh = useCallback(() => {
    identityStatus().then(setGate, (e: unknown) => setGate({ state: 'error', message: errText(e, 'The encryption identity could not be checked.') }));
  }, []);
  useEffect(() => {
    if (!ready) return;
    refresh();
    return onIdentityChanged(refresh);
  }, [ready, refresh]);
  return [gate, refresh];
}

/**
 * While this account has no identity or this device is unverified, a banner (it never blocks
 * the page) offers the setup or verification screen. An unverified device receives no room
 * keys, so the banner stays until it is verified. A failed check says so, with Retry.
 */
export function EncryptionIdentityGate({ gate, refresh }: { gate: GateState; refresh: () => void }) {
  const [open, setOpen] = useState(false);
  const [reset, setReset] = useState(false);
  if (gate.state === 'loading' || gate.state === 'verified') return null;
  if (gate.state === 'error') {
    return (
      <div className="chat-banner chat-banner-error" role="alert">
        <ShieldAlert size={16} aria-hidden="true" />
        <span>{gate.message}</span>
        <button type="button" className="btn-secondary" onClick={refresh}>Retry</button>
      </div>
    );
  }
  const close = () => { setOpen(false); setReset(false); };
  const done = () => { close(); refresh(); };
  return (
    <>
      <div className="chat-banner chat-banner-info" role="status">
        <ShieldAlert size={16} aria-hidden="true" />
        <span>
          {gate.state === 'none'
            ? 'Set up encryption to read messages sent to you.'
            : 'Verify this device to read messages sent to you. Until then nothing you send here can be read.'}
          {gate.quarantined && ' This browser set aside the keys of an identity the server no longer lists; they are kept, not deleted.'}
        </span>
        <button type="button" className="btn-secondary" onClick={() => setOpen(true)}>
          {gate.state === 'none' ? 'Set up encryption' : 'Verify this device'}
        </button>
      </div>
      {open && (gate.state === 'none' || reset
        ? <SetUpEncryption reset={reset} onClose={close} onDone={done} />
        : <VerifyThisDevice fingerprint={gate.fingerprint} onClose={close} onReset={() => setReset(true)} onDone={done} />)}
    </>
  );
}

/** The blocking warning for members of a room whose identity changed since this device pinned it. */
export function IdentityChangedBanner({ memberIds, nameOf }: { memberIds: string[]; nameOf: (userId: string) => string }) {
  const [changes, setChanges] = useState<IdentityChange[]>([]);
  const [err, setErr] = useState('');
  useEffect(() => {
    let live = true;
    const load = () => void identityChanges().then((c) => live && setChanges(c), () => undefined);
    load();
    const off = onIdentityChanged(load);
    return () => { live = false; off(); };
  }, []);
  const here = changes.filter((c) => memberIds.includes(c.user_id));
  if (here.length === 0) return null;
  return (
    <>
      {here.map((c) => (
        <div key={c.user_id} className="chat-banner chat-banner-error" role="alert">
          <ShieldAlert size={16} aria-hidden="true" />
          <span>
            {nameOf(c.user_id)}’s identity changed. Messages you send here are not shared with their devices until you accept the new identity.
            {' '}Check the whole fingerprint with them first: <code data-testid="new-fingerprint">{formatFingerprint(c.fingerprint)}</code>
          </span>
          <CopyButton text={formatFingerprint(c.fingerprint)} label="Copy fingerprint" />
          {/* Accepts exactly the fingerprint shown; if it changed meanwhile, nothing is accepted. */}
          <button type="button" className="btn-secondary" onClick={() => acceptIdentity(c.user_id, c.previous, c.fingerprint).catch((e: unknown) => setErr(errText(e, 'Could not accept the identity.')))}>
            Accept new identity
          </button>
        </div>
      ))}
      {err && <div className="chat-banner chat-banner-error" role="alert"><span>{err}</span></div>}
    </>
  );
}
