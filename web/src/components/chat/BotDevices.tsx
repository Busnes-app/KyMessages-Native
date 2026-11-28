// E4 (docs/superpowers/specs/2026-11-22-e2ee-design.md §8): the owner vouches for their bots'
// devices. Each device the bot uploaded is shown with its code; the owner types the code the bot
// itself prints (kybot.py init), and only a match is signed with the owner's master key. Removing
// a device signs a list without it, so colleagues stop sharing room keys with it. A device is
// vouched for only while its uploaded keys are the signed ones: other keys under its ID show as
// changed and need a fresh code.
import { useCallback, useEffect, useState } from 'react';
import { botDevices, ownBots, vouchForBot, type OwnBot } from '../../chat/e2ee';
import type { BotDevice } from '../../pqc/index';
import { ChatDialog } from './ChatModals';

type Shown = BotDevice & { code: string };
interface BotView {
  bot: OwnBot;
  uploaded: Shown[];
  vouched: BotDevice[];
  epoch: number;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);
const norm = (code: string) => code.toLowerCase().replace(/[^0-9a-f]/g, '');

export function BotDevices({ onClose }: { onClose: () => void }) {
  const [views, setViews] = useState<BotView[]>();
  const [typed, setTyped] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const load = useCallback(async () => {
    const bots = await ownBots();
    return Promise.all(bots.map(async (bot) => {
      const v = await botDevices(bot.user_id);
      return { bot, uploaded: v.uploaded, vouched: v.vouched, epoch: v.epoch };
    }));
  }, []);
  useEffect(() => {
    let live = true;
    load().then((v) => live && setViews(v), (e: unknown) => live && setErr(errText(e, 'Your bots could not be loaded.')));
    return () => { live = false; };
  }, [load]);

  const change = async (view: BotView, edit: { add?: Shown; remove?: string }) => {
    setBusy(true);
    setErr('');
    try {
      await vouchForBot(view.bot.user_id, view.epoch, edit);
      setViews(await load());
      setTyped({});
    } catch (e) {
      // The list may have moved on (another tab): show the server's list and let the user
      // retry against it, rather than resending a stale epoch forever.
      const msg = errText(e, 'The bot’s devices could not be changed.');
      setErr(msg);
      try {
        setViews(await load());
        setErr(`${msg} The list below is up to date: check it and try again.`);
      } catch {
        // Keep the first error; the old list stays until the dialog is reopened.
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <ChatDialog title="Your bots" onClose={onClose} busy={busy}>
      <div className="chat-modal-body chat-scroll">
        {err && <div className="dr-alert dr-alert-error" role="alert">{err}</div>}
        <p>A bot reads a room only on devices you vouch for. Vouch for a device once the code below matches the one your bot shows.</p>
        {views === undefined && !err && <p>Loading…</p>}
        {views?.length === 0 && <p>You own no bots.</p>}
        {views?.map((view) => {
          const signed = new Map(view.vouched.map((d) => [d.device_id, d]));
          const gone = view.vouched.filter((s) => !view.uploaded.some((d) => d.device_id === s.device_id));
          const remove = (id: string) => (
            <button type="button" className="btn-secondary" disabled={busy} onClick={() => void change(view, { remove: id })}>
              Remove
            </button>
          );
          return (
            <section key={view.bot.user_id} aria-label={`Bot ${view.bot.display_name || view.bot.username}`}>
              <h3>{view.bot.display_name || view.bot.username}</h3>
              {view.uploaded.length === 0 && <p>This bot has not set up encryption yet.</p>}
              <ul>
                {view.uploaded.map((d) => {
                  const key = `${view.bot.user_id}/${d.device_id}`;
                  const s = signed.get(d.device_id);
                  const on = s?.curve25519 === d.curve25519 && s.ed25519 === d.ed25519;
                  const matches = norm(typed[key] ?? '') === norm(d.code);
                  return (
                    <li key={d.device_id}>
                      <code>{d.device_id}</code> {on ? 'Vouched for' : s ? 'Changed: its keys are not the ones you vouched for' : 'Not vouched for'}
                      {on ? remove(d.device_id) : (
                        <>
                          {s && remove(d.device_id)}
                          <label>
                            Code your bot shows
                            <input value={typed[key] ?? ''} onChange={(e) => setTyped({ ...typed, [key]: e.target.value })} placeholder="xxxx-xxxx-xxxx-xxxx-xxxx" autoComplete="off" spellCheck={false} />
                          </label>
                          <button type="button" disabled={busy || !matches} onClick={() => void change(view, { add: d })}>
                            Vouch for this device
                          </button>
                          {typed[key] && !matches && norm(typed[key]).length >= 20 && <span role="alert">The codes differ: do not vouch for this device.</span>}
                        </>
                      )}
                    </li>
                  );
                })}
                {gone.map((s) => (
                  <li key={s.device_id}>
                    <code>{s.device_id}</code> Vouched for, but the bot no longer shows it
                    {remove(s.device_id)}
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
    </ChatDialog>
  );
}
