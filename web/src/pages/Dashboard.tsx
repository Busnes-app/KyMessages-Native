import React, { useEffect, useState } from 'react';
import { Activity, Archive, ArrowRight, Users } from 'lucide-react';
import { arr, obj } from '../dto';
import { parseHealth } from './Health';
import { backupAttempt } from './Backup';

interface DashboardProps {
  settings: { app_name?: string } | null;
  user: { display_name?: string; username?: string } | null;
  onNavigate: (tab: string) => void;
}
interface Card { text: string; tone: 'success' | 'warning' | 'danger' | 'muted' }
const OUTCOME = { success: 'Succeeded', warning: 'Needs attention', failure: 'Failed', unknown: 'Outcome unavailable' } as const;
const checking: Card = { text: 'Checking…', tone: 'muted' };
const TONE: Record<Card['tone'], string> = { success: 'dr-ok', warning: 'dr-warn', danger: 'dr-danger', muted: '' };

export const Dashboard: React.FC<DashboardProps> = ({ settings, user, onNavigate }) => {
  const [health, setHealth] = useState<Card>(checking);
  const [directory, setDirectory] = useState<Card>(checking);
  const [backup, setBackup] = useState<Card>(checking);

  useEffect(() => {
    const controller = new AbortController();
    const get = (path: string) => fetch(path, { signal: controller.signal, cache: 'no-store' });
    const settle = (set: (c: Card) => void, work: Promise<Card>) =>
      work.then(set, (err: unknown) => {
        if (!controller.signal.aborted) set({ text: `Unavailable: ${err instanceof Error ? err.message : 'request failed'}`, tone: 'danger' });
      });
    void settle(setHealth, get('/api/admin/health').then(async (res): Promise<Card> => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { components } = parseHealth(await res.json());
      const down = components.filter((c) => c.status === 'down').length;
      const off = components.filter((c) => c.mismatch).length;
      const text = `${components.length - down} of ${components.length} components up` +
        (off ? `, ${off} off their pinned version` : '');
      return { text, tone: down || off ? 'danger' : 'success' };
    }));
    void settle(setDirectory, get('/api/v1/users').then(async (res): Promise<Card> => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = obj(await res.json());
      const total = arr(body.users).length;
      return { text: `${total} active member${total === 1 ? '' : 's'}`, tone: 'muted' };
    }));
    void settle(setBackup, get('/api/backup/status').then(async (res): Promise<Card> => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body: unknown = await res.json();
      const last = backupAttempt(typeof body === 'object' && body !== null ? (body as { last_run?: unknown }).last_run : undefined);
      if (!last) return { text: 'Last backup: none recorded', tone: 'muted' };
      return {
        text: `Last backup: ${OUTCOME[last.outcome]} ${new Date(last.recorded_at).toLocaleString()}`,
        tone: last.outcome === 'success' ? 'success' : last.outcome === 'unknown' ? 'muted' : 'danger',
      };
    }));
    return () => controller.abort();
  }, []);

  const cards = [
    { title: 'Service health', card: health, Icon: Activity, tab: 'health', action: 'Open Health' },
    { title: 'Workspace directory', card: directory, Icon: Users, tab: 'scim', action: 'Open Directory & SCIM' },
    { title: 'Backups', card: backup, Icon: Archive, tab: 'backup', action: 'Open Backup & recovery' },
  ];
  return (
    <div className="operator-overview">
      <header className="operator-heading">
        <h1>Overview</h1>
        <p>{settings?.app_name || 'KyMessages'} administration · {user?.display_name || user?.username || 'Administrator'}</p>
      </header>
      <p className="operator-boundary">Monitor service health, directory provisioning, and backup snapshots for this workspace.</p>
      <div className="operator-summary">
        {cards.map(({ title, card, Icon, tab, action }) => (
          <section key={tab} className="operator-row" aria-label={title}>
            <h2><Icon size={19} aria-hidden="true" />{title}</h2>
            <p role="status" className={TONE[card.tone]}>{card.text}</p>
            <button type="button" className="btn-secondary" onClick={() => onNavigate(tab)}>
              <span>{action}</span><ArrowRight size={14} aria-hidden="true" />
            </button>
          </section>
        ))}
      </div>
    </div>
  );
};
