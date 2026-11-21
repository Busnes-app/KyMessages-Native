import React, { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Database, Palette, Radio, Wifi } from 'lucide-react';
import { ThemeSwitcher } from '../components/ThemeSwitcher';
import { BrandingPanel } from '../components/BrandingPanel';
import type { SiteSettings } from '../dto';
import { fetchAdminMediaPolicy, updateAdminMediaPolicy } from '../chat/client';
import type { AdminMediaPolicyResponse, MediaPolicyConfig } from '../chat/types';

interface SettingsProps {
  settings: SiteSettings | null;
  /** Re-reads /api/settings so the shell shows a new name. */
  onBrandingChanged: () => void;
}

export const Settings: React.FC<SettingsProps> = ({ settings, onBrandingChanged }) => {
  const driver = settings?.db_driver;
  const [mediaInfo, setMediaInfo] = useState<AdminMediaPolicyResponse | null>(null);
  const [policyForm, setPolicyForm] = useState<MediaPolicyConfig | null>(null);
  const [savingMedia, setSavingMedia] = useState(false);
  const [mediaNotice, setMediaNotice] = useState('');
  const [mediaError, setMediaError] = useState('');

  useEffect(() => {
    let active = true;
    void fetchAdminMediaPolicy()
      .then((res) => {
        if (!active) return;
        setMediaInfo(res);
        setPolicyForm(res.policy);
      })
      .catch(() => {
        // Non-admin or unavailable: hide card gracefully.
      });
    return () => {
      active = false;
    };
  }, []);

  const handleSaveMediaPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policyForm) return;
    setSavingMedia(true);
    setMediaNotice('');
    setMediaError('');
    try {
      const updated = await updateAdminMediaPolicy(policyForm);
      setMediaInfo((prev) => (prev ? { ...prev, policy: updated } : prev));
      setPolicyForm(updated);
      setMediaNotice('Calling media policy saved.');
    } catch (err) {
      setMediaError(err instanceof Error ? err.message : 'Could not update media policy');
    } finally {
      setSavingMedia(false);
    }
  };

  return (
    <div style={{ maxWidth: '1080px', margin: '0 auto', padding: '32px 20px' }}>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <SettingsIcon size={24} style={{ color: 'var(--accent)' }} />
          <span>System Settings & Architecture</span>
        </h1>
        <p style={{ color: 'var(--ink)', fontSize: '14px', marginTop: '4px' }}>
          Database, hybrid calling bandwidth policy, color theme defaults, and instance configuration.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 480px), 1fr))', gap: '20px' }}>
        {/* Pluggable Database Card */}
        <div className="panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Database size={20} style={{ color: 'var(--accent)' }} />
            <h3 style={{ fontSize: '16px' }}>Database</h3>
          </div>
          <p style={{ color: 'var(--ink)', fontSize: '13px', marginBottom: '16px' }}>
            The supported deployment is SQLite on a single instance.
          </p>

          <div style={{ background: 'var(--bg)', border: '1px solid var(--line)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
              <span style={{ color: 'var(--ink)' }}>Active storage driver:</span>
              <span className="badge badge-accent font-mono">{driver ?? 'unknown'}</span>
            </div>
          </div>
          {driver !== 'sqlite' && (
            <div className="dr-alert dr-alert-warn" role="alert" style={{ marginTop: '12px' }}>
              <span>
                {driver ? `This server runs on ${driver}.` : 'The database driver is unknown.'} Only SQLite is supported, and
                backup capsules can snapshot only SQLite: no capsule carries this database.
              </span>
            </div>
          )}
        </div>

        {/* Appearance */}
        <div className="panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Palette size={20} style={{ color: 'var(--accent)' }} />
            <h3 style={{ fontSize: '16px' }}>Appearance</h3>
          </div>
          <p style={{ color: 'var(--ink)', fontSize: '13px', marginBottom: '16px' }}>
            Color tokens: Patina Ky (`#0d0f14`/`#4deeea`), Cyber, Nord, Paper, OLED with Space Grotesk and IBM Plex Mono fonts.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--ink)' }}>Active Color Palette:</span>
            <ThemeSwitcher />
          </div>
        </div>
      </div>

      {mediaInfo && policyForm && (
        <div className="panel" style={{ marginTop: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', marginBottom: '12px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {policyForm.p2p_policy === 'hybrid' ? (
                <Wifi size={20} style={{ color: 'var(--accent)' }} />
              ) : (
                <Radio size={20} style={{ color: 'var(--accent)' }} />
              )}
              <h3 style={{ fontSize: '16px' }}>Calling & Hybrid Media Policy</h3>
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', fontSize: '12px' }}>
              <span className="badge badge-accent font-mono">
                LiveKit SFU: {mediaInfo.rtc.sfu_available ? 'configured' : 'not configured'}
              </span>
              <span className="badge font-mono">
                Calls: {mediaInfo.stats.active_calls} ({mediaInfo.stats.p2p_calls} P2P · {mediaInfo.stats.sfu_calls} SFU)
              </span>
            </div>
          </div>

          <p style={{ color: 'var(--ink)', fontSize: '13px', marginBottom: '16px' }}>
            Keep 1:1 video and small audio calls peer-to-peer to eliminate server media bandwidth, and automatically
            escalate larger calls, screen shares, or external guests to LiveKit SFU.
          </p>

          <form onSubmit={handleSaveMediaPolicy} style={{ display: 'grid', gap: '14px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
              <label style={{ display: 'grid', gap: '6px', fontSize: '13px' }}>
                <span>Routing Policy</span>
                <select
                  value={policyForm.p2p_policy}
                  onChange={(e) =>
                    setPolicyForm({
                      ...policyForm,
                      p2p_policy: e.target.value === 'sfu_only' ? 'sfu_only' : 'hybrid',
                    })
                  }
                >
                  <option value="hybrid">Hybrid P2P-first (recommended)</option>
                  <option value="sfu_only">SFU Only (route all calls via LiveKit)</option>
                </select>
              </label>

              <label style={{ display: 'grid', gap: '6px', fontSize: '13px' }}>
                <span>Max P2P Video Peers (0–6)</span>
                <input
                  type="number"
                  min={0}
                  max={6}
                  value={policyForm.p2p_max_video}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, p2p_max_video: Number(e.target.value) || 0 })
                  }
                />
              </label>

              <label style={{ display: 'grid', gap: '6px', fontSize: '13px' }}>
                <span>Max P2P Audio Peers (0–8)</span>
                <input
                  type="number"
                  min={0}
                  max={8}
                  value={policyForm.p2p_max_audio}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, p2p_max_audio: Number(e.target.value) || 0 })
                  }
                />
              </label>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={policyForm.guest_force_sfu}
                onChange={(e) => setPolicyForm({ ...policyForm, guest_force_sfu: e.target.checked })}
              />
              <span>Force LiveKit SFU when external meeting guests join (protects host &amp; guest IP addresses)</span>
            </label>

            {mediaError && <div className="dr-alert dr-alert-error" role="alert">{mediaError}</div>}
            {mediaNotice && <div className="dr-alert dr-alert-info" role="status">{mediaNotice}</div>}

            <div>
              <button type="submit" disabled={savingMedia}>
                {savingMedia ? 'Saving…' : 'Save Media Policy'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div style={{ display: 'grid', gap: '20px', marginTop: '20px' }}>
        <BrandingPanel onChanged={onBrandingChanged} />
      </div>
    </div>
  );
};

