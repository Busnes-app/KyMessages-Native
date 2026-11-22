import React, { useEffect, useState } from 'react';
import { Loader2, Mic, MicOff } from 'lucide-react';
import { AppHeader } from './components/AppHeader';
import { Dashboard } from './pages/Dashboard';
import { Login } from './pages/Login';
import { ChangePassword } from './pages/ChangePassword';
import { Backup } from './pages/Backup';
import { SCIMAdmin } from './pages/SCIMAdmin';
import { Agents } from './pages/Agents';
import { Settings } from './pages/Settings';
import { Health } from './pages/Health';
import { Audit } from './pages/Audit';
import { ConfirmItsYou } from './components/ConfirmItsYou';
import { TwoFactorSetup } from './components/TwoFactorSetup';
import { ThemeSwitcher } from './components/ThemeSwitcher';
import { Chat, type ActiveCallSummary } from './pages/Chat';
import { GuestMeeting } from './pages/GuestMeeting';
import './styles/theme.css';
import './ky-ui/tokens.css';
import './ky-ui/navigation.css';
import { errorMessage, secureFetch } from './api';
import { browserPushEndpoint, unsubscribeBrowserPush } from './chat/push';
import { parseSettings, parseUser, type SessionUser, type SiteSettings } from './dto';
import { ErrorBoundary } from './components/ErrorBoundary';

function extractMeetToken(): string | null {
  if (typeof window === 'undefined') return null;
  const match = /^\/meet\/([A-Za-z0-9_-]{8,128})\/?$/.exec(window.location.pathname);
  return match ? match[1] : null;
}

export const App: React.FC = () => {
  const meetToken = extractMeetToken();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState<boolean>(!meetToken);
  const [activeTab, setActiveTab] = useState<string>('chat');
  const [settings, setSettings] = useState<SiteSettings | null>(null);
  const [activeCallSummary, setActiveCallSummary] = useState<ActiveCallSummary | null>(null);

  useEffect(() => {
    if (meetToken) {
      void fetch('/api/settings')
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (data) setSettings(parseSettings(data));
        })
        .catch(() => undefined);
      return;
    }
    const checkAuth = async () => {
      try {
        const [authResp, setResp] = useResponses(
          await fetch('/api/auth/me'),
          await fetch('/api/settings')
        );

        if (setResp.ok) setSettings(parseSettings(await setResp.json()));

        if (authResp.ok) {
          const a: unknown = await authResp.json();
          if (typeof a === 'object' && a !== null && 'authenticated' in a && a.authenticated === true) {
            setUser(parseUser('user' in a ? a.user : undefined));
          }
        }
      } catch (err) {
        setError(`Could not load the console: ${err instanceof Error ? err.message : 'unknown error'}`);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  // /api/settings returns more fields once authenticated, so re-read it after login.
  const loadSettings = async () => {
    try {
      const resp = await fetch('/api/settings');
      if (resp.ok) setSettings(parseSettings(await resp.json()));
    } catch (err) {
      setError(`Could not load settings: ${err instanceof Error ? err.message : 'unknown error'}`);
    }
  };

  // Only a confirmed sign-out leaves the console; otherwise the session may still be live.
  const handleLogout = async () => {
    setError('');
    try {
      // The server drops this browser's push subscription with the session, so a refused
      // sign-out leaves notifications as they were.
      const pushEndpoint = await browserPushEndpoint();
      const res = await secureFetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ push_endpoint: pushEndpoint }),
      });
      if (!res.ok) throw new Error(await errorMessage(res, 'Sign-out failed'));
      if (pushEndpoint) void unsubscribeBrowserPush();
      setActiveCallSummary(null);
      setUser(null);
    } catch (err) {
      setError(`You are still signed in: ${err instanceof Error ? err.message : 'sign-out failed'}`);
    }
  };
  const errorAlert = error && <div className="dr-alert dr-alert-error" role="alert" style={{ margin: 16 }}><span>{error}</span></div>;

  if (meetToken) {
    return <GuestMeeting token={meetToken} appName={settings?.app_name || 'KyMessages'} />;
  }

  if (loading) {
    return (
      <div
        role="status"
        style={{
          minHeight: '100dvh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '12px',
          background: 'var(--bg)',
          color: 'var(--ink)',
        }}
      >
        <img src="/app-icon.png" width={40} height={40} alt="" />
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '14px' }}>
          <Loader2 size={16} className="animate-spin" aria-hidden="true" />
          <span>Loading {settings?.app_name || 'KyMessages'}…</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <>
      {notice && <p role="status" style={{ padding: 16 }}>{notice}</p>}
      {errorAlert}
      <Login
        appName={settings?.app_name || 'KyMessages'}
        onSuccess={(u) => {
          setNotice('');
          setError('');
          setUser(u);
          void loadSettings();
        }}
      />
      </>
    );
  }

  if (user.must_change_password) {
    return <>{errorAlert}<ChangePassword onLogout={handleLogout} onComplete={() => {
      setUser(null);
      setNotice('Password changed. Sign in with your new password.');
    }} /></>;
  }

  const isAdmin = user.role === 'admin';
  const currentTab = isAdmin ? activeTab : activeTab === 'settings' ? 'settings' : 'chat';
  const appName = settings?.app_name || 'KyMessages';
  const isChatView = currentTab === 'chat';

  return (
    <>
      <div
        className="app-shell app-shell-chat"
        hidden={!isChatView}
        style={isChatView ? undefined : { display: 'none' }}
      >
        {isAdmin && isChatView && <ConfirmItsYou />}
        {isChatView && error && (
          <div className="dr-alert dr-alert-error app-floating-alert" role="alert">
            <span>{error}</span>
          </div>
        )}
        <main className="app-main">
          <ErrorBoundary key="chat">
            <Chat
              appName={appName}
              user={user}
              isActive={isChatView}
              onOpenSettings={() => setActiveTab('settings')}
              onLogout={handleLogout}
              onActiveCallChange={setActiveCallSummary}
              onAuthRevoked={() => {
                setActiveCallSummary(null);
                setUser(null);
                setNotice('Your session ended. Sign in again to continue.');
              }}
            />
          </ErrorBoundary>
        </main>
      </div>

      {!isChatView && (
        <div className="app-shell">
          <AppHeader
            appName={appName}
            activeTab={currentTab}
            onTabChange={(t) => setActiveTab(t)}
            user={user}
            onLogout={handleLogout}
          />

          <div className="app-content-col">
            {activeCallSummary && (
              <div className="ky-call-mini-bar" role="region" aria-label="Active call controls">
                <span>
                  In call in <strong>{activeCallSummary.roomName}</strong> ({activeCallSummary.participantCount})
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className={`ky-lobby-btn ${activeCallSummary.audio ? 'is-neutral' : 'is-deny'}`}
                    aria-pressed={activeCallSummary.audio}
                    aria-label="Microphone"
                    title={activeCallSummary.audio ? 'Mute microphone' : 'Unmute microphone'}
                    onClick={activeCallSummary.onToggleAudio}
                  >
                    {activeCallSummary.audio ? (
                      <Mic size={12} aria-hidden="true" />
                    ) : (
                      <MicOff size={12} aria-hidden="true" />
                    )}
                    <span>{activeCallSummary.audio ? 'Mic' : 'Muted'}</span>
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => {
                      setActiveTab('chat');
                      activeCallSummary.onReturn();
                    }}
                  >
                    Return to call
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-deny"
                    onClick={activeCallSummary.onLeave}
                  >
                    Leave
                  </button>
                </div>
              </div>
            )}

            {isAdmin && <ConfirmItsYou />}

            <main className="app-main">
              {errorAlert}
              <ErrorBoundary key={currentTab}>
                {!isAdmin && currentTab === 'settings' && (
                  <div style={{ maxWidth: '720px', margin: '0 auto', padding: '32px 20px' }}>
                    <h1 style={{ fontSize: '22px', fontWeight: 700, marginBottom: '6px' }}>Preferences</h1>
                    <p style={{ color: 'var(--ink)', fontSize: '14px', marginBottom: '20px' }}>
                      Appearance and account details for {user.display_name || user.username}.
                    </p>
                    <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      <div>
                        <h2 style={{ fontSize: '15px', marginBottom: '6px' }}>Color theme</h2>
                        <p style={{ color: 'var(--ink)', fontSize: '13px', marginBottom: '10px' }}>
                          Choose a palette for this browser.
                        </p>
                        <ThemeSwitcher />
                      </div>
                      <div style={{ borderTop: '1px solid var(--line)', paddingTop: '14px', fontSize: '13px', color: 'var(--ink)' }}>
                        Signed in as <strong style={{ color: 'var(--ink-strong)' }}>{user.display_name || user.username}</strong> (@{user.username})
                      </div>
                    </div>
                  </div>
                )}
                {isAdmin && activeTab === 'dashboard' && <Dashboard settings={settings} user={user} onNavigate={(t) => setActiveTab(t)} />}
                {isAdmin && activeTab === 'health' && <Health />}
                {isAdmin && activeTab === 'audit' && <Audit />}
                {isAdmin && activeTab === 'scim' && <SCIMAdmin />}
                {isAdmin && activeTab === 'agents' && <Agents />}
                {isAdmin && activeTab === 'backup' && <Backup />}
                {isAdmin && activeTab === 'settings' && <Settings settings={settings} onBrandingChanged={() => void loadSettings()} />}
                {isAdmin && activeTab === 'settings' && <TwoFactorSetup />}
              </ErrorBoundary>
            </main>
          </div>
        </div>
      )}
    </>
  );
};

function useResponses(r1: Response, r2: Response): [Response, Response] {
  return [r1, r2];
}
