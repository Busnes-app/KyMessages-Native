import React from 'react';
import {
  Activity,
  Archive,
  ArrowLeft,
  LayoutDashboard,
  LogOut,
  ScrollText,
  Settings as SettingsIcon,
  Users,
} from 'lucide-react';
import type { SessionUser } from '../dto';

interface AppHeaderProps {
  appName: string;
  activeTab: string;
  onTabChange: (tab: string) => void;
  user: SessionUser | null;
  onLogout: () => void;
}

const memberSettingsItems = [
  { id: 'settings', label: 'Preferences', icon: SettingsIcon },
];

const adminSettingsItems = [
  { id: 'settings', label: 'Settings & DB', icon: SettingsIcon },
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'health', label: 'Health', icon: Activity },
  { id: 'audit', label: 'Audit', icon: ScrollText },
  { id: 'scim', label: 'Directory & SCIM', icon: Users },
  { id: 'backup', label: 'Backup & recovery', icon: Archive },
];

// Admin pages are refused server-side for non-admins; navigation only mirrors that.
export function navItemsFor(role: string) {
  return role === 'admin' ? adminSettingsItems : memberSettingsItems;
}

function userInitials(user: SessionUser): string {
  const source = (user.display_name || user.username || '?').trim();
  const parts = source.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return source.slice(0, 2).toUpperCase();
}

export const AppHeader: React.FC<AppHeaderProps> = ({ appName, activeTab, onTabChange, user, onLogout }) => {
  const navItems = navItemsFor(user?.role ?? '');

  return (
    <header className="app-header">
      <div className="app-brand">
        <img src="/app-icon.png" width={28} height={28} alt="" />
        <span>{appName || 'KyMessages'}</span>
      </div>

      <button
        type="button"
        className="btn-secondary app-back-chat"
        onClick={() => onTabChange('chat')}
      >
        <ArrowLeft size={15} aria-hidden="true" />
        <span>Back to Chat</span>
      </button>

      <nav className="app-nav" aria-label="Settings and administration">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onTabChange(item.id)}
              className={active ? 'ky-nav-item active' : 'ky-nav-item'}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={16} aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="app-header-actions">
        {user && (
          <div className="app-user">
            <span className="app-user-avatar" aria-hidden="true">{userInitials(user)}</span>
            <div className="app-user-copy">
              <div className="app-user-name">{user.display_name || user.username}</div>
              <div className="app-user-role">{user.role}</div>
            </div>
            <div className="app-user-buttons">
              <button
                type="button"
                className="app-footer-icon active"
                onClick={() => onTabChange('chat')}
                title="Close settings"
                aria-label="Settings"
                aria-pressed="true"
              >
                <SettingsIcon size={16} />
              </button>
              <button
                type="button"
                className="app-footer-icon danger"
                onClick={onLogout}
                title="Sign out"
                aria-label="Sign out"
              >
                <LogOut size={16} />
              </button>
            </div>
          </div>
        )}
      </div>
    </header>
  );
};
