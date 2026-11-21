import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Hash,
  Lock,
  LogOut,
  Phone,
  Plus,
  Search,
  Settings as SettingsIcon,
  Video,
  X,
} from 'lucide-react';
import type { CallState, ChatRoomSummary, WsStatus } from '../../chat/types';
import { initialsFor, sortRooms } from '../../chat/state';
import type { SessionUser } from '../../dto';

interface ChatSidebarProps {
  appName?: string;
  tenantName: string;
  rooms: ChatRoomSummary[];
  activeRoomId: string | null;
  activeCalls?: Record<string, CallState>;
  wsStatus: WsStatus;
  mobileOpen: boolean;
  user?: SessionUser | null;
  onCloseMobile: () => void;
  onSelectRoom: (roomId: string) => void;
  onOpenNewChannel: () => void;
  onOpenNewDM: () => void;
  onOpenSearch: () => void;
  onStartInstantMeeting?: () => void;
  onOpenSettings?: () => void;
  onLogout?: () => void;
}

function statusLabel(status: WsStatus): string {
  switch (status) {
    case 'live':
      return 'Live';
    case 'connecting':
      return 'Connecting';
    case 'reconnecting':
      return 'Reconnecting';
    case 'revoked':
      return 'Signed out';
    case 'offline':
      return 'Offline';
  }
}

export const ChatSidebar: React.FC<ChatSidebarProps> = ({
  appName,
  tenantName,
  rooms,
  activeRoomId,
  activeCalls,
  wsStatus,
  mobileOpen,
  user,
  onCloseMobile,
  onSelectRoom,
  onOpenNewChannel,
  onOpenNewDM,
  onOpenSearch,
  onStartInstantMeeting,
  onOpenSettings,
  onLogout,
}) => {
  const [channelsOpen, setChannelsOpen] = useState(true);
  const [dmsOpen, setDmsOpen] = useState(true);

  const channels = sortRooms(rooms.filter((r) => r.kind !== 'dm'));
  const dms = sortRooms(rooms.filter((r) => r.kind === 'dm'));

  const normalizedTenant = tenantName.trim();
  const brandTitle =
    normalizedTenant && normalizedTenant.toLowerCase() !== 'default'
      ? normalizedTenant
      : appName || 'KyMessages';

  const userLabel = user ? user.display_name || user.username : '';

  return (
    <aside className={mobileOpen ? 'chat-rail mobile-open' : 'chat-rail'} aria-label="Workspace and conversations">
      <div className="chat-rail-top">
        <div className="chat-rail-brand">
          <img src="/app-icon.png" width={26} height={26} alt="" />
          <span className="chat-rail-title" title={brandTitle}>
            {brandTitle}
          </span>
        </div>
        <div className="chat-rail-top-right">
          <span className={`chat-conn ${wsStatus}`} aria-live="polite" title={`Connection: ${statusLabel(wsStatus)}`}>
            <span className="chat-conn-dot" aria-hidden="true" />
            <span className="chat-conn-label">{statusLabel(wsStatus)}</span>
          </span>
          {mobileOpen && (
            <button
              type="button"
              className="chat-icon-btn"
              onClick={onCloseMobile}
              aria-label="Close room list"
            >
              <X size={16} />
            </button>
          )}
        </div>
      </div>

      <div className="chat-rail-actions">
        <button type="button" className="chat-search-trigger" onClick={onOpenSearch}>
          <span className="chat-search-trigger-left">
            <Search size={14} aria-hidden="true" />
            <span>Search</span>
          </span>
          <kbd className="chat-kbd">⌘K</kbd>
        </button>
        {onStartInstantMeeting && (
          <button
            type="button"
            className="chat-meet-trigger"
            onClick={onStartInstantMeeting}
            title="Start an instant meeting with a shareable guest link"
          >
            <Video size={14} aria-hidden="true" />
            <span>Meet</span>
          </button>
        )}
      </div>

      <div className="chat-rail-list chat-scroll">
        <section aria-labelledby="chat-channels-heading">
          <div className="chat-section-head">
            <button
              type="button"
              id="chat-channels-heading"
              className="chat-section-toggle"
              aria-expanded={channelsOpen}
              onClick={() => setChannelsOpen((o) => !o)}
            >
              {channelsOpen ? (
                <ChevronDown size={13} aria-hidden="true" />
              ) : (
                <ChevronRight size={13} aria-hidden="true" />
              )}
              <span className="chat-section-label">Channels</span>
              <span className="chat-section-count">{channels.length}</span>
            </button>
            <button
              type="button"
              className="chat-icon-btn"
              onClick={onOpenNewChannel}
              title="New channel"
              aria-label="New channel"
            >
              <Plus size={15} />
            </button>
          </div>

          {channelsOpen && (
            <div className="chat-room-group">
              {channels.length === 0 ? (
                <p className="chat-rail-empty">No channels yet</p>
              ) : (
                channels.map((room) => {
                  const active = room.id === activeRoomId;
                  const unread = !active && room.unread_count > 0;
                  const call = activeCalls?.[room.id];
                  const callCount = call && !call.ended ? call.peers.length : 0;
                  return (
                    <button
                      key={room.id}
                      type="button"
                      className={`chat-room-btn${active ? ' active' : ''}${unread ? ' unread' : ''}`}
                      aria-current={active ? 'true' : undefined}
                      onClick={() => {
                        onSelectRoom(room.id);
                        onCloseMobile();
                      }}
                    >
                      <span className="chat-room-btn-left">
                        {room.kind === 'meeting' ? (
                          <Video size={14} className="chat-room-icon" aria-hidden="true" />
                        ) : room.is_private ? (
                          <Lock size={14} className="chat-room-icon" aria-hidden="true" />
                        ) : (
                          <Hash size={14} className="chat-room-icon" aria-hidden="true" />
                        )}
                        <span className="chat-room-btn-name">{room.name || 'Untitled'}</span>
                      </span>
                      <span className="chat-room-btn-right">
                        {callCount > 0 && (
                          <span className="chat-live-call-pill" title="Call in progress">
                            <Phone size={10} />
                            <span>{callCount}</span>
                          </span>
                        )}
                        {unread && <span className="chat-unread-pill">{room.unread_count}</span>}
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          )}
        </section>

        <section aria-labelledby="chat-dms-heading">
          <div className="chat-section-head">
            <button
              type="button"
              id="chat-dms-heading"
              className="chat-section-toggle"
              aria-expanded={dmsOpen}
              onClick={() => setDmsOpen((o) => !o)}
            >
              {dmsOpen ? (
                <ChevronDown size={13} aria-hidden="true" />
              ) : (
                <ChevronRight size={13} aria-hidden="true" />
              )}
              <span className="chat-section-label">Direct messages</span>
              <span className="chat-section-count">{dms.length}</span>
            </button>
            <button
              type="button"
              className="chat-icon-btn"
              onClick={onOpenNewDM}
              title="New direct message"
              aria-label="New direct message"
            >
              <Plus size={15} />
            </button>
          </div>

          {dmsOpen && (
            <div className="chat-room-group">
              {dms.length === 0 ? (
                <p className="chat-rail-empty">No direct messages yet</p>
              ) : (
                dms.map((room) => {
                  const active = room.id === activeRoomId;
                  const unread = !active && room.unread_count > 0;
                  const label = room.name || 'Direct message';
                  const call = activeCalls?.[room.id];
                  const callCount = call && !call.ended ? call.peers.length : 0;
                  return (
                    <button
                      key={room.id}
                      type="button"
                      className={`chat-room-btn${active ? ' active' : ''}${unread ? ' unread' : ''}`}
                      aria-current={active ? 'true' : undefined}
                      onClick={() => {
                        onSelectRoom(room.id);
                        onCloseMobile();
                      }}
                    >
                      <span className="chat-room-btn-left">
                        <span className="chat-dm-avatar" aria-hidden="true">
                          {initialsFor(label)}
                        </span>
                        <span className="chat-room-btn-name">{label}</span>
                      </span>
                      <span className="chat-room-btn-right">
                        {callCount > 0 && (
                          <span className="chat-live-call-pill" title="Call in progress">
                            <Phone size={10} />
                            <span>{callCount}</span>
                          </span>
                        )}
                        {unread && <span className="chat-unread-pill">{room.unread_count}</span>}
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          )}
        </section>
      </div>

      {user && (
        <div className="chat-rail-footer">
          <div className="app-user">
            <span className="app-user-avatar" aria-hidden="true">
              {initialsFor(userLabel)}
            </span>
            <div className="app-user-copy">
              <div className="app-user-name">{userLabel}</div>
              <div className="app-user-role">{user.role}</div>
            </div>
            <div className="app-user-buttons">
              {onOpenSettings && (
                <button
                  type="button"
                  className="app-footer-icon"
                  onClick={onOpenSettings}
                  title="Settings"
                  aria-label="Settings"
                >
                  <SettingsIcon size={16} />
                </button>
              )}
              {onLogout && (
                <button
                  type="button"
                  className="app-footer-icon danger"
                  onClick={onLogout}
                  title="Sign out"
                  aria-label="Sign out"
                >
                  <LogOut size={16} />
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
