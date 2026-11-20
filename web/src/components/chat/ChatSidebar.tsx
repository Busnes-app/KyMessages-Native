import React from 'react';
import { Hash, Lock, Plus, Search, X } from 'lucide-react';
import type { ChatRoomSummary, WsStatus } from '../../chat/types';
import { initialsFor, sortRooms } from '../../chat/state';

interface ChatSidebarProps {
  tenantName: string;
  rooms: ChatRoomSummary[];
  activeRoomId: string | null;
  wsStatus: WsStatus;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onSelectRoom: (roomId: string) => void;
  onOpenNewChannel: () => void;
  onOpenNewDM: () => void;
  onOpenSearch: () => void;
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
  tenantName,
  rooms,
  activeRoomId,
  wsStatus,
  mobileOpen,
  onCloseMobile,
  onSelectRoom,
  onOpenNewChannel,
  onOpenNewDM,
  onOpenSearch,
}) => {
  const channels = sortRooms(rooms.filter((r) => r.kind !== 'dm'));
  const dms = sortRooms(rooms.filter((r) => r.kind === 'dm'));

  return (
    <aside className={mobileOpen ? 'chat-rail mobile-open' : 'chat-rail'} aria-label="Conversations">
      <div className="chat-rail-top">
        <span className="chat-rail-title" title={tenantName}>
          {tenantName}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <span className={`chat-conn ${wsStatus}`} aria-live="polite">
            <span className="chat-conn-dot" aria-hidden="true" />
            {statusLabel(wsStatus)}
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

      <button type="button" className="chat-search-trigger" onClick={onOpenSearch}>
        <span className="chat-search-trigger-left">
          <Search size={14} aria-hidden="true" />
          <span>Search messages</span>
        </span>
        <kbd className="chat-kbd">⌘K</kbd>
      </button>

      <div className="chat-rail-list chat-scroll">
        <section aria-labelledby="chat-channels-heading">
          <div className="chat-section-head">
            <span id="chat-channels-heading" className="chat-section-label">
              Channels
            </span>
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

          <div className="chat-room-group">
            {channels.length === 0 ? (
              <p className="chat-rail-empty">No channels yet</p>
            ) : (
              channels.map((room) => {
                const active = room.id === activeRoomId;
                const unread = !active && room.unread_count > 0;
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
                      {room.is_private ? (
                        <Lock size={14} className="chat-room-icon" aria-hidden="true" />
                      ) : (
                        <Hash size={14} className="chat-room-icon" aria-hidden="true" />
                      )}
                      <span className="chat-room-btn-name">{room.name || 'Untitled'}</span>
                    </span>
                    {unread && <span className="chat-unread-pill">{room.unread_count}</span>}
                  </button>
                );
              })
            )}
          </div>
        </section>

        <section aria-labelledby="chat-dms-heading">
          <div className="chat-section-head">
            <span id="chat-dms-heading" className="chat-section-label">
              Direct messages
            </span>
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

          <div className="chat-room-group">
            {dms.length === 0 ? (
              <p className="chat-rail-empty">No direct messages yet</p>
            ) : (
              dms.map((room) => {
                const active = room.id === activeRoomId;
                const unread = !active && room.unread_count > 0;
                const label = room.name || 'Direct message';
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
                    {unread && <span className="chat-unread-pill">{room.unread_count}</span>}
                  </button>
                );
              })
            )}
          </div>
        </section>
      </div>
    </aside>
  );
};
