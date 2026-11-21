import React, { useEffect, useRef, useState } from 'react';
import {
  Maximize2,
  Mic,
  MicOff,
  Minimize2,
  MonitorOff,
  MonitorUp,
  PhoneOff,
  Radio,
  Shield,
  Users,
  Video,
  VideoOff,
  Wifi,
} from 'lucide-react';
import type { CallParticipantTile, HybridCallSnapshot } from '../../rtc/hybridCall';

interface CallStageProps {
  snapshot: HybridCallSnapshot;
  sfuAvailable: boolean;
  onToggleAudio: () => void;
  onToggleVideo: () => void;
  onToggleScreenShare: () => void;
  onToggleProtectIp?: () => void;
  onLeave: () => void;
  defaultExpanded?: boolean;
}

const MediaTile: React.FC<{
  tile: CallParticipantTile;
  stream: MediaStream | null;
  isScreen?: boolean;
}> = ({ tile, stream, isScreen = false }) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);

  const hasVideoTrack = Boolean(
    stream && stream.getVideoTracks().some((t) => t.readyState === 'live' && t.enabled),
  );
  const showVideo = isScreen ? hasVideoTrack : tile.video && hasVideoTrack;

  useEffect(() => {
    const el = videoRef.current;
    if (!el) return;
    if (showVideo && stream) {
      if (el.srcObject !== stream) {
        el.srcObject = stream;
      }
    } else if (el.srcObject) {
      el.srcObject = null;
    }
  }, [stream, showVideo]);

  useEffect(() => {
    const el = audioRef.current;
    if (!el || tile.isLocal || isScreen) return;
    if (stream) {
      if (el.srcObject !== stream) {
        el.srcObject = stream;
      }
    } else if (el.srcObject) {
      el.srcObject = null;
    }
  }, [stream, tile.isLocal, isScreen]);

  const initials = (tile.displayName || '?')
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? '')
    .join('');

  return (
    <div className={`ky-call-tile ${isScreen ? 'is-screen' : ''} ${showVideo ? 'has-video' : ''}`}>
      {!tile.isLocal && !isScreen && <audio ref={audioRef} autoPlay playsInline />}
      {showVideo ? (
        <video
          ref={videoRef}
          autoPlay
          playsInline
          muted={tile.isLocal || isScreen}
          className={`ky-call-video ${tile.isLocal && !isScreen ? 'is-mirrored' : ''}`}
        />
      ) : (
        <div className="ky-call-avatar-wrap">
          <div className="ky-call-avatar">{initials || '?'}</div>
        </div>
      )}

      <div className="ky-call-tile-label">
        <span className="ky-call-tile-name">
          {tile.displayName}
          {tile.isLocal ? ' (You)' : ''}
          {isScreen ? ' · Screen' : ''}
        </span>
        {tile.isGuest && <span className="ky-call-guest-pill">Guest</span>}
        {!isScreen && (
          <span className={`ky-call-mic-dot ${tile.audio ? 'is-on' : 'is-off'}`} title={tile.audio ? 'Mic on' : 'Muted'}>
            {tile.audio ? <Mic size={11} /> : <MicOff size={11} />}
          </span>
        )}
      </div>
    </div>
  );
};

export const CallStage: React.FC<CallStageProps> = ({
  snapshot,
  sfuAvailable,
  onToggleAudio,
  onToggleVideo,
  onToggleScreenShare,
  onToggleProtectIp,
  onLeave,
  defaultExpanded = false,
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const isP2P = snapshot.mode === 'p2p_mesh';
  const screenTiles = snapshot.tiles.filter((t) => t.screenShare && t.screenStream);
  const gridClass =
    snapshot.tiles.length <= 1
      ? 'cols-1'
      : snapshot.tiles.length === 2
        ? 'cols-2'
        : snapshot.tiles.length <= 4
          ? 'cols-2-grid'
          : 'cols-3';

  return (
    <section
      className={`ky-call-stage ${expanded ? 'is-expanded' : ''}`}
      aria-label="Active call"
    >
      <div className="ky-call-topbar">
        <div className="ky-call-topbar-left">
          <span
            className={`ky-call-mode-badge ${isP2P ? 'is-p2p' : 'is-sfu'}`}
            title={
              isP2P
                ? 'Direct Peer-to-Peer WebRTC mesh — zero server media bandwidth'
                : 'LiveKit SFU relay — scales seamlessly and shields participant IPs'
            }
          >
            {isP2P ? <Wifi size={12} /> : <Radio size={12} />}
            <span>{isP2P ? 'P2P Direct' : 'LiveKit SFU'}</span>
          </span>
          <span className="ky-call-count">
            <Users size={13} />
            <span>{snapshot.tiles.length}</span>
          </span>
          {snapshot.migrating && (
            <span className="ky-call-migrating">
              {snapshot.migrationReason === 'stepping_down_to_p2p'
                ? 'Stepping down to P2P…'
                : 'Escalating to SFU…'}
            </span>
          )}
          {snapshot.notice && <span className="ky-call-notice">{snapshot.notice}</span>}
        </div>
        <div className="ky-call-topbar-right">
          <button
            type="button"
            className="ky-call-icon-btn"
            onClick={() => setExpanded((v) => !v)}
            title={expanded ? 'Compact call view' : 'Expand call view'}
            aria-label={expanded ? 'Compact call view' : 'Expand call view'}
          >
            {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        </div>
      </div>

      {screenTiles.length > 0 && (
        <div className="ky-call-screens">
          {screenTiles.map((t) => (
            <MediaTile key={`${t.id}-screen`} tile={t} stream={t.screenStream} isScreen />
          ))}
        </div>
      )}

      <div className={`ky-call-grid ${gridClass}`}>
        {snapshot.tiles.map((tile) => (
          <MediaTile key={tile.id} tile={tile} stream={tile.stream} />
        ))}
      </div>

      <div className="ky-call-dock" role="toolbar" aria-label="Call controls">
        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.audio ? '' : 'is-muted'}`}
          onClick={onToggleAudio}
          title={snapshot.audio ? 'Mute microphone' : 'Unmute microphone'}
          aria-pressed={!snapshot.audio}
        >
          {snapshot.audio ? <Mic size={17} /> : <MicOff size={17} />}
          <span>{snapshot.audio ? 'Mute' : 'Unmute'}</span>
        </button>

        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.video ? 'is-active' : ''}`}
          onClick={onToggleVideo}
          title={snapshot.video ? 'Turn camera off' : 'Turn camera on'}
          aria-pressed={snapshot.video}
        >
          {snapshot.video ? <Video size={17} /> : <VideoOff size={17} />}
          <span>{snapshot.video ? 'Stop Video' : 'Video'}</span>
        </button>

        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.screenShare ? 'is-active' : ''}`}
          onClick={onToggleScreenShare}
          title={snapshot.screenShare ? 'Stop sharing screen' : 'Share screen'}
          aria-pressed={snapshot.screenShare}
        >
          {snapshot.screenShare ? <MonitorOff size={17} /> : <MonitorUp size={17} />}
          <span>{snapshot.screenShare ? 'Stop Share' : 'Share'}</span>
        </button>

        {sfuAvailable && onToggleProtectIp && (
          <button
            type="button"
            className={`ky-call-ctrl ${snapshot.protectIp || !isP2P ? 'is-active' : ''}`}
            onClick={onToggleProtectIp}
            title={
              snapshot.protectIp
                ? 'IP Protection enabled (routing via SFU)'
                : 'Hide my IP address by routing through LiveKit SFU'
            }
            aria-pressed={snapshot.protectIp}
          >
            <Shield size={16} />
            <span>{snapshot.protectIp ? 'IP Hidden' : 'Hide IP'}</span>
          </button>
        )}

        <button
          type="button"
          className="ky-call-ctrl is-leave"
          onClick={onLeave}
          title="Leave call"
        >
          <PhoneOff size={17} />
          <span>Leave</span>
        </button>
      </div>
    </section>
  );
};
