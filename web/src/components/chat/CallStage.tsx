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

const RemoteAudioTrack: React.FC<{ stream: MediaStream | null }> = ({ stream }) => {
  const audioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    const el = audioRef.current;
    if (!el) return;
    if (stream) {
      if (el.srcObject !== stream) {
        el.srcObject = stream;
      }
    } else if (el.srcObject) {
      el.srcObject = null;
    }
  }, [stream]);

  return <audio ref={audioRef} autoPlay playsInline />;
};

/**
 * Persistent remote audio layer mounted above room switches so an active call
 * stays audible while browsing other rooms or settings.
 */
export const CallAudioLayer: React.FC<{ tiles: CallParticipantTile[] }> = ({ tiles }) => (
  <div className="sr-only" aria-hidden="true" data-testid="call-audio-layer">
    {tiles
      .filter((t) => !t.isLocal && t.stream)
      .map((t) => (
        <RemoteAudioTrack key={t.id} stream={t.stream} />
      ))}
  </div>
);

function formatCallDuration(totalSeconds: number): string {
  const hrs = Math.floor(totalSeconds / 3600);
  const mins = Math.floor((totalSeconds % 3600) / 60);
  const secs = totalSeconds % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return hrs > 0 ? `${hrs}:${pad(mins)}:${pad(secs)}` : `${pad(mins)}:${pad(secs)}`;
}

const isMac =
  typeof navigator !== 'undefined' && /mac|iphone|ipad|ipod/i.test(navigator.platform || navigator.userAgent);
const MOD_LABEL = isMac ? '⌘⇧' : 'Ctrl+Shift+';

interface CallStageProps {
  snapshot: HybridCallSnapshot;
  sfuAvailable: boolean;
  onToggleAudio: () => void;
  onToggleVideo: () => void;
  onToggleScreenShare: () => void;
  onToggleProtectIp?: () => void;
  onLeave: () => void;
  defaultExpanded?: boolean;
  expanded?: boolean;
  onExpandedChange?: (expanded: boolean) => void;
  /** When false, parent binds global call shortcuts (e.g. Chat across room switches). */
  bindShortcuts?: boolean;
  /** When true, remote audio is mounted externally via CallAudioLayer so <video> stays muted. */
  externalAudio?: boolean;
  stageRef?: React.RefObject<HTMLElement | null>;
}

const MediaTile: React.FC<{
  tile: CallParticipantTile;
  stream: MediaStream | null;
  isScreen?: boolean;
  isPipLocal?: boolean;
  externalAudio?: boolean;
}> = ({ tile, stream, isScreen = false, isPipLocal = false, externalAudio = false }) => {
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
    if (externalAudio) return;
    const el = audioRef.current;
    if (!el || tile.isLocal || isScreen) return;
    if (stream) {
      if (el.srcObject !== stream) {
        el.srcObject = stream;
      }
    } else if (el.srcObject) {
      el.srcObject = null;
    }
  }, [stream, tile.isLocal, isScreen, externalAudio]);

  const initials = (tile.displayName || '?')
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? '')
    .join('');

  return (
    <div
      className={`ky-call-tile${isScreen ? ' is-screen' : ''}${showVideo ? ' has-video' : ''}${isPipLocal ? ' is-pip-local' : ''}`}
    >
      {!externalAudio && !tile.isLocal && !isScreen && <audio ref={audioRef} autoPlay playsInline />}
      {showVideo ? (
        <video
          ref={videoRef}
          autoPlay
          playsInline
          muted
          className={`ky-call-video${tile.isLocal && !isScreen ? ' is-mirrored' : ''}${isScreen ? ' is-contain' : ''}`}
        />
      ) : (
        <div className="ky-call-avatar-wrap">
          <div className="ky-call-avatar" aria-hidden="true">
            {initials || '?'}
          </div>
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
          <span
            className={`ky-call-mic-dot ${tile.audio ? 'is-on' : 'is-off'}`}
            title={tile.audio ? 'Mic on' : 'Muted'}
          >
            {tile.audio ? <Mic size={11} aria-hidden="true" /> : <MicOff size={11} aria-hidden="true" />}
            <span className="sr-only">{tile.audio ? 'Mic on' : 'Muted'}</span>
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
  expanded: controlledExpanded,
  onExpandedChange,
  bindShortcuts = true,
  externalAudio = false,
  stageRef,
}) => {
  const [uncontrolledExpanded, setUncontrolledExpanded] = useState(defaultExpanded);
  const expanded = controlledExpanded ?? uncontrolledExpanded;
  const setExpanded = (next: boolean) => {
    if (onExpandedChange) onExpandedChange(next);
    else setUncontrolledExpanded(next);
  };

  const fallbackStartRef = useRef<number>(Date.now());
  const startedAt = snapshot.startedAt ?? fallbackStartRef.current;
  const [elapsedSec, setElapsedSec] = useState(() => Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));

  useEffect(() => {
    const compute = () => Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    setElapsedSec(compute());
    const id = window.setInterval(() => setElapsedSec(compute()), 1000);
    return () => window.clearInterval(id);
  }, [snapshot.callId, startedAt]);

  useEffect(() => {
    if (!bindShortcuts) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.repeat || !(e.metaKey || e.ctrlKey) || !e.shiftKey) return;
      const key = e.key.toLowerCase();
      if (key === 'm') {
        e.preventDefault();
        onToggleAudio();
      } else if (key === 'o') {
        e.preventDefault();
        onToggleVideo();
      } else if (key === 'e') {
        e.preventDefault();
        onToggleScreenShare();
      } else if (key === 'h') {
        e.preventDefault();
        onLeave();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [bindShortcuts, onToggleAudio, onToggleVideo, onToggleScreenShare, onLeave]);

  const isP2P = snapshot.mode === 'p2p_mesh';
  const screenTiles = snapshot.tiles.filter((t) => t.screenShare && t.screenStream);
  const hasScreen = screenTiles.length > 0;
  const isOneToOnePip =
    !hasScreen &&
    snapshot.tiles.length === 2 &&
    snapshot.tiles.some((t) => t.isLocal) &&
    snapshot.tiles.some((t) => !t.isLocal);

  const orderedTiles = isOneToOnePip
    ? [...snapshot.tiles].sort((a, b) => Number(a.isLocal) - Number(b.isLocal))
    : snapshot.tiles;

  const gridClass = hasScreen
    ? 'is-filmstrip'
    : isOneToOnePip
      ? 'is-pip'
      : snapshot.tiles.length <= 1
        ? 'cols-1'
        : snapshot.tiles.length <= 4
          ? 'cols-2-grid'
          : 'cols-3';

  return (
    <section
      ref={stageRef}
      tabIndex={-1}
      className={`ky-call-stage${expanded ? ' is-expanded' : ''}${hasScreen ? ' has-screen' : ''}`}
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
            {isP2P ? <Wifi size={12} aria-hidden="true" /> : <Radio size={12} aria-hidden="true" />}
            <span>{isP2P ? 'Direct' : 'Relayed · IP hidden'}</span>
          </span>
          <span className="ky-call-timer" title="Time in call">
            <span className="sr-only">Time in call </span>
            {formatCallDuration(elapsedSec)}
          </span>
          <span className="ky-call-count" title={`${snapshot.tiles.length} in call`}>
            <Users size={13} aria-hidden="true" />
            <span>{snapshot.tiles.length}</span>
          </span>
          {(snapshot.migrating || snapshot.protectIpPending) && (
            <span className="ky-call-migrating" role="status">
              {snapshot.migrationReason === 'stepping_down_to_p2p'
                ? 'Switching to direct…'
                : 'Switching to relay…'}
            </span>
          )}
          {snapshot.notice && (
            <span className="ky-call-notice" role="status">
              {snapshot.notice}
            </span>
          )}
        </div>
        <div className="ky-call-topbar-right">
          <button
            type="button"
            className="ky-call-icon-btn"
            onClick={() => setExpanded(!expanded)}
            title={expanded ? 'Compact call view' : 'Expand call view'}
            aria-label="Expand call view"
            aria-pressed={expanded}
          >
            {expanded ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
          </button>
        </div>
      </div>

      {hasScreen && (
        <div className="ky-call-screens">
          {screenTiles.map((t) => (
            <MediaTile key={`${t.id}-screen`} tile={t} stream={t.screenStream} isScreen externalAudio={externalAudio} />
          ))}
        </div>
      )}

      <div className={`ky-call-grid ${gridClass}`}>
        {orderedTiles.map((tile) => (
          <MediaTile
            key={tile.id}
            tile={tile}
            stream={tile.stream}
            isPipLocal={isOneToOnePip && tile.isLocal}
            externalAudio={externalAudio}
          />
        ))}
      </div>

      <div className="ky-call-dock" role="toolbar" aria-label="Call controls">
        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.audio ? '' : 'is-muted'}`}
          onClick={onToggleAudio}
          title={`${snapshot.audio ? 'Mute microphone' : 'Unmute microphone'} (${MOD_LABEL}M)`}
          aria-keyshortcuts="Control+Shift+M Meta+Shift+M"
          aria-pressed={snapshot.audio}
        >
          {snapshot.audio ? <Mic size={17} aria-hidden="true" /> : <MicOff size={17} aria-hidden="true" />}
          <span>Mic</span>
        </button>

        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.video ? 'is-active' : ''}`}
          onClick={onToggleVideo}
          title={`${snapshot.video ? 'Turn camera off' : 'Turn camera on'} (${MOD_LABEL}O)`}
          aria-keyshortcuts="Control+Shift+O Meta+Shift+O"
          aria-pressed={snapshot.video}
        >
          {snapshot.video ? <Video size={17} aria-hidden="true" /> : <VideoOff size={17} aria-hidden="true" />}
          <span>Camera</span>
        </button>

        <button
          type="button"
          className={`ky-call-ctrl ${snapshot.screenShare ? 'is-active' : ''}`}
          onClick={onToggleScreenShare}
          title={`${snapshot.screenShare ? 'Stop sharing screen' : 'Share screen'} (${MOD_LABEL}E)`}
          aria-keyshortcuts="Control+Shift+E Meta+Shift+E"
          aria-pressed={snapshot.screenShare}
        >
          {snapshot.screenShare ? <MonitorOff size={17} aria-hidden="true" /> : <MonitorUp size={17} aria-hidden="true" />}
          <span>Share</span>
        </button>

        {sfuAvailable && onToggleProtectIp && (
          <button
            type="button"
            className={`ky-call-ctrl ${snapshot.protectIp ? 'is-active' : ''}`}
            onClick={onToggleProtectIp}
            disabled={Boolean(snapshot.protectIpPending)}
            aria-busy={Boolean(snapshot.protectIpPending)}
            title={
              snapshot.protectIpPending
                ? 'Switching to relay to hide IP…'
                : snapshot.protectIp
                  ? 'Always hide IP enabled (staying on SFU relay)'
                  : !isP2P
                    ? 'Currently relayed via SFU (IP hidden). Enable to keep IP hidden if call steps down to direct.'
                    : 'Hide my IP address by routing through LiveKit SFU'
            }
            aria-pressed={snapshot.protectIp}
          >
            <Shield size={16} aria-hidden="true" />
            <span>{snapshot.protectIpPending ? 'Relaying…' : 'Hide IP'}</span>
          </button>
        )}

        <span className="ky-call-dock-sep" aria-hidden="true" />

        <button
          type="button"
          className="ky-call-ctrl is-leave"
          onClick={onLeave}
          title={`Leave call (${MOD_LABEL}H)`}
          aria-keyshortcuts="Control+Shift+H Meta+Shift+H"
        >
          <PhoneOff size={17} aria-hidden="true" />
          <span>Leave</span>
        </button>
      </div>
    </section>
  );
};
