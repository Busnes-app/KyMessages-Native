import type {
  CallJoinResponse,
  CallMigratePayload,
  CallMode,
  CallPeer,
  CallSignalData,
  CallState,
} from '../chat/types';
import { ChatSocket } from '../chat/client';

export interface CallParticipantTile {
  id: string;
  displayName: string;
  isLocal: boolean;
  isGuest: boolean;
  audio: boolean;
  video: boolean;
  screenShare: boolean;
  stream: MediaStream | null;
  screenStream: MediaStream | null;
}

export interface HybridCallSnapshot {
  callId: string;
  roomId: string;
  mode: CallMode;
  sfuSticky: boolean;
  migrating: boolean;
  migrationReason: string;
  audio: boolean;
  video: boolean;
  screenShare: boolean;
  protectIp: boolean;
  protectIpPending?: boolean;
  startedAt?: number;
  notice: string;
  tiles: CallParticipantTile[];
}

type LiveKitRoom = import('livekit-client').Room;
type LiveKitRemoteParticipant = import('livekit-client').RemoteParticipant;

interface PeerConnEntry {
  pc: RTCPeerConnection;
  remoteStream: MediaStream;
  remoteScreenStream: MediaStream;
  cameraStreamId: string | null;
  cameraSender: RTCRtpSender | null;
  audioSender: RTCRtpSender | null;
  screenSender: RTCRtpSender | null;
  pendingCandidates: RTCIceCandidateInit[];
  negotiation: Promise<void>;
  disconnectTimer: ReturnType<typeof setTimeout> | null;
}

export interface HybridCallControllerOptions {
  localUserId: string;
  localDisplayName: string;
  isGuest: boolean;
  socket: () => ChatSocket | null;
  rejoin?: (media: { audio: boolean; video: boolean; screenShare: boolean; protectIp: boolean }) => Promise<CallJoinResponse>;
  onChange: (snapshot: HybridCallSnapshot) => void;
 onEnded?: () => void;
}

const PROTECT_IP_TIMEOUT_MS = 10_000;

function peerKey(peer: CallPeer): string {
  return peer.peer_id || peer.user_id;
}

/**
 * Manages a single room's hybrid P2P-first WebRTC call with seamless mid-call
 * make-before-break escalation to LiveKit SFU (lazy-loaded on demand) and
 * automatic step-down back to P2P when the server signals a migration.
 */
export class HybridCallController {
  private callId = '';
  private roomId = '';
  private myPeerId = '';
  private mode: CallMode = 'p2p_mesh';
  private sfuSticky = false;
  private migrating = false;
  private migrationReason = '';
  private notice = '';
  private startedAt = Date.now();

  private audioEnabled = true;
  private videoEnabled = false;
  private screenShareEnabled = false;
  private protectIp = false;
  private protectIpPending = false;
  private protectIpTimer: ReturnType<typeof setTimeout> | null = null;

  private iceServers: RTCIceServer[] = [];
  private peersMeta = new Map<string, CallPeer>();
  private peerConns = new Map<string, PeerConnEntry>();

  private localStream: MediaStream | null = null;
  private screenStream: MediaStream | null = null;

  private livekitRoom: LiveKitRoom | null = null;
  private livekitStreams = new Map<string, { cam: MediaStream; screen: MediaStream }>();

  private disposed = false;
  private roomSocket: ChatSocket | null = null;
  private recovering = false;
  private cancelSocketStart: (() => void) | null = null;
  private epoch = 0;
  private mediaTransition: Promise<void> = Promise.resolve();
  private pendingSignals = 0;
  private pendingCallState: CallState | null = null;

  isRoomRouted(): boolean {
    return this.roomSocket !== null;
  }

  private signalSocket(): ChatSocket | null {
    return this.roomSocket ?? this.opts.socket();
  }

  private async openRoomSocket(path: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.roomSocket?.close();
        this.roomSocket = null;
        reject(new Error('Call connection unavailable; join again'));
      }, 10_000);
      this.cancelSocketStart = () => {
        clearTimeout(timer);
        reject(new Error('Call ended'));
      };
      let reconnect = false;
      const socket = new ChatSocket({
        onStatus: (status) => {
          if (status === 'revoked') this.dispose();
        },
        onEvent: (event) => {
          if (event.kind === 'hello') {
            clearTimeout(timer);
            this.cancelSocketStart = null;
            resolve();
            if (reconnect) {
              reconnect = false;
              void this.recoverRoom();
            }
          }
          if (event.kind === 'call.state') this.handleCallState(event.state);
          if (event.kind === 'call.signal') void this.handleSignal(event.signal);
          if (event.kind === 'call.migrate') void this.handleMigrate(event.migrate);
          if (event.kind === 'auth.revoked' || event.kind === 'room.closed') { this.dispose(); this.opts.onEnded?.(); }
        },
        onReconnect: () => { reconnect = true; },
      }, path);
      this.roomSocket = socket;
      socket.connect();
    });
  }

  // One controller owns one media connection and epoch. Start, recovery and migrations
  // share that writer so an older async disconnect cannot replace newer credentials.
  private runMediaTransition(operation: () => Promise<void>): Promise<void> {
    const next = this.mediaTransition.then(() => {
      if (!this.disposed) return operation();
    });
    this.mediaTransition = next.catch(() => undefined);
    return next;
  }

  private recoverRoom(): Promise<void> {
    return this.runMediaTransition(() => this.recoverMedia());
  }

  private async recoverMedia(): Promise<void> {
    if (this.disposed || this.recovering || !this.opts.rejoin) return;
    this.recovering = true;
    try {
      // A signaling-only reconnect must not destroy a still-live P2P answerer's link.
      // Keep it until the authoritative rejoin tells us whether the call/seat changed.
      if (this.mode !== 'p2p_mesh') {
        this.closeAllPeerConnections();
        await this.disconnectLiveKit();
      }
      if (this.disposed) return;
      const response = await this.opts.rejoin({
        audio: this.audioEnabled, video: this.videoEnabled, screenShare: this.screenShareEnabled,
        protectIp: this.protectIp || this.protectIpPending,
      });
      if (this.disposed) return;
      const sameP2PSeat = this.mode === 'p2p_mesh' && response.mode === 'p2p_mesh'
        && response.call_id === this.callId && (response.peer_id || this.opts.localUserId) === this.myPeerId;
      if (!sameP2PSeat) {
        this.closeAllPeerConnections();
        await this.disconnectLiveKit();
        if (this.disposed) return;
      }
      this.callId = response.call_id;
      this.myPeerId = response.peer_id || this.opts.localUserId;
      this.epoch = response.epoch ?? 0;
      this.mode = response.mode;
      this.sfuSticky = response.sfu_sticky;
      this.syncPeersMeta(response.peers);
      if (response.mode === 'sfu_livekit' && response.livekit_url && response.livekit_token) {
        await this.connectLiveKit(response.livekit_url, response.livekit_token);
      } else {
        this.reconcileP2PPeers();
      }
      this.notice = '';
    } catch {
      this.closeAllPeerConnections();
      await this.disconnectLiveKit();
      this.notice = 'Call connection interrupted — leave and join again to reconnect.';
    } finally {
      this.recovering = false;
      this.emit();
    }
  }

  constructor(private readonly opts: HybridCallControllerOptions) {
    this.myPeerId = opts.localUserId;
  }

  private isSelfPeer(peer: CallPeer): boolean {
    return peerKey(peer) === this.myPeerId || peer.user_id === this.opts.localUserId;
  }

  private clearProtectIpTimer(): void {
    if (this.protectIpTimer) {
      clearTimeout(this.protectIpTimer);
      this.protectIpTimer = null;
    }
  }

  start(
    joinResp: CallJoinResponse,
    initialMedia: { audio: boolean; video: boolean; protectIp: boolean },
  ): Promise<void> {
    return this.runMediaTransition(() => this.startMedia(joinResp, initialMedia));
  }

  private async startMedia(
    joinResp: CallJoinResponse,
    initialMedia: { audio: boolean; video: boolean; protectIp: boolean },
  ): Promise<void> {
    this.roomId = joinResp.room_id;
    if (joinResp.call_ws_path) {
      if (!this.opts.rejoin) throw new Error('Call reconnect is unavailable');
      try {
        await this.openRoomSocket(joinResp.call_ws_path);
        if (this.disposed) return;
        // A route change between HTTP join and socket registration must refresh the seat.
        joinResp = await this.opts.rejoin({ ...initialMedia, screenShare: false });
      } catch (error) {
        this.dispose();
        throw error;
      }
    }
    if (this.disposed) return;
    this.epoch = joinResp.epoch ?? 0;
    this.callId = joinResp.call_id;
    this.roomId = joinResp.room_id;
    this.myPeerId = joinResp.peer_id || this.opts.localUserId;
    this.mode = joinResp.mode;
    this.sfuSticky = joinResp.sfu_sticky;
    this.iceServers = joinResp.ice_servers;
    this.audioEnabled = initialMedia.audio;
    this.videoEnabled = initialMedia.video;
    this.protectIp = initialMedia.protectIp && joinResp.mode === 'sfu_livekit';
    this.protectIpPending = initialMedia.protectIp && joinResp.mode !== 'sfu_livekit';
    this.startedAt = Date.now();

    this.syncPeersMeta(joinResp.peers);
    await this.acquireLocalMedia(initialMedia.audio, initialMedia.video);
    if (this.disposed) return;
    this.emit();

    if (joinResp.mode === 'sfu_livekit' && joinResp.livekit_url && joinResp.livekit_token) {
      await this.connectLiveKit(joinResp.livekit_url, joinResp.livekit_token);
    } else {
      this.reconcileP2PPeers();
    }
    if (this.disposed) return;
    this.emit();
  }

  /** Called whenever the server broadcasts a `call.state` event for this room. */
  handleCallState(state: CallState): void {
    if (this.disposed || (this.roomId !== '' && state.room_id !== this.roomId)) return;
    if (this.roomSocket && (this.roomId === '' || (!state.ended && state.active !== false))) {
      if (this.pendingCallState?.call_id === state.call_id && (state.epoch ?? 0) < (this.pendingCallState.epoch ?? 0)) return;
      const queued = this.pendingCallState !== null;
      this.pendingCallState = state;
      if (!queued) void this.runMediaTransition(async () => {
        const latest = this.pendingCallState;
        this.pendingCallState = null;
        if (latest) this.applyCallState(latest);
      });
      return;
    }
    this.applyCallState(state);
  }

  private applyCallState(state: CallState): void {
    if (this.disposed || state.room_id !== this.roomId || (this.roomSocket && (state.call_id !== this.callId || (state.epoch !== undefined && state.epoch < this.epoch)))) return;
    if (state.ended || state.active === false) {
      this.dispose();
      this.opts.onEnded?.();
      return;
    }
    this.callId = state.call_id;
    this.sfuSticky = state.sfu_sticky;
    this.syncPeersMeta(state.peers);

    if (this.mode === 'p2p_mesh') {
      this.reconcileP2PPeers();
    }
    this.emit();
  }

  /** Called when the server relays a P2P WebRTC offer/answer/ICE candidate. */
  async handleSignal(sig: CallSignalData): Promise<void> {
    if (!this.roomSocket) return this.applySignal(sig);
    // Bound signals waiting for authenticated startup/recovery and local media capture.
    if (this.pendingSignals >= 128) return;
    this.pendingSignals++;
    try { await this.runMediaTransition(() => this.applySignal(sig)); }
    finally { this.pendingSignals--; }
  }

  private async applySignal(sig: CallSignalData): Promise<void> {
    if (this.disposed || this.mode !== 'p2p_mesh') return;
    if (sig.call_id !== this.callId) return;
    if (sig.from === this.myPeerId || sig.from === this.opts.localUserId) return;

    const entry = this.ensurePeerConnection(sig.from);
    const { pc } = entry;

    try {
      if (sig.kind === 'offer') {
        const desc = sig.payload as RTCSessionDescriptionInit;
        if (pc.signalingState !== 'stable') {
          await pc.setLocalDescription({ type: 'rollback' }).catch(() => undefined);
        }
        await pc.setRemoteDescription(new RTCSessionDescription(desc));
        await this.flushCandidates(entry);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        this.signalSocket()?.sendCallSignal(this.roomId, this.callId, sig.from, 'answer', pc.localDescription);
      } else if (sig.kind === 'answer') {
        if (pc.signalingState === 'have-local-offer') {
          const desc = sig.payload as RTCSessionDescriptionInit;
          await pc.setRemoteDescription(new RTCSessionDescription(desc));
          await this.flushCandidates(entry);
        }
      } else if (sig.kind === 'ice') {
        const cand = sig.payload as RTCIceCandidateInit;
        if (cand && cand.candidate) {
          if (pc.remoteDescription && pc.remoteDescription.type) {
            await pc.addIceCandidate(new RTCIceCandidate(cand)).catch(() => undefined);
          } else {
            entry.pendingCandidates.push(cand);
          }
        }
      }
    } catch {
      // Ignore transient signaling races during rapid joins/migrations.
    }
  }

  /** Called when the server instructs this peer to escalate (P2P -> SFU) or step down (SFU -> P2P). */
  handleMigrate(mig: CallMigratePayload): Promise<void> {
    return this.runMediaTransition(() => this.applyMigration(mig));
  }

  private async applyMigration(mig: CallMigratePayload): Promise<void> {
    if (this.disposed || mig.room_id !== this.roomId || (this.roomSocket && (mig.call_id !== this.callId || (mig.epoch !== undefined && mig.epoch < this.epoch)))) return;
    if (mig.ice_servers && mig.ice_servers.length > 0) {
      this.iceServers = mig.ice_servers;
    }

    if (mig.target_mode === 'sfu_livekit' && mig.livekit_url && mig.livekit_token) {
      if (this.mode === 'sfu_livekit' && this.livekitRoom) {
        if (!this.roomSocket || (mig.epoch ?? 0) <= this.epoch) return;
        await this.disconnectLiveKit();
      }
      if (this.disposed) return;
      this.epoch = mig.epoch ?? this.epoch;
      this.clearProtectIpTimer();
      this.migrating = true;
      this.migrationReason = mig.reason ?? 'escalating';
      this.emit();
      try {
        // Make-before-break: connect SFU first, then close P2P connections.
        await this.connectLiveKit(mig.livekit_url, mig.livekit_token);
        if (this.disposed) return;
        this.mode = 'sfu_livekit';
        this.closeAllPeerConnections();
        if (this.protectIpPending) {
          this.protectIp = true;
          this.protectIpPending = false;
        }
        this.notice = '';
        this.signalSocket()?.sendCallMigrated(this.roomId, this.callId, mig.epoch);
      } catch (err) {
        await this.disconnectLiveKit();
        if (this.protectIpPending) {
          this.protectIp = false;
          this.protectIpPending = false;
          this.sendMediaUpdate();
        }
        this.notice = err instanceof Error ? `Relay handoff failed: ${err.message}` : 'Relay handoff failed';
      } finally {
        this.migrating = false;
        this.migrationReason = '';
        this.emit();
      }
      return;
    }

    if (mig.target_mode === 'p2p_mesh') {
      this.epoch = mig.epoch ?? this.epoch;
      if (this.mode === 'p2p_mesh') {
        if (mig.reason === 'peer_signaling_ready') {
          for (const peer of mig.peers ?? []) {
            const id = peerKey(peer);
            if (!this.isSelfPeer(peer) && this.myPeerId < id && this.peersMeta.has(id)) {
              await this.renegotiatePeer(id, this.ensurePeerConnection(id), true);
            }
          }
        }
        return;
      }
      this.clearProtectIpTimer();
      const wasProtectingIp = this.protectIp || this.protectIpPending;
      this.migrating = true;
      this.migrationReason = 'stepping_down_to_p2p';
      this.emit();
      try {
        this.mode = 'p2p_mesh';
        this.protectIp = false;
        this.protectIpPending = false;
        if (wasProtectingIp) {
          this.notice = 'Switched to direct connection — IP protection is off';
        }
        this.reconcileP2PPeers();
        await this.disconnectLiveKit();
        if (this.disposed) return;
        this.signalSocket()?.sendCallMigrated(this.roomId, this.callId, mig.epoch);
      } finally {
        this.migrating = false;
        this.migrationReason = '';
        this.emit();
      }
    }
  }

  async toggleAudio(): Promise<void> {
    if (this.disposed) return;
    const next = !this.audioEnabled;
    if (next) {
      const liveAudio = (this.localStream?.getAudioTracks() ?? []).filter((t) => t.readyState === 'live');
      if (liveAudio.length === 0) {
        const track = await this.enableAudioTrack();
        if (this.disposed) return;
        if (!track) {
          this.emit();
          return;
        }
        this.audioEnabled = true;
        await this.publishLocalAudioTrack(track);
      } else {
        this.audioEnabled = true;
        for (const track of liveAudio) {
          track.enabled = true;
        }
      }
    } else {
      this.audioEnabled = false;
      if (this.localStream) {
        for (const track of this.localStream.getAudioTracks()) {
          track.enabled = false;
        }
      }
    }
    this.sendMediaUpdate();
    this.emit();
  }

  async toggleVideo(): Promise<void> {
    if (this.disposed) return;
    const next = !this.videoEnabled;
    if (next) {
      const track = await this.enableCameraTrack();
      if (this.disposed) return;
      if (!track) {
        this.emit();
        return;
      }
      this.videoEnabled = true;
      await this.publishLocalCameraTrack(track);
    } else {
      this.videoEnabled = false;
      const oldTracks = this.localStream?.getVideoTracks() ?? [];
      for (const track of oldTracks) {
        if (this.livekitRoom) {
          await this.livekitRoom.localParticipant.unpublishTrack(track).catch(() => undefined);
        }
        for (const entry of this.peerConns.values()) {
          if (entry.cameraSender && entry.cameraSender.track === track) {
            await entry.cameraSender.replaceTrack(null).catch(() => undefined);
          }
        }
        track.enabled = false;
        track.stop();
        this.localStream?.removeTrack(track);
      }
    }
    this.sendMediaUpdate();
    this.emit();
  }

  async toggleScreenShare(): Promise<void> {
    if (this.disposed) return;
    if (this.screenShareEnabled) {
      this.stopScreenShare();
      return;
    }
    if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getDisplayMedia) {
      this.notice = 'Screen sharing is not supported in this browser';
      this.emit();
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      if (this.disposed) {
        for (const t of stream.getTracks()) t.stop();
        return;
      }
      const track = stream.getVideoTracks()[0];
      if (!track) return;
      if (this.livekitRoom) {
        const { Track } = await import('livekit-client');
        if (this.disposed) {
          for (const t of stream.getTracks()) t.stop();
          return;
        }
        try {
          await this.livekitRoom.localParticipant.publishTrack(track, {
            source: Track.Source.ScreenShare,
          });
        } catch (err) {
          for (const t of stream.getTracks()) t.stop();
          this.notice =
            err instanceof Error ? `Could not share screen: ${err.message}` : 'Could not share screen';
          this.emit();
          return;
        }
      } else {
        for (const [peerId, entry] of this.peerConns) {
          entry.screenSender = entry.pc.addTrack(track, stream);
          void this.renegotiatePeer(peerId, entry);
        }
      }
      this.screenStream = stream;
      this.screenShareEnabled = true;
      this.notice = '';
      track.onended = () => {
        this.stopScreenShare();
      };
      this.sendMediaUpdate();
      this.emit();
    } catch {
      // User cancelled screen share prompt.
    }
  }

  private stopScreenShare(): void {
    if (!this.screenShareEnabled && !this.screenStream) return;
    const tracks = this.screenStream?.getTracks() ?? [];
    for (const track of tracks) {
      if (this.livekitRoom) {
        void this.livekitRoom.localParticipant.unpublishTrack(track).catch(() => undefined);
      }
      for (const [peerId, entry] of this.peerConns) {
        let removed = false;
        if (entry.screenSender && entry.screenSender.track === track) {
          try {
            entry.pc.removeTrack(entry.screenSender);
            removed = true;
          } catch {
            // Ignore.
          }
          entry.screenSender = null;
        } else {
          for (const sender of entry.pc.getSenders()) {
            if (sender.track === track) {
              try {
                entry.pc.removeTrack(sender);
                removed = true;
              } catch {
                // Ignore.
              }
            }
          }
        }
        if (removed && !this.disposed) {
          void this.renegotiatePeer(peerId, entry);
        }
      }
      track.stop();
    }
    this.screenStream = null;
    this.screenShareEnabled = false;
    if (!this.disposed) {
      this.sendMediaUpdate();
      this.emit();
    }
  }

  setProtectIp(protect: boolean): void {
    if (this.disposed) return;
    if (protect && (this.protectIp || this.protectIpPending)) return;
    if (!protect && !this.protectIp && !this.protectIpPending) return;

    const sock = this.signalSocket();
    if (!sock || !sock.isOpen()) {
      this.notice = 'Reconnect to change relay privacy mode';
      this.emit();
      return;
    }

    this.clearProtectIpTimer();

    if (protect) {
      const alreadySfu = this.mode === 'sfu_livekit';
      if (alreadySfu) {
        this.protectIp = true;
        this.protectIpPending = false;
      } else {
        // Stay pending until the SFU relay actually connects and P2P connections close.
        this.protectIpPending = true;
      }
      const sent = sock.sendCallMedia(this.roomId, this.callId, {
        audio: this.audioEnabled,
        video: this.videoEnabled,
        screenShare: this.screenShareEnabled,
        protectIp: true,
      });
      if (!sent) {
        this.protectIp = false;
        this.protectIpPending = false;
        this.notice = 'Could not request relay switch while offline';
      } else if (!alreadySfu) {
        this.protectIpTimer = setTimeout(() => {
          this.protectIpTimer = null;
          if (this.disposed || !this.protectIpPending) return;
          this.protectIpPending = false;
          this.protectIp = false;
          this.notice = 'Relay switch timed out — still using direct connection';
          this.sendMediaUpdate();
          this.emit();
        }, PROTECT_IP_TIMEOUT_MS);
      }
    } else {
      this.protectIp = false;
      this.protectIpPending = false;
      sock.sendCallMedia(this.roomId, this.callId, {
        audio: this.audioEnabled,
        video: this.videoEnabled,
        screenShare: this.screenShareEnabled,
        protectIp: false,
      });
    }
    this.emit();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.pendingCallState = null;
    this.cancelSocketStart?.();
    this.cancelSocketStart = null;
    this.roomSocket?.close();
    this.roomSocket = null;
    this.clearProtectIpTimer();
    this.stopScreenShare();
    this.closeAllPeerConnections();
    void this.disconnectLiveKit();
    if (this.localStream) {
      for (const t of this.localStream.getTracks()) {
        t.stop();
      }
      this.localStream = null;
    }
  }

  // -------------------------------------------------------------------
  // Media acquisition & track publication
  // -------------------------------------------------------------------

  private async acquireLocalMedia(wantAudio: boolean, wantVideo: boolean): Promise<void> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      this.notice = 'Listen-only mode (microphone/camera unavailable in this browser)';
      this.audioEnabled = false;
      this.videoEnabled = false;
      return;
    }
    if (!wantAudio && !wantVideo) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: wantAudio,
        video: wantVideo ? { width: { ideal: 1280 }, height: { ideal: 720 } } : false,
      });
      if (this.disposed) {
        for (const t of stream.getTracks()) t.stop();
        return;
      }
      this.localStream = stream;
      this.notice = '';
    } catch {
      if (this.disposed) return;
      if (wantVideo && wantAudio) {
        try {
          const audioStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
          if (this.disposed) {
            for (const t of audioStream.getTracks()) t.stop();
            return;
          }
          this.localStream = audioStream;
          this.videoEnabled = false;
          this.notice = 'Camera unavailable — joined with audio only';
          return;
        } catch {
          // Fall through to listen-only.
        }
      }
      this.audioEnabled = false;
      this.videoEnabled = false;
      this.notice = 'Microphone/camera unavailable — joined in listen-only mode';
    }
  }

  private async enableAudioTrack(): Promise<MediaStreamTrack | null> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      this.notice = 'Microphone is not available in this browser';
      return null;
    }
    try {
      const micStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      if (this.disposed) {
        for (const t of micStream.getTracks()) t.stop();
        return null;
      }
      const track = micStream.getAudioTracks()[0];
      if (!track) return null;
      if (!this.localStream) {
        this.localStream = new MediaStream();
      }
      this.localStream.addTrack(track);
      this.notice = '';
      return track;
    } catch {
      this.notice = 'Could not access microphone';
      return null;
    }
  }

  private async enableCameraTrack(): Promise<MediaStreamTrack | null> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      this.notice = 'Camera is not available in this browser';
      return null;
    }
    try {
      const camStream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      if (this.disposed) {
        for (const t of camStream.getTracks()) t.stop();
        return null;
      }
      const track = camStream.getVideoTracks()[0];
      if (!track) return null;
      if (!this.localStream) {
        this.localStream = new MediaStream();
      }
      this.localStream.addTrack(track);
      this.notice = '';
      return track;
    } catch {
      this.notice = 'Could not access camera';
      return null;
    }
  }

  private async publishLocalAudioTrack(track: MediaStreamTrack): Promise<void> {
    if (this.livekitRoom) {
      const { Track } = await import('livekit-client');
      if (this.disposed || !this.livekitRoom) return;
      await this.livekitRoom.localParticipant
        .publishTrack(track, { source: Track.Source.Microphone })
        .catch(() => undefined);
      return;
    }
    if (this.mode === 'p2p_mesh' && this.localStream) {
      for (const [peerId, entry] of this.peerConns) {
        if (entry.audioSender) {
          await entry.audioSender.replaceTrack(track).catch(() => undefined);
        } else {
          entry.audioSender = entry.pc.addTrack(track, this.localStream);
          await this.renegotiatePeer(peerId, entry);
        }
      }
    }
  }

  private async publishLocalCameraTrack(track: MediaStreamTrack): Promise<void> {
    if (this.livekitRoom) {
      const { Track } = await import('livekit-client');
      if (this.disposed || !this.livekitRoom) return;
      await this.livekitRoom.localParticipant
        .publishTrack(track, { source: Track.Source.Camera })
        .catch(() => undefined);
      return;
    }
    if (this.mode === 'p2p_mesh' && this.localStream) {
      for (const [peerId, entry] of this.peerConns) {
        if (entry.cameraSender) {
          await entry.cameraSender.replaceTrack(track).catch(() => undefined);
        } else {
          entry.cameraSender = entry.pc.addTrack(track, this.localStream);
          await this.renegotiatePeer(peerId, entry);
        }
      }
    }
  }

  // -------------------------------------------------------------------
  // P2P WebRTC Mesh
  // -------------------------------------------------------------------

  private reconcileP2PPeers(): void {
    const activeIds = new Set<string>();
    for (const peer of this.peersMeta.values()) {
      if (this.isSelfPeer(peer)) continue;
      const pid = peerKey(peer);
      activeIds.add(pid);
      const existed = this.peerConns.has(pid);
      const entry = this.ensurePeerConnection(pid);
      // Deterministic impolite peer initiates the WebRTC offer to avoid glare.
      if (!existed && this.myPeerId < pid) {
        void this.renegotiatePeer(pid, entry);
      }
    }
    for (const [pid, entry] of this.peerConns) {
      if (!activeIds.has(pid)) {
        this.closePeerEntry(pid, entry);
      }
    }
  }

  private ensurePeerConnection(peerId: string): PeerConnEntry {
    const existing = this.peerConns.get(peerId);
    if (existing) return existing;

    const pc = new RTCPeerConnection({
      iceServers: this.iceServers.length > 0 ? this.iceServers : [{ urls: 'stun:stun.l.google.com:19302' }],
    });
    const remoteStream = new MediaStream();
    const remoteScreenStream = new MediaStream();
    const entry: PeerConnEntry = {
      pc,
      remoteStream,
      remoteScreenStream,
      cameraStreamId: null,
      cameraSender: null,
      audioSender: null,
      screenSender: null,
      pendingCandidates: [],
      negotiation: Promise.resolve(),
      disconnectTimer: null,
    };
    this.peerConns.set(peerId, entry);

    if (this.localStream) {
      for (const track of this.localStream.getTracks()) {
        const sender = pc.addTrack(track, this.localStream);
        if (track.kind === 'audio') entry.audioSender = sender;
        else if (track.kind === 'video') entry.cameraSender = sender;
      }
    }
    if (this.screenStream) {
      for (const track of this.screenStream.getTracks()) {
        entry.screenSender = pc.addTrack(track, this.screenStream);
      }
    }

    pc.ontrack = (ev) => {
      const incomingStream = ev.streams && ev.streams[0] ? ev.streams[0] : null;
      const track = ev.track;
      if (!track) return;

      const peerMeta = this.peersMeta.get(peerId);
      const isSecondStream =
        !!incomingStream &&
        entry.cameraStreamId !== null &&
        incomingStream.id !== entry.cameraStreamId;
      const isScreenTrack =
        track.kind === 'video' &&
        (isSecondStream ||
          remoteStream.getVideoTracks().some((t) => t.id !== track.id && t.readyState === 'live') ||
          Boolean(peerMeta?.screen_share && !peerMeta?.video));

      const targetStream = isScreenTrack ? remoteScreenStream : remoteStream;
      if (!isScreenTrack && incomingStream && entry.cameraStreamId === null) {
        entry.cameraStreamId = incomingStream.id;
      }

      // Drop stale ended video tracks on the target stream before attaching the new one.
      if (track.kind === 'video') {
        for (const existingTrack of targetStream.getVideoTracks()) {
          if (existingTrack.id !== track.id && (isScreenTrack || existingTrack.readyState !== 'live')) {
            targetStream.removeTrack(existingTrack);
          }
        }
      }
      if (!targetStream.getTrackById(track.id)) {
        targetStream.addTrack(track);
      }

      const removeTrack = () => {
        if (targetStream.getTrackById(track.id)) {
          targetStream.removeTrack(track);
          this.emit();
        }
      };
      track.onended = removeTrack;
      if (incomingStream) {
        incomingStream.addEventListener(
          'removetrack',
          (remEv) => {
            if (remEv.track.id === track.id) removeTrack();
          },
          { once: true },
        );
      }
      this.emit();
    };

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this.signalSocket()?.sendCallSignal(this.roomId, this.callId, peerId, 'ice', ev.candidate.toJSON());
      }
    };

    pc.oniceconnectionstatechange = () => {
      const st = pc.iceConnectionState;
      if (st === 'connected' || st === 'completed') {
        if (entry.disconnectTimer) {
          clearTimeout(entry.disconnectTimer);
          entry.disconnectTimer = null;
        }
      } else if (st === 'failed') {
        this.signalSocket()?.sendCallICEFailed(this.roomId, this.callId);
      } else if (st === 'disconnected' && !entry.disconnectTimer) {
        entry.disconnectTimer = setTimeout(() => {
          entry.disconnectTimer = null;
          if (!this.disposed && this.mode === 'p2p_mesh' && pc.iceConnectionState === 'disconnected') {
            this.signalSocket()?.sendCallICEFailed(this.roomId, this.callId);
          }
        }, 8000);
      }
    };

    return entry;
  }

  private renegotiatePeer(peerId: string, entry: PeerConnEntry, resendUnanswered = false): Promise<void> {
    const next = entry.negotiation.then(async () => {
      if (this.disposed || this.mode !== 'p2p_mesh' || this.peerConns.get(peerId) !== entry) return;
      if (resendUnanswered && entry.pc.remoteDescription) return;
      try {
        if (!resendUnanswered || entry.pc.localDescription?.type !== 'offer') {
          const offer = await entry.pc.createOffer();
          await entry.pc.setLocalDescription(offer);
        }
        this.signalSocket()?.sendCallSignal(this.roomId, this.callId, peerId, 'offer', entry.pc.localDescription);
      } catch {
        // A later ready notification or media change may retry this negotiation.
      }
    });
    entry.negotiation = next.catch(() => undefined);
    return entry.negotiation;
  }

  private async flushCandidates(entry: PeerConnEntry): Promise<void> {
    const queued = entry.pendingCandidates.splice(0, entry.pendingCandidates.length);
    for (const c of queued) {
      await entry.pc.addIceCandidate(new RTCIceCandidate(c)).catch(() => undefined);
    }
  }

  private closePeerEntry(peerId: string, entry: PeerConnEntry): void {
    if (entry.disconnectTimer) {
      clearTimeout(entry.disconnectTimer);
      entry.disconnectTimer = null;
    }
    try {
      entry.pc.ontrack = null;
      entry.pc.onicecandidate = null;
      entry.pc.oniceconnectionstatechange = null;
      entry.pc.close();
    } catch {
      // Ignore.
    }
    this.peerConns.delete(peerId);
  }

  private closeAllPeerConnections(): void {
    for (const [peerId, entry] of Array.from(this.peerConns.entries())) {
      this.closePeerEntry(peerId, entry);
    }
  }

  // -------------------------------------------------------------------
  // Lazy-Loaded LiveKit SFU
  // -------------------------------------------------------------------

  private async connectLiveKit(url: string, token: string): Promise<void> {
    await this.disconnectLiveKit();
    // Dynamic import keeps livekit-client completely out of the cold chat bundle.
    const { Room, RoomEvent, Track } = await import('livekit-client');
    if (this.disposed) return;

    // adaptiveStream: false prevents LiveKit from pausing remote video tracks
    // when rendered via MediaStream srcObject instead of RemoteTrack.attach().
    // stopLocalTrackOnUnpublish: false ensures LiveKit never stops our shared
    // localStream / screenStream tracks when stepping down from SFU to P2P.
    const room = new Room({
      adaptiveStream: false,
      dynacast: true,
      stopLocalTrackOnUnpublish: false,
    });
    this.livekitRoom = room;

    const syncParticipantStreams = (participant: LiveKitRemoteParticipant) => {
      let bucket = this.livekitStreams.get(participant.identity);
      if (!bucket) {
        bucket = { cam: new MediaStream(), screen: new MediaStream() };
        this.livekitStreams.set(participant.identity, bucket);
      }

      const desiredCam = new Map<string, MediaStreamTrack>();
      const desiredScreen = new Map<string, MediaStreamTrack>();
      for (const pub of participant.trackPublications.values()) {
        const track = pub.track?.mediaStreamTrack;
        if (!track) continue;
        if (pub.source === Track.Source.ScreenShare) {
          desiredScreen.set(track.id, track);
        } else {
          desiredCam.set(track.id, track);
        }
      }

      // Mutate streams in place so <audio> playback does not reset when a peer toggles video.
      for (const t of bucket.cam.getTracks()) {
        if (!desiredCam.has(t.id)) bucket.cam.removeTrack(t);
      }
      for (const t of desiredCam.values()) {
        if (!bucket.cam.getTrackById(t.id)) bucket.cam.addTrack(t);
      }
      for (const t of bucket.screen.getTracks()) {
        if (!desiredScreen.has(t.id)) bucket.screen.removeTrack(t);
      }
      for (const t of desiredScreen.values()) {
        if (!bucket.screen.getTrackById(t.id)) bucket.screen.addTrack(t);
      }

      this.emit();
    };

    room.on(RoomEvent.TrackSubscribed, (_track, _pub, participant) => {
      syncParticipantStreams(participant);
    });
    room.on(RoomEvent.TrackUnsubscribed, (_track, _pub, participant) => {
      syncParticipantStreams(participant);
    });
    room.on(RoomEvent.ParticipantDisconnected, (participant) => {
      this.livekitStreams.delete(participant.identity);
      this.emit();
    });

    await room.connect(url, token);
    if (this.disposed) {
      await room.disconnect(false);
      return;
    }

    for (const participant of room.remoteParticipants.values()) {
      syncParticipantStreams(participant);
    }

    // Publish already-captured local tracks directly so we never open duplicate hardware captures.
    // Let failures propagate so handleMigrate rolls back cleanly instead of leaving silent tracks.
    if (this.localStream) {
      for (const audioTrack of this.localStream.getAudioTracks()) {
        if (audioTrack.readyState !== 'live') continue;
        audioTrack.enabled = this.audioEnabled;
        await room.localParticipant.publishTrack(audioTrack, {
          source: Track.Source.Microphone,
          stopMicTrackOnMute: false,
        });
      }
      if (this.videoEnabled) {
        for (const videoTrack of this.localStream.getVideoTracks()) {
          if (videoTrack.readyState !== 'live') continue;
          await room.localParticipant.publishTrack(videoTrack, {
            source: Track.Source.Camera,
          });
        }
      }
    }
    if (this.screenStream) {
      const scrTrack = this.screenStream.getVideoTracks()[0];
      if (scrTrack && scrTrack.readyState === 'live') {
        await room.localParticipant.publishTrack(scrTrack, {
          source: Track.Source.ScreenShare,
        });
      }
    }
  }

  private async disconnectLiveKit(): Promise<void> {
    if (!this.livekitRoom) return;
    const room = this.livekitRoom;
    this.livekitRoom = null;
    this.livekitStreams.clear();
    try {
      // Pass stopTracks = false so shared localStream / screenStream tracks survive SFU -> P2P step-down.
      await room.disconnect(false);
    } catch {
      // Ignore.
    }
  }

  // -------------------------------------------------------------------
  // State & Snapshot Projection
  // -------------------------------------------------------------------

  private syncPeersMeta(peers: CallPeer[]): void {
    this.peersMeta.clear();
    for (const p of peers) {
      this.peersMeta.set(peerKey(p), p);
    }
  }

  private sendMediaUpdate(): void {
    this.signalSocket()?.sendCallMedia(this.roomId, this.callId, {
      audio: this.audioEnabled,
      video: this.videoEnabled,
      screenShare: this.screenShareEnabled,
      protectIp: this.protectIp || this.protectIpPending,
    });
  }

  private emit(): void {
    if (this.disposed) return;
    const tiles: CallParticipantTile[] = [];

    // Always place local participant first.
    tiles.push({
      id: this.myPeerId,
      displayName: this.opts.localDisplayName || 'You',
      isLocal: true,
      isGuest: this.opts.isGuest,
      audio: this.audioEnabled,
      video: this.videoEnabled,
      screenShare: this.screenShareEnabled,
      stream: this.localStream,
      screenStream: this.screenStream,
    });

    for (const peer of this.peersMeta.values()) {
      if (this.isSelfPeer(peer)) continue;
      const pid = peerKey(peer);
      let stream: MediaStream | null = null;
      let screenStream: MediaStream | null = null;
      if (this.mode === 'sfu_livekit') {
        const lk = this.livekitStreams.get(pid) ?? this.livekitStreams.get(peer.user_id);
        stream = lk && lk.cam.getTracks().length > 0 ? lk.cam : null;
        screenStream = lk && lk.screen.getTracks().length > 0 ? lk.screen : null;
      } else {
        const conn = this.peerConns.get(pid) ?? this.peerConns.get(peer.user_id);
        stream = conn?.remoteStream ?? null;
        screenStream =
          conn && conn.remoteScreenStream.getVideoTracks().some((t) => t.readyState === 'live')
            ? conn.remoteScreenStream
            : null;
      }
      tiles.push({
        id: pid,
        displayName: peer.display_name || peer.user_id,
        isLocal: false,
        isGuest: peer.is_guest,
        audio: peer.audio,
        video: peer.video,
        screenShare: peer.screen_share,
        stream,
        screenStream,
      });
    }

    this.opts.onChange({
      callId: this.callId,
      roomId: this.roomId,
      mode: this.mode,
      sfuSticky: this.sfuSticky,
      migrating: this.migrating,
      migrationReason: this.migrationReason,
      audio: this.audioEnabled,
      video: this.videoEnabled,
      screenShare: this.screenShareEnabled,
      protectIp: this.protectIp,
      protectIpPending: this.protectIpPending,
      startedAt: this.startedAt,
      notice: this.notice,
      tiles,
    });
  }
}
