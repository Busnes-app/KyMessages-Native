import type {
  CallJoinResponse,
  CallMigratePayload,
  CallMode,
  CallPeer,
  CallSignalData,
  CallState,
} from '../chat/types';
import type { ChatSocket } from '../chat/client';

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
  notice: string;
  tiles: CallParticipantTile[];
}

type LiveKitRoom = import('livekit-client').Room;
type LiveKitRemoteParticipant = import('livekit-client').RemoteParticipant;

interface PeerConnEntry {
  pc: RTCPeerConnection;
  remoteStream: MediaStream;
  pendingCandidates: RTCIceCandidateInit[];
  disconnectTimer: ReturnType<typeof setTimeout> | null;
}

export interface HybridCallControllerOptions {
  localUserId: string;
  localDisplayName: string;
  isGuest: boolean;
  socket: () => ChatSocket | null;
  onChange: (snapshot: HybridCallSnapshot) => void;
}

/**
 * Manages a single room's hybrid P2P-first WebRTC call with seamless mid-call
 * make-before-break escalation to LiveKit SFU (lazy-loaded on demand) and
 * automatic step-down back to P2P when the server signals a migration.
 */
export class HybridCallController {
  private callId = '';
  private roomId = '';
  private mode: CallMode = 'p2p_mesh';
  private sfuSticky = false;
  private migrating = false;
  private migrationReason = '';
  private notice = '';

  private audioEnabled = true;
  private videoEnabled = false;
  private screenShareEnabled = false;
  private protectIp = false;

  private iceServers: RTCIceServer[] = [];
  private peersMeta = new Map<string, CallPeer>();
  private peerConns = new Map<string, PeerConnEntry>();

  private localStream: MediaStream | null = null;
  private screenStream: MediaStream | null = null;

  private livekitRoom: LiveKitRoom | null = null;
  private livekitStreams = new Map<string, { cam: MediaStream | null; screen: MediaStream | null }>();

  private disposed = false;

  constructor(private readonly opts: HybridCallControllerOptions) {}

  async start(
    joinResp: CallJoinResponse,
    initialMedia: { audio: boolean; video: boolean; protectIp: boolean },
  ): Promise<void> {
    this.callId = joinResp.call_id;
    this.roomId = joinResp.room_id;
    this.mode = joinResp.mode;
    this.sfuSticky = joinResp.sfu_sticky;
    this.iceServers = joinResp.ice_servers;
    this.audioEnabled = initialMedia.audio;
    this.videoEnabled = initialMedia.video;
    this.protectIp = initialMedia.protectIp;

    this.syncPeersMeta(joinResp.peers);
    await this.acquireLocalMedia(initialMedia.audio, initialMedia.video);
    this.emit();

    if (joinResp.mode === 'sfu_livekit' && joinResp.livekit_url && joinResp.livekit_token) {
      await this.connectLiveKit(joinResp.livekit_url, joinResp.livekit_token);
    } else {
      this.reconcileP2PPeers();
    }
    this.emit();
  }

  /** Called whenever the server broadcasts a `call.state` event for this room. */
  handleCallState(state: CallState): void {
    if (this.disposed || state.room_id !== this.roomId) return;
    if (state.ended) {
      this.dispose();
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
    if (this.disposed || this.mode !== 'p2p_mesh') return;
    if (sig.call_id !== this.callId || sig.from === this.opts.localUserId) return;

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
        this.opts.socket()?.sendCallSignal(this.roomId, this.callId, sig.from, 'answer', pc.localDescription);
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
  async handleMigrate(mig: CallMigratePayload): Promise<void> {
    if (this.disposed || mig.room_id !== this.roomId) return;
    if (mig.ice_servers && mig.ice_servers.length > 0) {
      this.iceServers = mig.ice_servers;
    }

    if (mig.target_mode === 'sfu_livekit' && mig.livekit_url && mig.livekit_token) {
      if (this.mode === 'sfu_livekit' && this.livekitRoom) return;
      this.migrating = true;
      this.migrationReason = mig.reason ?? 'escalating';
      this.emit();
      try {
        // Make-before-break: connect SFU first, then close P2P connections.
        await this.connectLiveKit(mig.livekit_url, mig.livekit_token);
        this.mode = 'sfu_livekit';
        this.closeAllPeerConnections();
        this.opts.socket()?.sendCallMigrated(this.roomId, this.callId);
      } catch (err) {
        this.notice = err instanceof Error ? `SFU handoff failed: ${err.message}` : 'SFU handoff failed';
      } finally {
        this.migrating = false;
        this.migrationReason = '';
        this.emit();
      }
      return;
    }

    if (mig.target_mode === 'p2p_mesh') {
      if (this.mode === 'p2p_mesh') return;
      this.migrating = true;
      this.migrationReason = 'stepping_down_to_p2p';
      this.emit();
      try {
        this.mode = 'p2p_mesh';
        this.reconcileP2PPeers();
        await this.disconnectLiveKit();
        this.opts.socket()?.sendCallMigrated(this.roomId, this.callId);
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
    this.audioEnabled = next;
    if (next && (!this.localStream || this.localStream.getAudioTracks().length === 0)) {
      await this.acquireLocalMedia(true, this.videoEnabled);
      await this.republishLocalTracks();
    } else if (this.localStream) {
      for (const track of this.localStream.getAudioTracks()) {
        track.enabled = next;
      }
    }
    if (this.livekitRoom) {
      await this.livekitRoom.localParticipant.setMicrophoneEnabled(next).catch(() => undefined);
    }
    this.sendMediaUpdate();
    this.emit();
  }

  async toggleVideo(): Promise<void> {
    if (this.disposed) return;
    const next = !this.videoEnabled;
    if (next) {
      const addedTrack = await this.enableCameraTrack();
      if (!addedTrack) {
        this.emit();
        return;
      }
      this.videoEnabled = true;
      await this.republishLocalTracks();
    } else {
      this.videoEnabled = false;
      if (this.localStream) {
        for (const track of this.localStream.getVideoTracks()) {
          track.enabled = false;
          track.stop();
          this.localStream.removeTrack(track);
        }
      }
    }
    if (this.livekitRoom) {
      await this.livekitRoom.localParticipant.setCameraEnabled(this.videoEnabled).catch(() => undefined);
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
      const track = stream.getVideoTracks()[0];
      if (!track) return;
      this.screenStream = stream;
      this.screenShareEnabled = true;
      track.onended = () => {
        this.stopScreenShare();
      };
      if (this.livekitRoom) {
        await this.livekitRoom.localParticipant.publishTrack(track).catch(() => undefined);
      } else {
        for (const [peerId, entry] of this.peerConns) {
          entry.pc.addTrack(track, stream);
          void this.renegotiatePeer(peerId, entry);
        }
      }
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
      for (const entry of this.peerConns.values()) {
        for (const sender of entry.pc.getSenders()) {
          if (sender.track === track) {
            try {
              entry.pc.removeTrack(sender);
            } catch {
              // Ignore.
            }
          }
        }
      }
      track.stop();
    }
    this.screenStream = null;
    this.screenShareEnabled = false;
    this.sendMediaUpdate();
    this.emit();
  }

  setProtectIp(protect: boolean): void {
    if (this.disposed || this.protectIp === protect) return;
    this.protectIp = protect;
    this.sendMediaUpdate();
    this.emit();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
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
  // Media acquisition
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
      this.localStream = stream;
      this.notice = '';
    } catch {
      // Fallback: if video+audio failed, try audio-only; otherwise listen-only.
      if (wantVideo && wantAudio) {
        try {
          this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
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

  private async enableCameraTrack(): Promise<boolean> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      this.notice = 'Camera is not available in this browser';
      return false;
    }
    try {
      const camStream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      const track = camStream.getVideoTracks()[0];
      if (!track) return false;
      if (!this.localStream) {
        this.localStream = new MediaStream();
      }
      this.localStream.addTrack(track);
      this.notice = '';
      return true;
    } catch {
      this.notice = 'Could not access camera';
      return false;
    }
  }

  private async republishLocalTracks(): Promise<void> {
    if (!this.localStream) return;
    if (this.mode === 'p2p_mesh') {
      for (const [peerId, entry] of this.peerConns) {
        const existingTracks = new Set(entry.pc.getSenders().map((s) => s.track));
        let changed = false;
        for (const track of this.localStream.getTracks()) {
          if (!existingTracks.has(track)) {
            entry.pc.addTrack(track, this.localStream);
            changed = true;
          }
        }
        if (changed) {
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
      if (peer.user_id === this.opts.localUserId) continue;
      activeIds.add(peer.user_id);
      const existed = this.peerConns.has(peer.user_id);
      const entry = this.ensurePeerConnection(peer.user_id);
      // Deterministic impolite peer initiates the WebRTC offer to avoid glare.
      if (!existed && this.opts.localUserId < peer.user_id) {
        void this.renegotiatePeer(peer.user_id, entry);
      }
    }
    for (const [peerId, entry] of this.peerConns) {
      if (!activeIds.has(peerId)) {
        this.closePeerEntry(peerId, entry);
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
    const entry: PeerConnEntry = {
      pc,
      remoteStream,
      pendingCandidates: [],
      disconnectTimer: null,
    };
    this.peerConns.set(peerId, entry);

    if (this.localStream) {
      for (const track of this.localStream.getTracks()) {
        pc.addTrack(track, this.localStream);
      }
    }
    if (this.screenStream) {
      for (const track of this.screenStream.getTracks()) {
        pc.addTrack(track, this.screenStream);
      }
    }

    pc.ontrack = (ev) => {
      if (ev.streams && ev.streams[0]) {
        for (const t of ev.streams[0].getTracks()) {
          if (!remoteStream.getTrackById(t.id)) {
            remoteStream.addTrack(t);
          }
        }
      } else if (ev.track && !remoteStream.getTrackById(ev.track.id)) {
        remoteStream.addTrack(ev.track);
      }
      this.emit();
    };

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this.opts.socket()?.sendCallSignal(this.roomId, this.callId, peerId, 'ice', ev.candidate.toJSON());
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
        this.opts.socket()?.sendCallICEFailed(this.roomId, this.callId);
      } else if (st === 'disconnected' && !entry.disconnectTimer) {
        entry.disconnectTimer = setTimeout(() => {
          entry.disconnectTimer = null;
          if (!this.disposed && this.mode === 'p2p_mesh' && pc.iceConnectionState === 'disconnected') {
            this.opts.socket()?.sendCallICEFailed(this.roomId, this.callId);
          }
        }, 8000);
      }
    };

    return entry;
  }

  private async renegotiatePeer(peerId: string, entry: PeerConnEntry): Promise<void> {
    if (this.disposed || this.mode !== 'p2p_mesh') return;
    try {
      const offer = await entry.pc.createOffer();
      await entry.pc.setLocalDescription(offer);
      this.opts.socket()?.sendCallSignal(this.roomId, this.callId, peerId, 'offer', entry.pc.localDescription);
    } catch {
      // Ignore transient renegotiation errors.
    }
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
    // Dynamic import keeps livekit-client completely out of the cold chat bundle!
    const { Room, RoomEvent, Track } = await import('livekit-client');
    if (this.disposed) return;

    const room = new Room({
      adaptiveStream: true,
      dynacast: true,
    });
    this.livekitRoom = room;

    const rebuildParticipantStreams = (participant: LiveKitRemoteParticipant) => {
      const camStream = new MediaStream();
      const scrStream = new MediaStream();
      for (const pub of participant.trackPublications.values()) {
        const track = pub.track?.mediaStreamTrack;
        if (!track) continue;
        if (pub.source === Track.Source.ScreenShare) {
          scrStream.addTrack(track);
        } else {
          camStream.addTrack(track);
        }
      }
      this.livekitStreams.set(participant.identity, {
        cam: camStream.getTracks().length > 0 ? camStream : null,
        screen: scrStream.getTracks().length > 0 ? scrStream : null,
      });
      this.emit();
    };

    room.on(RoomEvent.TrackSubscribed, (_track, _pub, participant) => {
      rebuildParticipantStreams(participant);
    });
    room.on(RoomEvent.TrackUnsubscribed, (_track, _pub, participant) => {
      rebuildParticipantStreams(participant);
    });
    room.on(RoomEvent.ParticipantDisconnected, (participant) => {
      this.livekitStreams.delete(participant.identity);
      this.emit();
    });

    await room.connect(url, token);
    if (this.disposed) {
      await room.disconnect();
      return;
    }

    for (const participant of room.remoteParticipants.values()) {
      rebuildParticipantStreams(participant);
    }

    // Publish existing local tracks into LiveKit SFU.
    if (this.audioEnabled) {
      await room.localParticipant.setMicrophoneEnabled(true).catch(() => undefined);
    }
    if (this.videoEnabled) {
      await room.localParticipant.setCameraEnabled(true).catch(() => undefined);
    }
    if (this.screenStream) {
      const scrTrack = this.screenStream.getVideoTracks()[0];
      if (scrTrack) {
        await room.localParticipant.publishTrack(scrTrack).catch(() => undefined);
      }
    }
  }

  private async disconnectLiveKit(): Promise<void> {
    if (!this.livekitRoom) return;
    const room = this.livekitRoom;
    this.livekitRoom = null;
    this.livekitStreams.clear();
    try {
      await room.disconnect();
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
      this.peersMeta.set(p.user_id, p);
    }
  }

  private sendMediaUpdate(): void {
    this.opts.socket()?.sendCallMedia(this.roomId, this.callId, {
      audio: this.audioEnabled,
      video: this.videoEnabled,
      screenShare: this.screenShareEnabled,
      protectIp: this.protectIp,
    });
  }

  private emit(): void {
    if (this.disposed) return;
    const tiles: CallParticipantTile[] = [];

    // Always place local participant first.
    tiles.push({
      id: this.opts.localUserId,
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
      if (peer.user_id === this.opts.localUserId) continue;
      let stream: MediaStream | null = null;
      let screenStream: MediaStream | null = null;
      if (this.mode === 'sfu_livekit') {
        const lk = this.livekitStreams.get(peer.user_id);
        stream = lk?.cam ?? null;
        screenStream = lk?.screen ?? null;
      } else {
        stream = this.peerConns.get(peer.user_id)?.remoteStream ?? null;
      }
      tiles.push({
        id: peer.user_id,
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
      notice: this.notice,
      tiles,
    });
  }
}
