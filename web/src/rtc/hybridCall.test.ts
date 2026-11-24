import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatSocket } from '../chat/client';
import { parseCallJoinResponse, parseWsEvent, type CallJoinResponse } from '../chat/types';
import { HybridCallController } from './hybridCall';

const { mockRoomInstances, mockDisconnect, mockPublishTrack, mockConnect } = vi.hoisted(() => ({
  mockRoomInstances: [] as Array<{ opts: unknown }>,
  mockDisconnect: vi.fn(),
  mockPublishTrack: vi.fn(),
  mockConnect: vi.fn(),
}));

vi.mock('livekit-client', () => {
  class MockRoom {
    remoteParticipants = new Map();
    localParticipant = {
      publishTrack: mockPublishTrack,
      unpublishTrack: vi.fn().mockResolvedValue(undefined),
      trackPublications: new Map(),
    };
    constructor(opts: unknown) {
      mockRoomInstances.push({ opts });
    }
    on = vi.fn();
    connect = mockConnect;
    disconnect = mockDisconnect;
  }
  return {
    Room: MockRoom,
    RoomEvent: {
      TrackSubscribed: 'trackSubscribed',
      TrackUnsubscribed: 'trackUnsubscribed',
      ParticipantDisconnected: 'participantDisconnected',
    },
    Track: {
      Source: {
        Microphone: 'microphone',
        Camera: 'camera',
        ScreenShare: 'screen_share',
      },
    },
  };
});

function makeFakeTrack(kind: 'audio' | 'video'): MediaStreamTrack {
  const track = {
    id: `${kind}_${Math.random().toString(36).slice(2)}`,
    kind,
    enabled: true,
    readyState: 'live' as MediaStreamTrackState,
    stop: vi.fn(() => {
      track.readyState = 'ended';
    }),
    onended: null as (() => void) | null,
  };
  return track as unknown as MediaStreamTrack;
}

function makeFakeStream(tracks: MediaStreamTrack[]): MediaStream {
  const list = [...tracks];
  return {
    id: `stream_${Math.random().toString(36).slice(2)}`,
    getTracks: () => [...list],
    getAudioTracks: () => list.filter((t) => t.kind === 'audio'),
    getVideoTracks: () => list.filter((t) => t.kind === 'video'),
    getTrackById: (id: string) => list.find((t) => t.id === id) ?? null,
    addTrack: (t: MediaStreamTrack) => {
      list.push(t);
    },
    removeTrack: (t: MediaStreamTrack) => {
      const idx = list.indexOf(t);
      if (idx >= 0) list.splice(idx, 1);
    },
    addEventListener: vi.fn(),
  } as unknown as MediaStream;
}

describe('HybridCallController SFU/P2P handoff', () => {
  const origMediaDevices = navigator.mediaDevices;

  beforeEach(() => {
    mockRoomInstances.length = 0;
    mockDisconnect.mockReset().mockResolvedValue(undefined);
    mockPublishTrack.mockReset().mockResolvedValue(undefined);
    mockConnect.mockReset().mockResolvedValue(undefined);
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'mediaDevices', {
      value: origMediaDevices,
      configurable: true,
    });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('keeps local mic/camera tracks live when stepping down from LiveKit SFU to P2P', async () => {
    const audioTrack = makeFakeTrack('audio');
    const videoTrack = makeFakeTrack('video');
    const stream = makeFakeStream([audioTrack, videoTrack]);

    Object.defineProperty(navigator, 'mediaDevices', {
      value: { getUserMedia: vi.fn().mockResolvedValue(stream) },
      configurable: true,
    });

    const sendCallMigrated = vi.fn();
    const socket = {
      sendCallMigrated,
      sendCallMedia: vi.fn(),
      sendCallSignal: vi.fn(),
      sendCallICEFailed: vi.fn(),
    } as unknown as ChatSocket;

    const ctrl = new HybridCallController({
      localUserId: 'u1',
      localDisplayName: 'Alice',
      isGuest: false,
      socket: () => socket,
      onChange: () => undefined,
    });

    await ctrl.start(
      {
        call_id: 'call_1',
        room_id: 'room_1',
        peer_id: 'peer_1',
        mode: 'sfu_livekit',
        epoch: 1,
        sfu_sticky: false,
        ice_servers: [],
        livekit_url: 'wss://lk.example.test',
        livekit_token: 'tok_1',
        peers: [
          {
            peer_id: 'peer_1',
            user_id: 'u1',
            display_name: 'Alice',
            is_guest: false,
            audio: true,
            video: true,
            screen_share: false,
            protect_ip: false,
            joined_at: 1,
          },
        ],
      },
      { audio: true, video: true, protectIp: false },
    );

    expect(mockRoomInstances).toHaveLength(1);
    expect(mockRoomInstances[0].opts).toMatchObject({
      adaptiveStream: false,
      stopLocalTrackOnUnpublish: false,
    });
    expect(mockPublishTrack).toHaveBeenCalledTimes(2);

    // Step down SFU -> P2P
    await ctrl.handleMigrate({
      call_id: 'call_1',
      room_id: 'room_1',
      epoch: 2,
      target_mode: 'p2p_mesh',
      reason: 'step_down',
    });

    // LiveKit disconnect MUST pass stopTracks = false so shared tracks stay live for P2P.
    expect(mockDisconnect).toHaveBeenCalledWith(false);
    expect(audioTrack.readyState).toBe('live');
    expect(videoTrack.readyState).toBe('live');
    expect(sendCallMigrated).toHaveBeenCalledWith('room_1', 'call_1', 2);

    ctrl.dispose();
  });

  it('rolls back SFU migration and disconnects room if active track publication fails', async () => {
    const audioTrack = makeFakeTrack('audio');
    const stream = makeFakeStream([audioTrack]);

    Object.defineProperty(navigator, 'mediaDevices', {
      value: { getUserMedia: vi.fn().mockResolvedValue(stream) },
      configurable: true,
    });
    mockPublishTrack.mockRejectedValueOnce(new Error('publish rejected'));

    const sendCallMigrated = vi.fn();
    const socket = {
      sendCallMigrated,
      sendCallMedia: vi.fn(),
      sendCallSignal: vi.fn(),
      sendCallICEFailed: vi.fn(),
    } as unknown as ChatSocket;

    const snapshots: Array<{ mode: string; notice: string }> = [];
    const ctrl = new HybridCallController({
      localUserId: 'u1',
      localDisplayName: 'Alice',
      isGuest: false,
      socket: () => socket,
      onChange: (snap) => snapshots.push({ mode: snap.mode, notice: snap.notice }),
    });

    await ctrl.start(
      {
        call_id: 'call_2',
        room_id: 'room_2',
        peer_id: 'peer_1',
        mode: 'p2p_mesh',
        epoch: 0,
        sfu_sticky: false,
        ice_servers: [],
        peers: [
          {
            peer_id: 'peer_1',
            user_id: 'u1',
            display_name: 'Alice',
            is_guest: false,
            audio: true,
            video: false,
            screen_share: false,
            protect_ip: false,
            joined_at: 1,
          },
        ],
      },
      { audio: true, video: false, protectIp: false },
    );

    await ctrl.handleMigrate({
      call_id: 'call_2',
      room_id: 'room_2',
      epoch: 1,
      target_mode: 'sfu_livekit',
      livekit_url: 'wss://lk.example.test',
      livekit_token: 'tok_2',
    });

    // Must remain on P2P, disconnect the half-built LiveKit room with stopTracks=false, and NOT ack migration.
    const latest = snapshots[snapshots.length - 1];
    expect(latest.mode).toBe('p2p_mesh');
    expect(latest.notice).toContain('publish rejected');
    expect(mockDisconnect).toHaveBeenCalledWith(false);
    expect(sendCallMigrated).not.toHaveBeenCalled();
    expect(audioTrack.readyState).toBe('live');

    ctrl.dispose();
  });
  it.each(['normal', 'step-down', 'overlap', 'recovery-overlap', 'dispose'])('keeps room signaling ordered and rebinds media after owner recovery (%s)', async (scenario) => {
    const stepDown = scenario === 'step-down';
    vi.useFakeTimers();
    class WireSocket {
      static OPEN = 1;
      static instances: WireSocket[] = [];
      readyState = 0;
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: ((event: { data: string }) => void) | null = null;
      sent: string[] = [];
      constructor(readonly url: string) { WireSocket.instances.push(this); }
      open() { this.readyState = 1; this.onopen?.(); }
      emit(value: unknown) { this.onmessage?.({ data: JSON.stringify(value) }); }
      send(value: string) { this.sent.push(value); }
      close() { this.readyState = 3; this.onclose?.(); }
    }
    vi.stubGlobal('WebSocket', WireSocket);
    const audio = makeFakeTrack('audio');
    Object.defineProperty(navigator, 'mediaDevices', {
      value: { getUserMedia: vi.fn().mockResolvedValue(makeFakeStream([audio])) }, configurable: true,
    });
    const response: CallJoinResponse = {
      call_id: 'call_owned', room_id: 'room_owned', peer_id: 'peer_old',
      call_ws_path: '/api/v1/rooms/room_owned/calls/ws', mode: 'sfu_livekit', epoch: 1,
      sfu_sticky: true, ice_servers: [], livekit_url: 'wss://lk.example.test', livekit_token: 'initial', peers: [],
    };
    const rejoin = vi.fn().mockResolvedValue(response);
    const globalMedia = vi.fn();
    const onEnded = vi.fn();
    const global = { sendCallMedia: globalMedia } as unknown as ChatSocket;
    const controller = new HybridCallController({ localUserId: 'alice', localDisplayName: 'Alice', isGuest: false,
      socket: () => global, rejoin, onEnded, onChange: () => undefined });
    const started = controller.start(response, { audio: true, video: false, protectIp: true });
    await Promise.resolve(); // Initial media setup starts on the controller's transition queue.
    const wire = WireSocket.instances[0];
    expect(wire.url).toContain(response.call_ws_path);
    wire.open();
    expect(rejoin).not.toHaveBeenCalled(); // Wait for authenticated hello, not only TCP open.
    wire.emit({ t: 'hello' });
    await started;
    expect(controller.isRoomRouted()).toBe(true);
    await controller.toggleAudio();
    expect(globalMedia).not.toHaveBeenCalled();
    expect(wire.sent.map((raw) => JSON.parse(raw))).toContainEqual(expect.objectContaining({ t: 'call.media', room: 'room_owned', audio: false }));
    if (scenario === 'overlap' || scenario === 'recovery-overlap' || scenario === 'dispose') {
      let releaseDisconnect: () => void = () => undefined;
      let markEntered: () => void = () => undefined;
      const disconnect = new Promise<void>((resolve) => { releaseDisconnect = resolve; });
      const entered = new Promise<void>((resolve) => { markEntered = resolve; });
      mockDisconnect.mockImplementationOnce(() => { markEntered(); return disconnect; });
      const older = controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 2,
        target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'replacement' });
      await entered;
      if (scenario === 'recovery-overlap') {
        rejoin.mockResolvedValue({ ...response, epoch: 4, livekit_token: 'recovered' });
        wire.close();
        await vi.advanceTimersByTimeAsync(1400);
        const recovered = WireSocket.instances[1];
        recovered.open(); recovered.emit({ t: 'hello' });
        await vi.advanceTimersByTimeAsync(0);
        releaseDisconnect();
        await older;
        await vi.advanceTimersByTimeAsync(0);
        expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'recovered');
        expect(audio.readyState).toBe('live');
        controller.dispose();
        return;
      }
      const newer = controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 3,
        target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'newest' });
      if (scenario === 'dispose') controller.dispose();
      // Let a competing handler finish while the older disconnect remains explicitly paused.
      await vi.advanceTimersByTimeAsync(0);
      releaseDisconnect();
      await Promise.all([older, newer]);
      if (scenario === 'dispose') {
        expect(mockConnect).toHaveBeenCalledTimes(1);
        expect(audio.readyState).toBe('ended');
        return;
      }
      expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'newest');
    } else {
      await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 2,
        target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'replacement' });
      expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'replacement');
    }
    const calls = mockConnect.mock.calls.length;
    await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 1,
      target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'stale' });
    expect(mockConnect).toHaveBeenCalledTimes(calls);
    if (stepDown) {
      await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id,
        epoch: 3, target_mode: 'p2p_mesh' });
      // A newer P2P epoch remains authoritative even when no media transition is needed.
      await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id,
        epoch: 4, target_mode: 'p2p_mesh' });
      for (const epoch of [2, 3]) {
        await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch,
          target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'retired' });
        expect(mockConnect).toHaveBeenCalledTimes(calls);
      }
    }
    rejoin.mockResolvedValue({ ...response, epoch: 5, peer_id: 'peer_recovered', livekit_token: 'recovered' });
    wire.close();
    await vi.advanceTimersByTimeAsync(1400);
    const recovered = WireSocket.instances[1];
    recovered.open(); recovered.emit({ t: 'hello' });
    await vi.advanceTimersByTimeAsync(0);
    expect(rejoin).toHaveBeenLastCalledWith({ audio: false, video: false, screenShare: false, protectIp: !stepDown });
    expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'recovered');
    expect(audio.readyState).toBe('live');
    recovered.emit({ t: 'room.closed', room: 'room_owned', d: {} });
    await vi.advanceTimersByTimeAsync(0);
    expect(onEnded).toHaveBeenCalledTimes(1);
    controller.dispose();
    expect(recovered.readyState).toBe(3);
    expect(audio.readyState).toBe('ended');
  });

  it.each(['same-seat', 'replacement-seat', 'refused', 'unanswered-offerer', 'healthy-offerer'])('recovers P2P signaling without silently dropping media (%s)', async (scenario) => {
    vi.useFakeTimers();
    const isOfferer = scenario.endsWith('offerer');
    class WireSocket {
      static OPEN = 1;
      static instances: WireSocket[] = [];
      readyState = 0;
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onmessage: ((event: { data: string }) => void) | null = null;
      constructor() { WireSocket.instances.push(this); }
      open() { this.readyState = 1; this.onopen?.(); }
      emit(value: unknown) { this.onmessage?.({ data: JSON.stringify(value) }); }
      sent: string[] = [];
      send(value: string) { this.sent.push(value); }
      close() { this.readyState = 3; this.onclose?.(); }
    }
    class PeerConnection {
      static instances: PeerConnection[] = [];
      connectionState = 'connected';
      remoteDescription: RTCSessionDescriptionInit | null = null;
      localDescription: RTCSessionDescriptionInit | null = null;
      createOffer = vi.fn(async () => ({ type: 'offer' as const, sdp: 'unanswered offer' }));
      setLocalDescription = vi.fn(async (description: RTCSessionDescriptionInit) => { this.localDescription = description; });
      close = vi.fn();
      constructor() { PeerConnection.instances.push(this); }
    }
    class EmptyStream {
      getTracks() { return []; }
      getAudioTracks() { return []; }
      getVideoTracks() { return []; }
    }
    vi.stubGlobal('WebSocket', WireSocket);
    vi.stubGlobal('RTCPeerConnection', PeerConnection);
    vi.stubGlobal('MediaStream', EmptyStream);
    const self = { peer_id: isOfferer ? 'a-offerer' : 'z-answerer', user_id: 'local', display_name: 'Local', is_guest: false,
      audio: false, video: false, screen_share: false, protect_ip: false, joined_at: 1 };
    const remote = { ...self, peer_id: isOfferer ? 'z-answerer' : 'a-offerer', user_id: 'remote' };
    const response: CallJoinResponse = { call_id: 'c', room_id: 'r', peer_id: self.peer_id, mode: 'p2p_mesh',
      call_ws_path: '/api/v1/rooms/r/calls/ws', epoch: 1, sfu_sticky: false, ice_servers: [], peers: [self, remote] };
    const rejoin = vi.fn().mockResolvedValue(response);
    const snapshots: Array<{ notice: string }> = [];
    const controller = new HybridCallController({ localUserId: 'local', localDisplayName: 'Local', isGuest: false,
      socket: () => null, rejoin, onChange: (snapshot) => snapshots.push(snapshot) });
    const started = controller.start(response, { audio: false, video: false, protectIp: false });
    await Promise.resolve();
    const first = WireSocket.instances[0];
    first.open(); first.emit({ t: 'hello' });
    await started;
    await vi.advanceTimersByTimeAsync(0);
    const connection = PeerConnection.instances[0];
    if (scenario === 'healthy-offerer') connection.remoteDescription = { type: 'answer', sdp: 'already connected' };
    expect(PeerConnection.instances).toHaveLength(1);
    if (scenario === 'replacement-seat') rejoin.mockResolvedValue({ ...response, peer_id: 'zz-replacement' });
    if (scenario === 'refused') rejoin.mockRejectedValue(new Error('seat refused'));
    first.close();
    await vi.advanceTimersByTimeAsync(1400);
    const recovered = WireSocket.instances[1];
    recovered.open(); recovered.emit({ t: 'hello' });
    await vi.advanceTimersByTimeAsync(0);
    expect(rejoin).toHaveBeenCalledTimes(2);
    if (scenario === 'same-seat' || isOfferer) {
      expect(connection.close).not.toHaveBeenCalled();
      expect(PeerConnection.instances).toHaveLength(1);
      expect(snapshots.at(-1)?.notice).toBe('');
      if (scenario === 'healthy-offerer') expect(recovered.sent.map((raw) => JSON.parse(raw)).filter((frame) => frame.kind === 'offer')).toHaveLength(0);
      if (scenario === 'unanswered-offerer') expect(recovered.sent.map((raw) => JSON.parse(raw))).toContainEqual(expect.objectContaining({ t: 'call.signal', kind: 'offer' }));
    } else {
      expect(connection.close).toHaveBeenCalledTimes(1);
      if (scenario === 'refused') expect(snapshots.at(-1)?.notice).toContain('interrupted');
      else expect(PeerConnection.instances).toHaveLength(2);
    }
    controller.dispose();
  });

  it('resends an unanswered offer when the new participant signaling socket becomes ready', async () => {
    vi.useFakeTimers();
    class PeerConnection {
      localDescription: RTCSessionDescriptionInit | null = null;
      remoteDescription = null;
      createOffer = vi.fn(async () => ({ type: 'offer' as const, sdp: 'gathered offer' }));
      setLocalDescription = vi.fn(async (description: RTCSessionDescriptionInit) => { this.localDescription = description; });
      close = vi.fn();
      static instances: PeerConnection[] = [];
      constructor() { PeerConnection.instances.push(this); }
    }
    class EmptyStream { getTracks() { return []; } getAudioTracks() { return []; } getVideoTracks() { return []; } }
    vi.stubGlobal('RTCPeerConnection', PeerConnection);
    vi.stubGlobal('MediaStream', EmptyStream);
    const sendCallSignal = vi.fn();
    const socket = { sendCallSignal } as unknown as ChatSocket;
    const self = { peer_id: 'a-offerer', user_id: 'local', display_name: 'Local', is_guest: false,
      audio: false, video: false, screen_share: false, protect_ip: false, joined_at: 1 };
    const remote = { ...self, peer_id: 'z-answerer', user_id: 'remote' };
    const controller = new HybridCallController({ localUserId: 'local', localDisplayName: 'Local', isGuest: false,
      socket: () => socket, onChange: () => undefined });
    await controller.start({ call_id: 'c', room_id: 'r', peer_id: self.peer_id, mode: 'p2p_mesh',
      epoch: 1, sfu_sticky: false, ice_servers: [], peers: [self, remote] }, { audio: false, video: false, protectIp: false });
    await vi.advanceTimersByTimeAsync(0);
    expect(sendCallSignal).toHaveBeenCalledTimes(1); // Lost before the answerer socket existed.
    const event = parseWsEvent({ t: 'call.migrate', room: 'r', d: { call_id: 'c', room_id: 'r', target_mode: 'p2p_mesh', epoch: 1,
      reason: 'peer_signaling_ready', peers: [remote] } });
    if (event?.kind !== 'call.migrate') throw new Error('readiness event rejected');
    await controller.handleMigrate(event.migrate);
    expect(sendCallSignal).toHaveBeenCalledTimes(2);
    expect(sendCallSignal).toHaveBeenLastCalledWith('r', 'c', remote.peer_id, 'offer', expect.objectContaining({ sdp: 'gathered offer' }));
    expect(PeerConnection.instances).toHaveLength(1);
    controller.handleCallState({ call_id: 'c', room_id: 'r', mode: 'p2p_mesh', epoch: 1, sfu_sticky: false, peers: [self] });
    await controller.handleMigrate(event.migrate);
    expect(sendCallSignal).toHaveBeenCalledTimes(2);
    expect(PeerConnection.instances).toHaveLength(1); // A stale ready notice cannot recreate the removed peer.
    controller.dispose();
  });

  it('queues early offers and rosters until initial identity and microphone are ready', async () => {
    vi.useFakeTimers();
    class WireSocket {
      static OPEN = 1;
      static instances: WireSocket[] = [];
      readyState = 0;
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onmessage: ((event: { data: string }) => void) | null = null;
      sent: string[] = [];
      constructor() { WireSocket.instances.push(this); }
      open() { this.readyState = 1; this.onopen?.(); }
      emit(value: unknown) { this.onmessage?.({ data: JSON.stringify(value) }); }
      send(value: string) { this.sent.push(value); }
      close() { this.readyState = 3; this.onclose?.(); }
    }
    class PeerConnection {
      static instances: PeerConnection[] = [];
      signalingState = 'stable';
      remoteDescription: RTCSessionDescriptionInit | null = null;
      localDescription: RTCSessionDescriptionInit | null = null;
      tracks: MediaStreamTrack[] = [];
      addTrack(track: MediaStreamTrack) { this.tracks.push(track); return { track }; }
      setRemoteDescription = vi.fn(async (description: RTCSessionDescriptionInit) => { this.remoteDescription = description; });
      setLocalDescription = vi.fn(async (description: RTCSessionDescriptionInit) => { this.localDescription = description; });
      createAnswer = vi.fn(async () => ({ type: 'answer' as const, sdp: 'answer with microphone' }));
      close = vi.fn();
      constructor() { PeerConnection.instances.push(this); }
    }
    vi.stubGlobal('WebSocket', WireSocket);
    vi.stubGlobal('RTCPeerConnection', PeerConnection);
    vi.stubGlobal('MediaStream', class { getTracks() { return []; } getVideoTracks() { return []; } getAudioTracks() { return []; } });
    vi.stubGlobal('RTCSessionDescription', class {
      type: RTCSdpType; sdp?: string;
      constructor(value: RTCSessionDescriptionInit) { this.type = value.type; this.sdp = value.sdp; }
    });
    let releaseMicrophone: (stream: MediaStream) => void = () => undefined;
    const microphone = new Promise<MediaStream>((resolve) => { releaseMicrophone = resolve; });
    Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: vi.fn(() => microphone) }, configurable: true });
    const self = { peer_id: 'z-answerer', user_id: 'local', display_name: 'Local', is_guest: false,
      audio: true, video: false, screen_share: false, protect_ip: false, joined_at: 1 };
    const remote = { ...self, peer_id: 'a-offerer', user_id: 'remote' };
    const response: CallJoinResponse = { call_id: 'c', room_id: 'r', peer_id: self.peer_id, mode: 'p2p_mesh',
      call_ws_path: '/api/v1/rooms/r/calls/ws', epoch: 1, sfu_sticky: false, ice_servers: [], peers: [self, remote] };
    const controller = new HybridCallController({ localUserId: 'local', localDisplayName: 'Local', isGuest: false,
      socket: () => null, rejoin: async () => response, onChange: () => undefined });
    const started = controller.start(response, { audio: true, video: false, protectIp: false });
    await Promise.resolve();
    const wire = WireSocket.instances[0]; wire.open(); wire.emit({ t: 'hello' });
    await vi.advanceTimersByTimeAsync(0);
    wire.emit({ t: 'call.state', room: 'r', d: { ...response, active: true } });
    wire.emit({ t: 'call.signal', room: 'r', d: { call_id: 'c', from_peer_id: remote.peer_id, to_peer_id: self.peer_id,
      kind: 'offer', data: { type: 'offer', sdp: 'early offer' } } });
    await vi.advanceTimersByTimeAsync(0);
    expect(PeerConnection.instances).toHaveLength(0);
    const audio = makeFakeTrack('audio'); releaseMicrophone(makeFakeStream([audio]));
    await started; await vi.advanceTimersByTimeAsync(0);
    expect(PeerConnection.instances).toHaveLength(1);
    expect(PeerConnection.instances[0].tracks).toEqual([audio]);
    expect(wire.sent.map((raw) => JSON.parse(raw))).toContainEqual(expect.objectContaining({ t: 'call.signal', kind: 'answer' }));
    controller.dispose();
  });

  it('closes an existing P2P connection when the authoritative roster removes that peer', async () => {
    class PeerConnection {
      static instances: PeerConnection[] = [];
      close = vi.fn();
      constructor() { PeerConnection.instances.push(this); }
    }
    class EmptyStream {
      getTracks() { return []; }
      getAudioTracks() { return []; }
      getVideoTracks() { return []; }
    }
    vi.stubGlobal('RTCPeerConnection', PeerConnection);
    vi.stubGlobal('MediaStream', EmptyStream);
    const self = { peer_id: 'z-local', user_id: 'local', display_name: 'Local', is_guest: false,
      audio: false, video: false, screen_share: false, protect_ip: false, joined_at: 1 };
    const remote = { ...self, peer_id: 'a-remote', user_id: 'remote' };
    const controller = new HybridCallController({ localUserId: 'local', localDisplayName: 'Local',
      isGuest: false, socket: () => null, onChange: () => undefined });
    await controller.start({ call_id: 'c', room_id: 'r', peer_id: self.peer_id, mode: 'p2p_mesh',
      epoch: 1, sfu_sticky: false, ice_servers: [], peers: [self, remote] },
      { audio: false, video: false, protectIp: false });
    expect(PeerConnection.instances).toHaveLength(1);
    controller.handleCallState({ call_id: 'c', room_id: 'r', mode: 'p2p_mesh', epoch: 1,
      sfu_sticky: false, active: true, peers: [self] });
    expect(PeerConnection.instances[0].close).toHaveBeenCalledTimes(1);
    controller.dispose();
  });

  it('refuses a socket path outside the joined room', () => {
    const reply = { call_id: 'c', room_id: 'one', mode: 'p2p_mesh', peers: [], ice_servers: [] };
    expect(() => parseCallJoinResponse({ ...reply, call_ws_path: '/api/v1/rooms/two/calls/ws' })).toThrow('Invalid call socket path');
    expect(() => parseCallJoinResponse({ ...reply, call_ws_path: '//outside.example/steal' })).toThrow('Invalid call socket path');
    expect(parseCallJoinResponse({ ...reply, call_ws_path: '/api/v1/rooms/one/calls/ws' }).call_ws_path).toBe('/api/v1/rooms/one/calls/ws');
  });

});
