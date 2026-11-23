import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatSocket } from '../chat/client';
import { parseCallJoinResponse, type CallJoinResponse } from '../chat/types';
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
  it('keeps room signaling separate and rebinds media after owner recovery', async () => {
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
    await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 2,
      target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'replacement' });
    expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'replacement');
    const calls = mockConnect.mock.calls.length;
    await controller.handleMigrate({ call_id: response.call_id, room_id: response.room_id, epoch: 1,
      target_mode: 'sfu_livekit', livekit_url: response.livekit_url, livekit_token: 'stale' });
    expect(mockConnect).toHaveBeenCalledTimes(calls);
    rejoin.mockResolvedValue({ ...response, epoch: 3, peer_id: 'peer_recovered', livekit_token: 'recovered' });
    wire.close();
    await vi.advanceTimersByTimeAsync(1400);
    const recovered = WireSocket.instances[1];
    recovered.open(); recovered.emit({ t: 'hello' });
    await vi.advanceTimersByTimeAsync(0);
    expect(rejoin).toHaveBeenLastCalledWith({ audio: false, video: false, screenShare: false, protectIp: true });
    expect(mockConnect).toHaveBeenLastCalledWith(response.livekit_url, 'recovered');
    expect(audio.readyState).toBe('live');
    recovered.emit({ t: 'room.closed', room: 'room_owned', d: {} });
    await vi.advanceTimersByTimeAsync(0);
    expect(onEnded).toHaveBeenCalledTimes(1);
    controller.dispose();
    expect(recovered.readyState).toBe(3);
    expect(audio.readyState).toBe('ended');
  });

  it('refuses a socket path outside the joined room', () => {
    const reply = { call_id: 'c', room_id: 'one', mode: 'p2p_mesh', peers: [], ice_servers: [] };
    expect(() => parseCallJoinResponse({ ...reply, call_ws_path: '/api/v1/rooms/two/calls/ws' })).toThrow('Invalid call socket path');
    expect(() => parseCallJoinResponse({ ...reply, call_ws_path: '//outside.example/steal' })).toThrow('Invalid call socket path');
    expect(parseCallJoinResponse({ ...reply, call_ws_path: '/api/v1/rooms/one/calls/ws' }).call_ws_path).toBe('/api/v1/rooms/one/calls/ws');
  });

});
