import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatSocket } from '../chat/client';
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
});
