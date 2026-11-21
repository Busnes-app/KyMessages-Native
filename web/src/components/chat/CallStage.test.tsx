import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CallStage } from './CallStage';
import { parseWsEvent } from '../../chat/types';
import { GuestMeeting } from '../../pages/GuestMeeting';
import type { HybridCallSnapshot } from '../../rtc/hybridCall';

afterEach(() => {
  cleanup();
});

describe('Phase 3 WS event parsing', () => {
  it('parses call.state, call.signal, call.migrate, lobby.knock, and lobby.decision', () => {
    const stateEv = parseWsEvent({
      t: 'call.state',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        room_id: 'room-1',
        mode: 'p2p_mesh',
        sfu_sticky: false,
        peers: [{ user_id: 'u1', display_name: 'Alice', audio: true, video: true }],
      },
    });
    expect(stateEv?.kind).toBe('call.state');
    if (stateEv?.kind === 'call.state') {
      expect(stateEv.state.mode).toBe('p2p_mesh');
      expect(stateEv.state.peers).toHaveLength(1);
    }

    const sigEv = parseWsEvent({
      t: 'call.signal',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        from: 'u2',
        to: 'u1',
        kind: 'offer',
        payload: { type: 'offer', sdp: 'v=0' },
      },
    });
    expect(sigEv?.kind).toBe('call.signal');

    const migEv = parseWsEvent({
      t: 'call.migrate',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        room_id: 'room-1',
        target_mode: 'sfu_livekit',
        reason: 'video_peer_limit',
        sfu_url: 'wss://lk.example.com',
        sfu_token: 'jwt-token',
      },
    });
    expect(migEv?.kind).toBe('call.migrate');
    if (migEv?.kind === 'call.migrate') {
      expect(migEv.migrate.target_mode).toBe('sfu_livekit');
    }

    const knockEv = parseWsEvent({
      t: 'lobby.knock',
      room: 'room-1',
      d: {
        guest_id: 'guest_1',
        meeting_id: 'meet_1',
        room_id: 'room-1',
        display_name: 'External Bob',
        status: 'waiting',
        knocked_at: 1700000000000,
      },
    });
    expect(knockEv?.kind).toBe('lobby.knock');

    const decEv = parseWsEvent({
      t: 'lobby.decision',
      room: 'room-1',
      d: {
        guest_id: 'guest_1',
        meeting_id: 'meet_1',
        decision: 'admitted',
      },
    });
    expect(decEv?.kind).toBe('lobby.decision');
    if (decEv?.kind === 'lobby.decision') {
      expect(decEv.decision).toBe('admitted');
    }
  });
});

describe('CallStage', () => {
  const baseSnapshot: HybridCallSnapshot = {
    callId: 'call-1',
    roomId: 'room-1',
    mode: 'p2p_mesh',
    sfuSticky: false,
    migrating: false,
    migrationReason: '',
    audio: true,
    video: false,
    screenShare: false,
    protectIp: false,
    notice: '',
    tiles: [
      {
        id: 'u1',
        displayName: 'Alice',
        isLocal: true,
        isGuest: false,
        audio: true,
        video: false,
        screenShare: false,
        stream: null,
        screenStream: null,
      },
      {
        id: 'guest_1',
        displayName: 'Client Bob',
        isLocal: false,
        isGuest: true,
        audio: true,
        video: false,
        screenShare: false,
        stream: null,
        screenStream: null,
      },
    ],
  };

  it('renders P2P Direct badge, participant tiles, and Hide IP toggle when SFU is available', () => {
    const onToggleAudio = vi.fn();
    const onToggleProtectIp = vi.fn();
    const onLeave = vi.fn();

    render(
      <CallStage
        snapshot={baseSnapshot}
        sfuAvailable={true}
        onToggleAudio={onToggleAudio}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={onToggleProtectIp}
        onLeave={onLeave}
      />,
    );

    expect(screen.getByText('P2P Direct')).toBeTruthy();
    expect(screen.getByText('Alice (You)')).toBeTruthy();
    expect(screen.getByText('Client Bob')).toBeTruthy();
    expect(screen.getByText('Guest')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /Mute/i }));
    expect(onToggleAudio).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /Hide IP/i }));
    expect(onToggleProtectIp).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: /Leave/i }));
    expect(onLeave).toHaveBeenCalledTimes(1);
  });

  it('renders LiveKit SFU badge and hides Hide IP button when SFU is unavailable', () => {
    render(
      <CallStage
        snapshot={{ ...baseSnapshot, mode: 'sfu_livekit' }}
        sfuAvailable={false}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(screen.getByText('LiveKit SFU')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Hide IP/i })).toBeNull();
  });
});

describe('GuestMeeting', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('loads meeting info and renders the knock form when the window is open', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          meeting_title: 'Quarterly Design Sync',
          closed: false,
          in_window: true,
          pow_required: false,
          sfu_available: true,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    render(<GuestMeeting token="tok_123" appName="KyMessages" />);

    await waitFor(() => {
      expect(screen.getByText('Quarterly Design Sync')).toBeTruthy();
    });
    expect(screen.getByLabelText(/Your name/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Ask to join/i })).toBeTruthy();
  });
});
