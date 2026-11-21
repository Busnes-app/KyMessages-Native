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

  it('renders Direct badge, 1:1 PiP tiles, fixed dock labels, and Hide IP toggle when SFU is available', () => {
    const onToggleAudio = vi.fn();
    const onToggleProtectIp = vi.fn();
    const onLeave = vi.fn();

    const { container } = render(
      <CallStage
        snapshot={baseSnapshot}
        sfuAvailable={true}
        externalAudio
        onToggleAudio={onToggleAudio}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={onToggleProtectIp}
        onLeave={onLeave}
      />,
    );

    expect(screen.getByText('Direct')).toBeTruthy();
    expect(screen.getByText('Alice (You)')).toBeTruthy();
    expect(screen.getByText('Client Bob')).toBeTruthy();
    expect(screen.getByText('Guest')).toBeTruthy();
    expect(container.querySelector('.ky-call-grid.is-pip')).toBeTruthy();
    expect(container.querySelector('.ky-call-tile.is-pip-local')).toBeTruthy();
    // External audio mode should not render duplicate <audio> tags inside CallStage
    expect(container.querySelectorAll('audio')).toHaveLength(0);

    const micBtn = screen.getByRole('button', { name: 'Mic' });
    expect(micBtn.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(micBtn);
    expect(onToggleAudio).toHaveBeenCalledTimes(1);

    const hideIpBtn = screen.getByRole('button', { name: /Hide IP/i });
    expect(hideIpBtn.getAttribute('aria-pressed')).toBe('false');
    fireEvent.click(hideIpBtn);
    expect(onToggleProtectIp).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: 'Leave' }));
    expect(onLeave).toHaveBeenCalledTimes(1);
  });

  it('renders Relayed badge, decouples Hide IP pressed state from SFU mode, and hides Hide IP when SFU is unavailable', () => {
    const { rerender } = render(
      <CallStage
        snapshot={{ ...baseSnapshot, mode: 'sfu_livekit', protectIp: false }}
        sfuAvailable={true}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(screen.getByText('Relayed · IP hidden')).toBeTruthy();
    // SFU routing alone must NOT falsely mark Hide IP as user-toggled pressed
    expect(screen.getByRole('button', { name: /Hide IP/i }).getAttribute('aria-pressed')).toBe('false');

    rerender(
      <CallStage
        snapshot={{ ...baseSnapshot, mode: 'sfu_livekit', protectIp: false }}
        sfuAvailable={false}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(screen.queryByRole('button', { name: /Hide IP/i })).toBeNull();
  });

  it('renders screen-share spotlight with participant filmstrip when a tile shares screen', () => {
    const fakeStream = {
      getVideoTracks: () => [{ readyState: 'live', enabled: true }],
    } as unknown as MediaStream;
    const screenSnapshot: HybridCallSnapshot = {
      ...baseSnapshot,
      tiles: [
        baseSnapshot.tiles[0],
        {
          ...baseSnapshot.tiles[1],
          screenShare: true,
          screenStream: fakeStream,
        },
      ],
    };

    const { container } = render(
      <CallStage
        snapshot={screenSnapshot}
        sfuAvailable={true}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(container.querySelector('.ky-call-stage.has-screen')).toBeTruthy();
    expect(container.querySelector('.ky-call-grid.is-filmstrip')).toBeTruthy();
    expect(screen.getByText('Client Bob · Screen')).toBeTruthy();
    const screenVideo = container.querySelector('.ky-call-tile.is-screen video');
    expect(screenVideo?.classList.contains('is-contain')).toBe(true);
    expect((screenVideo as HTMLVideoElement | null)?.muted).toBe(true);
  });

  it('shows pending Relaying state when protectIpPending is true without claiming active protection', () => {
    render(
      <CallStage
        snapshot={{ ...baseSnapshot, mode: 'p2p_mesh', protectIp: false, protectIpPending: true }}
        sfuAvailable={true}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={vi.fn()}
        onToggleProtectIp={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(screen.getByText('Direct')).toBeTruthy();
    const btn = screen.getByRole('button', { name: 'Relaying…' });
    expect(btn.getAttribute('aria-pressed')).toBe('false');
    expect(btn.getAttribute('aria-busy')).toBe('true');
    expect(screen.getByText('Switching to relay…')).toBeTruthy();
  });

  it('parses server-shaped call.signal (from_peer_id/to_peer_id/data), call.state active:false, and call.migrate epoch', () => {
    const endedEv = parseWsEvent({
      t: 'call.state',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        room_id: 'room-1',
        active: false,
        mode: 'p2p_mesh',
        peers: [{ peer_id: 'peer_1', user_id: 'u1', display_name: 'Alice', audio: true, video: false }],
      },
    });
    expect(endedEv?.kind).toBe('call.state');
    if (endedEv?.kind === 'call.state') {
      expect(endedEv.state.ended).toBe(true);
      expect(endedEv.state.active).toBe(false);
      expect(endedEv.state.peers[0]?.peer_id).toBe('peer_1');
    }

    const sigEv = parseWsEvent({
      t: 'call.signal',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        from_peer_id: 'peer_2',
        to_peer_id: 'peer_1',
        kind: 'answer',
        data: { type: 'answer', sdp: 'v=0' },
      },
    });
    expect(sigEv?.kind).toBe('call.signal');
    if (sigEv?.kind === 'call.signal') {
      expect(sigEv.signal.from).toBe('peer_2');
      expect(sigEv.signal.to).toBe('peer_1');
      expect(sigEv.signal.from_peer_id).toBe('peer_2');
      expect(sigEv.signal.to_peer_id).toBe('peer_1');
      expect(sigEv.signal.payload).toEqual({ type: 'answer', sdp: 'v=0' });
    }

    const migEv = parseWsEvent({
      t: 'call.migrate',
      room: 'room-1',
      d: {
        call_id: 'call-1',
        room_id: 'room-1',
        target_mode: 'sfu_livekit',
        reason: 'protect_ip',
        epoch: 3,
        sfu_url: 'wss://lk.example.com',
        sfu_token: 'jwt-token',
      },
    });
    expect(migEv?.kind).toBe('call.migrate');
    if (migEv?.kind === 'call.migrate') {
      expect(migEv.migrate.epoch).toBe(3);
    }
  });

  it('binds Ctrl+Shift+E to screen share and Ctrl+Shift+H to leave without hanging up on Share', () => {
    const onToggleScreenShare = vi.fn();
    const onLeave = vi.fn();
    render(
      <CallStage
        snapshot={baseSnapshot}
        sfuAvailable={true}
        onToggleAudio={vi.fn()}
        onToggleVideo={vi.fn()}
        onToggleScreenShare={onToggleScreenShare}
        onToggleProtectIp={vi.fn()}
        onLeave={onLeave}
      />,
    );

    fireEvent.keyDown(window, { key: 'E', ctrlKey: true, shiftKey: true });
    expect(onToggleScreenShare).toHaveBeenCalledTimes(1);
    expect(onLeave).not.toHaveBeenCalled();

    fireEvent.keyDown(window, { key: 'H', ctrlKey: true, shiftKey: true });
    expect(onLeave).toHaveBeenCalledTimes(1);
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
