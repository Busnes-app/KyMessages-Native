import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Clock,
  Loader2,
  MessageSquare,
  Phone,
  Send,
  ShieldCheck,
  Video,
  XCircle,
} from 'lucide-react';
import '../styles/chat.css';
import {
  ChatSocket,
  fetchGuestMeetInfo,
  fetchGuestMessages,
  joinGuestCall,
  knockGuestMeet,
  leaveGuestCall,
  sendGuestMessage,
} from '../chat/client';
import type { ChatMessage, GuestMeetInfo, WsServerEvent, WsStatus } from '../chat/types';
import { HybridCallController, type HybridCallSnapshot } from '../rtc/hybridCall';
import { CallStage } from '../components/chat/CallStage';
import { CaptchaWidget } from '../components/CaptchaWidget';

interface GuestMeetingProps {
  token: string;
  appName: string;
}

export const GuestMeeting: React.FC<GuestMeetingProps> = ({ token, appName }) => {
  const [info, setInfo] = useState<GuestMeetInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [displayName, setDisplayName] = useState('');
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaRound, setCaptchaRound] = useState(0);
  const [knocking, setKnocking] = useState(false);

  const [guestId, setGuestId] = useState('');
  const [roomId, setRoomId] = useState('');
  const [status, setStatus] = useState<'form' | 'waiting' | 'admitted' | 'denied' | 'closed'>('form');
  const [wsStatus, setWsStatus] = useState<WsStatus>('offline');

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const [sendingMsg, setSendingMsg] = useState(false);
  const [chatOpen, setChatOpen] = useState(true);

  const [callSnap, setCallSnap] = useState<HybridCallSnapshot | null>(null);
  const [callError, setCallError] = useState('');
  const [joiningCall, setJoiningCall] = useState(false);

  const socketRef = useRef<ChatSocket | null>(null);
  const callCtrlRef = useRef<HybridCallController | null>(null);
  const msgEndRef = useRef<HTMLDivElement | null>(null);

  const loadMessages = useCallback(async () => {
    try {
      const page = await fetchGuestMessages(token);
      setMessages(page.messages);
    } catch {
      // Ignore until admitted.
    }
  }, [token]);

  useEffect(() => {
    let active = true;
    const init = async () => {
      try {
        const res = await fetchGuestMeetInfo(token);
        if (!active) return;
        setInfo(res);
        if (res.closed) {
          setStatus('closed');
        } else if (res.session) {
          setGuestId(res.session.guest_id);
          setDisplayName(res.session.display_name);
          setRoomId(res.session.room_id);
          setStatus(res.session.status);
          if (res.session.status === 'admitted') {
            void loadMessages();
          }
        }
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Meeting link is invalid or expired');
      } finally {
        if (active) setLoading(false);
      }
    };
    void init();
    return () => {
      active = false;
    };
  }, [token, loadMessages]);

  // Connect guest WS whenever waiting or admitted.
  useEffect(() => {
    if (status !== 'waiting' && status !== 'admitted') return;
    const sock = new ChatSocket(
      {
        onStatus: setWsStatus,
        onReconnect: () => {
          if (status === 'admitted') void loadMessages();
        },
        onEvent: (ev: WsServerEvent) => {
          if (ev.kind === 'lobby.decision') {
            if (ev.decision === 'admitted') {
              if (ev.roomId) setRoomId(ev.roomId);
              setStatus('admitted');
              void loadMessages();
            } else {
              setStatus('denied');
            }
            return;
          }
          if (ev.kind === 'room.closed' || ev.kind === 'auth.revoked') {
            callCtrlRef.current?.dispose();
            callCtrlRef.current = null;
            setCallSnap(null);
            setStatus('closed');
            return;
          }
          if (ev.kind === 'message.new' && ev.message) {
            setMessages((prev) =>
              prev.some((m) => m.id === ev.message!.id) ? prev : [...prev, ev.message!],
            );
            return;
          }
          if (ev.kind === 'call.state') {
            callCtrlRef.current?.handleCallState(ev.state);
            return;
          }
          if (ev.kind === 'call.signal') {
            void callCtrlRef.current?.handleSignal(ev.signal);
            return;
          }
          if (ev.kind === 'call.migrate') {
            void callCtrlRef.current?.handleMigrate(ev.migrate);
          }
        },
      },
      `/api/meet/${encodeURIComponent(token)}/ws`,
    );
    socketRef.current = sock;
    sock.connect();
    return () => {
      sock.close();
      if (socketRef.current === sock) socketRef.current = null;
    };
  }, [status, token, loadMessages]);

  useEffect(() => {
    return () => {
      callCtrlRef.current?.dispose();
      callCtrlRef.current = null;
    };
  }, []);

  useEffect(() => {
    msgEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  const handleKnock = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = displayName.trim();
    if (!trimmed) {
      setError('Please enter your name');
      return;
    }
    setError('');
    setKnocking(true);
    try {
      const res = await knockGuestMeet(token, trimmed, captchaToken || undefined);
      setGuestId(res.guestId);
      setRoomId(res.roomId);
      setStatus(res.status === 'admitted' ? 'admitted' : 'waiting');
      if (res.status === 'admitted') {
        void loadMessages();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not join waiting room');
      setCaptchaToken('');
      setCaptchaRound((r) => r + 1);
    } finally {
      setKnocking(false);
    }
  };

  const handleJoinCall = async (withVideo: boolean) => {
    setCallError('');
    setJoiningCall(true);
    try {
      const joinResp = await joinGuestCall(token, { audio: true, video: withVideo });
      callCtrlRef.current?.dispose();
      const ctrl = new HybridCallController({
        localUserId: guestId,
        localDisplayName: displayName || 'Guest',
        isGuest: true,
        socket: () => socketRef.current,
        onChange: setCallSnap,
      });
      callCtrlRef.current = ctrl;
      await ctrl.start(joinResp, { audio: true, video: withVideo, protectIp: false });
    } catch (err) {
      setCallError(err instanceof Error ? err.message : 'Could not join call');
    } finally {
      setJoiningCall(false);
    }
  };

  const handleLeaveCall = async () => {
    callCtrlRef.current?.dispose();
    callCtrlRef.current = null;
    setCallSnap(null);
    await leaveGuestCall(token).catch(() => undefined);
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = draft.trim();
    if (!text || sendingMsg) return;
    setSendingMsg(true);
    try {
      const msg = await sendGuestMessage(token, text);
      setDraft('');
      setMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
    } catch (err) {
      setCallError(err instanceof Error ? err.message : 'Could not send message');
    } finally {
      setSendingMsg(false);
    }
  };

  if (loading) {
    return (
      <div className="ky-guest-center">
        <Loader2 size={24} className="ky-spin" />
        <span>Loading meeting…</span>
      </div>
    );
  }

  if (!info || error && status === 'form' && !info) {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <XCircle size={36} style={{ color: 'var(--danger, #dc2626)' }} />
          <h2>Meeting Unavailable</h2>
          <p>{error || 'This meeting link is invalid or has expired.'}</p>
        </div>
      </div>
    );
  }

  if (status === 'closed' || info.closed) {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <XCircle size={36} style={{ color: 'var(--ink-3)' }} />
          <h2>{info.meeting_title}</h2>
          <p>This meeting has ended.</p>
        </div>
      </div>
    );
  }

  if (status === 'denied') {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <XCircle size={36} style={{ color: 'var(--danger, #dc2626)' }} />
          <h2>Entry Declined</h2>
          <p>The host did not admit you to <strong>{info.meeting_title}</strong>.</p>
        </div>
      </div>
    );
  }

  if (status === 'form') {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <div className="ky-guest-brand">
            <ShieldCheck size={18} />
            <span>{appName} · Guest Waiting Room</span>
          </div>
          <h2>{info.meeting_title}</h2>
          {!info.in_window ? (
            <div className="ky-guest-notice">
              <Clock size={16} />
              <span>This meeting is not currently open. Please return within 15 minutes of the scheduled start time.</span>
            </div>
          ) : (
            <form onSubmit={handleKnock} className="ky-guest-form">
              <label htmlFor="guest-display-name">Your name</label>
              <input
                id="guest-display-name"
                type="text"
                placeholder="e.g. Alex Rivera"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                maxLength={80}
                autoFocus
                required
              />
              {info.pow_required && (
                <CaptchaWidget round={captchaRound} onToken={setCaptchaToken} />
              )}
              {error && <div className="dr-alert dr-alert-error" role="alert">{error}</div>}
              <button
                type="submit"
                className="ky-btn-primary"
                disabled={knocking || (info.pow_required && !captchaToken)}
              >
                {knocking ? 'Entering waiting room…' : 'Ask to Join'}
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  if (status === 'waiting') {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <Loader2 size={32} className="ky-spin" style={{ color: 'var(--accent)' }} />
          <h2>Waiting for host…</h2>
          <p>
            You knocked as <strong>{displayName}</strong> for <strong>{info.meeting_title}</strong>.
            A host will let you in shortly.
          </p>
          <span className="ky-guest-ws-pill">
            {wsStatus === 'live' ? 'Connected to waiting room' : 'Connecting…'}
          </span>
        </div>
      </div>
    );
  }

  // Admitted confined meeting room view.
  return (
    <div className="ky-guest-shell">
      <header className="ky-guest-header">
        <div className="ky-guest-header-title">
          <strong>{info.meeting_title}</strong>
          <span className="ky-call-guest-pill">Guest · {displayName}</span>
          <span className={`ky-ws-pill is-${wsStatus}`}>{wsStatus === 'live' ? 'Live' : wsStatus}</span>
        </div>
        <div className="ky-guest-header-actions">
          {!callSnap && (
            <>
              <button
                type="button"
                className="ky-header-call-btn"
                onClick={() => void handleJoinCall(false)}
                disabled={joiningCall}
              >
                <Phone size={15} />
                <span>Join Audio</span>
              </button>
              <button
                type="button"
                className="ky-header-call-btn is-primary"
                onClick={() => void handleJoinCall(true)}
                disabled={joiningCall}
              >
                <Video size={15} />
                <span>Join Video</span>
              </button>
            </>
          )}
          <button
            type="button"
            className={`ky-header-call-btn ${chatOpen ? 'is-active' : ''}`}
            onClick={() => setChatOpen((v) => !v)}
            title="Toggle meeting chat"
          >
            <MessageSquare size={15} />
            <span>Chat</span>
          </button>
        </div>
      </header>

      {callError && (
        <div className="dr-alert dr-alert-error" role="alert" style={{ margin: '10px 16px 0' }}>
          <span>{callError}</span>
        </div>
      )}

      <div className="ky-guest-body">
        <main className="ky-guest-stage-col">
          {callSnap ? (
            <CallStage
              snapshot={callSnap}
              sfuAvailable={info.sfu_available}
              onToggleAudio={() => void callCtrlRef.current?.toggleAudio()}
              onToggleVideo={() => void callCtrlRef.current?.toggleVideo()}
              onToggleScreenShare={() => void callCtrlRef.current?.toggleScreenShare()}
              onLeave={() => void handleLeaveCall()}
              defaultExpanded
            />
          ) : (
            <div className="ky-guest-ready">
              <h3>You&apos;re in the meeting</h3>
              <p>Join with audio or video whenever you&apos;re ready, or chat with participants on the right.</p>
              <div className="ky-guest-ready-actions">
                <button
                  type="button"
                  className="ky-header-call-btn"
                  onClick={() => void handleJoinCall(false)}
                  disabled={joiningCall}
                >
                  <Phone size={16} />
                  <span>Join Audio</span>
                </button>
                <button
                  type="button"
                  className="ky-header-call-btn is-primary"
                  onClick={() => void handleJoinCall(true)}
                  disabled={joiningCall}
                >
                  <Video size={16} />
                  <span>Join Video</span>
                </button>
              </div>
              {roomId && <small style={{ color: 'var(--ink-3)' }}>Room ID: {roomId}</small>}
            </div>
          )}
        </main>

        {chatOpen && (
          <aside className="ky-guest-chat">
            <div className="ky-guest-chat-head">Meeting Chat</div>
            <div className="ky-guest-chat-list">
              {messages.length === 0 ? (
                <div className="ky-guest-chat-empty">No messages yet. Say hello!</div>
              ) : (
                messages.map((m) => (
                  <div key={m.id} className="ky-guest-msg">
                    <div className="ky-guest-msg-sender">{m.sender_name || m.sender_id}</div>
                    <div className="ky-guest-msg-body">{m.body}</div>
                  </div>
                ))
              )}
              <div ref={msgEndRef} />
            </div>
            <form onSubmit={handleSendMessage} className="ky-guest-chat-form">
              <input
                type="text"
                placeholder="Message meeting…"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                maxLength={4000}
              />
              <button type="submit" disabled={!draft.trim() || sendingMsg} aria-label="Send message">
                <Send size={15} />
              </button>
            </form>
          </aside>
        )}
      </div>
    </div>
  );
};
