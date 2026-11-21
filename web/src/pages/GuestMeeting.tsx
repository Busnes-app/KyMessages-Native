import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Clock,
  Loader2,
  MessageSquare,
  Phone,
  Send,
  ShieldCheck,
  Video,
  X,
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
import { formatTime } from '../chat/state';
import type { ChatMessage, GuestMeetInfo, WsServerEvent, WsStatus } from '../chat/types';
import { HybridCallController, type HybridCallSnapshot } from '../rtc/hybridCall';
import { CallStage } from '../components/chat/CallStage';
import { CaptchaWidget } from '../components/CaptchaWidget';

interface GuestMeetingProps {
  token: string;
  appName: string;
}

function waitingConnectionLabel(status: WsStatus): string {
  switch (status) {
    case 'live':
      return 'Connected to waiting room';
    case 'reconnecting':
      return 'Reconnecting to waiting room…';
    case 'offline':
      return 'Connection lost — retrying…';
    default:
      return 'Connecting to waiting room…';
  }
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
  const [status, setStatus] = useState<'form' | 'waiting' | 'admitted' | 'denied' | 'closed'>('form');
  const [wsStatus, setWsStatus] = useState<WsStatus>('offline');

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const [sendingMsg, setSendingMsg] = useState(false);
  const [chatError, setChatError] = useState('');
  const [chatOpen, setChatOpen] = useState<boolean>(() =>
    typeof window !== 'undefined' ? window.innerWidth > 820 : true,
  );
  const [unreadChat, setUnreadChat] = useState(0);

  const [callSnap, setCallSnap] = useState<HybridCallSnapshot | null>(null);
  const [callError, setCallError] = useState('');
  const [joiningCall, setJoiningCall] = useState(false);

  const socketRef = useRef<ChatSocket | null>(null);
  const callCtrlRef = useRef<HybridCallController | null>(null);
  const msgEndRef = useRef<HTMLDivElement | null>(null);
  const chatToggleBtnRef = useRef<HTMLButtonElement | null>(null);
  const chatOpenRef = useRef(chatOpen);
  chatOpenRef.current = chatOpen;
  const statusRef = useRef(status);
  statusRef.current = status;

  const loadMessages = useCallback(async () => {
    try {
      const page = await fetchGuestMessages(token);
      setMessages(page.messages);
    } catch {
      // Ignore until admitted.
    }
  }, [token]);

  const reconcileGuestSession = useCallback(async () => {
    try {
      const res = await fetchGuestMeetInfo(token);
      setInfo(res);
      if (res.closed) {
        callCtrlRef.current?.dispose();
        callCtrlRef.current = null;
        setCallSnap(null);
        setStatus('closed');
        return;
      }
      if (res.session) {
        setGuestId(res.session.guest_id);
        setDisplayName(res.session.display_name);
        if (res.session.status === 'admitted' && statusRef.current !== 'admitted') {
          setStatus('admitted');
          void loadMessages();
        } else if (res.session.status === 'admitted') {
          void loadMessages();
        }
      } else if (statusRef.current === 'waiting') {
        setStatus('denied');
      }
    } catch {
      // Ignore transient network errors during reconnect.
    }
  }, [token, loadMessages]);

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

  const wsActive = status === 'waiting' || status === 'admitted';

  // Keep a single confined guest WS alive across waiting -> admitted without reconnect churn.
  useEffect(() => {
    if (!wsActive) return;
    const sock = new ChatSocket(
      {
        onStatus: (nextStatus) => {
          setWsStatus(nextStatus);
          if (nextStatus === 'reconnecting') {
            void reconcileGuestSession();
          }
        },
        onReconnect: () => {
          // The server removes a guest's call peer when their last WS disconnects.
          // Tear down any stale local call controller so the user can cleanly rejoin.
          if (callCtrlRef.current) {
            callCtrlRef.current.dispose();
            callCtrlRef.current = null;
            setCallSnap(null);
            setCallError('Connection interrupted — click Join Call to reconnect audio and video.');
          }
          void reconcileGuestSession();
        },
        onEvent: (ev: WsServerEvent) => {
          if (ev.kind === 'lobby.decision') {
            if (ev.decision === 'admitted') {
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
          if (ev.kind === 'message.new') {
            if (ev.message) {
              const incoming = ev.message;
              setMessages((prev) => (prev.some((m) => m.id === incoming.id) ? prev : [...prev, incoming]));
              if (!chatOpenRef.current) {
                setUnreadChat((n) => n + 1);
              }
            } else if (ev.refetch) {
              if (!chatOpenRef.current) {
                setUnreadChat((n) => n + 1);
              }
              void loadMessages();
            }
            return;
          }
          if (ev.kind === 'message.edit') {
            if (ev.message) {
              const updated = ev.message;
              setMessages((prev) => prev.map((m) => (m.id === updated.id ? updated : m)));
            } else if (ev.refetch) {
              void loadMessages();
            }
            return;
          }
          if (ev.kind === 'message.delete' && ev.messageId) {
            const delId = ev.messageId;
            setMessages((prev) =>
              prev.map((m) => (m.id === delId ? { ...m, deleted_at: Date.now(), body: '' } : m)),
            );
            return;
          }
          if (ev.kind === 'call.state') {
            callCtrlRef.current?.handleCallState(ev.state);
            if (ev.state.ended || ev.state.active === false) {
              callCtrlRef.current?.dispose();
              callCtrlRef.current = null;
              setCallSnap(null);
            }
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
  }, [wsActive, token, loadMessages, reconcileGuestSession]);

  useEffect(() => {
    return () => {
      callCtrlRef.current?.dispose();
      callCtrlRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (chatOpen) {
      setUnreadChat(0);
      const reduceMotion =
        typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      msgEndRef.current?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' });
    }
  }, [messages.length, chatOpen]);

  useEffect(() => {
    if (!chatOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && typeof window !== 'undefined' && window.innerWidth <= 820) {
        setChatOpen(false);
        chatToggleBtnRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [chatOpen]);

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

  const handleLeaveWaitingRoom = () => {
    socketRef.current?.close();
    socketRef.current = null;
    setWsStatus('offline');
    setStatus('form');
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
    setChatError('');
    try {
      const msg = await sendGuestMessage(token, text);
      setDraft('');
      setMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
    } catch (err) {
      setChatError(err instanceof Error ? err.message : 'Could not send message');
    } finally {
      setSendingMsg(false);
    }
  };

  if (loading) {
    return (
      <div className="ky-guest-center" role="status">
        <Loader2 size={24} className="ky-spin" aria-hidden="true" />
        <span>Loading meeting…</span>
      </div>
    );
  }

  if (!info || (error && status === 'form' && !info)) {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <XCircle size={36} style={{ color: 'var(--danger, #dc2626)' }} aria-hidden="true" />
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
          <XCircle size={36} style={{ color: 'var(--ink)' }} aria-hidden="true" />
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
          <XCircle size={36} style={{ color: 'var(--danger, #dc2626)' }} aria-hidden="true" />
          <h2>Entry Declined</h2>
          <p>
            The host did not admit you to <strong>{info.meeting_title}</strong>.
          </p>
        </div>
      </div>
    );
  }

  if (status === 'form') {
    return (
      <div className="ky-guest-center">
        <div className="ky-guest-card">
          <div className="ky-guest-brand">
            <ShieldCheck size={18} aria-hidden="true" />
            <span>{appName} · Guest Waiting Room</span>
          </div>
          <h2>{info.meeting_title}</h2>
          {!info.in_window ? (
            <div className="ky-guest-notice">
              <Clock size={16} aria-hidden="true" />
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
              {error && (
                <div className="dr-alert dr-alert-error" role="alert">
                  {error}
                </div>
              )}
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
          <Loader2 size={32} className="ky-spin" style={{ color: 'var(--accent)' }} aria-hidden="true" />
          <h2>Waiting for host…</h2>
          <p>
            You knocked as <strong>{displayName}</strong> for <strong>{info.meeting_title}</strong>.
            A host will let you in shortly.
          </p>
          <span className="ky-guest-ws-pill" role="status" aria-live="polite">
            {waitingConnectionLabel(wsStatus)}
          </span>
          <button
            type="button"
            className="btn-secondary"
            onClick={handleLeaveWaitingRoom}
            style={{ marginTop: '0.25rem' }}
          >
            Leave waiting room
          </button>
        </div>
      </div>
    );
  }

  // Admitted confined meeting room view.
  return (
    <div className="ky-guest-shell">
      <header className="ky-guest-header">
        <div className="ky-guest-header-title">
          <h1>{info.meeting_title}</h1>
          <span className="ky-guest-badge">Guest · {displayName}</span>
          <span className={`ky-ws-pill is-${wsStatus}`}>
            <span className="ky-ws-pill-dot" aria-hidden="true" />
            <span>{wsStatus === 'live' ? 'Live' : wsStatus}</span>
          </span>
        </div>
        <div className="ky-guest-header-actions">
          {!callSnap && (
            <>
              <button
                type="button"
                className="ky-header-call-btn"
                onClick={() => void handleJoinCall(false)}
                disabled={joiningCall}
                aria-label="Join audio call"
              >
                <Phone size={15} aria-hidden="true" />
                <span>Join Audio</span>
              </button>
              <button
                type="button"
                className="ky-header-call-btn is-primary"
                onClick={() => void handleJoinCall(true)}
                disabled={joiningCall}
                aria-label="Join video call"
              >
                <Video size={15} aria-hidden="true" />
                <span>Join Video</span>
              </button>
            </>
          )}
          <button
            ref={chatToggleBtnRef}
            type="button"
            className={`ky-header-call-btn ${chatOpen ? 'is-active' : ''}`}
            onClick={() => setChatOpen((v) => !v)}
            title="Toggle meeting chat"
            aria-label="Toggle meeting chat"
            aria-pressed={chatOpen}
          >
            <MessageSquare size={15} aria-hidden="true" />
            <span>Chat</span>
            {!chatOpen && unreadChat > 0 && (
              <span className="chat-unread-pill" aria-label={`${unreadChat} unread`}>
                {unreadChat}
              </span>
            )}
          </button>
        </div>
      </header>

      {callError && (
        <div className="dr-alert dr-alert-error" role="alert" style={{ margin: '10px 16px 0' }}>
          <span>{callError}</span>
          <button
            type="button"
            className="chat-icon-btn"
            aria-label="Dismiss error"
            onClick={() => setCallError('')}
          >
            <X size={14} />
          </button>
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
              <h2>You&apos;re in the meeting</h2>
              <p>Join with audio or video whenever you&apos;re ready, or chat with participants in the side panel.</p>
              <div className="ky-guest-ready-actions">
                <button
                  type="button"
                  className="ky-header-call-btn"
                  onClick={() => void handleJoinCall(false)}
                  disabled={joiningCall}
                >
                  <Phone size={16} aria-hidden="true" />
                  <span>Join Audio</span>
                </button>
                <button
                  type="button"
                  className="ky-header-call-btn is-primary"
                  onClick={() => void handleJoinCall(true)}
                  disabled={joiningCall}
                >
                  <Video size={16} aria-hidden="true" />
                  <span>Join Video</span>
                </button>
              </div>
              <small style={{ color: 'var(--ink)' }}>Camera and mic stay off until you join.</small>
            </div>
          )}
        </main>

        {chatOpen && (
          <aside className="ky-guest-chat" aria-label="Meeting chat">
            <div className="ky-guest-chat-head">
              <span>Meeting Chat</span>
              <button
                type="button"
                className="chat-icon-btn"
                onClick={() => {
                  setChatOpen(false);
                  chatToggleBtnRef.current?.focus();
                }}
                aria-label="Close meeting chat"
              >
                <X size={15} />
              </button>
            </div>
            {chatError && (
              <div className="dr-alert dr-alert-error" role="alert" style={{ margin: '8px 10px 0', padding: '0.45rem 0.6rem', fontSize: '0.78rem' }}>
                <span>{chatError}</span>
              </div>
            )}
            <div className="ky-guest-chat-list chat-scroll">
              {messages.length === 0 ? (
                <div className="ky-guest-chat-empty">No messages yet. Say hello!</div>
              ) : (
                messages.map((m) => (
                  <div key={m.id} className="ky-guest-msg">
                    <div className="ky-guest-msg-head">
                      <span className="ky-guest-msg-sender">{m.sender_name || 'Participant'}</span>
                      <time className="ky-guest-msg-time">{formatTime(m.created_at)}</time>
                    </div>
                    <div className="ky-guest-msg-body">
                      {m.deleted_at ? (
                        <em style={{ color: 'var(--ink)' }}>This message was deleted</em>
                      ) : (
                        <>
                          {m.body}
                          {m.edited_at ? (
                            <span style={{ color: 'var(--ink)', fontSize: '0.72rem', marginLeft: '0.35rem' }}>(edited)</span>
                          ) : null}
                        </>
                      )}
                    </div>
                  </div>
                ))
              )}
              <div ref={msgEndRef} />
            </div>
            <form onSubmit={handleSendMessage} className="ky-guest-chat-form">
              <input
                type="text"
                aria-label="Message meeting"
                placeholder="Message meeting…"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                maxLength={4000}
              />
              <button type="submit" disabled={!draft.trim() || sendingMsg} aria-label="Send message">
                <Send size={15} aria-hidden="true" />
              </button>
            </form>
          </aside>
        )}
      </div>
    </div>
  );
};
