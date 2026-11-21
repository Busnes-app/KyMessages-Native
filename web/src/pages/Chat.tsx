import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  ChevronDown,
  Copy,
  Hash,
  Lock,
  Menu,
  MessageSquarePlus,
  PanelRightClose,
  PanelRightOpen,
  Phone,
  PhoneOff,
  Search,
  Send,
  Video,
  X,
} from 'lucide-react';
import '../styles/chat.css';
import type { SessionUser } from '../dto';
import {
  ChatSocket,
  createChannel,
  createInstantMeeting,
  createRoomGuestLink,
  decideRoomLobby,
  deleteMessage,
  editMessage,
  fetchBootstrap,
  fetchDirectoryUsers,
  fetchMessages,
  fetchRoomDetail,
  fetchRoomLobby,
  fetchRooms,
  joinRoomCall,
  leaveRoomCall,
  markRoomRead,
  newIdempotencyKey,
  openDirectMessage,
  sendMessage,
  setReaction,
} from '../chat/client';
import {
  applyReactionDelta,
  formatDayDivider,
  isGroupedWithPrevious,
  mergeMessageBatch,
  sameCalendarDay,
  upsertMessage,
} from '../chat/state';
import type {
  CallState,
  ChatCurrentUser,
  ChatDirectoryUser,
  ChatMessage,
  ChatRoomDetail,
  ChatRoomSummary,
  LobbyGuest,
  WsServerEvent,
  WsStatus,
} from '../chat/types';
import { ChatSidebar } from '../components/chat/ChatSidebar';
import { MessageRow } from '../components/chat/MessageRow';
import { RoomDetailsDrawer } from '../components/chat/RoomDetailsDrawer';
import { CreateChannelModal, SearchModal, StartDMModal } from '../components/chat/ChatModals';
import { CallStage } from '../components/chat/CallStage';
import { HybridCallController, type HybridCallSnapshot } from '../rtc/hybridCall';

interface ChatProps {
  appName?: string;
  user?: SessionUser | null;
  onOpenSettings?: () => void;
  onLogout?: () => void;
  onAuthRevoked?: () => void;
}

type ActiveModal = 'none' | 'new-channel' | 'new-dm' | 'search';

interface RoomMessageBucket {
  messages: ChatMessage[];
  hasMore: boolean;
  loaded: boolean;
}

export const Chat: React.FC<ChatProps> = ({
  appName,
  user,
  onOpenSettings,
  onLogout,
  onAuthRevoked,
}) => {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [bannerError, setBannerError] = useState('');
  const [currentUser, setCurrentUser] = useState<ChatCurrentUser | null>(null);
  const [tenantName, setTenantName] = useState('KyMessages');
  const [rooms, setRooms] = useState<ChatRoomSummary[]>([]);
  const [directory, setDirectory] = useState<ChatDirectoryUser[]>([]);
  const [activeRoomId, setActiveRoomId] = useState<string | null>(null);
  const [buckets, setBuckets] = useState<Record<string, RoomMessageBucket>>({});
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');
  const [draft, setDraft] = useState('');
  const [replyTo, setReplyTo] = useState<ChatMessage | null>(null);
  const [modal, setModal] = useState<ActiveModal>('none');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [roomDetail, setRoomDetail] = useState<ChatRoomDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [mobileRailOpen, setMobileRailOpen] = useState(false);
  const [showJumpLatest, setShowJumpLatest] = useState(false);
  const [creatingGeneral, setCreatingGeneral] = useState(false);
  // Map of roomId -> Map<userId, expiryTimestampMs>
  const [typingByRoom, setTypingByRoom] = useState<Record<string, Record<string, number>>>({});
  // Phase 3: hybrid calls, SFU availability, waiting room lobby, guest invite banner
  const [activeCalls, setActiveCalls] = useState<Record<string, CallState>>({});
  const [sfuAvailable, setSfuAvailable] = useState(false);
  const [lobbyByRoom, setLobbyByRoom] = useState<Record<string, LobbyGuest[]>>({});
  const [callSnap, setCallSnap] = useState<HybridCallSnapshot | null>(null);
  const [joiningCall, setJoiningCall] = useState(false);
  const [guestLinkBanner, setGuestLinkBanner] = useState<{ roomId: string; url: string; copied: boolean } | null>(null);

  const socketRef = useRef<ChatSocket | null>(null);
  const callCtrlRef = useRef<HybridCallController | null>(null);
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const composerRef = useRef<HTMLTextAreaElement | null>(null);
  const nearBottomRef = useRef(true);
  const activeRoomIdRef = useRef<string | null>(null);
  const currentUserRef = useRef<ChatCurrentUser | null>(null);
  const bucketsRef = useRef<Record<string, RoomMessageBucket>>({});
  const drawerOpenRef = useRef(false);

  activeRoomIdRef.current = activeRoomId;
  currentUserRef.current = currentUser;
  bucketsRef.current = buckets;
  drawerOpenRef.current = drawerOpen;

  const activeRoom = useMemo(
    () => rooms.find((r) => r.id === activeRoomId) ?? null,
    [rooms, activeRoomId],
  );

  const activeBucket = activeRoomId ? buckets[activeRoomId] : undefined;
  const activeMessages = activeBucket?.messages ?? [];

  const directoryById = useMemo(
    () => new Map(directory.map((u) => [u.id, u])),
    [directory],
  );

  const scrollToBottom = useCallback(() => {
    const el = timelineRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    nearBottomRef.current = true;
    setShowJumpLatest(false);
  }, []);

  const syncReadCursor = useCallback(async (roomId: string, seq: number) => {
    if (seq <= 0) return;
    try {
      const updated = await markRoomRead(roomId, seq);
      setRooms((prev) =>
        prev.map((r) =>
          r.id === roomId
            ? {
                ...r,
                last_read_seq: Math.max(r.last_read_seq, updated),
                unread_count: Math.max(0, r.last_seq - Math.max(r.last_read_seq, updated)),
              }
            : r,
        ),
      );
    } catch {
      // Non-fatal; will catch up on next interaction.
    }
  }, []);

  const refreshRoomsList = useCallback(async () => {
    try {
      const next = await fetchRooms();
      setRooms(next);
    } catch {
      // Keep current list on transient failure.
    }
  }, []);

  const refreshRoomDetail = useCallback(async (roomId: string) => {
    setLoadingDetail(true);
    try {
      const detail = await fetchRoomDetail(roomId);
      if (activeRoomIdRef.current === roomId) {
        setRoomDetail(detail);
      }
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not load room details');
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  const loadRoomHistory = useCallback(
    async (roomId: string) => {
      setLoadingMessages(true);
      setBannerError('');
      try {
        const page = await fetchMessages(roomId, { limit: 50 });
        setBuckets((prev) => ({
          ...prev,
          [roomId]: {
            messages: mergeMessageBatch(prev[roomId]?.messages ?? [], page.messages),
            hasMore: page.has_more,
            loaded: true,
          },
        }));
        const latestSeq = page.messages.length > 0 ? page.messages[page.messages.length - 1].seq : 0;
        if (latestSeq > 0) {
          void syncReadCursor(roomId, latestSeq);
        }
        requestAnimationFrame(scrollToBottom);
      } catch (e) {
        setBannerError(e instanceof Error ? e.message : 'Could not load messages');
      } finally {
        setLoadingMessages(false);
      }
    },
    [scrollToBottom, syncReadCursor],
  );

  const catchUpRoom = useCallback(async (roomId: string) => {
    const bucket = bucketsRef.current[roomId];
    const maxSeq = (bucket?.messages ?? []).reduce((acc, m) => (m.delivery.kind === 'synced' && m.seq > acc ? m.seq : acc), 0);
    try {
      const page =
        maxSeq > 0
          ? await fetchMessages(roomId, { after: maxSeq, limit: 100 })
          : await fetchMessages(roomId, { limit: 50 });
      if (page.messages.length === 0) return;
      setBuckets((prev) => ({
        ...prev,
        [roomId]: {
          messages: mergeMessageBatch(prev[roomId]?.messages ?? [], page.messages),
          hasMore: prev[roomId]?.hasMore ?? page.has_more,
          loaded: true,
        },
      }));
      if (activeRoomIdRef.current === roomId && nearBottomRef.current) {
        const latest = page.messages[page.messages.length - 1].seq;
        void syncReadCursor(roomId, latest);
        requestAnimationFrame(scrollToBottom);
      }
    } catch {
      // Transient catch-up failure; next event or room switch will retry.
    }
  }, [scrollToBottom, syncReadCursor]);

  const handleWsEvent = useCallback(
    (event: WsServerEvent) => {
      switch (event.kind) {
        case 'hello':
        case 'pong':
          return;
        case 'auth.revoked':
          setBannerError('Your session has been revoked. Please sign in again.');
          onAuthRevoked?.();
          return;
        case 'message.new': {
          if (event.refetch || !event.message) {
            if (bucketsRef.current[event.roomId]?.loaded) {
              void catchUpRoom(event.roomId);
            } else {
              void refreshRoomsList();
            }
            return;
          }
          const incoming = event.message;
          setBuckets((prev) => {
            const current = prev[event.roomId];
            if (!current?.loaded && activeRoomIdRef.current !== event.roomId) {
              return prev;
            }
            return {
              ...prev,
              [event.roomId]: {
                messages: upsertMessage(current?.messages ?? [], incoming),
                hasMore: current?.hasMore ?? false,
                loaded: true,
              },
            };
          });
          // Clear typing state for sender immediately on message receipt.
          setTypingByRoom((prev) => {
            const roomTyping = prev[event.roomId];
            if (!roomTyping || !(incoming.sender_id in roomTyping)) return prev;
            const copy = { ...roomTyping };
            delete copy[incoming.sender_id];
            return { ...prev, [event.roomId]: copy };
          });

          const isViewing = activeRoomIdRef.current === event.roomId;
          const isSelf = incoming.sender_id === currentUserRef.current?.id;
          setRooms((prev) =>
            prev.map((r) => {
              if (r.id !== event.roomId) return r;
              const nextLastSeq = Math.max(r.last_seq, incoming.seq);
              const nextReadSeq = isViewing || isSelf ? Math.max(r.last_read_seq, incoming.seq) : r.last_read_seq;
              return {
                ...r,
                last_seq: nextLastSeq,
                last_read_seq: nextReadSeq,
                unread_count: Math.max(0, nextLastSeq - nextReadSeq),
              };
            }),
          );
          if (isViewing && !isSelf) {
            void syncReadCursor(event.roomId, incoming.seq);
          }
          if (isViewing && nearBottomRef.current) {
            requestAnimationFrame(scrollToBottom);
          } else if (isViewing && !isSelf) {
            setShowJumpLatest(true);
          }
          return;
        }
        case 'message.edit': {
          if (event.refetch || !event.message) {
            void catchUpRoom(event.roomId);
            return;
          }
          const edited = event.message;
          setBuckets((prev) => {
            const current = prev[event.roomId];
            if (!current) return prev;
            return {
              ...prev,
              [event.roomId]: {
                ...current,
                messages: upsertMessage(current.messages, edited),
              },
            };
          });
          return;
        }
        case 'message.delete': {
          setBuckets((prev) => {
            const current = prev[event.roomId];
            if (!current) return prev;
            return {
              ...prev,
              [event.roomId]: {
                ...current,
                messages: current.messages.map((m) =>
                  m.id === event.messageId ? { ...m, body: '', deleted_at: event.deletedAt } : m,
                ),
              },
            };
          });
          return;
        }
        case 'reaction.set': {
          setBuckets((prev) => {
            const current = prev[event.roomId];
            if (!current) return prev;
            return {
              ...prev,
              [event.roomId]: {
                ...current,
                messages: applyReactionDelta(
                  current.messages,
                  event.messageId,
                  event.userId,
                  event.emoji,
                  event.added,
                ),
              },
            };
          });
          return;
        }
        case 'room.member': {
          const selfId = currentUserRef.current?.id;
          if (event.userId === selfId) {
            if (event.action === 'removed') {
              setRooms((prev) => prev.filter((r) => r.id !== event.roomId));
              if (activeRoomIdRef.current === event.roomId) {
                setActiveRoomId(null);
                setDrawerOpen(false);
              }
            } else {
              void refreshRoomsList();
            }
          } else if (drawerOpenRef.current && activeRoomIdRef.current === event.roomId) {
            void refreshRoomDetail(event.roomId);
          }
          return;
        }
        case 'room.updated': {
          if (!event.room) {
            void refreshRoomsList();
            return;
          }
          const updated = event.room;
          setRooms((prev) =>
            prev.map((r) => (r.id === updated.id ? { ...r, name: updated.name, topic: updated.topic } : r)),
          );
          if (drawerOpenRef.current && activeRoomIdRef.current === updated.id) {
            setRoomDetail((prev) => (prev ? { ...prev, room: updated } : prev));
          }
          return;
        }
        case 'room.closed': {
          setRooms((prev) =>
            prev.map((r) => (r.id === event.roomId ? { ...r, closed_at: r.closed_at ?? Date.now() } : r)),
          );
          return;
        }
        case 'typing': {
          if (event.userId === currentUserRef.current?.id) return;
          setTypingByRoom((prev) => {
            const current = { ...(prev[event.roomId] ?? {}) };
            if (event.active) {
              current[event.userId] = Date.now() + 4500;
            } else {
              delete current[event.userId];
            }
            return { ...prev, [event.roomId]: current };
          });
          return;
        }
        case 'read.sync': {
          setRooms((prev) =>
            prev.map((r) =>
              r.id === event.roomId
                ? {
                    ...r,
                    last_read_seq: Math.max(r.last_read_seq, event.lastReadSeq),
                    unread_count: Math.max(0, r.last_seq - Math.max(r.last_read_seq, event.lastReadSeq)),
                  }
                : r,
            ),
          );
          return;
        }
        case 'call.state': {
          const st = event.state;
          setActiveCalls((prev) => {
            if (st.ended || st.peers.length === 0) {
              if (!(st.room_id in prev)) return prev;
              const next = { ...prev };
              delete next[st.room_id];
              return next;
            }
            return { ...prev, [st.room_id]: st };
          });
          callCtrlRef.current?.handleCallState(st);
          if (st.ended) {
            setCallSnap((cur) => (cur && cur.roomId === st.room_id ? null : cur));
          }
          return;
        }
        case 'call.signal': {
          void callCtrlRef.current?.handleSignal(event.signal);
          return;
        }
        case 'call.migrate': {
          void callCtrlRef.current?.handleMigrate(event.migrate);
          return;
        }
        case 'lobby.knock': {
          const g = event.guest;
          setLobbyByRoom((prev) => {
            const list = prev[event.roomId] ?? [];
            const filtered = list.filter((x) => x.guest_id !== g.guest_id);
            return { ...prev, [event.roomId]: [...filtered, g] };
          });
          return;
        }
        case 'lobby.decision': {
          if (event.roomId && event.guestId) {
            setLobbyByRoom((prev) => {
              const list = prev[event.roomId!];
              if (!list) return prev;
              return { ...prev, [event.roomId!]: list.filter((x) => x.guest_id !== event.guestId) };
            });
          }
          return;
        }
        default: {
          const _exhaustive: never = event;
          void _exhaustive;
        }
      }
    },
    [catchUpRoom, onAuthRevoked, refreshRoomDetail, refreshRoomsList, scrollToBottom, syncReadCursor],
  );

  // Initial bootstrap + WebSocket connection.
  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      try {
        const [boot, users] = await Promise.all([
          fetchBootstrap(),
          fetchDirectoryUsers().catch(() => [] as ChatDirectoryUser[]),
        ]);
        if (cancelled) return;
        setCurrentUser(boot.user);
        setTenantName(boot.tenant.display_name || 'KyMessages');
        setRooms(boot.rooms);
        setDirectory(users);
        setSfuAvailable(boot.rtc.sfu_available);
        const callMap: Record<string, CallState> = {};
        for (const [rid, c] of Object.entries(boot.active_calls)) {
          if (!c.ended && c.peers.length > 0) callMap[rid] = c;
        }
        setActiveCalls(callMap);
        if (boot.rooms.length > 0) {
          const requestedRoom = new URLSearchParams(window.location.search).get('room');
          const matched = requestedRoom ? boot.rooms.find((r) => r.id === requestedRoom) : undefined;
          setActiveRoomId(matched ? matched.id : boot.rooms[0].id);
        }
      } catch (e) {
        if (!cancelled) {
          setLoadError(e instanceof Error ? e.message : 'Could not connect to chat');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void init();

    const sock = new ChatSocket({
      onStatus: (status) => {
        if (!cancelled) setWsStatus(status);
      },
      onEvent: (ev) => {
        if (!cancelled) handleWsEvent(ev);
      },
      onReconnect: () => {
        if (cancelled) return;
        void refreshRoomsList();
        const active = activeRoomIdRef.current;
        if (active) {
          void catchUpRoom(active);
        }
      },
    });
    socketRef.current = sock;
    sock.connect();

    return () => {
      cancelled = true;
      callCtrlRef.current?.dispose();
      callCtrlRef.current = null;
      sock.close();
      socketRef.current = null;
    };
  }, [catchUpRoom, handleWsEvent, refreshRoomsList]);

  // Periodically expire stale typing indicators.
  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      setTypingByRoom((prev) => {
        let changed = false;
        const next: Record<string, Record<string, number>> = {};
        for (const [roomId, entries] of Object.entries(prev)) {
          const active: Record<string, number> = {};
          for (const [uid, exp] of Object.entries(entries)) {
            if (exp > now) active[uid] = exp;
            else changed = true;
          }
          if (Object.keys(active).length > 0) next[roomId] = active;
        }
        return changed ? next : prev;
      });
    }, 1500);
    return () => clearInterval(timer);
  }, []);

  // Global keyboard shortcuts (Cmd/Ctrl+K for Search, Esc to dismiss).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setModal((m) => (m === 'search' ? 'none' : 'search'));
      } else if (e.key === 'Escape') {
        if (modal !== 'none') setModal('none');
        else if (replyTo) setReplyTo(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [modal, replyTo]);

  // Load room history when switching active room.
  useEffect(() => {
    if (!activeRoomId) return;
    setReplyTo(null);
    setShowJumpLatest(false);
    const existing = bucketsRef.current[activeRoomId];
    if (!existing?.loaded) {
      void loadRoomHistory(activeRoomId);
    } else {
      const latest = existing.messages[existing.messages.length - 1]?.seq ?? 0;
      if (latest > 0) void syncReadCursor(activeRoomId, latest);
      requestAnimationFrame(scrollToBottom);
    }
    if (drawerOpenRef.current) {
      void refreshRoomDetail(activeRoomId);
    }
    void fetchRoomLobby(activeRoomId)
      .then((guests) => {
        setLobbyByRoom((prev) => ({ ...prev, [activeRoomId]: guests }));
      })
      .catch(() => {
        // Non-meeting rooms or transient failures simply show empty lobby.
      });
  }, [activeRoomId, loadRoomHistory, refreshRoomDetail, scrollToBottom, syncReadCursor]);

  const handleLoadOlder = async () => {
    if (!activeRoomId || loadingOlder || !activeBucket?.hasMore) return;
    const oldest = activeBucket.messages.find((m) => m.delivery.kind === 'synced');
    if (!oldest) return;
    const timeline = timelineRef.current;
    const prevScrollHeight = timeline?.scrollHeight ?? 0;
    setLoadingOlder(true);
    try {
      const page = await fetchMessages(activeRoomId, { before: oldest.seq, limit: 50 });
      setBuckets((prev) => ({
        ...prev,
        [activeRoomId]: {
          messages: mergeMessageBatch(prev[activeRoomId]?.messages ?? [], page.messages),
          hasMore: page.has_more,
          loaded: true,
        },
      }));
      requestAnimationFrame(() => {
        if (timeline) {
          timeline.scrollTop = timeline.scrollHeight - prevScrollHeight;
        }
      });
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not load older messages');
    } finally {
      setLoadingOlder(false);
    }
  };

  const dispatchSend = async (roomId: string, body: string, replyToId: string | undefined, clientKey: string) => {
    const me = currentUserRef.current;
    if (!me) return;

    const optimistic: ChatMessage = {
      id: `pending_${clientKey}`,
      tenant_id: 'default',
      room_id: roomId,
      seq: Number.MAX_SAFE_INTEGER,
      sender_id: me.id,
      sender_name: me.display_name || me.username,
      reply_to_id: replyToId,
      encoding: 'plain_v1',
      body,
      created_at: Date.now(),
      reactions: [],
      delivery: { kind: 'sending', idempotencyKey: clientKey },
    };

    setBuckets((prev) => {
      const current = prev[roomId] ?? { messages: [], hasMore: false, loaded: true };
      const cleaned = current.messages.filter(
        (m) => !(m.delivery.kind !== 'synced' && m.delivery.idempotencyKey === clientKey),
      );
      return {
        ...prev,
        [roomId]: {
          ...current,
          messages: [...cleaned, optimistic],
          loaded: true,
        },
      };
    });
    requestAnimationFrame(scrollToBottom);

    try {
      const confirmed = await sendMessage({ roomId, body, replyToId, idempotencyKey: clientKey });
      setBuckets((prev) => {
        const current = prev[roomId] ?? { messages: [], hasMore: false, loaded: true };
        return {
          ...prev,
          [roomId]: {
            ...current,
            messages: upsertMessage(current.messages, confirmed, clientKey),
            loaded: true,
          },
        };
      });
      setRooms((prev) =>
        prev.map((r) =>
          r.id === roomId
            ? {
                ...r,
                last_seq: Math.max(r.last_seq, confirmed.seq),
                last_read_seq: Math.max(r.last_read_seq, confirmed.seq),
                unread_count: 0,
              }
            : r,
        ),
      );
      void syncReadCursor(roomId, confirmed.seq);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Send failed';
      setBuckets((prev) => {
        const current = prev[roomId];
        if (!current) return prev;
        return {
          ...prev,
          [roomId]: {
            ...current,
            messages: current.messages.map((m) =>
              m.delivery.kind !== 'synced' && m.delivery.idempotencyKey === clientKey
                ? { ...m, delivery: { kind: 'failed', idempotencyKey: clientKey, error: msg } }
                : m,
            ),
          },
        };
      });
    }
  };

  const handleComposerSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeRoomId || activeRoom?.closed_at) return;
    const trimmed = draft.trim();
    if (!trimmed) return;
    const clientKey = newIdempotencyKey();
    const targetReply = replyTo?.id;
    setDraft('');
    setReplyTo(null);
    socketRef.current?.sendTyping(activeRoomId, false);
    if (composerRef.current) {
      composerRef.current.style.height = 'auto';
    }
    void dispatchSend(activeRoomId, trimmed, targetReply, clientKey);
  };

  const handleToggleReaction = (messageId: string, emoji: string, currentlyReacted: boolean) => {
    if (!activeRoomId || !currentUser) return;
    const add = !currentlyReacted;
    // Optimistically toggle reaction pill.
    setBuckets((prev) => {
      const current = prev[activeRoomId];
      if (!current) return prev;
      return {
        ...prev,
        [activeRoomId]: {
          ...current,
          messages: applyReactionDelta(current.messages, messageId, currentUser.id, emoji, add),
        },
      };
    });
    void setReaction(activeRoomId, messageId, emoji, add).catch((e) => {
      // Roll back on error.
      setBuckets((prev) => {
        const current = prev[activeRoomId];
        if (!current) return prev;
        return {
          ...prev,
          [activeRoomId]: {
            ...current,
            messages: applyReactionDelta(current.messages, messageId, currentUser.id, emoji, !add),
          },
        };
      });
      setBannerError(e instanceof Error ? e.message : 'Could not update reaction');
    });
  };

  const handleEditMessage = async (messageId: string, newBody: string) => {
    if (!activeRoomId) return;
    const updated = await editMessage(activeRoomId, messageId, newBody);
    setBuckets((prev) => {
      const current = prev[activeRoomId];
      if (!current) return prev;
      return {
        ...prev,
        [activeRoomId]: {
          ...current,
          messages: upsertMessage(current.messages, updated),
        },
      };
    });
  };

  const handleDeleteMessage = async (messageId: string) => {
    if (!activeRoomId) return;
    const deleted = await deleteMessage(activeRoomId, messageId);
    setBuckets((prev) => {
      const current = prev[activeRoomId];
      if (!current) return prev;
      return {
        ...prev,
        [activeRoomId]: {
          ...current,
          messages: current.messages.map((m) =>
            m.id === messageId ? { ...m, body: '', deleted_at: deleted.deleted_at ?? Date.now() } : m,
          ),
        },
      };
    });
  };

  const handleCreateChannel = async (params: {
    name: string;
    topic: string;
    isPrivate: boolean;
    memberIds: string[];
  }) => {
    const room = await createChannel(params);
    await refreshRoomsList();
    setActiveRoomId(room.id);
  };

  const handleQuickGeneral = async () => {
    setCreatingGeneral(true);
    setBannerError('');
    try {
      const room = await createChannel({
        name: 'general',
        topic: 'Team-wide announcements and everyday conversation',
        isPrivate: false,
        memberIds: directory.filter((u) => u.id !== currentUser?.id).map((u) => u.id),
      });
      await refreshRoomsList();
      setActiveRoomId(room.id);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not create #general');
    } finally {
      setCreatingGeneral(false);
    }
  };

  const handleStartDM = async (userId: string) => {
    const { room } = await openDirectMessage(userId);
    await refreshRoomsList();
    setActiveRoomId(room.id);
  };

  const handleLeaveCall = useCallback(async () => {
    const leavingRoomId = callSnap?.roomId;
    callCtrlRef.current?.dispose();
    callCtrlRef.current = null;
    setCallSnap(null);
    if (leavingRoomId) {
      await leaveRoomCall(leavingRoomId).catch(() => undefined);
    }
  }, [callSnap?.roomId]);

  const handleJoinCall = async (roomId: string, withVideo: boolean) => {
    const me = currentUserRef.current;
    if (!me || joiningCall) return;
    setJoiningCall(true);
    setBannerError('');
    try {
      // Leave any existing call in another room first.
      if (callSnap && callSnap.roomId !== roomId) {
        await handleLeaveCall();
      }
      const joinResp = await joinRoomCall(roomId, { audio: true, video: withVideo });
      callCtrlRef.current?.dispose();
      const ctrl = new HybridCallController({
        localUserId: me.id,
        localDisplayName: me.display_name || me.username,
        isGuest: false,
        socket: () => socketRef.current,
        onChange: setCallSnap,
      });
      callCtrlRef.current = ctrl;
      await ctrl.start(joinResp, { audio: true, video: withVideo, protectIp: false });
      setActiveCalls((prev) => ({
        ...prev,
        [roomId]: {
          call_id: joinResp.call_id,
          room_id: roomId,
          mode: joinResp.mode,
          sfu_sticky: joinResp.sfu_sticky,
          peers: joinResp.peers,
          ended: false,
        },
      }));
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not join call');
    } finally {
      setJoiningCall(false);
    }
  };

  const handleDecideLobby = async (roomId: string, guestId: string, admit: boolean) => {
    try {
      await decideRoomLobby(roomId, guestId, admit);
      setLobbyByRoom((prev) => ({
        ...prev,
        [roomId]: (prev[roomId] ?? []).filter((g) => g.guest_id !== guestId),
      }));
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not update waiting room');
    }
  };

  const handleStartInstantMeeting = async () => {
    setBannerError('');
    try {
      const stamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const created = await createInstantMeeting({ title: `Quick Meeting (${stamp})` });
      await refreshRoomsList();
      setActiveRoomId(created.room.id);
      const fullUrl = created.guestUrl || `${window.location.origin}${created.guestPath}`;
      setGuestLinkBanner({ roomId: created.room.id, url: fullUrl, copied: false });
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not create meeting');
    }
  };

  const handleCreateGuestLink = async (roomId: string): Promise<string> => {
    const res = await createRoomGuestLink(roomId);
    const fullUrl = res.guestUrl || `${window.location.origin}${res.guestPath}`;
    setGuestLinkBanner({ roomId, url: fullUrl, copied: false });
    return fullUrl;
  };

  const handleTimelineScroll = () => {
    const el = timelineRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    const near = distanceFromBottom < 80;
    nearBottomRef.current = near;
    if (near) {
      setShowJumpLatest(false);
    }
  };

  const activeTypers = useMemo(() => {
    if (!activeRoomId) return [];
    const entries = typingByRoom[activeRoomId];
    if (!entries) return [];
    const now = Date.now();
    return Object.entries(entries)
      .filter(([, exp]) => exp > now)
      .map(([uid]) => directoryById.get(uid)?.display_name || 'Someone');
  }, [activeRoomId, typingByRoom, directoryById]);

  const messageById = useMemo(
    () => new Map(activeMessages.map((m) => [m.id, m])),
    [activeMessages],
  );

  const canModerateActiveRoom =
    currentUser?.role === 'admin' || activeRoom?.role === 'owner' || activeRoom?.role === 'admin';
  const activeRoomCall = activeRoomId ? activeCalls[activeRoomId] : undefined;
  const inActiveRoomCall = Boolean(callSnap && activeRoomId && callSnap.roomId === activeRoomId);
  const inOtherRoomCall = Boolean(callSnap && activeRoomId && callSnap.roomId !== activeRoomId);
  const otherCallRoomName = callSnap
    ? rooms.find((r) => r.id === callSnap.roomId)?.name || 'call'
    : '';
  const activeRoomLobby = activeRoomId ? lobbyByRoom[activeRoomId] ?? [] : [];

  if (loading) {
    return (
      <div className="chat-empty-stage" style={{ height: '100vh' }}>
        <p>Connecting to {tenantName}…</p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="chat-empty-stage" style={{ height: '100vh' }}>
        <h2>Could not load chat</h2>
        <p role="alert">{loadError}</p>
        <button type="button" onClick={() => window.location.reload()}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className={drawerOpen && activeRoom ? 'chat-workspace has-drawer' : 'chat-workspace'}>
      <ChatSidebar
        appName={appName}
        tenantName={tenantName}
        rooms={rooms}
        activeRoomId={activeRoomId}
        activeCalls={activeCalls}
        wsStatus={wsStatus}
        mobileOpen={mobileRailOpen}
        user={user}
        onCloseMobile={() => setMobileRailOpen(false)}
        onSelectRoom={(id) => setActiveRoomId(id)}
        onOpenNewChannel={() => setModal('new-channel')}
        onOpenNewDM={() => setModal('new-dm')}
        onOpenSearch={() => setModal('search')}
        onStartInstantMeeting={() => void handleStartInstantMeeting()}
        onOpenSettings={onOpenSettings}
        onLogout={onLogout}
      />

      <section className="chat-stage" aria-label="Conversation">
        {activeRoom ? (
          <>
            <header className="chat-header">
              <div className="chat-header-main">
                <button
                  type="button"
                  className="chat-icon-btn chat-mobile-menu"
                  onClick={() => setMobileRailOpen(true)}
                  aria-label="Open room list"
                >
                  <Menu size={18} />
                </button>
                <div className="chat-header-title-wrap">
                  <h1 className="chat-header-title">
                    {activeRoom.kind === 'dm' ? null : activeRoom.kind === 'meeting' ? (
                      <Video size={16} aria-hidden="true" />
                    ) : activeRoom.is_private ? (
                      <Lock size={16} aria-hidden="true" />
                    ) : (
                      <Hash size={16} aria-hidden="true" />
                    )}
                    <span>{activeRoom.name || 'Direct message'}</span>
                  </h1>
                  {activeRoom.topic && <p className="chat-header-topic">{activeRoom.topic}</p>}
                </div>
              </div>

              <div className="chat-header-actions">
                {!activeRoom.closed_at && !inActiveRoomCall && (
                  <>
                    <button
                      type="button"
                      className="ky-header-call-btn"
                      title="Start or join audio call (P2P-first)"
                      aria-label="Audio call"
                      disabled={joiningCall}
                      onClick={() => void handleJoinCall(activeRoom.id, false)}
                    >
                      <Phone size={15} />
                      <span>Call</span>
                    </button>
                    <button
                      type="button"
                      className="ky-header-call-btn is-primary"
                      title="Start or join video call (P2P-first)"
                      aria-label="Video call"
                      disabled={joiningCall}
                      onClick={() => void handleJoinCall(activeRoom.id, true)}
                    >
                      <Video size={15} />
                      <span>Video</span>
                    </button>
                  </>
                )}
                {inActiveRoomCall && (
                  <button
                    type="button"
                    className="ky-header-call-btn is-danger"
                    title="Leave active call"
                    onClick={() => void handleLeaveCall()}
                  >
                    <PhoneOff size={15} />
                    <span>Leave</span>
                  </button>
                )}
                <button
                  type="button"
                  className="chat-icon-btn"
                  title="Search messages (Cmd/Ctrl+K)"
                  aria-label="Search messages"
                  onClick={() => setModal('search')}
                >
                  <Search size={17} />
                </button>
                <button
                  type="button"
                  className={drawerOpen ? 'chat-header-panel-btn active' : 'chat-header-panel-btn'}
                  title={drawerOpen ? 'Collapse room panel' : 'Open room panel'}
                  aria-label={drawerOpen ? 'Collapse room panel' : 'Room details'}
                  aria-expanded={drawerOpen}
                  onClick={() => {
                    const next = !drawerOpen;
                    setDrawerOpen(next);
                    if (next) void refreshRoomDetail(activeRoom.id);
                  }}
                >
                  {drawerOpen ? <PanelRightClose size={16} aria-hidden="true" /> : <PanelRightOpen size={16} aria-hidden="true" />}
                  <span>
                    {drawerOpen ? 'Hide' : 'Details'}
                    {activeRoomLobby.length > 0 ? ` (${activeRoomLobby.length})` : ''}
                  </span>
                </button>
              </div>
            </header>

            {bannerError && (
              <div className="chat-banner chat-banner-error" role="alert">
                <span>{bannerError}</span>
                <button
                  type="button"
                  className="chat-icon-btn"
                  onClick={() => setBannerError('')}
                  aria-label="Dismiss error"
                >
                  <X size={14} />
                </button>
              </div>
            )}

            {inOtherRoomCall && callSnap && (
              <div className="ky-call-mini-bar" role="status">
                <span>
                  In {callSnap.mode === 'p2p_mesh' ? 'P2P' : 'SFU'} call in <strong>{otherCallRoomName}</strong> ({callSnap.tiles.length})
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => setActiveRoomId(callSnap.roomId)}
                  >
                    Return to call
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-deny"
                    onClick={() => void handleLeaveCall()}
                  >
                    Leave
                  </button>
                </div>
              </div>
            )}

            {guestLinkBanner && guestLinkBanner.roomId === activeRoom.id && (
              <div className="ky-guest-banner" role="status">
                <span>
                  Guest waiting-room link ready: <code>{guestLinkBanner.url}</code>
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => {
                      void navigator.clipboard.writeText(guestLinkBanner.url).then(() => {
                        setGuestLinkBanner((b) => (b ? { ...b, copied: true } : b));
                      }).catch(() => undefined);
                    }}
                  >
                    {guestLinkBanner.copied ? <Check size={12} /> : <Copy size={12} />}
                    <span>{guestLinkBanner.copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    type="button"
                    className="chat-icon-btn"
                    onClick={() => setGuestLinkBanner(null)}
                    aria-label="Dismiss guest link"
                  >
                    <X size={14} />
                  </button>
                </div>
              </div>
            )}

            {activeRoomLobby.length > 0 && (
              <div className="ky-lobby-banner" role="status">
                <span>
                  <strong>{activeRoomLobby[0].display_name}</strong>
                  {activeRoomLobby.length > 1 ? ` and ${activeRoomLobby.length - 1} other` : ''} waiting to join
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => void handleDecideLobby(activeRoom.id, activeRoomLobby[0].guest_id, true)}
                  >
                    Admit
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-deny"
                    onClick={() => void handleDecideLobby(activeRoom.id, activeRoomLobby[0].guest_id, false)}
                  >
                    Deny
                  </button>
                </div>
              </div>
            )}

            {!inActiveRoomCall && activeRoomCall && !activeRoomCall.ended && activeRoomCall.peers.length > 0 && (
              <div className="ky-active-call-banner" role="status">
                <span>
                  <strong>Call in progress</strong> · {activeRoomCall.peers.length}{' '}
                  {activeRoomCall.peers.length === 1 ? 'person' : 'people'} ·{' '}
                  {activeRoomCall.mode === 'p2p_mesh' ? 'P2P Direct' : 'LiveKit SFU'}
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    disabled={joiningCall}
                    onClick={() => void handleJoinCall(activeRoom.id, false)}
                  >
                    Join Audio
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    disabled={joiningCall}
                    onClick={() => void handleJoinCall(activeRoom.id, true)}
                  >
                    Join Video
                  </button>
                </div>
              </div>
            )}

            {inActiveRoomCall && callSnap && (
              <CallStage
                snapshot={callSnap}
                sfuAvailable={sfuAvailable}
                onToggleAudio={() => void callCtrlRef.current?.toggleAudio()}
                onToggleVideo={() => void callCtrlRef.current?.toggleVideo()}
                onToggleScreenShare={() => void callCtrlRef.current?.toggleScreenShare()}
                onToggleProtectIp={() => callCtrlRef.current?.setProtectIp(!callSnap.protectIp)}
                onLeave={() => void handleLeaveCall()}
              />
            )}

            {activeRoom.closed_at && (
              <div className="chat-banner chat-banner-info" role="status">
                <span>This room is closed. History remains readable, but new messages are disabled.</span>
              </div>
            )}

            <div className="chat-timeline-wrap">
              <div
                ref={timelineRef}
                className="chat-timeline chat-scroll"
                onScroll={handleTimelineScroll}
                role="log"
                aria-live="polite"
                aria-relevant="additions"
              >
                {activeBucket?.hasMore && (
                  <button
                    type="button"
                    className="btn-secondary chat-load-older"
                    disabled={loadingOlder}
                    onClick={() => void handleLoadOlder()}
                  >
                    {loadingOlder ? 'Loading older messages…' : 'Load older messages'}
                  </button>
                )}

                {loadingMessages && activeMessages.length === 0 ? (
                  <div className="chat-empty-stage">
                    <p>Loading messages…</p>
                  </div>
                ) : activeMessages.length === 0 ? (
                  <div className="chat-empty-stage">
                    <h2>
                      {activeRoom.kind === 'dm'
                        ? `Start a conversation with ${activeRoom.name || 'your teammate'}`
                        : `Welcome to #${activeRoom.name}`}
                    </h2>
                    <p>
                      {activeRoom.topic ||
                        'Send the first message below. Everything syncs in real time across your workspace.'}
                    </p>
                  </div>
                ) : (
                  activeMessages.map((msg, idx) => {
                    const prev = idx > 0 ? activeMessages[idx - 1] : undefined;
                    const showDivider = !prev || !sameCalendarDay(prev.created_at, msg.created_at);
                    const grouped = !showDivider && isGroupedWithPrevious(prev, msg);
                    return (
                      <React.Fragment key={msg.id}>
                        {showDivider && (
                          <div className="chat-day-divider">
                            <span>{formatDayDivider(msg.created_at)}</span>
                          </div>
                        )}
                        <MessageRow
                          message={msg}
                          grouped={grouped}
                          currentUserId={currentUser?.id ?? ''}
                          canModerate={Boolean(canModerateActiveRoom)}
                          replyTarget={msg.reply_to_id ? messageById.get(msg.reply_to_id) : undefined}
                          onReply={(target) => {
                            setReplyTo(target);
                            composerRef.current?.focus();
                          }}
                          onToggleReaction={handleToggleReaction}
                          onEdit={handleEditMessage}
                          onDelete={handleDeleteMessage}
                          onRetryFailed={(failed) => {
                            if (failed.delivery.kind === 'failed') {
                              void dispatchSend(
                                failed.room_id,
                                failed.body,
                                failed.reply_to_id,
                                failed.delivery.idempotencyKey,
                              );
                            }
                          }}
                          onDismissFailed={(key) => {
                            setBuckets((prevBuckets) => {
                              const current = prevBuckets[activeRoom.id];
                              if (!current) return prevBuckets;
                              return {
                                ...prevBuckets,
                                [activeRoom.id]: {
                                  ...current,
                                  messages: current.messages.filter(
                                    (m) => !(m.delivery.kind === 'failed' && m.delivery.idempotencyKey === key),
                                  ),
                                },
                              };
                            });
                          }}
                        />
                      </React.Fragment>
                    );
                  })
                )}
              </div>

              {showJumpLatest && (
                <button type="button" className="chat-jump-btn" onClick={scrollToBottom}>
                  <ChevronDown size={14} />
                  Jump to latest
                </button>
              )}
            </div>

            <div className="chat-typing-bar" aria-live="polite">
              {activeTypers.length === 1 && `${activeTypers[0]} is typing…`}
              {activeTypers.length === 2 && `${activeTypers[0]} and ${activeTypers[1]} are typing…`}
              {activeTypers.length > 2 && `${activeTypers.length} people are typing…`}
            </div>

            <div className="chat-composer-wrap">
              {replyTo && (
                <div className="chat-reply-banner">
                  <span className="chat-reply-banner-copy">
                    Replying to <strong>{replyTo.sender_name || 'Member'}</strong>: {replyTo.body}
                  </span>
                  <button
                    type="button"
                    className="chat-icon-btn"
                    onClick={() => setReplyTo(null)}
                    aria-label="Cancel reply"
                  >
                    <X size={14} />
                  </button>
                </div>
              )}

              <form
                className={replyTo ? 'chat-composer has-reply' : 'chat-composer'}
                onSubmit={handleComposerSubmit}
              >
                <textarea
                  ref={composerRef}
                  rows={1}
                  disabled={Boolean(activeRoom.closed_at)}
                  placeholder={
                    activeRoom.closed_at
                      ? 'Room is closed'
                      : activeRoom.kind === 'dm'
                        ? `Message ${activeRoom.name || 'teammate'}`
                        : `Message #${activeRoom.name}`
                  }
                  aria-label="Message input"
                  value={draft}
                  onChange={(e) => {
                    setDraft(e.target.value);
                    e.target.style.height = 'auto';
                    e.target.style.height = `${Math.min(e.target.scrollHeight, 144)}px`;
                    if (activeRoomId && e.target.value.trim()) {
                      socketRef.current?.sendTyping(activeRoomId, true);
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleComposerSubmit(e);
                    }
                  }}
                />
                <button
                  type="submit"
                  className="chat-send-btn"
                  disabled={Boolean(activeRoom.closed_at) || !draft.trim()}
                  aria-label="Send message"
                >
                  <Send size={15} />
                  Send
                </button>
              </form>

              <div className="chat-composer-hint">
                <span>Enter to send · Shift+Enter for new line</span>
                {draft.length > 1000 && <span>{draft.length.toLocaleString()} / 16,384</span>}
              </div>
            </div>
          </>
        ) : (
          <>
            <header className="chat-header">
              <div className="chat-header-main">
                <button
                  type="button"
                  className="chat-icon-btn chat-mobile-menu"
                  onClick={() => setMobileRailOpen(true)}
                  aria-label="Open room list"
                >
                  <Menu size={18} />
                </button>
                <h1 className="chat-header-title">
                  <span>{tenantName}</span>
                </h1>
              </div>
            </header>

            {bannerError && (
              <div className="chat-banner chat-banner-error" role="alert">
                <span>{bannerError}</span>
              </div>
            )}

            <div className="chat-empty-stage">
              <MessageSquarePlus size={36} style={{ color: 'var(--accent)' }} aria-hidden="true" />
              <h2>Start your workspace chat</h2>
              <p>
                Create your first channel or start a direct message. Messages stream live over a single
                WebSocket backed directly by your database.
              </p>
              <div className="chat-empty-actions">
                <button type="button" disabled={creatingGeneral} onClick={() => void handleQuickGeneral()}>
                  <Hash size={15} />
                  {creatingGeneral ? 'Creating #general…' : 'Create #general'}
                </button>
                <button type="button" className="btn-secondary" onClick={() => setModal('new-channel')}>
                  New channel
                </button>
                <button type="button" className="btn-secondary" onClick={() => setModal('new-dm')}>
                  New direct message
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {drawerOpen && activeRoom && (
        <RoomDetailsDrawer
          detail={roomDetail}
          loading={loadingDetail}
          currentUserId={currentUser?.id ?? ''}
          isGlobalAdmin={currentUser?.role === 'admin'}
          directory={directory}
          messages={activeMessages}
          lobbyGuests={activeRoomLobby}
          onClose={() => setDrawerOpen(false)}
          onRefresh={async () => {
            await Promise.all([refreshRoomDetail(activeRoom.id), refreshRoomsList()]);
          }}
          onDecideLobby={(guestId, admit) => handleDecideLobby(activeRoom.id, guestId, admit)}
          onCreateGuestLink={() => handleCreateGuestLink(activeRoom.id)}
          onLeftRoom={(leftId) => {
            setDrawerOpen(false);
            setRoomDetail(null);
            setRooms((prev) => {
              const remaining = prev.filter((r) => r.id !== leftId);
              setActiveRoomId(remaining[0]?.id ?? null);
              return remaining;
            });
          }}
          onOpenSearch={() => setModal('search')}
          onStartDM={handleStartDM}
        />
      )}

      {modal === 'new-channel' && (
        <CreateChannelModal
          directory={directory}
          currentUserId={currentUser?.id ?? ''}
          onClose={() => setModal('none')}
          onCreate={handleCreateChannel}
        />
      )}

      {modal === 'new-dm' && (
        <StartDMModal
          directory={directory}
          currentUserId={currentUser?.id ?? ''}
          onClose={() => setModal('none')}
          onSelectUser={handleStartDM}
        />
      )}

      {modal === 'search' && (
        <SearchModal
          rooms={rooms}
          activeRoomId={activeRoomId}
          onClose={() => setModal('none')}
          onSelectHit={(roomId) => setActiveRoomId(roomId)}
        />
      )}
    </div>
  );
};
