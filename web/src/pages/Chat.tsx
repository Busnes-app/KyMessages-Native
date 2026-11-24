import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  ChevronDown,
  Copy,
  Download,
  FileText,
  Hash,
  Loader2,
  Lock,
  Menu,
  MessageSquarePlus,
  Mic,
  MicOff,
  PanelRightClose,
  PanelRightOpen,
  Paperclip,
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
  deleteAttachment,
  listStagedAttachments,
  openDirectMessage,
  sendMessage,
  setReaction,
  uploadAttachment,
} from '../chat/client';
import {
  applyReactionDelta,
  formatDayDivider,
  isGroupedWithPrevious,
  mergeMessageBatch,
  sameCalendarDay,
  upsertMessage,
} from '../chat/state';
import {
  disableBrowserPush,
  enableBrowserPush,
  syncExistingPushSubscription,
  type PushState,
} from '../chat/push';
import {
  DEFAULT_ATTACHMENT_LIMITS,
  attachmentUrl,
  formatBytes,
  isInlineImageAttachment,
  type CallState,
  type ChatAttachment,
  type ChatAttachmentLimits,
  type ChatCurrentUser,
  type ChatDirectoryUser,
  type ChatMessage,
  type ChatPushConfig,
  type ChatRoomDetail,
  type ChatRoomSummary,
  type LobbyGuest,
  type NotifyMode,
  type WsServerEvent,
  type WsStatus,
} from '../chat/types';
import { ChatSidebar } from '../components/chat/ChatSidebar';
import { MessageRow } from '../components/chat/MessageRow';
import { RoomDetailsDrawer, type DrawerTab } from '../components/chat/RoomDetailsDrawer';
import { CreateChannelModal, SearchModal, StartDMModal } from '../components/chat/ChatModals';
import { searchIndexFor } from '../chat/searchIndex';
import { keyGeneration, onRoomKeys, openMessages, receiveRoomKeys, retryable, roomMemberLeft, startE2EE } from '../chat/e2ee';
import { CallAudioLayer, CallStage } from '../components/chat/CallStage';
import { HybridCallController, type HybridCallSnapshot } from '../rtc/hybridCall';

export interface ActiveCallSummary {
  roomId: string;
  roomName: string;
  participantCount: number;
  audio: boolean;
  onToggleAudio: () => void;
  onReturn: () => void;
  onLeave: () => void;
}

interface ChatProps {
  appName?: string;
  user?: SessionUser | null;
  isActive?: boolean;
  onOpenSettings?: () => void;
  onLogout?: () => void;
  onAuthRevoked?: () => void;
  onActiveCallChange?: (summary: ActiveCallSummary | null) => void;
}

type ActiveModal = 'none' | 'new-channel' | 'new-dm' | 'search';

// What a row says about its encryption state; a retry replaces the row only when this changes.
const e2eeLabel = (m: ChatMessage) => (m.e2ee?.kind === 'failed' ? `failed:${m.e2ee.reason}` : m.e2ee?.kind ?? '');

interface RoomMessageBucket {
  messages: ChatMessage[];
  hasMore: boolean;
  loaded: boolean;
  hasGapAfter?: boolean;
}

type StagedAttachment =
  | { kind: 'uploading'; localId: string; filename: string; sizeBytes: number; previewUrl?: string }
  | { kind: 'ready'; localId: string; attachment: ChatAttachment; previewUrl?: string }
  | { kind: 'error'; localId: string; filename: string; error: string };

const isMac =
  typeof navigator !== 'undefined' && /mac|iphone|ipad|ipod/i.test(navigator.platform || navigator.userAgent);
const SEARCH_HINT = isMac ? '⌘K' : 'Ctrl+K';

export const Chat: React.FC<ChatProps> = ({
  appName,
  user,
  isActive = true,
  onOpenSettings,
  onLogout,
  onAuthRevoked,
  onActiveCallChange,
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
  const [draftsByRoom, setDraftsByRoom] = useState<Record<string, string>>({});
  const [replyByRoom, setReplyByRoom] = useState<Record<string, ChatMessage | null>>({});
  const [stagedByRoom, setStagedByRoom] = useState<Record<string, StagedAttachment[]>>({});
  const [attachmentLimits, setAttachmentLimits] = useState<ChatAttachmentLimits>(DEFAULT_ATTACHMENT_LIMITS);
  const [lightboxAttachment, setLightboxAttachment] = useState<ChatAttachment | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [modal, setModal] = useState<ActiveModal>('none');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [requestedDrawerTab, setRequestedDrawerTab] = useState<{ tab: DrawerTab; seq: number } | null>(null);
  const [roomDetail, setRoomDetail] = useState<ChatRoomDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [mobileRailOpen, setMobileRailOpen] = useState(false);
  const [showJumpLatest, setShowJumpLatest] = useState(false);
  const [missedCount, setMissedCount] = useState(0);
  const [unreadDividerSeq, setUnreadDividerSeq] = useState<number | null>(null);
  const [highlightedSeq, setHighlightedSeq] = useState<number | null>(null);
  const [pendingJump, setPendingJump] = useState<{ roomId: string; seq: number } | null>(null);
  const [editTrigger, setEditTrigger] = useState<{ messageId: string; seq: number } | null>(null);
  const [srAnnouncement, setSrAnnouncement] = useState('');
  const [creatingGeneral, setCreatingGeneral] = useState(false);
  const [creatingMeeting, setCreatingMeeting] = useState(false);
  const [lobbyBusy, setLobbyBusy] = useState(false);
  // Map of roomId -> Map<userId, expiryTimestampMs>
  const [typingByRoom, setTypingByRoom] = useState<Record<string, Record<string, number>>>({});
  // Phase 3: hybrid calls, SFU availability, waiting room lobby, guest invite banner
  const [activeCalls, setActiveCalls] = useState<Record<string, CallState>>({});
  const [sfuAvailable, setSfuAvailable] = useState(false);
  const [lobbyByRoom, setLobbyByRoom] = useState<Record<string, LobbyGuest[]>>({});
  const [callSnap, setCallSnap] = useState<HybridCallSnapshot | null>(null);
  const [callExpanded, setCallExpanded] = useState(false);
  const [joiningCall, setJoiningCall] = useState(false);
  const [guestLinkBanner, setGuestLinkBanner] = useState<{ roomId: string; url: string; copied: boolean } | null>(null);
  const [pushConfig, setPushConfig] = useState<ChatPushConfig>({ available: false, vapid_public_key: '' });
  const [pushState, setPushState] = useState<PushState>({ kind: 'unavailable' });
  const [pushBusy, setPushBusy] = useState(false);

  const activeCallsRef = useRef(activeCalls);
  const callRevisionsRef = useRef<Record<string, number>>({});
  const socketRef = useRef<ChatSocket | null>(null);
  const callCtrlRef = useRef<HybridCallController | null>(null);
  const callStageRef = useRef<HTMLElement | null>(null);
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const composerRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const previewUrlsRef = useRef<Set<string>>(new Set());
  const dragDepthRef = useRef(0);
  const stagedByRoomRef = useRef<Record<string, StagedAttachment[]>>({});
  const cancelledUploadsRef = useRef<Set<string>>(new Set());
  const uploadControllersRef = useRef<Map<string, AbortController>>(new Map());
  const nearBottomRef = useRef(true);
  const activeRoomIdRef = useRef<string | null>(null);
  const currentUserRef = useRef<ChatCurrentUser | null>(null);
  const bucketsRef = useRef<Record<string, RoomMessageBucket>>({});
  const roomsRef = useRef<ChatRoomSummary[]>([]);
  const drawerOpenRef = useRef(false);
  const highlightTimerRef = useRef<number | null>(null);
  const isActiveRef = useRef(isActive);
  const onAuthRevokedRef = useRef(onAuthRevoked);
  const onActiveCallChangeRef = useRef(onActiveCallChange);
  const pendingJumpRef = useRef(pendingJump);
  const callRoomIdRef = useRef<string | null>(null);

  activeRoomIdRef.current = activeRoomId;
  currentUserRef.current = currentUser;
  activeCallsRef.current = activeCalls;

  const updateCallState = useCallback((roomId: string, state: CallState | null) => {
    const next = { ...activeCallsRef.current };
    if (!state || state.ended || state.active === false || state.peers.length === 0) delete next[roomId];
    else next[roomId] = state;
    // Advance synchronously with the event, before a pending bootstrap can complete.
    callRevisionsRef.current[roomId] = (callRevisionsRef.current[roomId] ?? 0) + 1;
    activeCallsRef.current = next;
    setActiveCalls(next);
  }, []);

  // Search runs on this device: index every message as it is read, edited or deleted. Only
  // messages whose text or state changed since they were last indexed are written again.
  const indexedRef = useRef(new Map<string, string>());
  const forgetIndexed = useCallback((id: string | undefined) => {
    const user = currentUserRef.current;
    if (!id || !user) return;
    indexedRef.current.delete(id);
    void searchIndexFor(user.id)
      .then((index) => index.remove([id]))
      .catch(() => undefined);
  }, []);
  useEffect(() => {
    if (!currentUser) return;
    const changed: ChatMessage[] = [];
    for (const bucket of Object.values(buckets)) {
      for (const m of bucket.messages) {
        const sig = `${m.body}\u0000${m.edited_at ?? ''}\u0000${m.deleted_at ?? ''}\u0000${m.delivery.kind}`;
        if (indexedRef.current.get(m.id) !== sig) {
          indexedRef.current.set(m.id, sig);
          changed.push(m);
        }
      }
    }
    if (changed.length === 0) return;
    void searchIndexFor(currentUser.id)
      .then((index) => index.put(changed))
      .catch(() => {
        // Search is best effort: a browser without IndexedDB still chats.
        for (const m of changed) indexedRef.current.delete(m.id);
      });
  }, [buckets, currentUser]);
  // A message whose key had not arrived (or whose device had not started) is opened again
  // when keys arrive.
  const reopen = useCallback((retry: ChatMessage[]) => {
    void openMessages(retry).then((list) => {
      const opened = new Map(list.map((m) => [m.id, m]));
      setBuckets((prev) => {
        let changed = false;
        const next: Record<string, RoomMessageBucket> = {};
        for (const [rid, b] of Object.entries(prev)) {
          next[rid] = {
            ...b,
            // Only fill in what is still unopened and not deleted: an edit or a deletion may
            // have landed meanwhile. Merge just what opening sets, so the row keeps its later
            // state (deletion, reactions, pins). A row still waiting takes the newer generation.
            messages: b.messages.map((m) => {
              const o = opened.get(m.id);
              if (!o || m.deleted_at || m.envelope !== o.envelope || m.e2ee?.kind === 'decrypted') return m;
              const gen = (e: ChatMessage['e2ee']) => (e && e.kind !== 'decrypted' ? e.gen : undefined);
              if (e2eeLabel(m) === e2eeLabel(o) && gen(m.e2ee) === gen(o.e2ee)) return m;
              changed = true;
              return { ...m, body: o.body, reply_to_id: o.reply_to_id, e2ee: o.e2ee };
            }),
          };
        }
        return changed ? next : prev;
      });
    });
  }, []);
  useEffect(
    () =>
      onRoomKeys(() => {
        const retry = Object.values(bucketsRef.current).flatMap((b) =>
          b.messages.filter((m) => m.e2ee?.kind === 'waiting' || (m.e2ee?.kind === 'failed' && retryable(m.e2ee.reason))),
        );
        if (retry.length > 0) reopen(retry);
      }),
    [reopen],
  );
  // Keys (or the device's start) can land between a message's open and its display, when no row
  // was there to retry: a waiting or retryable row opened before the latest generation is opened again.
  useEffect(() => {
    const now = keyGeneration();
    const stale = Object.values(buckets).flatMap((b) =>
      b.messages.filter((m) => {
        const e = m.e2ee;
        const again = e?.kind === 'waiting' || (e?.kind === 'failed' && retryable(e.reason));
        return again && e.gen !== undefined && e.gen < now;
      }),
    );
    if (stale.length > 0) reopen(stale);
  }, [buckets, reopen]);
  bucketsRef.current = buckets;
  roomsRef.current = rooms;
  stagedByRoomRef.current = stagedByRoom;
  drawerOpenRef.current = drawerOpen;
  isActiveRef.current = isActive;
  onAuthRevokedRef.current = onAuthRevoked;
  onActiveCallChangeRef.current = onActiveCallChange;
  pendingJumpRef.current = pendingJump;
  callRoomIdRef.current = callSnap?.roomId ?? null;

  useEffect(() => {
    const urls = previewUrlsRef.current;
    const controllers = uploadControllersRef.current;
    const cancelled = cancelledUploadsRef.current;
    return () => {
      for (const [id, ctrl] of controllers) {
        cancelled.add(id);
        ctrl.abort();
      }
      controllers.clear();
      for (const u of urls) {
        URL.revokeObjectURL(u);
      }
      urls.clear();
    };
  }, []);

  // Rebuild the tray from the server once per room: a reload or another tab may have left
  // staged uploads that still count against the pending quota.
  const stagedFetchedRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (!activeRoomId || stagedFetchedRef.current.has(activeRoomId)) return;
    const roomId = activeRoomId;
    stagedFetchedRef.current.add(roomId);
    listStagedAttachments(roomId)
      .then((list) => {
        setStagedByRoom((prev) => {
          const current = prev[roomId] ?? [];
          const known = new Set(
            current.flatMap((item) => (item.kind === 'ready' ? [item.attachment.id] : [])),
          );
          const restored: StagedAttachment[] = list
            .filter((a) => !known.has(a.id))
            .map((a) => ({ kind: 'ready', localId: a.id, attachment: a }));
          return restored.length ? { ...prev, [roomId]: [...restored, ...current] } : prev;
        });
      })
      .catch(() => {
        stagedFetchedRef.current.delete(roomId);
      });
  }, [activeRoomId]);

  useEffect(() => {
    if (!lightboxAttachment) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setLightboxAttachment(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [lightboxAttachment]);

  const activeRoom = useMemo(
    () => rooms.find((r) => r.id === activeRoomId) ?? null,
    [rooms, activeRoomId],
  );

  const activeBucket = activeRoomId ? buckets[activeRoomId] : undefined;
  const activeMessages = activeBucket?.messages ?? [];
  const draft = activeRoomId ? draftsByRoom[activeRoomId] ?? '' : '';
  const replyTo = activeRoomId ? replyByRoom[activeRoomId] ?? null : null;
  const activeStaged = activeRoomId ? stagedByRoom[activeRoomId] ?? [] : [];
  const hasUploadingAttachments = activeStaged.some((item) => item.kind === 'uploading');
  const readyStagedAttachments = activeStaged
    .filter((item): item is Extract<StagedAttachment, { kind: 'ready' }> => item.kind === 'ready')
    .map((item) => item.attachment);

  const setActiveDraft = useCallback((value: string) => {
    const rid = activeRoomIdRef.current;
    if (!rid) return;
    setDraftsByRoom((prev) => ({ ...prev, [rid]: value }));
  }, []);

  const setActiveReplyTo = useCallback((target: ChatMessage | null) => {
    const rid = activeRoomIdRef.current;
    if (!rid) return;
    setReplyByRoom((prev) => ({ ...prev, [rid]: target }));
  }, []);

  const directoryById = useMemo(
    () => new Map(directory.map((u) => [u.id, u])),
    [directory],
  );

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

  const scrollToBottom = useCallback(() => {
    const el = timelineRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
    nearBottomRef.current = true;
    setShowJumpLatest(false);
    setMissedCount(0);
    const rid = activeRoomIdRef.current;
    if (rid) {
      const msgs = bucketsRef.current[rid]?.messages ?? [];
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].delivery.kind === 'synced') {
          void syncReadCursor(rid, msgs[i].seq);
          break;
        }
      }
    }
  }, [syncReadCursor]);

  const highlightAndScrollSeq = useCallback((seq: number): boolean => {
    const root = timelineRef.current;
    if (!root) return false;
    const target = root.querySelector<HTMLElement>(`[data-seq="${seq}"]`);
    if (!target) return false;
    const reduceMotion =
      typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
    setHighlightedSeq(seq);
    if (highlightTimerRef.current) window.clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = window.setTimeout(() => setHighlightedSeq(null), 1900);
    return true;
  }, []);

  const jumpToMessageSeq = useCallback(
    async (roomId: string, seq: number) => {
      if (highlightAndScrollSeq(seq)) return;
      try {
        const page = await fetchMessages(roomId, { before: seq + 25, limit: 50 });
        if (activeRoomIdRef.current !== roomId) return;
        let hasGap = false;
        setBuckets((prev) => {
          const existing = prev[roomId]?.messages ?? [];
          const syncedExisting = existing.filter((m) => m.delivery.kind === 'synced');
          const minExistingSeq = syncedExisting.length > 0 ? syncedExisting[0].seq : 0;
          const maxPageSeq = page.messages.length > 0 ? page.messages[page.messages.length - 1].seq : 0;
          const isContiguous = syncedExisting.length === 0 || maxPageSeq >= minExistingSeq - 1;
          hasGap = !isContiguous && syncedExisting.length > 0;
          return {
            ...prev,
            [roomId]: isContiguous
              ? {
                  messages: mergeMessageBatch(existing, page.messages),
                  hasMore: prev[roomId]?.hasMore || page.has_more,
                  loaded: true,
                  hasGapAfter: prev[roomId]?.hasGapAfter ?? false,
                }
              : {
                  messages: page.messages,
                  hasMore: page.has_more,
                  loaded: true,
                  hasGapAfter: true,
                },
          };
        });
        if (hasGap) {
          setShowJumpLatest(true);
        }
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            if (!highlightAndScrollSeq(seq)) {
              setBannerError('Referenced message is no longer available.');
            }
          });
        });
      } catch {
        setBannerError('Could not load referenced message.');
      }
    },
    [highlightAndScrollSeq],
  );

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
    async (roomId: string, hasUnreadDivider = false) => {
      setLoadingMessages(true);
      setBannerError('');
      try {
        const page = await fetchMessages(roomId, { limit: 50 });
        setBuckets((prev) => {
          const prevBucket = prev[roomId];
          const messages = prevBucket?.hasGapAfter
            ? page.messages
            : mergeMessageBatch(prevBucket?.messages ?? [], page.messages);
          return {
            ...prev,
            [roomId]: {
              messages,
              hasMore: page.has_more,
              loaded: true,
              hasGapAfter: false,
            },
          };
        });
        if (activeRoomIdRef.current !== roomId) return;
        const latestSeq = page.messages.length > 0 ? page.messages[page.messages.length - 1].seq : 0;
        if (pendingJumpRef.current?.roomId === roomId) return;
        requestAnimationFrame(() => {
          const el = timelineRef.current;
          if (!el) return;
          if (hasUnreadDivider) {
            const divider = el.querySelector<HTMLElement>('.chat-unread-divider');
            if (divider) {
              divider.scrollIntoView({ behavior: 'auto', block: 'center' });
              const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
              nearBottomRef.current = nearBottom;
              if (!nearBottom) {
                setShowJumpLatest(true);
                return;
              }
            }
          }
          el.scrollTop = el.scrollHeight;
          nearBottomRef.current = true;
          setShowJumpLatest(false);
          if (latestSeq > 0 && isActiveRef.current) {
            void syncReadCursor(roomId, latestSeq);
          }
        });
      } catch (e) {
        if (activeRoomIdRef.current === roomId) {
          setBannerError(e instanceof Error ? e.message : 'Could not load messages');
        }
      } finally {
        setLoadingMessages(false);
      }
    },
    [syncReadCursor],
  );

  const catchUpRoom = useCallback(
    async (roomId: string) => {
      const bucket = bucketsRef.current[roomId];
      const maxSeq = (bucket?.messages ?? []).reduce(
        (acc, m) => (m.delivery.kind === 'synced' && m.seq > acc ? m.seq : acc),
        0,
      );
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
        const visible = isActiveRef.current && (typeof document === 'undefined' || document.visibilityState === 'visible');
        if (visible && activeRoomIdRef.current === roomId && nearBottomRef.current) {
          const latest = page.messages[page.messages.length - 1].seq;
          void syncReadCursor(roomId, latest);
          requestAnimationFrame(scrollToBottom);
        }
      } catch {
        // Transient catch-up failure; next event or room switch will retry.
      }
    },
    [scrollToBottom, syncReadCursor],
  );

  const handleWsEvent = useCallback(
    (event: WsServerEvent) => {
      switch (event.kind) {
        case 'hello':
        case 'pong':
          return;
        case 'auth.revoked':
          setBannerError('Your session has been revoked. Please sign in again.');
          onAuthRevokedRef.current?.();
          return;
        case 'to_device':
          receiveRoomKeys();
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
            // If the user is viewing a non-contiguous historical jump slice, keep it
            // untouched until they click "Jump to latest" so we never create a silent gap.
            if (current?.hasGapAfter) {
              return prev;
            }
            return {
              ...prev,
              [event.roomId]: {
                messages: upsertMessage(current?.messages ?? [], incoming),
                hasMore: current?.hasMore ?? false,
                hasGapAfter: false,
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

          const isViewing =
            isActiveRef.current &&
            (typeof document === 'undefined' || document.visibilityState === 'visible') &&
            activeRoomIdRef.current === event.roomId;
          const isSelf = incoming.sender_id === currentUserRef.current?.id;
          const markAsReadNow = isSelf || (isViewing && nearBottomRef.current);

          setRooms((prev) =>
            prev.map((r) => {
              if (r.id !== event.roomId) return r;
              const nextLastSeq = Math.max(r.last_seq, incoming.seq);
              const nextReadSeq = markAsReadNow ? Math.max(r.last_read_seq, incoming.seq) : r.last_read_seq;
              return {
                ...r,
                last_seq: nextLastSeq,
                last_read_seq: nextReadSeq,
                unread_count: Math.max(0, nextLastSeq - nextReadSeq),
              };
            }),
          );

          if (isViewing && !isSelf) {
            setSrAnnouncement(`${incoming.sender_name || 'Member'}: ${incoming.body}`);
          }

          if (markAsReadNow && !isSelf) {
            void syncReadCursor(event.roomId, incoming.seq);
          }
          if (isViewing && nearBottomRef.current) {
            requestAnimationFrame(scrollToBottom);
          } else if (isViewing && !isSelf) {
            setShowJumpLatest(true);
            setMissedCount((c) => c + 1);
          }
          return;
        }
        case 'message.edit': {
          // Not loaded here: the indexed copy is out of date, so drop it (re-indexed when viewed).
          if (!bucketsRef.current[event.roomId]) forgetIndexed(event.message?.id);
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
          forgetIndexed(event.messageId);
          setBuckets((prev) => {
            const current = prev[event.roomId];
            if (!current) return prev;
            return {
              ...prev,
              [event.roomId]: {
                ...current,
                messages: current.messages.map((m) =>
                  m.id === event.messageId
                    ? { ...m, body: '', attachments: [], deleted_at: event.deletedAt ?? Date.now() }
                    : m,
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
          const self = event.userId === currentUserRef.current?.id;
          // Every send lists the room's devices afresh; a departure also starts a new session.
          if (event.action === 'removed') roomMemberLeft(event.roomId);
          if (self && event.action === 'removed') {
            updateCallState(event.roomId, null);
            setRooms((prev) => prev.filter((r) => r.id !== event.roomId));
            if (activeRoomIdRef.current === event.roomId) {
              setActiveRoomId(null);
              setDrawerOpen(false);
            }
            return;
          }
          if (self) void refreshRoomsList();
          if (drawerOpenRef.current && activeRoomIdRef.current === event.roomId) {
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
          updateCallState(event.roomId, null);
          setRooms((prev) =>
            prev.map((r) => (r.id === event.roomId ? { ...r, closed_at: r.closed_at ?? Date.now() } : r)),
          );
          if (activeRoomIdRef.current === event.roomId && drawerOpenRef.current) {
            void refreshRoomDetail(event.roomId);
          }
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
          const isEnded = Boolean(st.ended || st.active === false);
          updateCallState(st.room_id, st);
          callCtrlRef.current?.handleCallState(st);
          if (isEnded && callRoomIdRef.current === st.room_id) {
            callCtrlRef.current?.dispose();
            callCtrlRef.current = null;
            setCallSnap(null);
            setCallExpanded(false);
          }
          return;
        }
        case 'call.signal': {
          if (!callCtrlRef.current?.isRoomRouted()) void callCtrlRef.current?.handleSignal(event.signal);
          return;
        }
        case 'call.migrate': {
          if (!callCtrlRef.current?.isRoomRouted()) void callCtrlRef.current?.handleMigrate(event.migrate);
          return;
        }
        case 'lobby.knock': {
          const g = event.guest;
          setLobbyByRoom((prev) => {
            const list = prev[event.roomId] ?? [];
            const filtered = list.filter((x) => x.guest_id !== g.guest_id);
            if (g.status !== 'waiting') {
              return { ...prev, [event.roomId]: filtered };
            }
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
    [catchUpRoom, forgetIndexed, refreshRoomDetail, refreshRoomsList, scrollToBottom, syncReadCursor, updateCallState],
  );

  // Initial bootstrap + WebSocket connection.
  useEffect(() => {
    let cancelled = false;
    // A suite link (POST /api/suite/chat) opens the app on #dm=<user id>; read it before the
    // room hash replaces it.
    const dmTarget = window.location.hash.match(/^#dm=([A-Za-z0-9_-]{1,128})$/)?.[1];
    const init = async () => {
      try {
        const [boot, users] = await Promise.all([
          fetchBootstrap(() => ({ calls: activeCallsRef.current, revisions: callRevisionsRef.current })),
          fetchDirectoryUsers().catch(() => [] as ChatDirectoryUser[]),
        ]);
        if (cancelled) return;
        // Start this browser's encryption device before any room's messages are opened.
        void startE2EE(boot.user.id).catch(() => {
          if (!cancelled) setBannerError('Encryption could not start in this browser, so messages cannot be sent or read.');
        });
        setCurrentUser(boot.user);
        setTenantName(boot.tenant.display_name || 'KyMessages');
        setRooms(boot.rooms);
        setDirectory(users);
        setSfuAvailable(boot.rtc.sfu_available);
        setAttachmentLimits(boot.attachments);
        setPushConfig(boot.push);
        void syncExistingPushSubscription(boot.push).then((state) => {
          if (!cancelled) setPushState(state);
        });
        const callMap: Record<string, CallState> = {};
        for (const [rid, c] of Object.entries(boot.active_calls)) {
          if (!c.ended && c.active !== false && c.peers.length > 0) callMap[rid] = c;
        }
        activeCallsRef.current = callMap;
        setActiveCalls(callMap);
        if (boot.rooms.length > 0) {
          const queryRoom = new URLSearchParams(window.location.search).get('room');
          const hashMatch = window.location.hash.match(/^#room=([^&]+)/);
          let hashRoom: string | null = null;
          if (hashMatch) {
            try {
              hashRoom = decodeURIComponent(hashMatch[1]);
            } catch {
              hashRoom = null;
            }
          }
          const requestedRoom = hashRoom || queryRoom;
          const matched = requestedRoom ? boot.rooms.find((r) => r.id === requestedRoom) : undefined;
          setActiveRoomId(matched ? matched.id : boot.rooms[0].id);
        }
        if (dmTarget) {
          try {
            const { room } = await openDirectMessage(dmTarget);
            if (cancelled) return;
            await refreshRoomsList();
            setActiveRoomId(room.id);
          } catch (e) {
            if (!cancelled) setBannerError(e instanceof Error ? e.message : 'Could not open direct message');
          }
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
        void (async () => {
          try {
            const boot = await fetchBootstrap(() => ({ calls: activeCallsRef.current, revisions: callRevisionsRef.current }));
            if (cancelled) return;
            // Mail may have arrived while offline, or the device may not have started.
            void startE2EE(boot.user.id).then(receiveRoomKeys, () => undefined);
            setRooms(boot.rooms);
            const callMap: Record<string, CallState> = {};
            for (const [rid, c] of Object.entries(boot.active_calls)) {
              if (!c.ended && c.active !== false && c.peers.length > 0) callMap[rid] = c;
            }
            activeCallsRef.current = callMap;
            setActiveCalls(callMap);
            const activeCallRoom = callRoomIdRef.current;
            const myUid = currentUserRef.current?.id;
            if (activeCallRoom && myUid && !callCtrlRef.current?.isRoomRouted()) {
              const serverCall = callMap[activeCallRoom];
              const stillJoined = Boolean(serverCall?.peers.some((p) => p.user_id === myUid));
              if (!stillJoined) {
                callCtrlRef.current?.dispose();
                callCtrlRef.current = null;
                setCallSnap(null);
                setCallExpanded(false);
                setBannerError('Call connection was interrupted while offline — click Join to rejoin.');
              }
            }
          } catch {
            void refreshRoomsList();
          }
        })();
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
      if (highlightTimerRef.current) window.clearTimeout(highlightTimerRef.current);
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

  // Close chat modals when navigating to Settings/Admin, and preserve unread divider when returning.
  useEffect(() => {
    if (!isActive) {
      setModal('none');
      return;
    }
    const rid = activeRoomIdRef.current;
    if (!rid) return;
    const room = roomsRef.current.find((r) => r.id === rid);
    if (room && room.unread_count > 0) {
      setUnreadDividerSeq((prev) => (prev === null ? room.last_read_seq : prev));
      setShowJumpLatest(true);
      return;
    }
    if (nearBottomRef.current) {
      const msgs = bucketsRef.current[rid]?.messages ?? [];
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].delivery.kind === 'synced') {
          void syncReadCursor(rid, msgs[i].seq);
          break;
        }
      }
    }
  }, [isActive, syncReadCursor]);

  // Global keyboard shortcuts (Cmd/Ctrl+K for Search, Esc to dismiss drawers/reply).
  useEffect(() => {
    if (!isActive) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setModal((m) => (m === 'search' ? 'none' : 'search'));
      } else if (e.key === 'Escape' && modal === 'none') {
        if (mobileRailOpen) setMobileRailOpen(false);
        else if (drawerOpen) setDrawerOpen(false);
        else if (replyTo) setActiveReplyTo(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isActive, modal, mobileRailOpen, drawerOpen, replyTo, setActiveReplyTo]);

  // Load room history when switching active room.
  useEffect(() => {
    if (!activeRoomId) return;
    setShowJumpLatest(false);
    setMissedCount(0);

    const entering = roomsRef.current.find((r) => r.id === activeRoomId);
    const hasUnreadDivider = Boolean(entering && entering.unread_count > 0 && entering.last_read_seq > 0);
    if (hasUnreadDivider && entering) {
      setUnreadDividerSeq(entering.last_read_seq);
    } else {
      setUnreadDividerSeq(null);
    }

    // Re-fit composer height for the newly selected room's draft.
    if (composerRef.current) {
      composerRef.current.style.height = 'auto';
      composerRef.current.style.height = `${Math.min(composerRef.current.scrollHeight, 144)}px`;
    }

    const existing = bucketsRef.current[activeRoomId];
    if (!existing?.loaded) {
      void loadRoomHistory(activeRoomId, hasUnreadDivider);
    } else {
      const latest = existing.messages[existing.messages.length - 1]?.seq ?? 0;
      if (latest > 0 && isActiveRef.current) void syncReadCursor(activeRoomId, latest);
      if (pendingJumpRef.current?.roomId !== activeRoomId) {
        requestAnimationFrame(() => {
          const el = timelineRef.current;
          if (!el) return;
          if (hasUnreadDivider) {
            const divider = el.querySelector<HTMLElement>('.chat-unread-divider');
            if (divider) {
              divider.scrollIntoView({ behavior: 'auto', block: 'center' });
              nearBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
              return;
            }
          }
          el.scrollTop = el.scrollHeight;
          nearBottomRef.current = true;
        });
      }
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
  }, [activeRoomId, loadRoomHistory, refreshRoomDetail, syncReadCursor]);

  // Fulfill pending search-result message jump once target room messages render.
  useEffect(() => {
    if (!pendingJump || pendingJump.roomId !== activeRoomId) return;
    if (!activeBucket?.loaded) return;
    const { roomId, seq } = pendingJump;
    setPendingJump(null);
    requestAnimationFrame(() => {
      void jumpToMessageSeq(roomId, seq);
    });
  }, [pendingJump, activeRoomId, activeBucket?.loaded, activeMessages.length, jumpToMessageSeq]);

  const handleLoadOlder = async () => {
    if (!activeRoomId || loadingOlder || !activeBucket?.hasMore) return;
    const oldest = activeBucket.messages.find((m) => m.delivery.kind === 'synced');
    if (!oldest) return;
    const timeline = timelineRef.current;
    const prevScrollHeight = timeline?.scrollHeight ?? 0;
    const prevScrollTop = timeline?.scrollTop ?? 0;
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
          timeline.scrollTop = prevScrollTop + (timeline.scrollHeight - prevScrollHeight);
        }
      });
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not load older messages');
    } finally {
      setLoadingOlder(false);
    }
  };

  const releasePreviewUrl = useCallback((url?: string) => {
    if (!url) return;
    if (previewUrlsRef.current.has(url)) {
      URL.revokeObjectURL(url);
      previewUrlsRef.current.delete(url);
    }
  }, []);

  const removeStagedAttachment = useCallback(
    (roomId: string, localId: string) => {
      const existing = (stagedByRoomRef.current[roomId] ?? []).find((item) => item.localId === localId);
      if (existing && existing.kind === 'ready') {
        void deleteAttachment(existing.attachment.id).catch(() => {
          // Best-effort cleanup; orphan sweep also expires abandoned uploads.
        });
      } else {
        cancelledUploadsRef.current.add(localId);
        const ctrl = uploadControllersRef.current.get(localId);
        if (ctrl) {
          uploadControllersRef.current.delete(localId);
          ctrl.abort();
        }
      }
      setStagedByRoom((prev) => {
        const current = prev[roomId] ?? [];
        const target = current.find((item) => item.localId === localId);
        if (target && target.kind !== 'error') {
          releasePreviewUrl(target.previewUrl);
        }
        return {
          ...prev,
          [roomId]: current.filter((item) => item.localId !== localId),
        };
      });
    },
    [releasePreviewUrl],
  );

  const uploadFilesForRoom = useCallback(
    (roomId: string, files: File[]) => {
      if (files.length === 0 || !attachmentLimits.available) return;
      const room = roomsRef.current.find((r) => r.id === roomId);
      if (room?.closed_at) return;

      const existingCount = (stagedByRoomRef.current[roomId] ?? []).filter((item) => item.kind !== 'error').length;
      const availableSlots = Math.max(0, attachmentLimits.max_per_message - existingCount);
      if (availableSlots === 0) {
        setBannerError(`You can attach up to ${attachmentLimits.max_per_message} files per message.`);
        return;
      }

      const accepted = files.slice(0, availableSlots);
      if (files.length > availableSlots) {
        setBannerError(`Only the first ${availableSlots} file(s) were added (max ${attachmentLimits.max_per_message} per message).`);
      }

      for (const file of accepted) {
        const localId = newIdempotencyKey();
        if (file.size <= 0) {
          setStagedByRoom((prev) => ({
            ...prev,
            [roomId]: [
              ...(prev[roomId] ?? []),
              { kind: 'error', localId, filename: file.name || 'file', error: 'File is empty' },
            ],
          }));
          continue;
        }
        if (file.size > attachmentLimits.max_upload_bytes) {
          setStagedByRoom((prev) => ({
            ...prev,
            [roomId]: [
              ...(prev[roomId] ?? []),
              {
                kind: 'error',
                localId,
                filename: file.name || 'file',
                error: `Exceeds ${formatBytes(attachmentLimits.max_upload_bytes)} limit`,
              },
            ],
          }));
          continue;
        }

        let previewUrl: string | undefined;
        if (isInlineImageAttachment({ mime_type: file.type })) {
          previewUrl = URL.createObjectURL(file);
          previewUrlsRef.current.add(previewUrl);
        }

        setStagedByRoom((prev) => ({
          ...prev,
          [roomId]: [
            ...(prev[roomId] ?? []),
            {
              kind: 'uploading',
              localId,
              filename: file.name || 'file',
              sizeBytes: file.size,
              previewUrl,
            },
          ],
        }));

        const controller = new AbortController();
        uploadControllersRef.current.set(localId, controller);

        void uploadAttachment(roomId, file, controller.signal)
          .then((att) => {
            uploadControllersRef.current.delete(localId);
            let cleanedOrphan = false;
            const cleanupOrphan = () => {
              if (cleanedOrphan) return;
              cleanedOrphan = true;
              releasePreviewUrl(previewUrl);
              void deleteAttachment(att.id).catch(() => {
                // Best-effort cleanup; orphan sweep also expires abandoned uploads.
              });
            };
            if (cancelledUploadsRef.current.delete(localId)) {
              cleanupOrphan();
              return;
            }
            setStagedByRoom((prev) => {
              const list = prev[roomId] ?? [];
              const exists = list.some((item) => item.localId === localId);
              if (!exists) {
                cleanupOrphan();
                return prev;
              }
              const inlineSafe = isInlineImageAttachment(att);
              if (!inlineSafe) {
                releasePreviewUrl(previewUrl);
              }
              return {
                ...prev,
                [roomId]: list.map((item) =>
                  item.localId === localId
                    ? {
                        kind: 'ready',
                        localId,
                        attachment: att,
                        previewUrl: inlineSafe ? previewUrl : undefined,
                      }
                    : item,
                ),
              };
            });
          })
          .catch((e) => {
            uploadControllersRef.current.delete(localId);
            cancelledUploadsRef.current.delete(localId);
            releasePreviewUrl(previewUrl);
            const msg = e instanceof Error ? e.message : 'Upload failed';
            setStagedByRoom((prev) => {
              const list = prev[roomId] ?? [];
              if (!list.some((item) => item.localId === localId)) return prev;
              return {
                ...prev,
                [roomId]: list.map((item) =>
                  item.localId === localId
                    ? { kind: 'error', localId, filename: file.name || 'file', error: msg }
                    : item,
                ),
              };
            });
          });
      }
    },
    [attachmentLimits, releasePreviewUrl],
  );

  const dispatchSend = async (
    roomId: string,
    body: string,
    replyToId: string | undefined,
    clientKey: string,
    attachments: ChatAttachment[] = [],
  ) => {
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
      encoding: 'e2ee_room_v1',
      e2ee: { kind: 'decrypted' },
      body,
      created_at: Date.now(),
      reactions: [],
      attachments,
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
      const confirmed = await sendMessage({
        roomId,
        body,
        replyToId,
        attachmentIds: attachments.map((a) => a.id),
        idempotencyKey: clientKey,
      });
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
    if (hasUploadingAttachments) return;
    const trimmed = draft.trim();
    const attachmentsToSend = readyStagedAttachments;
    if (!trimmed && attachmentsToSend.length === 0) return;
    const clientKey = newIdempotencyKey();
    const targetReply = replyTo?.id;
    setActiveDraft('');
    setActiveReplyTo(null);
    setStagedByRoom((prev) => {
      const current = prev[activeRoomId] ?? [];
      for (const item of current) {
        if (item.kind === 'ready') {
          releasePreviewUrl(item.previewUrl);
        }
      }
      const remaining = current.filter((item) => item.kind === 'uploading');
      return { ...prev, [activeRoomId]: remaining };
    });
    setUnreadDividerSeq(null);
    socketRef.current?.sendTyping(activeRoomId, false);
    if (composerRef.current) {
      composerRef.current.style.height = 'auto';
    }
    void dispatchSend(activeRoomId, trimmed, targetReply, clientKey, attachmentsToSend);
  };

  const handleToggleReaction = (messageId: string, emoji: string, currentlyReacted: boolean) => {
    if (!activeRoomId || !currentUser) return;
    const add = !currentlyReacted;
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
    const original = bucketsRef.current[activeRoomId]?.messages.find((m) => m.id === messageId);
    const updated = await editMessage(activeRoomId, messageId, newBody, original?.reply_to_id);
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
    const leavingRoomId = callRoomIdRef.current;
    callCtrlRef.current?.dispose();
    callCtrlRef.current = null;
    setCallSnap(null);
    setCallExpanded(false);
    if (leavingRoomId) {
      await leaveRoomCall(leavingRoomId).catch(() => undefined);
    }
  }, []);

  // Keep in-call keyboard shortcuts (Cmd/Ctrl+Shift+M/O/E/H) working across room switches & Settings.
  useEffect(() => {
    if (!callSnap) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.repeat || !e.shiftKey || !(e.metaKey || e.ctrlKey) || e.altKey) return;
      const key = e.key.toLowerCase();
      if (key === 'm') {
        e.preventDefault();
        void callCtrlRef.current?.toggleAudio();
      } else if (key === 'o') {
        e.preventDefault();
        void callCtrlRef.current?.toggleVideo();
      } else if (key === 'e') {
        e.preventDefault();
        void callCtrlRef.current?.toggleScreenShare();
      } else if (key === 'h') {
        e.preventDefault();
        void handleLeaveCall();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [Boolean(callSnap), handleLeaveCall]);

  // Publish active call summary so App.tsx can display a persistent return-to-call bar in Settings/Admin.
  useEffect(() => {
    const notify = onActiveCallChangeRef.current;
    if (!notify) return;
    if (!callSnap) {
      notify(null);
      return;
    }
    const callRoomName = roomsRef.current.find((r) => r.id === callSnap.roomId)?.name || 'call';
    notify({
      roomId: callSnap.roomId,
      roomName: callRoomName,
      participantCount: callSnap.tiles.length,
      audio: callSnap.audio,
      onToggleAudio: () => {
        void callCtrlRef.current?.toggleAudio();
      },
      onReturn: () => {
        setActiveRoomId(callSnap.roomId);
        requestAnimationFrame(() => callStageRef.current?.focus());
      },
      onLeave: () => {
        void handleLeaveCall();
      },
    });
  }, [callSnap, handleLeaveCall]);

  const handleJoinCall = async (roomId: string, withVideo: boolean) => {
    const me = currentUserRef.current;
    if (!me || joiningCall) return;
    setJoiningCall(true);
    setBannerError('');
    try {
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
        rejoin: (media) => joinRoomCall(roomId,media),
        onEnded: () => { callCtrlRef.current = null; setCallSnap(null); setCallExpanded(false); },
        onChange: setCallSnap,
      });
      callCtrlRef.current = ctrl;
      await ctrl.start(joinResp, { audio: true, video: withVideo, protectIp: false });
      updateCallState(roomId, {
        call_id: joinResp.call_id, room_id: roomId, mode: joinResp.mode,
        epoch: joinResp.epoch, sfu_sticky: joinResp.sfu_sticky,
        peers: joinResp.peers, ended: false,
      });
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not join call');
    } finally {
      setJoiningCall(false);
    }
  };

  const handleDecideLobby = async (roomId: string, guestId: string, admit: boolean) => {
    setLobbyBusy(true);
    try {
      await decideRoomLobby(roomId, guestId, admit);
      setLobbyByRoom((prev) => ({
        ...prev,
        [roomId]: (prev[roomId] ?? []).filter((g) => g.guest_id !== guestId),
      }));
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not update waiting room');
    } finally {
      setLobbyBusy(false);
    }
  };

  const handleAdmitAllLobby = async (roomId: string) => {
    const guests = lobbyByRoom[roomId] ?? [];
    if (guests.length === 0) return;
    setLobbyBusy(true);
    try {
      await Promise.all(guests.map((g) => decideRoomLobby(roomId, g.guest_id, true)));
      setLobbyByRoom((prev) => ({ ...prev, [roomId]: [] }));
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not admit waiting guests');
    } finally {
      setLobbyBusy(false);
    }
  };

  const handleStartInstantMeeting = async () => {
    if (creatingMeeting) return;
    setCreatingMeeting(true);
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
    } finally {
      setCreatingMeeting(false);
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
      setMissedCount(0);
      if (activeRoomId) {
        for (let i = activeMessages.length - 1; i >= 0; i--) {
          if (activeMessages[i].delivery.kind === 'synced') {
            void syncReadCursor(activeRoomId, activeMessages[i].seq);
            break;
          }
        }
      }
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

  const firstUnreadMsgId = useMemo(() => {
    if (!unreadDividerSeq) return null;
    const found = activeMessages.find((m) => m.delivery.kind === 'synced' && m.seq > unreadDividerSeq);
    return found ? found.id : null;
  }, [activeMessages, unreadDividerSeq]);

  const canModerateActiveRoom =
    currentUser?.role === 'admin' || activeRoom?.role === 'owner' || activeRoom?.role === 'admin';
  const activeRoomCall = activeRoomId ? activeCalls[activeRoomId] : undefined;
  const livePeerCount = activeRoomCall && !activeRoomCall.ended ? activeRoomCall.peers.length : 0;
  const inActiveRoomCall = Boolean(callSnap && activeRoomId && callSnap.roomId === activeRoomId);
  const inOtherRoomCall = Boolean(callSnap && activeRoomId && callSnap.roomId !== activeRoomId);
  const otherCallRoomName = callSnap
    ? rooms.find((r) => r.id === callSnap.roomId)?.name || 'call'
    : '';
  const activeRoomLobby = activeRoomId ? lobbyByRoom[activeRoomId] ?? [] : [];
  const otherLobbyCount = activeRoomLobby.length - 1;

  // The hash names the room on screen, and the service worker skips that room's notifications,
  // so it is cleared while Chat is hidden behind Settings or a console page.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const base = `${window.location.pathname}${window.location.search}`;
    if (!isActive) {
      if (window.location.hash.startsWith('#room=')) window.history.replaceState(null, '', base);
      return;
    }
    if (!activeRoomId) return;
    const nextHash = `#room=${encodeURIComponent(activeRoomId)}`;
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, '', `${base}${nextHash}`);
    }
  }, [activeRoomId, isActive]);

  useEffect(() => {
    if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return;
    const onSwMessage = (ev: MessageEvent) => {
      const data: unknown = ev.data;
      if (!data || typeof data !== 'object') return;
      if (
        'type' in data &&
        data.type === 'kymessages.navigate' &&
        'roomId' in data &&
        typeof data.roomId === 'string' &&
        data.roomId
      ) {
        const target = roomsRef.current.find((r) => r.id === data.roomId);
        if (target) {
          setActiveRoomId(target.id);
        }
      }
    };
    navigator.serviceWorker.addEventListener('message', onSwMessage);
    return () => navigator.serviceWorker.removeEventListener('message', onSwMessage);
  }, []);

  const handleTogglePush = useCallback(async () => {
    if (pushBusy) return;
    setPushBusy(true);
    setBannerError('');
    try {
      if (pushState.kind === 'enabled') {
        const next = await disableBrowserPush();
        setPushState(next);
      } else {
        const next = await enableBrowserPush(pushConfig.vapid_public_key);
        setPushState(next);
      }
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : 'Could not update desktop notifications');
    } finally {
      setPushBusy(false);
    }
  }, [pushBusy, pushConfig.vapid_public_key, pushState.kind]);

  const handleNotifyModeChanged = useCallback((roomId: string, mode: NotifyMode) => {
    setRooms((prev) => prev.map((r) => (r.id === roomId ? { ...r, notify_mode: mode } : r)));
    setRoomDetail((prev) =>
      prev && prev.room.id === roomId ? { ...prev, member: { ...prev.member, notify_mode: mode } } : prev,
    );
  }, []);

  if (loading) {
    return (
      <div className="chat-empty-stage" style={{ height: '100dvh' }} role="status">
        <img src="/app-icon.png" width={36} height={36} alt="" />
        <p style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
          <Loader2 size={15} className="ky-spin" aria-hidden="true" />
          <span>Connecting to {tenantName}…</span>
        </p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="chat-empty-stage" style={{ height: '100dvh' }}>
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
      {/* Persistent remote audio layer so calls stay audible across room switches and Settings */}
      {callSnap && <CallAudioLayer tiles={callSnap.tiles} />}

      {/* Single polite live region for incoming active-room messages */}
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {srAnnouncement}
      </div>

      {/* Dismissible scrim for narrow-viewport rail and room drawer overlays */}
      {(mobileRailOpen || (drawerOpen && activeRoom)) && (
        <div
          className={`chat-scrim${mobileRailOpen ? ' is-rail' : ''}${drawerOpen ? ' is-drawer' : ''}`}
          aria-hidden="true"
          onClick={() => {
            setMobileRailOpen(false);
            setDrawerOpen(false);
          }}
        />
      )}

      <ChatSidebar
        appName={appName}
        tenantName={tenantName}
        rooms={rooms}
        activeRoomId={activeRoomId}
        activeCalls={activeCalls}
        lobbyByRoom={lobbyByRoom}
        wsStatus={wsStatus}
        mobileOpen={mobileRailOpen}
        user={user}
        creatingMeeting={creatingMeeting}
        pushState={pushState}
        pushBusy={pushBusy}
        onTogglePush={() => void handleTogglePush()}
        onCloseMobile={() => setMobileRailOpen(false)}
        onSelectRoom={(id) => setActiveRoomId(id)}
        onOpenNewChannel={() => setModal('new-channel')}
        onOpenNewDM={() => setModal('new-dm')}
        onOpenSearch={() => setModal('search')}
        onStartInstantMeeting={() => void handleStartInstantMeeting()}
        onOpenSettings={onOpenSettings}
        onLogout={onLogout}
      />

      <section
        className={`chat-stage${dragActive ? ' is-drag-over' : ''}`}
        aria-label="Conversation"
        onDragEnter={(e) => {
          if (!activeRoom || activeRoom.closed_at || !attachmentLimits.available) return;
          if (!Array.from(e.dataTransfer.types).includes('Files')) return;
          e.preventDefault();
          dragDepthRef.current += 1;
          setDragActive(true);
        }}
        onDragOver={(e) => {
          if (!activeRoom || activeRoom.closed_at || !attachmentLimits.available) return;
          if (!Array.from(e.dataTransfer.types).includes('Files')) return;
          e.preventDefault();
          e.dataTransfer.dropEffect = 'copy';
        }}
        onDragLeave={(e) => {
          if (!activeRoom || !attachmentLimits.available) return;
          if (!Array.from(e.dataTransfer.types).includes('Files')) return;
          e.preventDefault();
          dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
          if (dragDepthRef.current === 0) setDragActive(false);
        }}
        onDrop={(e) => {
          if (!activeRoom || activeRoom.closed_at || !attachmentLimits.available) return;
          e.preventDefault();
          dragDepthRef.current = 0;
          setDragActive(false);
          const dropped = Array.from(e.dataTransfer.files);
          if (dropped.length > 0) {
            uploadFilesForRoom(activeRoom.id, dropped);
          }
        }}
      >
        {dragActive && activeRoom && !activeRoom.closed_at && attachmentLimits.available && (
          <div className="chat-drop-overlay" aria-hidden="true">
            <div className="chat-drop-card">
              <Paperclip size={24} />
              <strong>
                Drop files to attach to {activeRoom.kind === 'dm' ? activeRoom.name || 'this chat' : `#${activeRoom.name}`}
              </strong>
              <span>Up to {formatBytes(attachmentLimits.max_upload_bytes)} per file</span>
            </div>
          </div>
        )}
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
                      className={`ky-header-call-btn${livePeerCount > 0 ? ' is-joining' : ''}`}
                      title={
                        livePeerCount > 0
                          ? `Join active call with audio (${livePeerCount} in call)`
                          : 'Start audio call'
                      }
                      aria-label={livePeerCount > 0 ? `Join audio call (${livePeerCount} in call)` : 'Audio call'}
                      disabled={joiningCall}
                      onClick={() => void handleJoinCall(activeRoom.id, false)}
                    >
                      <Phone size={15} aria-hidden="true" />
                      <span className="ky-header-btn-label">{livePeerCount > 0 ? 'Join' : 'Call'}</span>
                    </button>
                    <button
                      type="button"
                      className={`ky-header-call-btn is-primary${livePeerCount > 0 ? ' is-live-call' : ''}`}
                      title={
                        livePeerCount > 0
                          ? `Join active video call (${livePeerCount} in call)`
                          : 'Start video call'
                      }
                      aria-label={livePeerCount > 0 ? `Join video call (${livePeerCount} in call)` : 'Video call'}
                      disabled={joiningCall}
                      onClick={() => void handleJoinCall(activeRoom.id, true)}
                    >
                      {livePeerCount > 0 && <span className="ky-live-dot" aria-hidden="true" />}
                      <Video size={15} aria-hidden="true" />
                      <span className="ky-header-btn-label">{livePeerCount > 0 ? `Join (${livePeerCount})` : 'Video'}</span>
                    </button>
                  </>
                )}
                {inActiveRoomCall && (
                  <button
                    type="button"
                    className="ky-header-call-btn is-danger"
                    title="Leave active call"
                    aria-label="Leave active call"
                    onClick={() => void handleLeaveCall()}
                  >
                    <PhoneOff size={15} aria-hidden="true" />
                    <span className="ky-header-btn-label">Leave</span>
                  </button>
                )}
                <button
                  type="button"
                  className="chat-icon-btn"
                  title={`Search messages (${SEARCH_HINT})`}
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
                  {drawerOpen ? (
                    <PanelRightClose size={16} aria-hidden="true" />
                  ) : (
                    <PanelRightOpen size={16} aria-hidden="true" />
                  )}
                  <span className="chat-header-panel-label">{drawerOpen ? 'Hide' : 'Details'}</span>
                  {activeRoomLobby.length > 0 && (
                    <span className="chat-lobby-pill">{activeRoomLobby.length}</span>
                  )}
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
              <div className="ky-call-mini-bar" role="region" aria-label="Active call controls">
                <span>
                  In call in <strong>{otherCallRoomName}</strong> ({callSnap.tiles.length})
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className={`ky-lobby-btn ${callSnap.audio ? 'is-neutral' : 'is-deny'}`}
                    aria-pressed={callSnap.audio}
                    aria-label="Microphone"
                    title={callSnap.audio ? 'Mute microphone' : 'Unmute microphone'}
                    onClick={() => void callCtrlRef.current?.toggleAudio()}
                  >
                    {callSnap.audio ? <Mic size={12} aria-hidden="true" /> : <MicOff size={12} aria-hidden="true" />}
                    <span>{callSnap.audio ? 'Mic' : 'Muted'}</span>
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => {
                      setActiveRoomId(callSnap.roomId);
                      requestAnimationFrame(() => callStageRef.current?.focus());
                    }}
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
                <span className="ky-guest-banner-copy">
                  Guest waiting-room link ready: <code>{guestLinkBanner.url}</code>
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    onClick={() => {
                      void navigator.clipboard
                        .writeText(guestLinkBanner.url)
                        .then(() => {
                          setGuestLinkBanner((b) => (b ? { ...b, copied: true } : b));
                        })
                        .catch(() => undefined);
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
                  {otherLobbyCount > 0
                    ? ` and ${otherLobbyCount} ${otherLobbyCount === 1 ? 'other' : 'others'}`
                    : ''}{' '}
                  waiting to join
                </span>
                <div className="ky-call-mini-actions">
                  <button
                    type="button"
                    className="ky-lobby-btn is-admit"
                    disabled={lobbyBusy}
                    onClick={() => void handleDecideLobby(activeRoom.id, activeRoomLobby[0].guest_id, true)}
                  >
                    Admit
                  </button>
                  <button
                    type="button"
                    className="ky-lobby-btn is-deny"
                    disabled={lobbyBusy}
                    onClick={() => void handleDecideLobby(activeRoom.id, activeRoomLobby[0].guest_id, false)}
                  >
                    Deny
                  </button>
                  {activeRoomLobby.length > 1 && (
                    <>
                      <button
                        type="button"
                        className="ky-lobby-btn is-admit"
                        disabled={lobbyBusy}
                        onClick={() => void handleAdmitAllLobby(activeRoom.id)}
                      >
                        Admit all
                      </button>
                      <button
                        type="button"
                        className="ky-lobby-btn is-neutral"
                        onClick={() => {
                          setDrawerOpen(true);
                          setRequestedDrawerTab({ tab: 'about', seq: Date.now() });
                          void refreshRoomDetail(activeRoom.id);
                        }}
                      >
                        Review
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}

            {inActiveRoomCall && callSnap && (
              <CallStage
                stageRef={callStageRef}
                snapshot={callSnap}
                sfuAvailable={sfuAvailable}
                externalAudio
                expanded={callExpanded}
                onExpandedChange={setCallExpanded}
                bindShortcuts={false}
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
                        : activeRoom.kind === 'meeting'
                          ? activeRoom.name || 'Meeting room'
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
                    const showUnreadDivider = firstUnreadMsgId === msg.id;
                    const grouped = !showDivider && !showUnreadDivider && isGroupedWithPrevious(prev, msg);
                    return (
                      <React.Fragment key={msg.id}>
                        {showDivider && (
                          <div className="chat-day-divider">
                            <span>{formatDayDivider(msg.created_at)}</span>
                          </div>
                        )}
                        {showUnreadDivider && (
                          <div className="chat-unread-divider" role="separator" aria-label="New messages">
                            <span>New messages</span>
                          </div>
                        )}
                        <MessageRow
                          message={msg}
                          grouped={grouped}
                          currentUserId={currentUser?.id ?? ''}
                          canModerate={Boolean(canModerateActiveRoom)}
                          replyTarget={msg.reply_to_id ? messageById.get(msg.reply_to_id) : undefined}
                          highlighted={highlightedSeq === msg.seq}
                          editTrigger={editTrigger?.messageId === msg.id ? editTrigger.seq : 0}
                          onEditTriggerConsumed={() => setEditTrigger(null)}
                          onEditEnd={() => composerRef.current?.focus()}
                          onReply={(target) => {
                            setActiveReplyTo(target);
                            composerRef.current?.focus();
                          }}
                          onJumpToMessage={(seq) => {
                            void jumpToMessageSeq(activeRoom.id, seq);
                          }}
                          onPreviewImage={(att) => setLightboxAttachment(att)}
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
                                failed.attachments,
                              );
                            }
                          }}
                          onDismissFailed={(key) => {
                            // A dismissed send's uploads are never posted: free their quota now.
                            const dismissed = bucketsRef.current[activeRoom.id]?.messages.find(
                              (m) => m.delivery.kind === 'failed' && m.delivery.idempotencyKey === key,
                            );
                            for (const a of dismissed?.attachments ?? []) {
                              void deleteAttachment(a.id).catch(() => {
                                // Best-effort; the orphan sweep expires it otherwise.
                              });
                            }
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

              {(showJumpLatest || activeBucket?.hasGapAfter) && (
                <button
                  type="button"
                  className="chat-jump-btn"
                  onClick={() => {
                    setUnreadDividerSeq(null);
                    if (activeBucket?.hasGapAfter) {
                      void loadRoomHistory(activeRoom.id, false);
                    } else {
                      scrollToBottom();
                    }
                  }}
                >
                  <ChevronDown size={14} aria-hidden="true" />
                  <span>
                    {missedCount > 0 ? `Jump to latest (${missedCount} new)` : 'Jump to latest'}
                  </span>
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
                    Replying to <strong>{replyTo.sender_name || 'Member'}</strong>:{' '}
                    {replyTo.body ||
                      (replyTo.attachments.length === 1
                        ? `Attachment: ${replyTo.attachments[0].filename}`
                        : `${replyTo.attachments.length} attachments`)}
                  </span>
                  <button
                    type="button"
                    className="chat-icon-btn"
                    onClick={() => setActiveReplyTo(null)}
                    aria-label="Cancel reply"
                  >
                    <X size={14} />
                  </button>
                </div>
              )}

              {activeStaged.length > 0 && (
                <div
                  className={replyTo ? 'chat-staged-tray has-reply' : 'chat-staged-tray'}
                  role="list"
                  aria-label="Pending attachments"
                >
                  {activeStaged.map((item) => (
                    <div
                      key={item.localId}
                      role="listitem"
                      className={`chat-staged-chip${item.kind === 'error' ? ' is-error' : ''}${item.kind === 'uploading' ? ' is-uploading' : ''}`}
                    >
                      {item.kind !== 'error' && item.previewUrl ? (
                        <img
                          src={item.previewUrl}
                          alt=""
                          className="chat-staged-thumb"
                        />
                      ) : (
                        <span className="chat-staged-icon" aria-hidden="true">
                          {item.kind === 'uploading' ? (
                            <Loader2 size={14} className="ky-spin" />
                          ) : (
                            <FileText size={14} />
                          )}
                        </span>
                      )}
                      <span className="chat-staged-meta">
                        <span
                          className="chat-staged-name"
                          title={item.kind === 'ready' ? item.attachment.filename : item.filename}
                        >
                          {item.kind === 'ready' ? item.attachment.filename : item.filename}
                        </span>
                        <span className="chat-staged-sub">
                          {item.kind === 'uploading'
                            ? `Uploading (${formatBytes(item.sizeBytes)})…`
                            : item.kind === 'ready'
                              ? formatBytes(item.attachment.size_bytes)
                              : item.error}
                        </span>
                      </span>
                      <button
                        type="button"
                        className="chat-icon-btn chat-staged-remove"
                        aria-label={`Remove ${item.kind === 'ready' ? item.attachment.filename : item.filename}`}
                        onClick={() => removeStagedAttachment(activeRoom.id, item.localId)}
                      >
                        <X size={13} />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="sr-only"
                aria-label="Upload files"
                disabled={Boolean(activeRoom.closed_at)}
                onChange={(e) => {
                  const picked = e.target.files ? Array.from(e.target.files) : [];
                  e.target.value = '';
                  if (picked.length > 0 && activeRoomId) {
                    uploadFilesForRoom(activeRoomId, picked);
                  }
                }}
              />

              <form
                className={replyTo || activeStaged.length > 0 ? 'chat-composer has-reply' : 'chat-composer'}
                onSubmit={handleComposerSubmit}
              >
                {attachmentLimits.available && (
                  <button
                    type="button"
                    className="chat-attach-btn"
                    disabled={Boolean(activeRoom.closed_at)}
                    title={`Attach files (max ${formatBytes(attachmentLimits.max_upload_bytes)} each)`}
                    aria-label="Attach files"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <Paperclip size={16} aria-hidden="true" />
                  </button>
                )}
                <textarea
                  ref={composerRef}
                  rows={1}
                  disabled={Boolean(activeRoom.closed_at)}
                  placeholder={
                    activeRoom.closed_at
                      ? 'Room is closed'
                      : activeRoom.kind === 'dm'
                        ? `Message ${activeRoom.name || 'teammate'}`
                        : activeRoom.kind === 'meeting'
                          ? `Message ${activeRoom.name || 'meeting'}`
                          : `Message #${activeRoom.name}`
                  }
                  aria-label="Message input"
                  value={draft}
                  onChange={(e) => {
                    setActiveDraft(e.target.value);
                    e.target.style.height = 'auto';
                    e.target.style.height = `${Math.min(e.target.scrollHeight, 144)}px`;
                    if (activeRoomId && e.target.value.trim()) {
                      socketRef.current?.sendTyping(activeRoomId, true);
                    }
                  }}
                  onPaste={(e) => {
                    if (!activeRoomId || activeRoom.closed_at) return;
                    const files = Array.from(e.clipboardData.files);
                    if (files.length > 0) {
                      e.preventDefault();
                      uploadFilesForRoom(activeRoomId, files);
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.nativeEvent.isComposing || e.keyCode === 229) return;
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleComposerSubmit(e);
                    } else if (e.key === 'ArrowUp' && !draft && currentUser) {
                      for (let i = activeMessages.length - 1; i >= 0; i--) {
                        const m = activeMessages[i];
                        if (m.delivery.kind === 'synced' && !m.deleted_at && m.sender_id === currentUser.id) {
                          e.preventDefault();
                          setEditTrigger({ messageId: m.id, seq: Date.now() });
                          break;
                        }
                      }
                    }
                  }}
                />
                <button
                  type="submit"
                  className="chat-send-btn"
                  disabled={
                    Boolean(activeRoom.closed_at) ||
                    hasUploadingAttachments ||
                    (!draft.trim() && readyStagedAttachments.length === 0)
                  }
                  aria-label="Send message"
                >
                  <Send size={15} aria-hidden="true" />
                  <span>Send</span>
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
              <p>Create a channel for your team or start a direct message to get talking.</p>
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
          requestedTab={requestedDrawerTab}
          onClose={() => setDrawerOpen(false)}
          onRefresh={async () => {
            await Promise.all([refreshRoomDetail(activeRoom.id), refreshRoomsList()]);
          }}
          onDecideLobby={(guestId, admit) => handleDecideLobby(activeRoom.id, guestId, admit)}
          onAdmitAllLobby={() => handleAdmitAllLobby(activeRoom.id)}
          onCreateGuestLink={() => handleCreateGuestLink(activeRoom.id)}
          onNotifyModeChanged={handleNotifyModeChanged}
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

      {modal === 'search' && currentUser && (
        <SearchModal
          userId={currentUser.id}
          rooms={rooms}
          activeRoomId={activeRoomId}
          onClose={() => setModal('none')}
          onSelectHit={(roomId, seq) => {
            if (roomId === activeRoomId && seq) {
              void jumpToMessageSeq(roomId, seq);
            } else {
              setActiveRoomId(roomId);
              if (seq) setPendingJump({ roomId, seq });
            }
          }}
        />
      )}

      {lightboxAttachment && (
        <div
          className="chat-lightbox-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label={`Image preview: ${lightboxAttachment.filename}`}
          onClick={() => setLightboxAttachment(null)}
        >
          <div className="chat-lightbox-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="chat-lightbox-header">
              <div className="chat-lightbox-title">
                <strong>{lightboxAttachment.filename}</strong>
                <span>{formatBytes(lightboxAttachment.size_bytes)}</span>
              </div>
              <div className="chat-lightbox-actions">
                <a
                  href={attachmentUrl(lightboxAttachment.id)}
                  download={lightboxAttachment.filename}
                  className="btn-secondary chat-lightbox-dl"
                >
                  <Download size={14} aria-hidden="true" />
                  <span>Download</span>
                </a>
                <button
                  type="button"
                  className="chat-icon-btn"
                  aria-label="Close image preview"
                  onClick={() => setLightboxAttachment(null)}
                >
                  <X size={16} />
                </button>
              </div>
            </div>
            <div className="chat-lightbox-body">
              <img
                src={attachmentUrl(lightboxAttachment.id, true)}
                alt={lightboxAttachment.filename}
                className="chat-lightbox-img"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
