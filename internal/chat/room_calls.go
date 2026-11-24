package chat

import (
	"context"
	"errors"
	"hash/fnv"
	"strconv"
	"sync"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

const roomOwnerTTL = 90 * time.Second

// Room affinity keeps each room's latency-sensitive seats and SDP on one process. The
// database holds a fenced recovery record, not a second distributed signaling engine.
type roomRouting struct {
	holder    string
	afterFunc func(time.Duration, func()) *time.Timer
	locks     [64]sync.Mutex // bounded stripes; colliding rooms only serialize control operations
}

func (m *CallManager) EnableRoomRouting() {
	m.routing = &roomRouting{holder: uuid.NewString(), afterFunc: time.AfterFunc}
}

func (m *CallManager) lockRoom(room string) func() {
	h := fnv.New64a()
	_, _ = h.Write([]byte(room))
	lock := &m.routing.locks[h.Sum64()%uint64(len(m.routing.locks))]
	lock.Lock()
	return lock.Unlock
}

// ClaimRoom is called only after HTTP/WS authentication and exact room authorization.
func (m *CallManager) ClaimRoom(ctx context.Context, tenant, room string) error {
	if m.routing == nil {
		return nil
	}
	defer m.lockRoom(room)()
	_, err := m.ownedRoom(ctx, tenant, room)
	return err
}

// ownedRoom is serialized by the room stripe. A new generation recovers the persisted
// call identity/policy, retires old media and requires peers to rejoin with fresh credentials.
func (m *CallManager) ownedRoom(ctx context.Context, tenant, room string) (*activeCall, error) {
	lease, err := m.chatStore.AcquireCallRoom(ctx, tenant, room, m.routing.holder, roomOwnerTTL)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	cached := m.calls[room]
	m.mu.Unlock()
	if cached == nil || cached.session.OwnerGeneration != lease.Generation {
		previousOwner := cached != nil
		session, err := m.chatStore.RecoverCallSession(ctx, lease)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, m.DrainCleanup(ctx, tenant, "")
		}
		policy, err := m.chatStore.GetTenant(ctx, tenant)
		if err != nil {
			return nil, err
		}
		cached = &activeCall{session: *session, tenant: *policy, peers: make(map[string]*callPeer)}
		m.mu.Lock()
		m.forgetRoomLocked(room)
		m.calls[room] = cached
		m.mu.Unlock()
		if previousOwner && m.hub != nil {
			m.hub.CloseRoomCalls(room)
		}
	}
	if cached.ending {
		return nil, m.endOwnedRoom(ctx, cached)
	}
	fresh, err := m.chatStore.GetActiveCallSession(ctx, tenant, room)
	if err != nil {
		return nil, err
	}
	fresh.OwnerID, fresh.OwnerGeneration = lease.Holder, lease.Generation
	seats, err := m.chatStore.CallSeats(ctx, tenant, room)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	changed := fresh.Epoch != cached.session.Epoch || fresh.Mode != cached.session.Mode
	cached.session = *fresh
	// Primary seat deletion is authoritative even when this process missed its bus event.
	var removed []string
	for id, peer := range cached.peers {
		valid := false
		for _, seat := range seats {
			if seat.UserID == peer.UserID && seat.PeerID == id && seat.SessionHash == peer.sessionHash {
				valid = true
				break
			}
		}
		if valid && peer.issuedEpoch < fresh.Epoch {
			changed = true
		}
		if !valid {
			removed = append(removed, id)
		}
	}
	empty := len(cached.peers) > 0 && len(removed) == len(cached.peers)
	if !empty {
		for _, id := range removed {
			m.removePeerLocked(room, cached, id)
		}
	}
	if !empty && len(cached.peers) > 0 {
		m.maybeScheduleStepDownLocked(room, cached)
	}
	var roster CallStatePayload
	if len(removed) > 0 && !empty {
		roster = m.buildStateLocked(cached, true)
	}
	m.mu.Unlock()
	if empty {
		// A newly recovered owner has no cached peers and still permits a fresh rejoin.
		return nil, m.endOwnedRoom(ctx, cached)
	}
	if len(removed) > 0 {
		// Roster revocation must not wait for media cleanup or an epoch change.
		m.broadcastState(ctx, room, roster)
	}
	if err := m.DrainCleanup(ctx, tenant, ""); err != nil {
		return nil, err
	}
	if changed {
		if err := m.migrateOwnedPeers(ctx, cached, "media_reconciled"); err != nil {
			return nil, err
		}
	}
	return cached, nil
}

// endOwnedRoom retains explicit end intent across a failed durable write. Empty recovery
// caches remain distinct: only a failed start or a previously populated call enters here.
func (m *CallManager) endOwnedRoom(ctx context.Context, c *activeCall) error {
	m.mu.Lock()
	c.ending = true
	state := m.buildStateLocked(c, false)
	state.Peers = []CallPeerState{}
	m.mu.Unlock()
	m.broadcastState(ctx, c.session.RoomID, state)
	if err := m.chatStore.EndOwnedCallSession(ctx, &c.session, 0); err != nil {
		return err
	}
	m.mu.Lock()
	m.forgetRoomLocked(c.session.RoomID)
	m.mu.Unlock()
	return m.DrainCleanup(ctx, c.session.TenantID, "")
}

func (m *CallManager) forgetRoomLocked(room string) {
	if c := m.calls[room]; c != nil {
		c.stopStepDownLocked()
		for id := range c.peers {
			m.removePeerLocked(room, c, id)
		}
	}
	delete(m.calls, room)
}

func (m *CallManager) removePeerLocked(room string, c *activeCall, id string) {
	p := c.peers[id]
	if p.disconnectTimer != nil {
		p.disconnectTimer.Stop()
	}
	delete(c.peers, id)
	if calls := m.userCalls[p.UserID]; calls != nil {
		delete(calls, room)
		if len(calls) == 0 {
			delete(m.userCalls, p.UserID)
		}
	}
}

func (m *CallManager) joinOwned(ctx context.Context, req JoinCallRequest) (response *JoinCallResponse, err error) {
	defer m.lockRoom(req.RoomID)()
	c, err := m.ownedRoom(ctx, req.TenantID, req.RoomID)
	if err != nil {
		return nil, err
	}
	tenant, err := m.chatStore.GetTenant(ctx, req.TenantID)
	if err != nil || tenant.Status != store.TenantStatusActive {
		return nil, ErrTenantInactive
	}
	m.mu.Lock()
	var previous *callPeer
	if c != nil {
		for _, p := range c.peers {
			if p.UserID == req.UserID {
				previous = p
				break
			}
		}
	}
	m.mu.Unlock()
	// Another authenticated session cannot inherit its predecessor's SFU bearer or SDP seat.
	if previous != nil && previous.sessionHash != req.SessionHash {
		if err := m.chatStore.QueueOwnedCallSeatRemoval(ctx, &c.session, store.CallSeat{UserID: req.UserID, PeerID: previous.PeerID, SessionHash: previous.sessionHash, Guest: previous.IsGuest}); err != nil {
			return nil, err
		}
		c, err = m.ownedRoom(ctx, req.TenantID, req.RoomID)
		if err != nil {
			return nil, err
		}
		previous = nil
	}
	created := c == nil
	if created {
		lease, err := m.chatStore.AcquireCallRoom(ctx, req.TenantID, req.RoomID, m.routing.holder, roomOwnerTTL)
		if err != nil {
			return nil, err
		}
		c = &activeCall{session: store.CallSession{ID: "call_" + uuid.Must(uuid.NewV7()).String(), TenantID: req.TenantID, RoomID: req.RoomID, Mode: store.CallModeP2PMesh, Epoch: 1, StartedBy: req.UserID, OwnerID: lease.Holder, OwnerGeneration: lease.Generation}, tenant: *tenant, peers: make(map[string]*callPeer)}
	}
	peerID := "peer_" + uuid.Must(uuid.NewV7()).String()
	if previous != nil {
		peerID = previous.PeerID
	}
	peer := &callPeer{CallPeerState: CallPeerState{PeerID: peerID, UserID: req.UserID, DisplayName: req.DisplayName, IsGuest: req.IsGuest, Audio: req.Audio, Video: req.Video, ScreenShare: req.ScreenShare, ProtectIP: req.ProtectIP, ECDHPubJWK: req.ECDHPubJWK, JoinedAt: time.Now().UTC().UnixMilli()}, sessionHash: req.SessionHash}
	m.mu.Lock()
	candidate := make(map[string]*callPeer, len(c.peers)+1)
	for k, v := range c.peers {
		candidate[k] = v
	}
	candidate[peerID] = peer
	mode, reason, strict := evaluateCallMode(*tenant, c.session.SFUSticky, candidate)
	session := c.session
	m.mu.Unlock()
	if !created && session.Mode == store.CallModeSFULiveKit && mode == store.CallModeP2PMesh {
		// Only stepDownOwned may lower privacy after its delay and durable retirement.
		mode = store.CallModeSFULiveKit
		strict = true
	}
	if mode == store.CallModeSFULiveKit && m.livekit == nil {
		if strict {
			return nil, ErrSFUUnavailable
		}
		mode = store.CallModeP2PMesh
	}
	changed := session.Mode != mode
	if changed {
		session.Mode = mode
		session.Epoch++
	}
	if mode == store.CallModeSFULiveKit && (session.LiveKitRoom == "" || changed) {
		session.LiveKitRoom = mediaRoom(session)
	}
	seat := store.CallSeat{UserID: req.UserID, PeerID: peerID, SessionHash: req.SessionHash, Guest: req.IsGuest}
	if created {
		err = m.chatStore.CreateOwnedCallSession(ctx, &session, seat)
	} else {
		err = m.chatStore.UpdateCallSession(ctx, &session)
		if err == nil {
			err = m.chatStore.PutCallSeat(ctx, &session, seat)
		}
	}
	if err != nil {
		return nil, err
	}
	completed := false
	defer func() {
		if !completed {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if created {
				// Cache end intent even when external setup failed before the normal cache install.
				m.mu.Lock()
				c.session = session
				m.calls[req.RoomID] = c
				m.mu.Unlock()
				err = errors.Join(err, m.endOwnedRoom(cleanupCtx, c))
			} else {
				err = errors.Join(err, m.chatStore.QueueOwnedCallSeatRemoval(cleanupCtx, &session, seat))
			}
		}
	}()
	if mode == store.CallModeSFULiveKit {
		if err := m.livekit.CreateRoom(ctx, session.LiveKitRoom, req.RoomID); err != nil {
			return nil, err
		}
	}
	m.mu.Lock()
	c.session = session
	c.tenant = *tenant
	peer.issuedEpoch = session.Epoch
	if previous != nil && previous.disconnectTimer != nil {
		previous.disconnectTimer.Stop()
	}
	c.peers[peerID] = peer
	m.calls[req.RoomID] = c
	if m.userCalls[req.UserID] == nil {
		m.userCalls[req.UserID] = make(map[string]string)
	}
	m.userCalls[req.UserID][req.RoomID] = peerID
	m.maybeScheduleStepDownLocked(req.RoomID, c)
	state := m.buildStateLocked(c, true)
	m.mu.Unlock()
	if changed {
		if err := m.migrateOwnedPeers(ctx, c, reason); err != nil {
			return nil, err
		}
	}
	// Repeat the durable admission check after external work, before returning a credential.
	if err := m.chatStore.PutCallSeat(ctx, &session, store.CallSeat{UserID: req.UserID, PeerID: peerID, SessionHash: req.SessionHash, Guest: req.IsGuest}); err != nil {
		return nil, err
	}
	response = &JoinCallResponse{CallID: session.ID, RoomID: req.RoomID, PeerID: peerID, Mode: mode, Epoch: session.Epoch, SFUSticky: session.SFUSticky, SFUAvailable: m.SFUAvailable(), ICEServers: m.ICEServers(), Peers: state.Peers, Started: created}
	if mode == store.CallModeSFULiveKit {
		response.LiveKitURL = m.LiveKitURL()
		response.LiveKitToken = m.livekit.JoinToken(session.LiveKitRoom, peerID, req.DisplayName, "", rtc.DefaultTokenTTL)
	}
	m.broadcastState(ctx, req.RoomID, state)
	if mode == store.CallModeP2PMesh && m.hub != nil && m.hub.HasRoomCallSocket(req.UserID, req.RoomID, req.SessionHash) {
		if err := m.notifyP2PPeerReady(ctx, c, peerID); err != nil {
			return nil, err
		}
	}
	completed = true
	return response, nil
}

// notifyP2PPeerReady asks only existing authenticated seats to resend an unanswered
// offer after the newcomer's socket exists. It changes no epoch, mode or bearer.
func (m *CallManager) notifyP2PPeerReady(ctx context.Context, c *activeCall, peerID string) error {
	m.mu.Lock()
	session := c.session
	ready := c.peers[peerID].CallPeerState
	var peers []callPeer
	for id, p := range c.peers {
		if id != peerID {
			peers = append(peers, *p)
		}
	}
	m.mu.Unlock()
	for _, p := range peers {
		if err := m.chatStore.PutCallSeat(ctx, &session, store.CallSeat{UserID: p.UserID, PeerID: p.PeerID, SessionHash: p.sessionHash, Guest: p.IsGuest}); err != nil {
			return err
		}
		notice := CallMigratePayload{CallID: session.ID, RoomID: session.RoomID, Epoch: session.Epoch, TargetMode: store.CallModeP2PMesh, Reason: "peer_signaling_ready", Peers: []CallPeerState{ready}}
		if err := m.hub.PublishUser(ctx, p.UserID, Event{Type: EventCallMigrate, RoomID: session.RoomID, UserID: p.UserID, SessionHash: p.sessionHash, Data: MustMarshalData(notice)}); err != nil {
			return err
		}
	}
	return nil
}

func mediaRoom(cs store.CallSession) string { return "ky_" + cs.ID + "_e" + strconv.Itoa(cs.Epoch) }

// migrateOwnedPeers binds the exact new epoch to each still-valid principal before
// sending a credential. A primary failure never becomes a guessed successful grant.
func (m *CallManager) migrateOwnedPeers(ctx context.Context, c *activeCall, reason string) error {
	m.mu.Lock()
	session := c.session
	state := m.buildStateLocked(c, true)
	peers := make([]callPeer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, *p)
	}
	m.mu.Unlock()
	if session.Mode == store.CallModeSFULiveKit {
		if m.livekit == nil {
			return ErrSFUUnavailable
		}
		if err := m.livekit.CreateRoom(ctx, session.LiveKitRoom, session.RoomID); err != nil {
			return err
		}
	}
	for _, p := range peers {
		if p.issuedEpoch >= session.Epoch {
			continue
		}
		if err := m.chatStore.PutCallSeat(ctx, &session, store.CallSeat{UserID: p.UserID, PeerID: p.PeerID, SessionHash: p.sessionHash, Guest: p.IsGuest}); err != nil {
			return err
		}
		migration := CallMigratePayload{CallID: session.ID, RoomID: session.RoomID, Epoch: session.Epoch, TargetMode: session.Mode, Reason: reason, Peers: state.Peers}
		if session.Mode == store.CallModeSFULiveKit {
			migration.LiveKitURL = m.LiveKitURL()
			migration.LiveKitToken = m.livekit.JoinToken(session.LiveKitRoom, p.PeerID, p.DisplayName, "", rtc.DefaultTokenTTL)
		}
		if m.hub != nil {
			if err := m.hub.PublishUser(ctx, p.UserID, Event{Type: EventCallMigrate, RoomID: session.RoomID, UserID: p.UserID, SessionHash: p.sessionHash, Data: MustMarshalData(migration)}); err != nil {
				return err
			}
		}
		m.mu.Lock()
		if current := c.peers[p.PeerID]; current != nil {
			current.issuedEpoch = session.Epoch
		}
		m.mu.Unlock()
	}
	m.broadcastState(ctx, session.RoomID, state)
	return nil
}

// HandleRoomDisconnect allows the existing 20s guest/reconnect window for transport
// loss only. Explicit leave and primary revocation still remove seats immediately.
func (m *CallManager) HandleRoomDisconnect(user, room, hash string) {
	defer m.lockRoom(room)()
	if m.hub != nil && m.hub.HasRoomCallSocket(user, room, hash) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.calls[room]
	if c == nil || c.ending {
		return
	}
	for _, peer := range c.peers {
		if peer.UserID != user || peer.sessionHash != hash {
			continue
		}
		m.scheduleRoomDisconnectLocked(user, room, hash, peer)
		return
	}
}

func (m *CallManager) scheduleRoomDisconnectLocked(user, room, hash string, peer *callPeer) {
	if peer.disconnectTimer != nil {
		peer.disconnectTimer.Stop()
	}
	peer.disconnectTimer = m.routing.afterFunc(DefaultGuestLeaveGrace, func() { m.expireRoomDisconnect(user, room, hash, peer) })
}

func (m *CallManager) expireRoomDisconnect(user, room, hash string, expected *callPeer) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer m.lockRoom(room)()
	m.mu.Lock()
	c := m.calls[room]
	current := c != nil && c.peers[expected.PeerID] == expected
	if current {
		expected.disconnectTimer = nil
	}
	m.mu.Unlock()
	if !current {
		return
	} // Rejoin replaced the peer, even if its socket is still opening.
	if err := m.leaveOwnedLocked(ctx, room, user, hash, true); err != nil {
		m.mu.Lock()
		if c := m.calls[room]; c != nil && c.peers[expected.PeerID] == expected {
			m.scheduleRoomDisconnectLocked(user, room, hash, expected)
		}
		m.mu.Unlock()
	}
}

func (m *CallManager) leaveOwned(ctx context.Context, room, user, hash string, disconnected bool) error {
	defer m.lockRoom(room)()
	return m.leaveOwnedLocked(ctx, room, user, hash, disconnected)
}

func (m *CallManager) leaveOwnedLocked(ctx context.Context, room, user, hash string, disconnected bool) error {
	if disconnected && m.hub != nil && m.hub.HasRoomCallSocket(user, room, hash) {
		return nil
	}
	m.mu.Lock()
	c := m.calls[room]
	m.mu.Unlock()
	if c == nil {
		if !disconnected && hash == "" {
			return m.chatStore.QueueCallSeatRemoval(ctx, room, user)
		}
		return nil
	}
	c, err := m.ownedRoom(ctx, c.session.TenantID, room)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	m.mu.Lock()
	var removed *callPeer
	for _, p := range c.peers {
		if p.UserID == user && (hash == "" || hash == p.sessionHash) {
			copy := *p
			removed = &copy
			break
		}
	}
	m.mu.Unlock()
	if removed != nil {
		if err := m.chatStore.QueueOwnedCallSeatRemoval(ctx, &c.session, store.CallSeat{UserID: user, PeerID: removed.PeerID, SessionHash: removed.sessionHash, Guest: removed.IsGuest}); err != nil {
			return err
		}
		c, err = m.ownedRoom(ctx, c.session.TenantID, room)
		if err != nil {
			return err
		}
		if c == nil {
			return nil // Primary reconciliation already ended and cleaned the empty call.
		}
	}
	m.mu.Lock()
	empty := len(c.peers) == 0
	state := m.buildStateLocked(c, !empty)
	if !empty {
		m.maybeScheduleStepDownLocked(room, c)
	}
	m.mu.Unlock()
	if empty {
		if err := m.chatStore.EndOwnedCallSession(ctx, &c.session, 0); err != nil {
			return err
		}
		m.mu.Lock()
		m.forgetRoomLocked(room)
		m.mu.Unlock()
	}
	m.broadcastState(ctx, room, state)
	return m.DrainCleanup(ctx, c.session.TenantID, "")
}

func (m *CallManager) escalateOwned(ctx context.Context, room, user, reason string) (*CallStatePayload, error) {
	defer m.lockRoom(room)()
	m.mu.Lock()
	c := m.calls[room]
	m.mu.Unlock()
	if c == nil {
		return nil, ErrCallNotActive
	}
	c, err := m.ownedRoom(ctx, c.session.TenantID, room)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrCallNotActive
	}
	m.mu.Lock()
	inCall := false
	for _, p := range c.peers {
		if p.UserID == user {
			inCall = true
			break
		}
	}
	session := c.session
	m.mu.Unlock()
	if !inCall {
		return nil, store.ErrForbidden
	}
	if m.livekit == nil {
		return nil, ErrSFUUnavailable
	}
	if reason == "ice_failed" {
		session.SFUSticky = true
	}
	if session.Mode != store.CallModeSFULiveKit {
		session.Mode = store.CallModeSFULiveKit
		session.Epoch++
		session.LiveKitRoom = mediaRoom(session)
	}
	if err := m.chatStore.UpdateCallSession(ctx, &session); err != nil {
		return nil, err
	}
	m.mu.Lock()
	c.session = session
	c.stopStepDownLocked()
	m.mu.Unlock()
	if err := m.migrateOwnedPeers(ctx, c, reason); err != nil {
		return nil, err
	}
	m.mu.Lock()
	state := m.buildStateLocked(c, true)
	m.mu.Unlock()
	return &state, nil
}

func (m *CallManager) handleOwnedFrame(ctx context.Context, user string, frame ClientFrame) {
	unlock := m.lockRoom(frame.RoomID)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	m.mu.Lock()
	c := m.calls[frame.RoomID]
	m.mu.Unlock()
	if c == nil {
		return
	}
	c, err := m.ownedRoom(ctx, c.session.TenantID, frame.RoomID)
	if err != nil || c == nil || c.session.ID != frame.CallID {
		return
	}
	m.mu.Lock()
	var from *callPeer
	for _, p := range c.peers {
		if p.UserID == user && p.sessionHash == frame.SessionHash {
			copy := *p
			from = &copy
			break
		}
	}
	m.mu.Unlock()
	if from == nil {
		return
	}
	if err := m.chatStore.PutCallSeat(ctx, &c.session, store.CallSeat{UserID: user, PeerID: from.PeerID, SessionHash: from.sessionHash, Guest: from.IsGuest}); err != nil {
		return
	}
	switch frame.Type {
	case ClientFrameCallSignal:
		switch frame.Kind {
		case "offer", "answer", "ice", "e2ee_key":
		default:
			return
		}
		if len(frame.Data) == 0 {
			return
		}
		m.mu.Lock()
		target := c.peers[frame.ToPeerID]
		var to callPeer
		if target != nil {
			to = *target
		}
		m.mu.Unlock()
		if target == nil || from.PeerID == to.PeerID {
			return
		}
		if err := m.chatStore.PutCallSeat(ctx, &c.session, store.CallSeat{UserID: to.UserID, PeerID: to.PeerID, SessionHash: to.sessionHash, Guest: to.IsGuest}); err != nil {
			return
		}
		_ = m.hub.PublishUser(ctx, to.UserID, Event{Type: EventCallSignal, RoomID: frame.RoomID, UserID: to.UserID, SessionHash: to.sessionHash, Data: MustMarshalData(CallSignalPayload{CallID: c.session.ID, RoomID: frame.RoomID, FromPeerID: from.PeerID, ToPeerID: to.PeerID, Kind: frame.Kind, Data: frame.Data})})
	case ClientFrameCallICEFailed:
		unlock()
		unlock = nil
		_, _ = m.escalateOwned(ctx, frame.RoomID, user, "ice_failed")
	case ClientFrameCallMigrated:
		m.mu.Lock()
		if p := c.peers[from.PeerID]; p != nil && frame.Epoch == c.session.Epoch {
			p.migratedEpoch = frame.Epoch
		}
		m.mu.Unlock()
	case ClientFrameCallMedia:
		m.mu.Lock()
		p := c.peers[from.PeerID]
		if frame.Audio != nil {
			p.Audio = *frame.Audio
		}
		if frame.Video != nil {
			p.Video = *frame.Video
		}
		if frame.ScreenShare != nil {
			p.ScreenShare = *frame.ScreenShare
		}
		if frame.ProtectIP != nil && (!*frame.ProtectIP || m.livekit != nil) {
			p.ProtectIP = *frame.ProtectIP
		}
		mode, reason, _ := evaluateCallMode(c.tenant, c.session.SFUSticky, c.peers)
		escalate := c.session.Mode == store.CallModeP2PMesh && mode == store.CallModeSFULiveKit && m.livekit != nil
		if !escalate {
			m.maybeScheduleStepDownLocked(frame.RoomID, c)
		}
		state := m.buildStateLocked(c, true)
		m.mu.Unlock()
		if escalate {
			unlock()
			unlock = nil
			_, _ = m.escalateOwned(ctx, frame.RoomID, user, reason)
		} else {
			m.broadcastState(ctx, frame.RoomID, state)
		}
	}
}

func (m *CallManager) stepDownOwned(room, call string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer m.lockRoom(room)()
	m.mu.Lock()
	c := m.calls[room]
	m.mu.Unlock()
	if c == nil || c.session.ID != call {
		return
	}
	c, err := m.ownedRoom(ctx, c.session.TenantID, room)
	if err != nil || c == nil {
		return
	}
	m.mu.Lock()
	c.stepDownTimer = nil
	mode, reason, _ := evaluateCallMode(c.tenant, c.session.SFUSticky, c.peers)
	session := c.session
	empty := len(c.peers) == 0
	m.mu.Unlock()
	if empty || mode != store.CallModeP2PMesh || session.Mode != store.CallModeSFULiveKit {
		return
	}
	// Retire the SFU address before handing out a lower-privacy transport epoch.
	if err := m.chatStore.QueueCallRoomRemoval(ctx, session.TenantID, session.LiveKitRoom); err != nil {
		return
	}
	if err := m.DrainCleanup(ctx, session.TenantID, ""); err != nil {
		return
	}
	session.Mode = mode
	session.Epoch++
	session.LiveKitRoom = ""
	if err := m.chatStore.UpdateCallSession(ctx, &session); err != nil {
		return
	}
	m.mu.Lock()
	c.session = session
	m.mu.Unlock()
	_ = m.migrateOwnedPeers(ctx, c, reason)
}

func (m *CallManager) reconcileOwned(ctx context.Context) {
	m.mu.Lock()
	rooms := make(map[string]string, len(m.calls))
	for room, c := range m.calls {
		rooms[room] = c.session.TenantID
	}
	m.mu.Unlock()
	for room, tenant := range rooms {
		unlock := m.lockRoom(room)
		_, err := m.ownedRoom(ctx, tenant, room)
		if errors.Is(err, store.ErrCallOwnerLost) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrForbidden) {
			m.mu.Lock()
			m.forgetRoomLocked(room)
			m.mu.Unlock()
			if m.hub != nil {
				m.hub.CloseRoomCalls(room)
			}
		}
		unlock()
	}
}

// LeaveCall reports durable cleanup failure to an HTTP caller instead of acknowledging an
// incomplete SFU departure. Lobby and revocation callbacks retain their retryable queue.
func (m *CallManager) LeaveCall(ctx context.Context, room, user string) error {
	if m.routing != nil {
		return m.leaveOwned(ctx, room, user, "", false)
	}
	m.Leave(ctx, room, user)
	return nil
}
