package chat

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

const (
	// DefaultStepDownDelay prevents ping-ponging between SFU and P2P when participants
	// briefly leave and reconnect.
	DefaultStepDownDelay = 60 * time.Second
)

var (
	// ErrSFUUnavailable is returned when policy or privacy requires SFU mode (sfu_only,
	// protect_ip, or guest_force_sfu) but LiveKit is not configured on this server.
	ErrSFUUnavailable = errors.New("livekit sfu is not configured on this server")
	// ErrTenantInactive is returned when the call's organization is suspended or deleted.
	ErrTenantInactive = errors.New("organization is suspended or inactive")
	// ErrCallSeatLost is returned when the joining peer left or was replaced during setup.
	ErrCallSeatLost = errors.New("call seat ended while joining")
	// ErrCallNotActive is returned when operating on a room without an active call.
	ErrCallNotActive = errors.New("no active call in this room")
)

// JoinCallRequest carries client capabilities and preferences when joining a room call.
type JoinCallRequest struct {
	TenantID    string          `json:"-"`
	RoomID      string          `json:"-"`
	UserID      string          `json:"-"`
	DisplayName string          `json:"-"`
	IsGuest     bool            `json:"-"`
	Audio       bool            `json:"audio"`
	Video       bool            `json:"video"`
	ScreenShare bool            `json:"screen_share"`
	ProtectIP   bool            `json:"protect_ip"`
	ECDHPubJWK  json.RawMessage `json:"ecdh_pub_jwk,omitempty"`
}

// JoinCallResponse returns the authoritative transport mode, peer roster, STUN servers,
// and (when in sfu_livekit mode) a scoped LiveKit JWT.
type JoinCallResponse struct {
	CallID       string          `json:"call_id"`
	RoomID       string          `json:"room_id"`
	PeerID       string          `json:"peer_id"`
	Mode         string          `json:"mode"`
	Epoch        int             `json:"epoch"`
	SFUSticky    bool            `json:"sfu_sticky"`
	SFUAvailable bool            `json:"sfu_available"`
	ICEServers   []ICEServer     `json:"ice_servers"`
	LiveKitURL   string          `json:"livekit_url,omitempty"`
	LiveKitToken string          `json:"livekit_token,omitempty"`
	Peers        []CallPeerState `json:"peers"`
	Started      bool            `json:"-"`
}

// ICEServer matches the browser RTCIceServer JSON shape.
type ICEServer struct {
	URLs []string `json:"urls"`
}

// CallStats summarizes live voice/video calls across the pod.
type CallStats struct {
	ActiveCalls int `json:"active_calls"`
	P2PCalls    int `json:"p2p_calls"`
	SFUCalls    int `json:"sfu_calls"`
	ActivePeers int `json:"active_peers"`
}

type activeCall struct {
	session       store.CallSession
	tenant        store.Tenant
	peers         map[string]*callPeer // peerID -> peer
	stepDownTimer *time.Timer
}

type callPeer struct {
	CallPeerState
	migratedEpoch int
}

// CallManager coordinates hybrid P2P-first / LiveKit SFU voice and video calls.
type CallManager struct {
	chatStore     store.ChatStore
	hub           *Hub
	livekit       *rtc.Client
	stunURLs      []string
	stepDownDelay time.Duration

	// userActive, when set, reports whether a member's account still serves; reconciliation
	// takes out of their calls the peers whose account does not (a missed revocation).
	userActive func(ctx context.Context, userID string) (bool, error)

	mu        sync.Mutex
	calls     map[string]*activeCall       // roomID -> call
	userCalls map[string]map[string]string // userID -> roomID -> peerID
}

// NewCallManager constructs a CallManager and wires it into Hub for signaling & cleanup.
func NewCallManager(chatStore store.ChatStore, hub *Hub, livekit *rtc.Client, stunURLs []string) *CallManager {
	m := &CallManager{
		chatStore:     chatStore,
		hub:           hub,
		livekit:       livekit,
		stunURLs:      append([]string(nil), stunURLs...),
		stepDownDelay: DefaultStepDownDelay,
		calls:         make(map[string]*activeCall),
		userCalls:     make(map[string]map[string]string),
	}
	if hub != nil {
		hub.SetCallFrameHandler(m.HandleClientFrame)
	}
	return m
}

// SetStepDownDelay overrides the SFU -> P2P hysteretic step-down wait (useful for tests).
func (m *CallManager) SetStepDownDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stepDownDelay = d
}

// SFUAvailable reports whether LiveKit SFU escalation is configured.
func (m *CallManager) SFUAvailable() bool {
	return m.livekit != nil
}

// LiveKitURL returns the browser-facing wss:// or ws:// LiveKit URL, or "" if disabled.
func (m *CallManager) LiveKitURL() string {
	if m.livekit == nil {
		return ""
	}
	return m.livekit.WSURL()
}

// ICEServers returns the configured STUN servers for P2P calls.
func (m *CallManager) ICEServers() []ICEServer {
	if len(m.stunURLs) == 0 {
		return []ICEServer{}
	}
	return []ICEServer{{URLs: append([]string(nil), m.stunURLs...)}}
}

// Stats returns live call metrics for health/dashboard reporting.
func (m *CallManager) Stats() CallStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s CallStats
	s.ActiveCalls = len(m.calls)
	for _, c := range m.calls {
		if c.session.Mode == store.CallModeSFULiveKit {
			s.SFUCalls++
		} else {
			s.P2PCalls++
		}
		s.ActivePeers += len(c.peers)
	}
	return s
}

// GetState returns the current call state for roomID, or nil if no call is active.
func (m *CallManager) GetState(roomID string) *CallStatePayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.calls[roomID]
	if c == nil {
		return nil
	}
	st := m.buildStateLocked(c, true)
	return &st
}

// Join starts or joins the active call in req.RoomID, evaluating P2P vs SFU policy.
func (m *CallManager) Join(ctx context.Context, req JoinCallRequest) (*JoinCallResponse, error) {
	if req.TenantID == "" {
		req.TenantID = store.DefaultTenantID
	}
	tenant, err := m.chatStore.GetTenant(ctx, req.TenantID)
	if err == nil && tenant.Status != store.TenantStatusActive {
		return nil, ErrTenantInactive
	}
	if err != nil {
		// Fall back to safe defaults if tenant row is missing in unit tests.
		tenant = &store.Tenant{
			ID:            req.TenantID,
			P2PPolicy:     store.P2PPolicyHybrid,
			P2PMaxVideo:   2,
			P2PMaxAudio:   4,
			GuestForceSFU: true,
		}
	}

	m.mu.Lock()
	c := m.calls[req.RoomID]
	created := false
	if c == nil {
		callID := "call_" + uuid.Must(uuid.NewV7()).String()
		c = &activeCall{
			session: store.CallSession{
				ID:        callID,
				TenantID:  req.TenantID,
				RoomID:    req.RoomID,
				Mode:      store.CallModeP2PMesh,
				Epoch:     1,
				StartedBy: req.UserID,
				StartedAt: time.Now().UTC().UnixMilli(),
			},
			tenant: *tenant,
			peers:  make(map[string]*callPeer),
		}
		created = true
	} else {
		// Refresh tenant policy on join so admin changes take effect promptly.
		c.tenant = *tenant
	}

	// Replace any stale peer record for the same userID in this room (e.g. tab refresh).
	var existingPeerID string
	for pid, p := range c.peers {
		if p.UserID == req.UserID {
			existingPeerID = pid
			break
		}
	}
	peerID := existingPeerID
	if peerID == "" {
		peerID = "peer_" + uuid.Must(uuid.NewV7()).String()
	}

	peer := &callPeer{
		CallPeerState: CallPeerState{
			PeerID:      peerID,
			UserID:      req.UserID,
			DisplayName: req.DisplayName,
			IsGuest:     req.IsGuest,
			Audio:       req.Audio,
			Video:       req.Video,
			ScreenShare: req.ScreenShare,
			ProtectIP:   req.ProtectIP,
			ECDHPubJWK:  req.ECDHPubJWK,
			JoinedAt:    time.Now().UTC().UnixMilli(),
		},
	}

	// Temporarily evaluate candidate peer map before mutating live state so strict privacy
	// failures (ErrSFUUnavailable) leave existing call state untouched.
	candPeers := make(map[string]*callPeer, len(c.peers)+1)
	for k, v := range c.peers {
		candPeers[k] = v
	}
	candPeers[peerID] = peer

	desiredMode, reason, strictSFU := evaluateCallMode(c.tenant, c.session.SFUSticky, candPeers)
	if desiredMode == store.CallModeSFULiveKit && m.livekit == nil {
		if strictSFU {
			m.mu.Unlock()
			return nil, ErrSFUUnavailable
		}
		// LiveKit is optional in local/small deployments: continue best-effort P2P when
		// escalation was only due to participant count/video budget.
		desiredMode = store.CallModeP2PMesh
	}

	// Commit peer into activeCall.
	prevMode := c.session.Mode
	c.peers[peerID] = peer
	if created {
		c.session.Mode = desiredMode
		if desiredMode == store.CallModeSFULiveKit {
			c.session.LiveKitRoom = "ky_" + c.session.ID
		}
		m.calls[req.RoomID] = c
	}

	if m.userCalls[req.UserID] == nil {
		m.userCalls[req.UserID] = make(map[string]string)
	}
	m.userCalls[req.UserID][req.RoomID] = peerID

	var migrateTargets []*callPeer
	escalated := false
	if !created && prevMode == store.CallModeP2PMesh && desiredMode == store.CallModeSFULiveKit {
		c.stopStepDownLocked()
		c.session.Mode = store.CallModeSFULiveKit
		c.session.Epoch++
		if c.session.LiveKitRoom == "" {
			c.session.LiveKitRoom = "ky_" + c.session.ID
		}
		escalated = true
		for _, p := range c.peers {
			if p.PeerID != peerID {
				migrateTargets = append(migrateTargets, p)
			}
		}
	} else if desiredMode == store.CallModeSFULiveKit {
		c.stopStepDownLocked()
	}

	sessionCopy := c.session
	statePayload := m.buildStateLocked(c, true)
	lkRoom := c.session.LiveKitRoom
	modeNow := c.session.Mode
	epochNow := c.session.Epoch
	stickyNow := c.session.SFUSticky
	m.mu.Unlock()

	// Check the org again now the peer is registered, before any token exists. A suspension that
	// committed first is seen here and the join takes itself back out; one that commits later
	// finds the peer and its revocation removes it.
	if !m.tenantStillActive(ctx, req.TenantID) {
		m.Leave(ctx, req.RoomID, req.UserID)
		return nil, ErrTenantInactive
	}

	// Persist call session row.
	if created {
		if err := m.chatStore.CreateCallSession(ctx, &sessionCopy); err != nil {
			log.Printf("[CALL] persist new call session %s failed: %v", sessionCopy.ID, err)
		}
	} else if escalated {
		if err := m.chatStore.UpdateCallSession(ctx, &sessionCopy); err != nil {
			log.Printf("[CALL] persist escalated call session %s failed: %v", sessionCopy.ID, err)
		}
	}

	var lkURL, lkToken string
	if modeNow == store.CallModeSFULiveKit && m.livekit != nil {
		if created || escalated {
			_ = m.livekit.CreateRoom(ctx, lkRoom, req.RoomID)
		}
		lkURL = m.livekit.WSURL()
		lkToken = m.livekit.JoinToken(lkRoom, peerID, req.DisplayName, "", rtc.DefaultTokenTTL)
	}
	// The token is handed out only if the org is still active and the peer outlived setup. A
	// peer that left or was replaced by a newer join is not touched: that seat is not ours now.
	if !m.tenantStillActive(ctx, req.TenantID) {
		m.Leave(ctx, req.RoomID, req.UserID)
		return nil, ErrTenantInactive
	}
	if !m.peerRegistered(req.RoomID, peerID) {
		return nil, ErrCallSeatLost
	}

	// Broadcast updated call state to the room.
	m.broadcastState(ctx, req.RoomID, statePayload)

	// Send individualized make-before-break migration frames to pre-existing peers.
	if escalated && m.livekit != nil {
		m.sendMigrations(ctx, req.RoomID, sessionCopy, reason, statePayload.Peers, migrateTargets)
	}

	return &JoinCallResponse{
		CallID:       sessionCopy.ID,
		RoomID:       req.RoomID,
		PeerID:       peerID,
		Mode:         modeNow,
		Epoch:        epochNow,
		SFUSticky:    stickyNow,
		SFUAvailable: m.livekit != nil,
		ICEServers:   m.ICEServers(),
		LiveKitURL:   lkURL,
		LiveKitToken: lkToken,
		Peers:        statePayload.Peers,
		Started:      created,
	}, nil
}

func (m *CallManager) peerRegistered(roomID, peerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.calls[roomID]
	return c != nil && c.peers[peerID] != nil
}

// RevokeTenant takes every peer of tenantID's calls on this pod out of its call, members and
// guests alike, whether or not they hold a chat socket here.
func (m *CallManager) RevokeTenant(ctx context.Context, tenantID string) {
	type seat struct{ roomID, userID string }
	var seats []seat
	m.mu.Lock()
	for roomID, c := range m.calls {
		if c.session.TenantID != tenantID {
			continue
		}
		for _, p := range c.peers {
			seats = append(seats, seat{roomID, p.UserID})
		}
	}
	m.mu.Unlock()
	for _, s := range seats {
		m.Leave(ctx, s.roomID, s.userID)
	}
}

// SetUserCheck registers the account check ReconcileTenants applies to member peers.
func (m *CallManager) SetUserCheck(fn func(ctx context.Context, userID string) (bool, error)) {
	m.userActive = fn
}

// ReconcileTenants takes the peers of every call whose org is no longer active out of their
// calls, so a tenant.revoked notification this pod missed still takes effect, and with a user
// check the member peers whose account no longer serves, for a missed user revocation.
func (m *CallManager) ReconcileTenants(ctx context.Context) {
	defer m.reconcileUsers(ctx)
	m.mu.Lock()
	tenants := map[string]struct{}{}
	for _, c := range m.calls {
		tenants[c.session.TenantID] = struct{}{}
	}
	m.mu.Unlock()
	for tenantID := range tenants {
		tenant, err := m.chatStore.GetTenant(ctx, tenantID)
		if err == nil && tenant.Status != store.TenantStatusActive {
			m.RevokeTenant(ctx, tenantID)
		}
	}
}

func (m *CallManager) reconcileUsers(ctx context.Context) {
	if m.userActive == nil {
		return
	}
	m.mu.Lock()
	users := make([]string, 0, len(m.userCalls))
	for uid := range m.userCalls {
		if !strings.HasPrefix(uid, "guest_") {
			users = append(users, uid)
		}
	}
	m.mu.Unlock()
	for _, uid := range users {
		// Only a definite answer removes anyone: an outage must not end every call.
		if ok, err := m.userActive(ctx, uid); err == nil && !ok {
			m.HandleDisconnect(uid, 0)
		}
	}
}

func (m *CallManager) tenantStillActive(ctx context.Context, tenantID string) bool {
	tenant, err := m.chatStore.GetTenant(ctx, tenantID)
	if errors.Is(err, store.ErrNotFound) {
		return true // unit tests without a tenant row, as above
	}
	return err == nil && tenant.Status == store.TenantStatusActive
}

// Leave removes userID from the active call in roomID, ending the call if empty or
// arming the 60s hysteretic SFU -> P2P step-down timer if conditions now fit P2P.
func (m *CallManager) Leave(ctx context.Context, roomID, userID string) {
	m.mu.Lock()
	c := m.calls[roomID]
	if c == nil {
		m.mu.Unlock()
		return
	}

	var removedPeer *callPeer
	for pid, p := range c.peers {
		if p.UserID == userID {
			removedPeer = p
			delete(c.peers, pid)
			break
		}
	}
	if rooms := m.userCalls[userID]; rooms != nil {
		delete(rooms, roomID)
		if len(rooms) == 0 {
			delete(m.userCalls, userID)
		}
	}
	if removedPeer == nil {
		m.mu.Unlock()
		return
	}

	lkRoom := c.session.LiveKitRoom
	if len(c.peers) == 0 {
		c.stopStepDownLocked()
		delete(m.calls, roomID)
		endPayload := m.buildStateLocked(c, false)
		sessionID := c.session.ID
		tenantID := c.session.TenantID
		m.mu.Unlock()

		_ = m.chatStore.EndCallSession(ctx, tenantID, sessionID, time.Now().UTC().UnixMilli())
		if lkRoom != "" && m.livekit != nil {
			_ = m.livekit.RemoveParticipant(ctx, lkRoom, removedPeer.PeerID)
		}
		m.broadcastState(ctx, roomID, endPayload)
		return
	}

	// Re-evaluate whether SFU can step down to P2P after the hysteresis delay.
	m.maybeScheduleStepDownLocked(roomID, c)
	statePayload := m.buildStateLocked(c, true)
	m.mu.Unlock()

	if lkRoom != "" && m.livekit != nil {
		_ = m.livekit.RemoveParticipant(ctx, lkRoom, removedPeer.PeerID)
	}
	m.broadcastState(ctx, roomID, statePayload)
}

// ForceEscalate escalates the active call in roomID to LiveKit SFU (e.g. ICE failure or
// user-requested escalation). Sets SFUSticky=true when reason is "ice_failed".
func (m *CallManager) ForceEscalate(ctx context.Context, roomID, userID, reason string) (*CallStatePayload, error) {
	if reason == "" {
		reason = "manual"
	}
	m.mu.Lock()
	c := m.calls[roomID]
	if c == nil {
		m.mu.Unlock()
		return nil, ErrCallNotActive
	}
	// Verify requester is in the call.
	inCall := false
	for _, p := range c.peers {
		if p.UserID == userID {
			inCall = true
			break
		}
	}
	if !inCall {
		m.mu.Unlock()
		return nil, store.ErrForbidden
	}
	if m.livekit == nil {
		m.mu.Unlock()
		return nil, ErrSFUUnavailable
	}

	if reason == "ice_failed" {
		c.session.SFUSticky = true
	}
	c.stopStepDownLocked()

	alreadySFU := c.session.Mode == store.CallModeSFULiveKit
	if !alreadySFU {
		c.session.Mode = store.CallModeSFULiveKit
		c.session.Epoch++
		if c.session.LiveKitRoom == "" {
			c.session.LiveKitRoom = "ky_" + c.session.ID
		}
	}

	sessionCopy := c.session
	statePayload := m.buildStateLocked(c, true)
	targets := make([]*callPeer, 0, len(c.peers))
	for _, p := range c.peers {
		targets = append(targets, p)
	}
	m.mu.Unlock()

	_ = m.chatStore.UpdateCallSession(ctx, &sessionCopy)
	if !alreadySFU {
		_ = m.livekit.CreateRoom(ctx, sessionCopy.LiveKitRoom, roomID)
	}
	m.broadcastState(ctx, roomID, statePayload)
	if !alreadySFU {
		m.sendMigrations(ctx, roomID, sessionCopy, reason, statePayload.Peers, targets)
	}
	return &statePayload, nil
}

// HandleClientFrame processes inbound WebSocket call.* frames from Hub.
func (m *CallManager) HandleClientFrame(ctx context.Context, userID string, _ bool, frame ClientFrame) {
	switch frame.Type {
	case ClientFrameCallSignal:
		m.handleSignal(ctx, userID, frame)
	case ClientFrameCallMedia:
		m.handleMediaUpdate(ctx, userID, frame)
	case ClientFrameCallICEFailed:
		if frame.RoomID != "" {
			_, _ = m.ForceEscalate(ctx, frame.RoomID, userID, "ice_failed")
		}
	case ClientFrameCallMigrated:
		m.handleMigratedAck(userID, frame)
	}
}

// HandleDisconnect removes a user from active calls when their last WebSocket closes.
func (m *CallManager) HandleDisconnect(userID string, remainingConns int) {
	if remainingConns > 0 {
		return
	}
	m.mu.Lock()
	roomMap := m.userCalls[userID]
	roomIDs := make([]string, 0, len(roomMap))
	for rid := range roomMap {
		roomIDs = append(roomIDs, rid)
	}
	m.mu.Unlock()

	if len(roomIDs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, rid := range roomIDs {
		m.Leave(ctx, rid, userID)
	}
}

func (m *CallManager) handleSignal(ctx context.Context, userID string, frame ClientFrame) {
	if frame.RoomID == "" || frame.ToPeerID == "" || len(frame.Data) == 0 {
		return
	}
	switch frame.Kind {
	case "offer", "answer", "ice", "e2ee_key":
	default:
		return
	}

	m.mu.Lock()
	c := m.calls[frame.RoomID]
	if c == nil {
		m.mu.Unlock()
		return
	}
	var fromPeer *callPeer
	for _, p := range c.peers {
		if p.UserID == userID {
			fromPeer = p
			break
		}
	}
	toPeer := c.peers[frame.ToPeerID]
	if fromPeer == nil || toPeer == nil || fromPeer.PeerID == toPeer.PeerID {
		m.mu.Unlock()
		return
	}
	callID := c.session.ID
	targetUserID := toPeer.UserID
	fromPeerID := fromPeer.PeerID
	m.mu.Unlock()

	ev := Event{
		Type:   EventCallSignal,
		RoomID: frame.RoomID,
		UserID: targetUserID,
		Data: MustMarshalData(CallSignalPayload{
			CallID:     callID,
			RoomID:     frame.RoomID,
			FromPeerID: fromPeerID,
			ToPeerID:   frame.ToPeerID,
			Kind:       frame.Kind,
			Data:       frame.Data,
		}),
	}
	m.deliverToUser(ctx, targetUserID, ev)
}

func (m *CallManager) handleMediaUpdate(ctx context.Context, userID string, frame ClientFrame) {
	if frame.RoomID == "" {
		return
	}

	m.mu.Lock()
	c := m.calls[frame.RoomID]
	if c == nil {
		m.mu.Unlock()
		return
	}
	var sender *callPeer
	for _, p := range c.peers {
		if p.UserID == userID {
			sender = p
			break
		}
	}
	if sender == nil {
		m.mu.Unlock()
		return
	}

	if frame.Audio != nil {
		sender.Audio = *frame.Audio
	}
	if frame.Video != nil {
		sender.Video = *frame.Video
	}
	if frame.ScreenShare != nil {
		sender.ScreenShare = *frame.ScreenShare
	}
	if frame.ProtectIP != nil && (!*frame.ProtectIP || m.livekit != nil) {
		sender.ProtectIP = *frame.ProtectIP
	}

	desiredMode, reason, _ := evaluateCallMode(c.tenant, c.session.SFUSticky, c.peers)
	escalated := false
	var targets []*callPeer
	if c.session.Mode == store.CallModeP2PMesh && desiredMode == store.CallModeSFULiveKit && m.livekit != nil {
		c.stopStepDownLocked()
		c.session.Mode = store.CallModeSFULiveKit
		c.session.Epoch++
		if c.session.LiveKitRoom == "" {
			c.session.LiveKitRoom = "ky_" + c.session.ID
		}
		escalated = true
		for _, p := range c.peers {
			targets = append(targets, p)
		}
	} else if c.session.Mode == store.CallModeSFULiveKit {
		if desiredMode == store.CallModeSFULiveKit {
			c.stopStepDownLocked()
		} else {
			m.maybeScheduleStepDownLocked(frame.RoomID, c)
		}
	}

	sessionCopy := c.session
	statePayload := m.buildStateLocked(c, true)
	m.mu.Unlock()

	if escalated {
		_ = m.chatStore.UpdateCallSession(ctx, &sessionCopy)
		_ = m.livekit.CreateRoom(ctx, sessionCopy.LiveKitRoom, frame.RoomID)
	}
	m.broadcastState(ctx, frame.RoomID, statePayload)
	if escalated {
		m.sendMigrations(ctx, frame.RoomID, sessionCopy, reason, statePayload.Peers, targets)
	}
}

func (m *CallManager) handleMigratedAck(userID string, frame ClientFrame) {
	if frame.RoomID == "" || frame.Epoch <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.calls[frame.RoomID]
	if c == nil {
		return
	}
	for _, p := range c.peers {
		if p.UserID == userID && frame.Epoch > p.migratedEpoch {
			p.migratedEpoch = frame.Epoch
		}
	}
}

func (m *CallManager) maybeScheduleStepDownLocked(roomID string, c *activeCall) {
	if c.session.Mode != store.CallModeSFULiveKit || c.session.SFUSticky {
		return
	}
	desiredMode, _, _ := evaluateCallMode(c.tenant, c.session.SFUSticky, c.peers)
	if desiredMode != store.CallModeP2PMesh {
		c.stopStepDownLocked()
		return
	}
	if c.stepDownTimer != nil {
		return // already scheduled
	}
	callID := c.session.ID
	delay := m.stepDownDelay
	c.stepDownTimer = time.AfterFunc(delay, func() {
		m.executeStepDown(roomID, callID)
	})
}

func (m *CallManager) executeStepDown(roomID, callID string) {
	m.mu.Lock()
	c := m.calls[roomID]
	if c == nil || c.session.ID != callID {
		m.mu.Unlock()
		return
	}
	c.stepDownTimer = nil
	if c.session.Mode != store.CallModeSFULiveKit || c.session.SFUSticky || len(c.peers) == 0 {
		m.mu.Unlock()
		return
	}
	desiredMode, reason, _ := evaluateCallMode(c.tenant, c.session.SFUSticky, c.peers)
	if desiredMode != store.CallModeP2PMesh {
		m.mu.Unlock()
		return
	}

	c.session.Mode = store.CallModeP2PMesh
	c.session.Epoch++
	sessionCopy := c.session
	statePayload := m.buildStateLocked(c, true)
	targets := make([]*callPeer, 0, len(c.peers))
	for _, p := range c.peers {
		targets = append(targets, p)
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = m.chatStore.UpdateCallSession(ctx, &sessionCopy)
	m.broadcastState(ctx, roomID, statePayload)
	m.sendMigrations(ctx, roomID, sessionCopy, reason, statePayload.Peers, targets)
}

func (c *activeCall) stopStepDownLocked() {
	if c.stepDownTimer != nil {
		c.stepDownTimer.Stop()
		c.stepDownTimer = nil
	}
}

func (m *CallManager) buildStateLocked(c *activeCall, active bool) CallStatePayload {
	peers := make([]CallPeerState, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p.CallPeerState)
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].JoinedAt != peers[j].JoinedAt {
			return peers[i].JoinedAt < peers[j].JoinedAt
		}
		return peers[i].PeerID < peers[j].PeerID
	})
	return CallStatePayload{
		CallID:       c.session.ID,
		RoomID:       c.session.RoomID,
		Active:       active,
		Mode:         c.session.Mode,
		Epoch:        c.session.Epoch,
		SFUSticky:    c.session.SFUSticky,
		SFUAvailable: m.livekit != nil,
		LiveKitURL:   m.LiveKitURL(),
		Peers:        peers,
	}
}

func (m *CallManager) broadcastState(ctx context.Context, roomID string, payload CallStatePayload) {
	if m.hub == nil {
		return
	}
	_ = m.hub.PublishRoom(ctx, roomID, Event{
		Type:   EventCallState,
		RoomID: roomID,
		Data:   MustMarshalData(payload),
	})
}

func (m *CallManager) sendMigrations(ctx context.Context, roomID string, session store.CallSession, reason string, peers []CallPeerState, targets []*callPeer) {
	if m.hub == nil {
		return
	}
	for _, p := range targets {
		mig := CallMigratePayload{
			CallID:     session.ID,
			RoomID:     roomID,
			Epoch:      session.Epoch,
			TargetMode: session.Mode,
			Reason:     reason,
			Peers:      peers,
		}
		if session.Mode == store.CallModeSFULiveKit && m.livekit != nil {
			mig.LiveKitURL = m.livekit.WSURL()
			mig.LiveKitToken = m.livekit.JoinToken(session.LiveKitRoom, p.PeerID, p.DisplayName, "", rtc.DefaultTokenTTL)
		}
		m.deliverToUser(ctx, p.UserID, Event{
			Type:   EventCallMigrate,
			RoomID: roomID,
			UserID: p.UserID,
			Data:   MustMarshalData(mig),
		})
	}
}

func (m *CallManager) deliverToUser(ctx context.Context, userID string, ev Event) {
	if m.hub == nil || userID == "" {
		return
	}
	if !m.hub.SendToUserLocal(userID, ev) {
		_ = m.hub.PublishUser(ctx, userID, ev)
	}
}

// evaluateCallMode implements the authoritative hybrid P2P-first / SFU escalation rules
// from Section 6.2 of the design spec.
// strictSFU is true when privacy or tenant policy forbids falling back to P2P if LiveKit is unset.
func evaluateCallMode(tenant store.Tenant, sfuSticky bool, peers map[string]*callPeer) (mode, reason string, strictSFU bool) {
	if tenant.P2PPolicy == store.P2PPolicySFUOnly {
		return store.CallModeSFULiveKit, "tenant_policy", true
	}
	if sfuSticky {
		return store.CallModeSFULiveKit, "ice_failed", false
	}
	maxVideo := tenant.P2PMaxVideo
	if maxVideo <= 0 {
		maxVideo = 2
	}
	maxAudio := tenant.P2PMaxAudio
	if maxAudio <= 0 {
		maxAudio = 4
	}

	var anyVideo, anyScreen bool
	for _, p := range peers {
		if p.ProtectIP {
			return store.CallModeSFULiveKit, "protect_ip", true
		}
		if p.IsGuest && tenant.GuestForceSFU {
			return store.CallModeSFULiveKit, "guest_joined", true
		}
		if p.Video {
			anyVideo = true
		}
		if p.ScreenShare {
			anyScreen = true
		}
	}

	n := len(peers)
	if anyScreen && n > 2 {
		return store.CallModeSFULiveKit, "screen_share", false
	}
	if anyVideo && n > maxVideo {
		return store.CallModeSFULiveKit, "video_limit", false
	}
	if n > maxAudio {
		return store.CallModeSFULiveKit, "audio_limit", false
	}
	return store.CallModeP2PMesh, "within_p2p_budget", false
}
