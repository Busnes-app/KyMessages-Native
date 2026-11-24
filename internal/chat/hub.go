package chat

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	clientSendBuffer   = 128
	clientMaxReadBytes = 64 << 10 // 64 KiB max inbound control frame (WebRTC SDP + ICE)
	clientWriteTimeout = 10 * time.Second
	clientPingInterval = 25 * time.Second
	typingMinInterval  = 2 * time.Second
)

// CallFrameHandler handles inbound WebRTC signaling and call control frames from WS clients.
type CallFrameHandler func(ctx context.Context, userID string, isGuest bool, frame ClientFrame)

// DisconnectHandler is invoked whenever a client disconnects, with the user's remaining socket count.
type DisconnectHandler func(userID string, isGuest bool, remainingConns int)

// Hub manages live WebSocket connections on this pod and routes EventBus frames to them.
type Hub struct {
	bus EventBus

	mu      sync.RWMutex
	clients map[*Client]struct{}
	byUser  map[string]map[*Client]struct{}
	byRoom  map[string]map[*Client]struct{}

	// sessionValid, when set, is re-checked on every ping so a socket never outlives
	// its session, whichever path revoked or expired it. An error skips that tick.
	sessionValid   func(ctx context.Context, userID, sessionHash string) (bool, error)
	callFrameHook  CallFrameHandler
	disconnectHook DisconnectHandler
	tenantRevoked  func(tenantID string)
	userRevoked    func(userID string)
	// guestValid, when set, reports whether a guest still holds a lobby session. It is checked
	// when the socket registers and on every ping, as sessionValid is for members.
	guestValid   func(guestID string) bool
	pingInterval time.Duration

	// roomSource, when set, rebuilds each socket's rooms from the store after it registers
	// and on every ping, so a membership change the bus never delivered (one made during
	// connect, or while the Postgres listener reconnected) lasts one ping at most.
	roomSource           func(ctx context.Context, tenantID, userID string) ([]string, error)
	roomCalls            bool
	roomCallDisconnected func(userID, roomID, sessionHash string)
}

// Client represents one authenticated WebSocket connection (member or confined guest).
type Client struct {
	hub         *Hub
	conn        *websocket.Conn
	userID      string
	tenantID    string
	sessionHash string
	callRoomID  string
	isGuest     bool

	roomsMu sync.RWMutex
	rooms   map[string]struct{}
	// memberEvents counts membership events applied to this client, under hub.mu, so a
	// resync that raced one discards its now-stale list.
	memberEvents uint64

	send      chan []byte
	stop      chan struct{}
	closeOnce sync.Once
	closeCode websocket.StatusCode
	closeMsg  string
	closeMu   sync.Mutex

	typingMu   sync.Mutex
	lastTyping map[string]time.Time
}

// NewHub constructs a Hub backed by bus. If bus is a *MemoryBus, its handler is wired
// immediately so events work even before Run is started.
func NewHub(bus EventBus) *Hub {
	if bus == nil {
		bus = NewMemoryBus()
	}
	h := &Hub{
		bus:     bus,
		clients: make(map[*Client]struct{}),
		byUser:  make(map[string]map[*Client]struct{}),
		byRoom:  make(map[string]map[*Client]struct{}),

		pingInterval: clientPingInterval,
	}
	if mb, ok := bus.(*MemoryBus); ok {
		mb.SetHandler(h.Dispatch)
	}
	return h
}

// EnableRoomCalls confines hosted signaling to a room-addressed socket, so edge affinity
// routes both HTTP and WebSocket call control to the same owner. Configure before serving.
func (h *Hub) EnableRoomCalls(onDisconnect func(userID, roomID, sessionHash string)) {
	h.roomCalls = true
	h.roomCallDisconnected = onDisconnect
}

// SetSessionCheck registers the per-ping session check. Call it before serving connections.
func (h *Hub) SetSessionCheck(fn func(ctx context.Context, userID, sessionHash string) (bool, error)) {
	h.sessionValid = fn
}

// SetCallFrameHandler registers the handler for inbound call.* WebSocket frames.
func (h *Hub) SetCallFrameHandler(fn CallFrameHandler) {
	h.callFrameHook = fn
}

// SetDisconnectHandler registers a callback invoked when a WebSocket client disconnects.
func (h *Hub) SetDisconnectHandler(fn DisconnectHandler) {
	h.disconnectHook = fn
}

// SetGuestCheck registers the guest session lookup. Call it before serving connections.
func (h *Hub) SetGuestCheck(fn func(guestID string) bool) {
	h.guestValid = fn
}

// SetUserRevokeHandler registers what each pod does when a user (not one session) is revoked,
// beyond closing its sockets: a call seat may live on a pod with no socket of that user.
func (h *Hub) SetUserRevokeHandler(fn func(userID string)) {
	h.userRevoked = fn
}

// SetTenantRevokeHandler registers what each pod does when a tenant's access is revoked.
func (h *Hub) SetTenantRevokeHandler(fn func(tenantID string)) {
	h.tenantRevoked = fn
}

// SetRoomSource registers the store lookup resync uses. Call it before serving connections.
func (h *Hub) SetRoomSource(fn func(ctx context.Context, tenantID, userID string) ([]string, error)) {
	h.roomSource = fn
}

// Run starts consuming events from the EventBus and dispatching them until ctx is canceled.
func (h *Hub) Run(ctx context.Context) error {
	return h.bus.Run(ctx, h.Dispatch)
}

// WaitReady blocks until the backing EventBus is subscribed and ready to deliver events,
// or until ctx is canceled. In-memory buses return immediately.
func (h *Hub) WaitReady(ctx context.Context) error {
	r, ok := h.bus.(interface{ Ready() <-chan struct{} })
	if !ok {
		return nil
	}
	select {
	case <-r.Ready():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PublishRoom emits a room-scoped event onto the bus (all pods). It clears UserID, which
// names a recipient (see Event), so a room event always reaches the whole room.
func (h *Hub) PublishRoom(ctx context.Context, roomID string, ev Event) error {
	ev.UserID = ""
	return h.bus.PublishRoom(ctx, roomID, ev)
}

// PublishUser emits a user-scoped event onto the bus (all pods).
func (h *Hub) PublishUser(ctx context.Context, userID string, ev Event) error {
	return h.bus.PublishUser(ctx, userID, ev)
}

// RevokeUser immediately disconnects every live WebSocket for userID across all pods.
func (h *Hub) RevokeUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return h.bus.PublishUser(ctx, userID, Event{
		Type:   EventAuthRevoked,
		UserID: userID,
	})
}

// RevokeTenant tells every pod that tenantID lost access, so each drops its guests.
func (h *Hub) RevokeTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return nil
	}
	return h.bus.PublishUser(ctx, "", Event{
		Type: EventTenantRevoked,
		Data: MustMarshalData(tenantRevoke{TenantID: tenantID}),
	})
}

type tenantRevoke struct {
	TenantID string `json:"tenant_id"`
}

// RevokeSession disconnects the user's WebSockets bound to sessionHash across all pods.
func (h *Hub) RevokeSession(ctx context.Context, userID, sessionHash string) error {
	if userID == "" || sessionHash == "" {
		return nil
	}
	return h.bus.PublishUser(ctx, userID, Event{
		Type:   EventAuthRevoked,
		UserID: userID,
		Data:   MustMarshalData(sessionRevoke{Session: sessionHash}),
	})
}

// sessionRevoke narrows an EventAuthRevoked to one session. It travels only on the bus.
type sessionRevoke struct {
	Session string `json:"session"`
}

// Close terminates all active WebSocket connections on shutdown.
func (h *Hub) Close() {
	h.mu.RLock()
	targets := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		targets = append(targets, c)
	}
	h.mu.RUnlock()

	for _, c := range targets {
		c.kick(websocket.StatusGoingAway, "server shutting down")
	}
}

// Stats returns live counts of connected clients, unique users, and subscribed rooms.
func (h *Hub) Stats() (clients, users, rooms int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients), len(h.byUser), len(h.byRoom)
}

// Dispatch delivers an EventBus event to all matching local WebSocket clients.
func (h *Hub) Dispatch(ev Event) {
	sessionHash := ev.SessionHash
	ev.SessionHash = ""
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}

	if h.roomCalls && (ev.Type == EventCallSignal || ev.Type == EventCallMigrate) {
		h.dispatchRoomCall(ev, sessionHash, raw)
		return
	}
	switch ev.Type {
	case EventTenantRevoked:
		var t tenantRevoke
		if json.Unmarshal(ev.Data, &t) == nil && t.TenantID != "" && h.tenantRevoked != nil {
			h.tenantRevoked(t.TenantID)
		}
		return

	case EventAuthRevoked:
		if ev.UserID == "" {
			return
		}
		// Without a readable session it revokes every socket the user has.
		var only sessionRevoke
		if len(ev.Data) > 0 {
			_ = json.Unmarshal(ev.Data, &only)
			raw, _ = json.Marshal(Event{Type: EventAuthRevoked, UserID: ev.UserID})
		}
		if only.Session == "" && h.userRevoked != nil {
			go h.userRevoked(ev.UserID) // may call LiveKit; never block the bus
		}
		h.mu.RLock()
		targets := copyClients(h.byUser[ev.UserID])
		h.mu.RUnlock()
		for _, c := range targets {
			if only.Session != "" && c.sessionHash != only.Session {
				continue
			}
			c.tryEnqueue(raw)
			c.kick(websocket.StatusPolicyViolation, "session revoked")
		}
		return

	case EventRoomMember:
		var delta RoomMemberDelta
		if len(ev.Data) > 0 && json.Unmarshal(ev.Data, &delta) == nil && delta.UserID != "" && ev.RoomID != "" {
			switch delta.Action {
			case "added":
				h.subscribeUserToRoom(delta.UserID, ev.RoomID)
				h.broadcastRoom(ev.RoomID, raw)
				return
			case "removed":
				h.broadcastRoom(ev.RoomID, raw)
				h.unsubscribeUserFromRoom(delta.UserID, ev.RoomID)
				return
			}
		}
	}

	// A user-targeted event (call signal, call migration, lobby decision) may also name its
	// room; it still goes only to that user, never to everyone in the room.
	if ev.UserID != "" {
		// An admission decided on another replica subscribes the guest's sockets here.
		if ev.Type == EventLobbyDecision && ev.RoomID != "" {
			var d LobbyDecisionPayload
			if json.Unmarshal(ev.Data, &d) == nil && d.Decision == "admitted" && d.GuestID == ev.UserID {
				h.subscribeUserToRoom(ev.UserID, ev.RoomID)
			}
		}
		h.broadcastUser(ev.UserID, raw)
		return
	}
	if ev.RoomID != "" {
		h.broadcastRoom(ev.RoomID, raw)
		if h.roomCalls && (ev.Type == EventCallState || ev.Type == EventRoomClosed) {
			h.mu.RLock()
			targets := copyClients(h.byRoom[ev.RoomID])
			h.mu.RUnlock()
			for _, c := range targets {
				if c.callRoomID == ev.RoomID {
					c.enqueue(raw)
				}
			}
		}
	}
}

func (h *Hub) broadcastRoom(roomID string, raw []byte) {
	h.mu.RLock()
	targets := copyClients(h.byRoom[roomID])
	h.mu.RUnlock()

	for _, c := range targets {
		if c.callRoomID == "" {
			c.enqueue(raw)
		}
	}
}

func (h *Hub) broadcastUser(userID string, raw []byte) {
	h.mu.RLock()
	targets := copyClients(h.byUser[userID])
	h.mu.RUnlock()

	for _, c := range targets {
		if c.callRoomID == "" {
			c.enqueue(raw)
		}
	}
}

func copyClients(set map[*Client]struct{}) []*Client {
	if len(set) == 0 {
		return nil
	}
	out := make([]*Client, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

// SendToUserLocal delivers ev directly to local WebSocket connections for userID without
// passing through the PostgreSQL NOTIFY bus (preserving full >4 KiB WebRTC SDP frames).
// Returns true if at least one local connection for userID was found.
func (h *Hub) SendToUserLocal(userID string, ev Event) bool {
	if userID == "" {
		return false
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	h.mu.RLock()
	targets := copyClients(h.byUser[userID])
	h.mu.RUnlock()
	if len(targets) == 0 {
		return false
	}
	for _, c := range targets {
		if c.callRoomID == "" {
			c.enqueue(raw)
		}
	}
	return true
}

// SubscribeUserToRoom subscribes all local WebSocket connections for userID to roomID.
func (h *Hub) SubscribeUserToRoom(userID, roomID string) {
	h.subscribeUserToRoom(userID, roomID)
}

// UnsubscribeUserFromRoom unsubscribes all local WebSocket connections for userID from roomID.
func (h *Hub) UnsubscribeUserFromRoom(userID, roomID string) {
	h.unsubscribeUserFromRoom(userID, roomID)
}

func (h *Hub) register(c *Client, roomIDs []string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if c.callRoomID != "" {
		n := 0
		for other := range h.byUser[c.userID] {
			if other.callRoomID == c.callRoomID {
				n++
			}
		}
		if n >= 8 {
			return false
		}
	}
	h.clients[c] = struct{}{}
	if h.byUser[c.userID] == nil {
		h.byUser[c.userID] = make(map[*Client]struct{})
	}
	h.byUser[c.userID][c] = struct{}{}

	c.roomsMu.Lock()
	for _, rid := range roomIDs {
		if rid == "" {
			continue
		}
		c.rooms[rid] = struct{}{}
		if h.byRoom[rid] == nil {
			h.byRoom[rid] = make(map[*Client]struct{})
		}
		h.byRoom[rid][c] = struct{}{}
	}
	c.roomsMu.Unlock()
	return true
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()

	delete(h.clients, c)
	remaining := 0
	if set := h.byUser[c.userID]; set != nil {
		delete(set, c)
		remaining = len(set)
		if remaining == 0 {
			delete(h.byUser, c.userID)
		}
	}

	c.roomsMu.Lock()
	for rid := range c.rooms {
		if set := h.byRoom[rid]; set != nil {
			delete(set, c)
			if len(set) == 0 {
				delete(h.byRoom, rid)
			}
		}
	}
	c.roomsMu.Unlock()
	remainingCalls := 0
	if c.callRoomID != "" {
		for other := range h.byUser[c.userID] {
			if other.callRoomID == c.callRoomID && other.sessionHash == c.sessionHash {
				remainingCalls++
			}
		}
	}
	hook := h.disconnectHook
	h.mu.Unlock()
	if c.callRoomID != "" && remainingCalls == 0 && h.roomCallDisconnected != nil {
		h.roomCallDisconnected(c.userID, c.callRoomID, c.sessionHash)
	}

	if hook != nil {
		hook(c.userID, c.isGuest, remaining)
	}
}

func (h *Hub) subscribeUserToRoom(userID, roomID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	set := h.byUser[userID]
	if len(set) == 0 {
		return
	}
	if h.byRoom[roomID] == nil {
		h.byRoom[roomID] = make(map[*Client]struct{})
	}
	for c := range set {
		if c.callRoomID != "" && c.callRoomID != roomID {
			continue
		}
		c.memberEvents++
		c.roomsMu.Lock()
		c.rooms[roomID] = struct{}{}
		c.roomsMu.Unlock()
		h.byRoom[roomID][c] = struct{}{}
	}
}

func (h *Hub) unsubscribeUserFromRoom(userID, roomID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	set := h.byUser[userID]
	roomSet := h.byRoom[roomID]
	for c := range set {
		c.memberEvents++
		c.roomsMu.Lock()
		delete(c.rooms, roomID)
		c.roomsMu.Unlock()
		if roomSet != nil {
			delete(roomSet, c)
		}
	}
	if roomSet != nil && len(roomSet) == 0 {
		delete(h.byRoom, roomID)
	}
}

// resync replaces c's rooms with the store's list. A membership event that lands while
// the list is loading makes it stale, so it retries; after three races the next ping does.
// Guests have no store membership: the lobby admits them, so they are left alone.
func (h *Hub) resync(ctx context.Context, c *Client) {
	if h.roomSource == nil || c.isGuest {
		return
	}
	for range 3 {
		h.mu.RLock()
		seen := c.memberEvents
		h.mu.RUnlock()
		ids, err := h.roomSource(ctx, c.tenantID, c.userID)
		if err != nil {
			return // keep the current rooms; the next ping retries
		}
		h.mu.Lock()
		if _, live := h.clients[c]; !live {
			h.mu.Unlock()
			return // unregistered while the list loaded: never re-add it
		}
		if c.memberEvents != seen {
			h.mu.Unlock()
			continue
		}
		want := make(map[string]struct{}, len(ids))
		for _, rid := range ids {
			if rid != "" && (c.callRoomID == "" || rid == c.callRoomID) {
				want[rid] = struct{}{}
			}
		}
		c.roomsMu.Lock()
		for rid := range c.rooms {
			if _, ok := want[rid]; ok {
				continue
			}
			delete(c.rooms, rid)
			if set := h.byRoom[rid]; set != nil {
				delete(set, c)
				if len(set) == 0 {
					delete(h.byRoom, rid)
				}
			}
		}
		for rid := range want {
			c.rooms[rid] = struct{}{}
			if h.byRoom[rid] == nil {
				h.byRoom[rid] = make(map[*Client]struct{})
			}
			h.byRoom[rid][c] = struct{}{}
		}
		c.roomsMu.Unlock()
		h.mu.Unlock()
		return
	}
}

// ServeConn registers conn, sends the hello frame, and runs its read/write pumps until closed.
func (h *Hub) ServeConn(ctx context.Context, conn *websocket.Conn, tenantID, userID, sessionHash string, roomIDs []string) {
	h.serveClient(ctx, conn, tenantID, userID, sessionHash, false, roomIDs, "")
}

// ServeGuestConn serves a strictly confined WebSocket for an external meeting guest.
// Until admitted, roomIDs is empty and the guest only receives targeted lobby.decision events.
func (h *Hub) ServeGuestConn(ctx context.Context, conn *websocket.Conn, tenantID, guestID string, roomIDs []string) {
	h.serveClient(ctx, conn, tenantID, guestID, "", true, roomIDs, "")
}

// ServeRoomCallConn is a member's room-affine signaling socket; chat stays on ServeConn.
func (h *Hub) ServeRoomCallConn(ctx context.Context, conn *websocket.Conn, tenantID, userID, sessionHash, roomID string) {
	h.serveClient(ctx, conn, tenantID, userID, sessionHash, false, []string{roomID}, roomID)
}

// ServeGuestRoomCallConn requires an already-admitted guest of this exact room.
func (h *Hub) ServeGuestRoomCallConn(ctx context.Context, conn *websocket.Conn, tenantID, guestID, roomID string) {
	h.serveClient(ctx, conn, tenantID, guestID, "", true, []string{roomID}, roomID)
}

func (h *Hub) serveClient(ctx context.Context, conn *websocket.Conn, tenantID, userID, sessionHash string, isGuest bool, roomIDs []string, callRoomID string) {
	conn.SetReadLimit(clientMaxReadBytes)

	c := &Client{
		hub:         h,
		conn:        conn,
		userID:      userID,
		tenantID:    tenantID,
		sessionHash: sessionHash,
		callRoomID:  callRoomID,
		isGuest:     isGuest,
		rooms:       make(map[string]struct{}, len(roomIDs)),
		send:        make(chan []byte, clientSendBuffer),
		stop:        make(chan struct{}),
		closeCode:   websocket.StatusNormalClosure,
		lastTyping:  make(map[string]time.Time),
	}

	if !h.register(c, roomIDs) {
		_ = conn.Close(websocket.StatusPolicyViolation, "too many call sockets")
		return
	}
	defer func() {
		c.kick(websocket.StatusNormalClosure, "")
		h.unregister(c)
	}()
	// A guest authenticated before a revocation swept its session may register after the
	// sweep's kick; registered first, this check or the kick always catches it.
	if isGuest && h.guestValid != nil && !h.guestValid(userID) {
		_ = conn.Close(websocket.StatusPolicyViolation, "guest session ended")
		return
	}
	// roomIDs was listed before register, so a change between the two reached no client.
	rctx, rcancel := context.WithTimeout(ctx, clientWriteTimeout)
	h.resync(rctx, c)
	rcancel()

	hello, _ := json.Marshal(Event{
		Type: EventHello,
		Data: MustMarshalData(map[string]any{
			"user_id":     userID,
			"is_guest":    isGuest,
			"server_time": time.Now().UTC().UnixMilli(),
		}),
	})
	c.enqueue(hello)

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.writeLoop(connCtx, cancel)
	}()

	c.readLoop(connCtx)
	cancel()
	c.kick(websocket.StatusNormalClosure, "")
	wg.Wait()
}

func (c *Client) hasRoom(roomID string) bool {
	c.roomsMu.RLock()
	_, ok := c.rooms[roomID]
	c.roomsMu.RUnlock()
	return ok
}

func (c *Client) enqueue(data []byte) {
	select {
	case <-c.stop:
		return
	default:
	}
	select {
	case c.send <- data:
	case <-c.stop:
	default:
		// Slow consumer: disconnect rather than growing server memory.
		c.kick(websocket.StatusTryAgainLater, "slow consumer")
	}
}

func (c *Client) tryEnqueue(data []byte) {
	select {
	case c.send <- data:
	default:
	}
}

func (c *Client) kick(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		c.closeCode = code
		c.closeMsg = reason
		c.closeMu.Unlock()
		close(c.stop)
	})
}

func (c *Client) writeLoop(ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(c.hub.pingInterval)
	defer ticker.Stop()

	flushFinal := func() {
		// Drain any queued final control frame (e.g. auth.revoked) before closing.
		select {
		case msg := <-c.send:
			wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = c.conn.Write(wctx, websocket.MessageText, msg)
			wcancel()
		default:
		}
		c.closeMu.Lock()
		code, reason := c.closeCode, c.closeMsg
		c.closeMu.Unlock()
		_ = c.conn.Close(code, reason)
		cancel()
	}

	for {
		select {
		case <-c.stop:
			flushFinal()
			return
		case <-ctx.Done():
			c.kick(websocket.StatusNormalClosure, "")
			flushFinal()
			return
		case msg := <-c.send:
			wctx, wcancel := context.WithTimeout(ctx, clientWriteTimeout)
			err := c.conn.Write(wctx, websocket.MessageText, msg)
			wcancel()
			if err != nil {
				c.kick(websocket.StatusGoingAway, "")
				cancel()
				return
			}
		case <-ticker.C:
			if c.isGuest && c.hub.guestValid != nil && !c.hub.guestValid(c.userID) {
				c.kick(websocket.StatusPolicyViolation, "guest session ended")
				continue
			}
			if !c.isGuest && c.hub.sessionValid != nil {
				vctx, vcancel := context.WithTimeout(ctx, clientWriteTimeout)
				valid, err := c.hub.sessionValid(vctx, c.userID, c.sessionHash)
				vcancel()
				// A store outage must not sign everyone out: only a definite answer revokes.
				if err == nil && !valid {
					frame, _ := json.Marshal(Event{Type: EventAuthRevoked})
					c.tryEnqueue(frame)
					c.kick(websocket.StatusPolicyViolation, "session revoked")
					continue // the stop case flushes the frame and closes
				}
			}
			rctx, rcancel := context.WithTimeout(ctx, clientWriteTimeout)
			c.hub.resync(rctx, c)
			rcancel()
			pctx, pcancel := context.WithTimeout(ctx, clientWriteTimeout)
			err := c.conn.Ping(pctx)
			pcancel()
			if err != nil {
				c.kick(websocket.StatusGoingAway, "ping timeout")
				cancel()
				return
			}
		}
	}
}

func (c *Client) readLoop(ctx context.Context) {
	for {
		msgType, data, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
		if msgType != websocket.MessageText {
			continue
		}
		var frame ClientFrame
		if err := json.Unmarshal(data, &frame); err != nil {
			continue
		}
		switch frame.Type {
		case ClientFramePing:
			pong, _ := json.Marshal(Event{Type: EventPong})
			c.enqueue(pong)
		case ClientFrameTyping:
			if c.callRoomID != "" {
				continue
			}
			if frame.RoomID == "" || !c.hasRoom(frame.RoomID) {
				continue
			}
			now := time.Now()
			c.typingMu.Lock()
			if frame.Active && now.Sub(c.lastTyping[frame.RoomID]) < typingMinInterval {
				c.typingMu.Unlock()
				continue
			}
			c.lastTyping[frame.RoomID] = now
			c.typingMu.Unlock()

			_ = c.hub.PublishRoom(ctx, frame.RoomID, Event{
				Type:   EventTyping,
				RoomID: frame.RoomID,
				Data:   MustMarshalData(TypingPayload{UserID: c.userID, Active: frame.Active}),
			})
		case ClientFrameCallSignal, ClientFrameCallMedia, ClientFrameCallMigrated, ClientFrameCallICEFailed:
			if c.hub.roomCalls && (c.callRoomID == "" || frame.RoomID != c.callRoomID || !c.hasRoom(c.callRoomID)) {
				continue
			}
			frame.SessionHash = c.sessionHash
			if c.hub.callFrameHook != nil {
				c.hub.callFrameHook(ctx, c.userID, c.isGuest, frame)
			}
		}
	}
}

// dispatchRoomCall never sends a fresh media grant to another session or the global chat
// socket. Primary revocation checks precede delivery; transient database failures just defer it.
func (h *Hub) dispatchRoomCall(ev Event, sessionHash string, raw []byte) {
	if ev.UserID == "" || ev.RoomID == "" {
		return
	}
	h.mu.RLock()
	targets := copyClients(h.byUser[ev.UserID])
	h.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, c := range targets {
		if c.callRoomID != ev.RoomID || !c.hasRoom(ev.RoomID) {
			continue
		}
		if c.isGuest {
			if h.guestValid != nil && !h.guestValid(c.userID) {
				continue
			}
		} else {
			if sessionHash == "" || c.sessionHash != sessionHash {
				continue
			}
			if h.sessionValid != nil {
				valid, err := h.sessionValid(ctx, c.userID, c.sessionHash)
				if err != nil {
					continue
				}
				if !valid {
					c.kick(websocket.StatusPolicyViolation, "session revoked")
					continue
				}
			}
		}
		c.enqueue(raw)
	}
}

// CloseRoomCalls makes clients reconnect through the room's new edge affinity after loss
// of ownership. Ordinary chat and another room's sockets remain connected.
func (h *Hub) CloseRoomCalls(roomID string) {
	h.mu.RLock()
	targets := copyClients(h.byRoom[roomID])
	h.mu.RUnlock()
	for _, c := range targets {
		if c.callRoomID == roomID {
			c.kick(websocket.StatusGoingAway, "call owner changed")
		}
	}
}

// HasRoomCallSocket rechecks a captured disconnect after acquiring room control. A late
// callback must not evict the same session's already-connected replacement socket.
func (h *Hub) HasRoomCallSocket(user, room, hash string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.byUser[user] {
		if c.callRoomID == room && c.sessionHash == hash {
			select {
			case <-c.stop:
			default:
				return true
			}
		}
	}
	return false
}
