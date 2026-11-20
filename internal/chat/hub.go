package chat

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	clientSendBuffer   = 64
	clientMaxReadBytes = 8 << 10 // 8 KiB max inbound control frame
	clientWriteTimeout = 10 * time.Second
	clientPingInterval = 25 * time.Second
	typingMinInterval  = 2 * time.Second
)

// Hub manages live WebSocket connections on this pod and routes EventBus frames to them.
type Hub struct {
	bus EventBus

	mu      sync.RWMutex
	clients map[*Client]struct{}
	byUser  map[string]map[*Client]struct{}
	byRoom  map[string]map[*Client]struct{}
}

// Client represents one authenticated WebSocket connection.
type Client struct {
	hub         *Hub
	conn        *websocket.Conn
	userID      string
	tenantID    string
	sessionHash string

	roomsMu sync.RWMutex
	rooms   map[string]struct{}

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
	}
	if mb, ok := bus.(*MemoryBus); ok {
		mb.SetHandler(h.Dispatch)
	}
	return h
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

// PublishRoom emits a room-scoped event onto the bus (all pods).
func (h *Hub) PublishRoom(ctx context.Context, roomID string, ev Event) error {
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

// RevokeSession disconnects local WebSocket connections bound to a specific session hash.
func (h *Hub) RevokeSession(sessionHash string) {
	if sessionHash == "" {
		return
	}
	h.mu.RLock()
	var targets []*Client
	for c := range h.clients {
		if c.sessionHash == sessionHash {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()

	frame, _ := json.Marshal(Event{Type: EventAuthRevoked})
	for _, c := range targets {
		c.tryEnqueue(frame)
		c.kick(websocket.StatusPolicyViolation, "session revoked")
	}
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
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}

	switch ev.Type {
	case EventAuthRevoked:
		if ev.UserID == "" {
			return
		}
		h.mu.RLock()
		targets := copyClients(h.byUser[ev.UserID])
		h.mu.RUnlock()
		for _, c := range targets {
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

	if ev.RoomID != "" {
		h.broadcastRoom(ev.RoomID, raw)
		return
	}
	if ev.UserID != "" {
		h.broadcastUser(ev.UserID, raw)
	}
}

func (h *Hub) broadcastRoom(roomID string, raw []byte) {
	h.mu.RLock()
	targets := copyClients(h.byRoom[roomID])
	h.mu.RUnlock()

	for _, c := range targets {
		c.enqueue(raw)
	}
}

func (h *Hub) broadcastUser(userID string, raw []byte) {
	h.mu.RLock()
	targets := copyClients(h.byUser[userID])
	h.mu.RUnlock()

	for _, c := range targets {
		c.enqueue(raw)
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

func (h *Hub) register(c *Client, roomIDs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()

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
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.clients, c)
	if set := h.byUser[c.userID]; set != nil {
		delete(set, c)
		if len(set) == 0 {
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

// ServeConn registers conn, sends the hello frame, and runs its read/write pumps until closed.
func (h *Hub) ServeConn(ctx context.Context, conn *websocket.Conn, tenantID, userID, sessionHash string, roomIDs []string) {
	conn.SetReadLimit(clientMaxReadBytes)

	c := &Client{
		hub:         h,
		conn:        conn,
		userID:      userID,
		tenantID:    tenantID,
		sessionHash: sessionHash,
		rooms:       make(map[string]struct{}, len(roomIDs)),
		send:        make(chan []byte, clientSendBuffer),
		stop:        make(chan struct{}),
		closeCode:   websocket.StatusNormalClosure,
		lastTyping:  make(map[string]time.Time),
	}

	h.register(c, roomIDs)
	defer func() {
		c.kick(websocket.StatusNormalClosure, "")
		h.unregister(c)
	}()

	hello, _ := json.Marshal(Event{
		Type: EventHello,
		Data: MustMarshalData(map[string]any{
			"user_id":     userID,
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
	ticker := time.NewTicker(clientPingInterval)
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
		}
	}
}
