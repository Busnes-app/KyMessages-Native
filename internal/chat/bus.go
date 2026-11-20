package chat

import (
	"context"
	"sync"
)

// EventBus distributes real-time room and user events across one or more KyMessages pods.
type EventBus interface {
	PublishRoom(ctx context.Context, roomID string, ev Event) error
	PublishUser(ctx context.Context, userID string, ev Event) error
	// Run blocks until ctx is canceled, delivering incoming events to onEvent.
	Run(ctx context.Context, onEvent func(Event)) error
}

// MemoryBus is a zero-allocation, in-process EventBus for single-node SQLite deployments
// and deterministic unit tests.
type MemoryBus struct {
	mu      sync.RWMutex
	handler func(Event)
}

func NewMemoryBus() *MemoryBus {
	return &MemoryBus{}
}

func (b *MemoryBus) SetHandler(onEvent func(Event)) {
	b.mu.Lock()
	b.handler = onEvent
	b.mu.Unlock()
}

func (b *MemoryBus) PublishRoom(_ context.Context, roomID string, ev Event) error {
	if ev.RoomID == "" {
		ev.RoomID = roomID
	}
	b.dispatch(ev)
	return nil
}

func (b *MemoryBus) PublishUser(_ context.Context, userID string, ev Event) error {
	if ev.UserID == "" {
		ev.UserID = userID
	}
	b.dispatch(ev)
	return nil
}

func (b *MemoryBus) dispatch(ev Event) {
	b.mu.RLock()
	h := b.handler
	b.mu.RUnlock()
	if h != nil {
		h(ev)
	}
}

func (b *MemoryBus) Run(ctx context.Context, onEvent func(Event)) error {
	b.SetHandler(onEvent)
	<-ctx.Done()
	return ctx.Err()
}
