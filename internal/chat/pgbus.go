package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// NumPGShards spreads NOTIFY fan-out across 16 channels to avoid single-channel contention.
	NumPGShards = 16
	// UserBusChannel carries targeted user control events (auth.revoked, read.sync, membership).
	UserBusChannel = "km_user_bus"
	// MaxNotifyBytes keeps every pg_notify payload well below PostgreSQL's 8000-byte limit.
	MaxNotifyBytes = 4096
)

// Notifier emits PostgreSQL NOTIFY statements (satisfied by store.Store).
type Notifier interface {
	Notify(ctx context.Context, channel, payload string) error
}

// ShardChannel returns the deterministic LISTEN/NOTIFY channel name for a room ID.
func ShardChannel(roomID string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(roomID))
	return fmt.Sprintf("km_bus_%d", h.Sum32()%NumPGShards)
}

// PostgresBus fans out real-time events across horizontally scaled KyMessages pods using
// sharded PostgreSQL LISTEN/NOTIFY without requiring Redis or Kafka.
type PostgresBus struct {
	dsn      string
	notifier Notifier
}

func NewPostgresBus(dsn string, notifier Notifier) *PostgresBus {
	return &PostgresBus{
		dsn:      dsn,
		notifier: notifier,
	}
}

func encodeNotifyPayload(ev Event) (string, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	if len(b) <= MaxNotifyBytes {
		return string(b), nil
	}
	// Oversized payload: drop full body and signal clients to catch up by sequence number.
	slim := Event{
		Type:   ev.Type,
		RoomID: ev.RoomID,
		Seq:    ev.Seq,
		UserID: ev.UserID,
		Data:   json.RawMessage(`{"refetch":true}`),
	}
	b, err = json.Marshal(slim)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (b *PostgresBus) PublishRoom(ctx context.Context, roomID string, ev Event) error {
	if ev.RoomID == "" {
		ev.RoomID = roomID
	}
	payload, err := encodeNotifyPayload(ev)
	if err != nil {
		return err
	}
	return b.notifier.Notify(ctx, ShardChannel(roomID), payload)
}

func (b *PostgresBus) PublishUser(ctx context.Context, userID string, ev Event) error {
	if ev.UserID == "" {
		ev.UserID = userID
	}
	payload, err := encodeNotifyPayload(ev)
	if err != nil {
		return err
	}
	return b.notifier.Notify(ctx, UserBusChannel, payload)
}

// Run maintains a dedicated PostgreSQL LISTEN session with exponential-backoff reconnect.
func (b *PostgresBus) Run(ctx context.Context, onEvent func(Event)) error {
	backoff := 200 * time.Millisecond
	const maxBackoff = 5 * time.Second

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := b.listenOnce(ctx, onEvent)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("[CHAT BUS] PostgreSQL LISTEN disconnected (%v); reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (b *PostgresBus) listenOnce(ctx context.Context, onEvent func(Event)) error {
	conn, err := pgx.Connect(ctx, b.dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = conn.Close(closeCtx)
		cancel()
	}()

	for i := 0; i < NumPGShards; i++ {
		if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN km_bus_%d", i)); err != nil {
			return fmt.Errorf("listen shard %d: %w", i, err)
		}
	}
	if _, err := conn.Exec(ctx, "LISTEN "+UserBusChannel); err != nil {
		return fmt.Errorf("listen user bus: %w", err)
	}

	for {
		notif, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var ev Event
		if err := json.Unmarshal([]byte(notif.Payload), &ev); err != nil {
			log.Printf("[CHAT BUS] ignoring malformed notify on %s: %v", notif.Channel, err)
			continue
		}
		onEvent(ev)
	}
}
