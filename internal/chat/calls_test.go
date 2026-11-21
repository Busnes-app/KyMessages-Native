package chat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func openChatTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func fakeLiveKitClient(t *testing.T) *rtc.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return rtc.NewClient(srv.URL, "testkey", "testsecret1234567890")
}

type captureBus struct {
	mu     sync.Mutex
	events []Event
}

func (b *captureBus) PublishRoom(_ context.Context, roomID string, ev Event) error {
	ev.RoomID = roomID
	b.mu.Lock()
	b.events = append(b.events, ev)
	b.mu.Unlock()
	return nil
}

func (b *captureBus) PublishUser(_ context.Context, userID string, ev Event) error {
	ev.UserID = userID
	b.mu.Lock()
	b.events = append(b.events, ev)
	b.mu.Unlock()
	return nil
}

func (b *captureBus) Run(_ context.Context, _ func(Event)) error { return nil }

func (b *captureBus) snapshot() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.events))
	copy(out, b.events)
	return out
}

func TestCallManagerHybridEscalationAndStepDown(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	room := &store.Room{Kind: store.RoomKindChannel, Name: "war-room", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1", "u2", "u3", "u4", "u5"}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	bus := &captureBus{}
	hub := NewHub(bus)
	mgr := NewCallManager(st.Chat(), hub, fakeLiveKitClient(t), []string{"stun:stun.example.com:3478"})
	mgr.SetStepDownDelay(40 * time.Millisecond)

	// 1) Peer 1 joins audio-only -> p2p_mesh, epoch 1.
	r1, err := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u1", DisplayName: "Alice", Audio: true, Video: false})
	if err != nil {
		t.Fatalf("u1 join: %v", err)
	}
	if r1.Mode != store.CallModeP2PMesh || r1.Epoch != 1 || r1.LiveKitToken != "" {
		t.Fatalf("expected p2p_mesh epoch 1 without token, got %+v", r1)
	}

	// 2) Peer 2 joins with video -> still <= p2p_max_video (2), stays p2p_mesh!
	r2, err := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u2", DisplayName: "Bob", Audio: true, Video: true})
	if err != nil {
		t.Fatalf("u2 join: %v", err)
	}
	if r2.Mode != store.CallModeP2PMesh || r2.Epoch != 1 {
		t.Fatalf("2-person video call must stay p2p_mesh, got %+v", r2)
	}

	// 3) Peer 3 joins with video -> exceeds p2p_max_video (2) -> escalates to sfu_livekit epoch 2!
	r3, err := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u3", DisplayName: "Carol", Audio: true, Video: true})
	if err != nil {
		t.Fatalf("u3 join: %v", err)
	}
	if r3.Mode != store.CallModeSFULiveKit || r3.Epoch != 2 || r3.LiveKitToken == "" || !strings.HasPrefix(r3.LiveKitURL, "ws") {
		t.Fatalf("3rd video peer must escalate to sfu_livekit epoch 2 with JWT, got %+v", r3)
	}

	// Verify u1 and u2 received call.migrate events with their own LiveKit JWTs.
	evs := bus.snapshot()
	migratedUsers := map[string]CallMigratePayload{}
	for _, ev := range evs {
		if ev.Type == EventCallMigrate {
			var mp CallMigratePayload
			if err := json.Unmarshal(ev.Data, &mp); err == nil {
				migratedUsers[ev.UserID] = mp
			}
		}
	}
	if len(migratedUsers) != 2 || migratedUsers["u1"].LiveKitToken == "" || migratedUsers["u2"].LiveKitToken == "" {
		t.Fatalf("expected u1 and u2 to receive call.migrate with JWTs, got %+v", migratedUsers)
	}

	// 4) Peer 3 leaves -> drops back to 2 peers -> after 40ms step-down delay, returns to p2p_mesh epoch 3!
	mgr.Leave(ctx, room.ID, "u3")
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		stNow := mgr.GetState(room.ID)
		if stNow != nil && stNow.Mode == store.CallModeP2PMesh && stNow.Epoch == 3 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	stNow := mgr.GetState(room.ID)
	if stNow == nil || stNow.Mode != store.CallModeP2PMesh || stNow.Epoch != 3 {
		t.Fatalf("expected hysteretic step-down to p2p_mesh epoch 3, got %+v", stNow)
	}

	// 5) Audio-only 4-person mesh stays P2P (p2p_max_audio=4), then turning on camera escalates!
	off := false
	mgr.HandleClientFrame(ctx, "u2", false, ClientFrame{Type: ClientFrameCallMedia, RoomID: room.ID, Video: &off})
	if _, err := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u3", DisplayName: "Carol", Audio: true, Video: false}); err != nil {
		t.Fatalf("u3 audio join: %v", err)
	}
	r4, err := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u4", DisplayName: "Dave", Audio: true, Video: false})
	if err != nil {
		t.Fatalf("u4 audio join: %v", err)
	}
	if r4.Mode != store.CallModeP2PMesh {
		t.Fatalf("4-person audio-only call must stay p2p_mesh, got %s", r4.Mode)
	}

	// Turning on video for u4 with 4 peers immediately escalates to sfu_livekit!
	on := true
	mgr.HandleClientFrame(ctx, "u4", false, ClientFrame{Type: ClientFrameCallMedia, RoomID: room.ID, Video: &on})
	if stAfter := mgr.GetState(room.ID); stAfter == nil || stAfter.Mode != store.CallModeSFULiveKit {
		t.Fatalf("enabling video with 4 peers must escalate to sfu_livekit, got %+v", stAfter)
	}
}

func TestCallManagerICEFailedStickyAndPrivacyRules(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	room := &store.Room{Kind: store.RoomKindChannel, Name: "priv", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1", "u2"}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	// Without LiveKit configured, ProtectIP must refuse P2P fallback.
	noLK := NewCallManager(st.Chat(), NewHub(&captureBus{}), nil, nil)
	if _, err := noLK.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u1", Audio: true, ProtectIP: true}); !errors.Is(err, ErrSFUUnavailable) {
		t.Fatalf("expected ErrSFUUnavailable when ProtectIP=true and LiveKit unset, got %v", err)
	}

	// With LiveKit configured, ICE failure sets SFUSticky=true and never steps back down.
	mgr := NewCallManager(st.Chat(), NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
	mgr.SetStepDownDelay(25 * time.Millisecond)

	_, _ = mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u1", Audio: true})
	_, _ = mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u2", Audio: true})
	mgr.HandleClientFrame(ctx, "u1", false, ClientFrame{Type: ClientFrameCallICEFailed, RoomID: room.ID})

	stAfter := mgr.GetState(room.ID)
	if stAfter == nil || stAfter.Mode != store.CallModeSFULiveKit || !stAfter.SFUSticky {
		t.Fatalf("expected sticky sfu_livekit after ice_failed, got %+v", stAfter)
	}

	mgr.Leave(ctx, room.ID, "u2")
	time.Sleep(60 * time.Millisecond)
	if stStill := mgr.GetState(room.ID); stStill == nil || stStill.Mode != store.CallModeSFULiveKit {
		t.Fatalf("sticky SFU call must not step back down to P2P, got %+v", stStill)
	}
}

func TestCallSignalRelayedOnlyToPeerInSameCall(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	room := &store.Room{Kind: store.RoomKindChannel, Name: "sig", CreatedBy: "u1"}
	_ = st.Chat().CreateRoom(ctx, room, []string{"u1", "u2"})

	bus := &captureBus{}
	mgr := NewCallManager(st.Chat(), NewHub(bus), nil, nil)

	r1, _ := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u1", Audio: true})
	r2, _ := mgr.Join(ctx, JoinCallRequest{RoomID: room.ID, UserID: "u2", Audio: true})

	mgr.HandleClientFrame(ctx, "u1", false, ClientFrame{
		Type:     ClientFrameCallSignal,
		RoomID:   room.ID,
		ToPeerID: r2.PeerID,
		Kind:     "offer",
		Data:     json.RawMessage(`{"type":"offer","sdp":"v=0..."}`),
	})

	var found *CallSignalPayload
	for _, ev := range bus.snapshot() {
		if ev.Type == EventCallSignal && ev.UserID == "u2" {
			var p CallSignalPayload
			_ = json.Unmarshal(ev.Data, &p)
			found = &p
		}
	}
	if found == nil || found.FromPeerID != r1.PeerID || found.ToPeerID != r2.PeerID || found.Kind != "offer" {
		t.Fatalf("expected relayed offer from %s to %s, got %+v", r1.PeerID, r2.PeerID, found)
	}
}
