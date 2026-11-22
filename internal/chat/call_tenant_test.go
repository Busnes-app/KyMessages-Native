package chat

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// suspendsMidJoin reports the tenant active on the first read and suspended after: a suspension
// that commits between a join's authorization and its registration.
type suspendsMidJoin struct {
	store.ChatStore
	reads atomic.Int32
}

func (s *suspendsMidJoin) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	t, err := s.ChatStore.GetTenant(ctx, id)
	if err == nil && s.reads.Add(1) > 1 {
		t.Status = store.TenantStatusSuspended
	}
	return t, err
}

func TestCallJoinFencedByTenantSuspension(t *testing.T) {
	ctx := context.Background()
	st := openChatTestStore(t)
	if _, err := st.Chat().EnsureTenant(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: "org-a", Kind: store.RoomKindChannel, Name: "standup", CreatedBy: "u1"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u1"}); err != nil {
		t.Fatal(err)
	}
	join := func(mgr *CallManager, user string, guest bool) (*JoinCallResponse, error) {
		return mgr.Join(ctx, JoinCallRequest{TenantID: "org-a", RoomID: room.ID, UserID: user, DisplayName: user, IsGuest: guest, Audio: true, Video: true, ProtectIP: true})
	}

	// Suspended between authorization and registration: no token, no surviving peer.
	for _, guest := range []bool{false, true} {
		racing := NewCallManager(&suspendsMidJoin{ChatStore: st.Chat()}, NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
		resp, err := join(racing, "u1", guest)
		if !errors.Is(err, ErrTenantInactive) || resp != nil {
			t.Fatalf("guest=%v join racing a suspension = %+v, %v; want ErrTenantInactive and no token", guest, resp, err)
		}
		if state := racing.GetState(room.ID); state != nil && len(state.Peers) != 0 {
			t.Fatalf("guest=%v: peer survived the suspension: %+v", guest, state.Peers)
		}
	}

	// Already suspended: refused before anything is registered.
	mgr := NewCallManager(st.Chat(), NewHub(&captureBus{}), fakeLiveKitClient(t), nil)
	if err := st.Chat().SetTenantStatus(ctx, "org-a", store.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	for _, guest := range []bool{false, true} {
		if _, err := join(mgr, "u1", guest); !errors.Is(err, ErrTenantInactive) {
			t.Fatalf("guest=%v join on a suspended org = %v, want ErrTenantInactive", guest, err)
		}
	}
	if state := mgr.GetState(room.ID); state != nil && len(state.Peers) != 0 {
		t.Fatalf("peers on a suspended org's call: %+v", state.Peers)
	}

	// Active again: joins work and get a media token.
	if err := st.Chat().SetTenantStatus(ctx, "org-a", store.TenantStatusActive); err != nil {
		t.Fatal(err)
	}
	if resp, err := join(mgr, "u1", false); err != nil || resp.LiveKitToken == "" {
		t.Fatalf("join on an active org = %+v, %v; want a LiveKit token", resp, err)
	}
}
