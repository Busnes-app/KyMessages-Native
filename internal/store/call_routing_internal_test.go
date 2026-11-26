package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func callRoutingStore(t *testing.T) (*SQLStore, config.DatabaseConfig) {
	t.Helper()
	cfg := testdb.Config(t)
	opened, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := opened.(*SQLStore)
	t.Cleanup(func() { s.Close() })
	return s, cfg
}

func seedCallRoom(t *testing.T, s *SQLStore, org, roomID, userID string) (*User, *CallSession) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatalf("seed step: %v", err)
	}
	if err := s.Chat().ApplyTenantDirectory(ctx, TenantDirectoryEntry{TenantID: org, Status: TenantStatusActive, Enabled: true, Valid: true, Revision: 1}); err != nil {
		t.Fatalf("seed step: %v", err)
	}
	u := &User{ID: userID, Username: userID, SSOProvider: "kyidentity", SSOSubject: userID, OrgID: org, Role: "user", Status: "active"}
	if err := s.Users().CreateUser(ctx, u); err != nil {
		t.Fatalf("seed step: %v", err)
	}
	if err := s.Chat().CreateRoom(ctx, &Room{ID: roomID, TenantID: org, Kind: RoomKindChannel, CreatedBy: userID}, nil); err != nil {
		t.Fatalf("seed step: %v", err)
	}
	l, err := s.Chat().AcquireCallRoom(ctx, org, roomID, "owner-a", time.Minute)
	if err != nil {
		t.Fatalf("seed step: %v", err)
	}
	cs := &CallSession{ID: "call-" + roomID, TenantID: org, RoomID: roomID, Mode: CallModeSFULiveKit, Epoch: 1, LiveKitRoom: "sfu-" + roomID, StartedBy: userID, OwnerID: l.Holder, OwnerGeneration: l.Generation}
	if err := s.Chat().CreateCallSession(ctx, cs); err != nil {
		t.Fatalf("seed step: %v", err)
	}
	if err := s.Sessions().CreateSession(ctx, &Session{TokenHash: "call-session-" + userID, UserID: userID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour), SSOSession: SSOSession{Issuer: "https://id.example", SID: "sid-a-" + userID, IssuedAt: time.Now().Unix()}}, u.PasswordHash); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: userID, PeerID: "peer-" + userID, SessionHash: "call-session-" + userID}); err != nil {
		t.Fatalf("seat: %v", err)
	}
	return u, cs
}

func TestCallRoomLeaseFencesStaleOwnerAndWrongOrg(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-000000000064"
	_, cs := seedCallRoom(t, s, org, "routed-room", "routed-user")
	if _, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, "owner-b", time.Minute); !errors.Is(err, ErrCallOwnerLost) {
		t.Fatalf("second owner admitted: %v", err)
	}
	renewed, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, cs.OwnerID, time.Minute)
	if err != nil || renewed.Generation != cs.OwnerGeneration {
		t.Fatalf("renew changed generation: %+v %v", renewed, err)
	}
	// Use explicit DB state, not wall-clock sleeps, to model an owner which died.
	if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE call_room_owners SET expires_at=0 WHERE room_id=?`), cs.RoomID); err != nil {
		t.Fatal(err)
	}
	next, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, "owner-b", time.Minute)
	if err != nil || next.Generation <= cs.OwnerGeneration {
		t.Fatalf("handover: %+v %v", next, err)
	}
	for name, write := range map[string]func() error{
		"update": func() error { return s.Chat().UpdateCallSession(ctx, cs) },
		"end":    func() error { return s.Chat().EndOwnedCallSession(ctx, cs, 0) },
		"seat": func() error {
			return s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: "routed-user", PeerID: "stale-peer", SessionHash: "call-session-routed-user"})
		},
	} {
		if err := write(); !errors.Is(err, ErrCallOwnerLost) {
			t.Fatalf("stale %s: %v", name, err)
		}
	}
	if err := s.Chat().ReleaseCallRoom(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	if held, err := s.Chat().CallRoomHeld(ctx, next); err != nil || !held {
		t.Fatalf("stale release removed new owner: %v %v", held, err)
	}
	wrong := next
	wrong.TenantID = "00000000-0000-4000-8000-000000000065"
	if held, err := s.Chat().CallRoomHeld(ctx, wrong); err != nil || held {
		t.Fatalf("wrong org held lease: %v %v", held, err)
	}
	if err := s.Chat().ReleaseCallRoom(ctx, next); err != nil {
		t.Fatal(err)
	}
	again, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, "owner-b", time.Minute)
	if err != nil || again.Generation <= next.Generation {
		t.Fatalf("same process after release reused fence: %+v %v", again, err)
	}
}

func TestCallSeatErasureKeepsCleanupAndCompletionAtomic(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-000000000066"
	u, cs := seedCallRoom(t, s, org, "cleanup-room", "cleanup-user")
	survivor := &User{ID: "survivor", Username: "survivor", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "survivor", Role: "user", Status: "active"}
	if err := s.Users().CreateUser(ctx, survivor); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().AddRoomMember(ctx, &RoomMember{TenantID: org, RoomID: cs.RoomID, UserID: survivor.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions().CreateSession(ctx, &Session{TokenHash: "survivor-session", UserID: survivor.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}, survivor.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: survivor.ID, PeerID: "peer-survivor", SessionHash: "survivor-session"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chat().EraseUser(ctx, org, u); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Chat().GetActiveCallSession(ctx, org, cs.RoomID)
	if err != nil || fresh.Epoch <= cs.Epoch || fresh.LiveKitRoom == cs.LiveKitRoom {
		t.Fatalf("media target was not retired: %+v %v", fresh, err)
	}
	if err := s.Chat().UpdateCallSession(ctx, cs); !errors.Is(err, ErrCallStateStale) {
		t.Fatalf("stale media epoch restored: %v", err)
	}
	if err := s.Chat().ClearPendingBlobDeletes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 0 {
		t.Fatalf("audit before SFU cleanup: %d %v", n, err)
	}
	pending, err := s.Chat().PendingCallEvictions(ctx, org, u.ID, 10)
	if err != nil || len(pending) != 1 || pending[0].PeerID != "peer-"+u.ID {
		t.Fatalf("lost opaque cleanup: %+v %v", pending, err)
	}
	wrong := pending[0]
	wrong.TenantID = "other-org"
	if err := s.Chat().ClearCallEviction(ctx, wrong); err != nil {
		t.Fatal(err)
	}
	if left, err := s.Chat().PendingCallEvictions(ctx, org, u.ID, 10); err != nil || len(left) != 1 {
		t.Fatalf("wrong org cleared cleanup: %+v %v", left, err)
	}
	if err := s.Chat().ClearCallEviction(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.Chat().EraseUser(ctx, org, u); err != nil {
			t.Fatal(err)
		}
		if err := s.Chat().ClearPendingBlobDeletes(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 1 {
		t.Fatalf("completion audit: %d %v", n, err)
	}
	var seats int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats WHERE user_id='survivor'`).Scan(&seats); err != nil || seats != 1 {
		t.Fatalf("other member seat lost: %d %v", seats, err)
	}
}

func TestCallPurgeRetainsSFUCleanupUntilTerminalMark(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const gone = "00000000-0000-4000-8000-000000000067"
	const keep = "00000000-0000-4000-8000-000000000068"
	_, cs := seedCallRoom(t, s, gone, "purge-call-room", "purge-call-user")
	_, other := seedCallRoom(t, s, keep, "keep-call-room", "keep-call-user")
	if err := s.Chat().QueueCallSeatRemoval(ctx, other.RoomID, other.StartedBy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chat().ApplyTenantLifecycle(ctx, gone, TenantStatusDeleted, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().PurgeTenantRows(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().MarkTenantPurged(ctx, gone); !errors.Is(err, ErrCallCleanupPending) {
		t.Fatalf("purge hid SFU residue: %v", err)
	}
	for _, table := range []string{"call_room_owners", "call_seats"} {
		var n int
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM `+table+` WHERE tenant_id=?`), gone).Scan(&n); err != nil || n != 0 {
			t.Fatalf("purge retained %s: %d %v", table, n, err)
		}
	}
	pending, err := s.Chat().PendingCallEvictions(ctx, gone, "", 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("whole-room/issued-seat cleanup lost: %+v %v", pending, err)
	}
	whole := false
	for _, p := range pending {
		if p.LiveKitRoom != cs.LiveKitRoom {
			t.Fatalf("wrong SFU purge target: %+v", p)
		}
		if p.PeerID == "" {
			whole = true
		}
		if err := s.Chat().ClearCallEviction(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if !whole {
		t.Fatal("purge did not retain whole-room cleanup")
	}

	for range 2 {
		if err := s.Chat().PurgeTenantRows(ctx, gone); err != nil {
			t.Fatal(err)
		}
		if err := s.Chat().MarkTenantPurged(ctx, gone); err != nil {
			t.Fatal(err)
		}
	}
	if pending, err := s.Chat().PendingCallEvictions(ctx, keep, "", 10); err != nil || len(pending) != 1 {
		t.Fatalf("other org cleanup changed: %+v %v", pending, err)
	}
}

func TestCallRoomLeaseHasOneWinnerAcrossConnections(t *testing.T) {
	ctx := context.Background()
	s, cfg := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-000000000069"
	_, cs := seedCallRoom(t, s, org, "race-call-room", "race-call-user")
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	for i := range 8 {
		if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE call_room_owners SET expires_at=0 WHERE room_id=?`), cs.RoomID); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for j, st := range []Store{s, opened} {
			wg.Add(1)
			go func(j int, st Store) {
				defer wg.Done()
				<-start
				_, err := st.Chat().AcquireCallRoom(ctx, org, cs.RoomID, fmt.Sprintf("replica-%d-%d", i, j), time.Minute)
				errs <- err
			}(j, st)
		}
		close(start)
		wg.Wait()
		close(errs)
		winners := 0
		for err := range errs {
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrCallOwnerLost) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("%d lease winners", winners)
		}
	}
}

func TestCallRestoreInvalidatesOwnerAndRetainsSFUWork(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-00000000006a"
	_, cs := seedCallRoom(t, s, org, "restore-call-room", "restore-call-user")
	before := CallLease{TenantID: org, RoomID: cs.RoomID, Holder: cs.OwnerID, Generation: cs.OwnerGeneration}
	if err := s.InvalidateRestoredGrants(ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := s.Chat().CallRoomHeld(ctx, before); err != nil || held {
		t.Fatalf("restored owner kept lease: %v %v", held, err)
	}
	if _, err := s.Chat().GetActiveCallSession(ctx, org, cs.RoomID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restored call stayed active: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("restored seats remain: %d %v", n, err)
	}
	if pending, err := s.Chat().PendingCallEvictions(ctx, org, "", 10); err != nil || len(pending) != 1 || pending[0].LiveKitRoom != cs.LiveKitRoom {
		t.Fatalf("restored media cleanup lost: %+v %v", pending, err)
	}
	if _, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, "restored-owner", time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale restored org acquired call room before sync: %v", err)
	}
	if err := s.Chat().ApplyTenantDirectory(ctx, TenantDirectoryEntry{TenantID: org, Status: TenantStatusActive, Enabled: true, Valid: true, Revision: 1}); err != nil {
		t.Fatalf("re-admit org after restore: %v", err)
	}
	next, err := s.Chat().AcquireCallRoom(ctx, org, cs.RoomID, "restored-owner", time.Minute)
	if err != nil || next.Generation <= cs.OwnerGeneration {
		t.Fatalf("restored generation reused: %+v %v", next, err)
	}
}

func TestCallLeaseCannotChangeAnotherRoomSession(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-00000000006b"
	_, a := seedCallRoom(t, s, org, "leased-room-a", "lease-user-a")
	_, b := seedCallRoom(t, s, org, "leased-room-b", "lease-user-b")
	forged := *b
	forged.RoomID = a.RoomID
	forged.Mode = CallModeP2PMesh
	forged.Epoch = 1000
	if err := s.Chat().UpdateCallSession(ctx, &forged); !errors.Is(err, ErrCallStateStale) {
		t.Fatalf("lease changed another room: %v", err)
	}
	if err := s.Chat().EndOwnedCallSession(ctx, &forged, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease ended another room: %v", err)
	}
	if got, err := s.Chat().GetActiveCallSession(ctx, org, b.RoomID); err != nil || got.Mode != b.Mode || got.Epoch != b.Epoch {
		t.Fatalf("other room changed: %+v %v", got, err)
	}
	if pending, err := s.Chat().PendingCallEvictions(ctx, org, "", 10); err != nil || len(pending) != 0 {
		t.Fatalf("wrong room queued cleanup: %+v %v", pending, err)
	}
}

func TestCallSeatSIDLogoutPreservesAnotherSessionAndRetiresOnlyItsEpoch(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-00000000006c"
	u, cs := seedCallRoom(t, s, org, "sid-call-room", "sid-call-user")
	makeSession := func(hash, sid string) {
		t.Helper()
		if err := s.Sessions().CreateSession(ctx, &Session{TokenHash: hash, UserID: u.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), SSOSession: SSOSession{Issuer: "https://id.example", SID: sid, IssuedAt: time.Now().Unix()}}, u.PasswordHash); err != nil {
			t.Fatal(err)
		}
	}
	makeSession("sid-session-b", "sid-b")
	if err := s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: u.ID, PeerID: "peer-b", SessionHash: "sid-session-b"}); !errors.Is(err, ErrCallStateStale) {
		t.Fatalf("silent replacement lost old session linkage: %v", err)
	}
	if err := s.Chat().QueueCallSeatRemoval(ctx, cs.RoomID, u.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Chat().PendingCallEvictions(ctx, org, u.ID, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("replacement cleanup: %+v %v", pending, err)
	}
	if err := s.Chat().ClearCallEviction(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	current, err := s.Chat().GetActiveCallSession(ctx, org, cs.RoomID)
	if err != nil {
		t.Fatal(err)
	}
	current.OwnerID = cs.OwnerID
	current.OwnerGeneration = cs.OwnerGeneration
	if err := s.Chat().PutCallSeat(ctx, current, CallSeat{UserID: u.ID, PeerID: "peer-b", SessionHash: "sid-session-b"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Sessions().ApplySSOLogout(ctx, "https://id.example", u.SSOSubject, org, "sid-a-"+u.ID, "old-sid-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats WHERE session_hash='sid-session-b'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("different SID removed current seat: %d %v", n, err)
	}
	if p, err := s.Chat().PendingCallEvictions(ctx, org, "", 10); err != nil || len(p) != 0 {
		t.Fatalf("different SID retired current media: %+v %v", p, err)
	}
	if _, _, err := s.Sessions().ApplySSOLogout(ctx, "https://id.example", u.SSOSubject, "wrong-org", "sid-b", "wrong-org-sid", time.Now().Unix()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong org logout: %v", err)
	}
	if _, _, err := s.Sessions().ApplySSOLogout(ctx, "https://id.example", u.SSOSubject, org, "sid-b", "current-sid-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats WHERE user_id='sid-call-user'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("current SID left seat: %d %v", n, err)
	}
	pending, err = s.Chat().PendingCallEvictions(ctx, org, u.ID, 10)
	if err != nil || len(pending) != 1 || pending[0].LiveKitRoom != current.LiveKitRoom {
		t.Fatalf("SID cleanup lost: %+v %v", pending, err)
	}
	if _, _, err := s.Sessions().ApplySSOLogout(ctx, "https://id.example", u.SSOSubject, org, "sid-b", "current-sid-logout", time.Now().Unix()); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("logout replay: %v", err)
	}
	makeSession("sid-session-c", "sid-c")
	fresh, err := s.Chat().GetActiveCallSession(ctx, org, cs.RoomID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.OwnerID = cs.OwnerID
	fresh.OwnerGeneration = cs.OwnerGeneration
	if fresh.Epoch <= current.Epoch || fresh.LiveKitRoom == current.LiveKitRoom {
		t.Fatal("SID logout did not retire old bearer target")
	}
	if err := s.Chat().PutCallSeat(ctx, fresh, CallSeat{UserID: u.ID, PeerID: "peer-c", SessionHash: "sid-session-c"}); !errors.Is(err, ErrCallCleanupPending) {
		t.Fatalf("new media admitted before cleanup: %v", err)
	}
	if pending[0].LiveKitRoom == fresh.LiveKitRoom {
		t.Fatal("old cleanup targets replacement media")
	}
	if err := s.Chat().ClearCallEviction(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().PutCallSeat(ctx, fresh, CallSeat{UserID: u.ID, PeerID: "peer-c", SessionHash: "sid-session-c"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().ClearCallEviction(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats WHERE session_hash='sid-session-c'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("old cleanup removed replacement seat: %d %v", n, err)
	}
}

func TestCallSeatIssuanceRacingSessionDeletionCannotSurvive(t *testing.T) {
	ctx := context.Background()
	s, cfg := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-00000000006d"
	u, cs := seedCallRoom(t, s, org, "session-race-room", "session-race-user")
	opened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	for i := range 8 {
		if err := s.Chat().QueueCallSeatRemoval(ctx, cs.RoomID, u.ID); err != nil {
			t.Fatal(err)
		}
		pending, err := s.Chat().PendingCallEvictions(ctx, org, u.ID, 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pending {
			if err := s.Chat().ClearCallEviction(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		current, err := s.Chat().GetActiveCallSession(ctx, org, cs.RoomID)
		if err != nil {
			t.Fatal(err)
		}
		current.OwnerID = cs.OwnerID
		current.OwnerGeneration = cs.OwnerGeneration
		hash := fmt.Sprintf("racing-session-%d", i)
		if err := s.Sessions().CreateSession(ctx, &Session{TokenHash: hash, UserID: u.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}, u.PasswordHash); err != nil {
			t.Fatal(err)
		}
		seat := CallSeat{UserID: u.ID, PeerID: fmt.Sprintf("racing-peer-%d", i), SessionHash: hash}
		if err := s.Chat().PutCallSeat(ctx, current, seat); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var putErr, deleteErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; putErr = s.Chat().PutCallSeat(ctx, current, seat) }()
		go func() { defer wg.Done(); <-start; deleteErr = opened.Sessions().DeleteSession(ctx, hash) }()
		close(start)
		wg.Wait()
		if deleteErr != nil || putErr != nil && !errors.Is(putErr, ErrNotFound) {
			t.Fatalf("concurrent grant/revoke: %v %v", putErr, deleteErr)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM call_seats WHERE session_hash=?`), hash).Scan(&n); err != nil || n != 0 {
			t.Fatalf("revoked session kept seat: %d %v", n, err)
		}
	}
}

func TestCallSeatExpiredSessionAndDeadOwnerAreRetired(t *testing.T) {
	for _, reason := range []string{"expired-session", "dead-owner"} {
		t.Run(reason, func(t *testing.T) {
			ctx := context.Background()
			s, _ := callRoutingStore(t)
			const org = "00000000-0000-4000-8000-00000000006e"
			u, cs := seedCallRoom(t, s, org, "expired-room", "expired-user")
			if reason == "expired-session" {
				if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE sessions SET expires_at=? WHERE token_hash=?`), time.Now().UTC().Add(-time.Minute), "call-session-"+u.ID); err != nil {
					t.Fatal(err)
				}
				if err := s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: u.ID, PeerID: "peer-" + u.ID, SessionHash: "call-session-" + u.ID}); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expired grant issued a seat: %v", err)
				}
				if err := s.Sessions().CleanExpiredSessions(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE call_room_owners SET expires_at=0 WHERE room_id=?`), cs.RoomID); err != nil {
					t.Fatal(err)
				}
				if err := s.Chat().PruneCallSeats(ctx, 25*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			pending, err := s.Chat().PendingCallEvictions(ctx, org, u.ID, 10)
			if err != nil || len(pending) != 1 || pending[0].LiveKitRoom != cs.LiveKitRoom {
				t.Fatalf("retired target lost: %+v %v", pending, err)
			}
			var n int
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_seats`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("retired seat remains: %d %v", n, err)
			}
		})
	}
}

func TestCallConcurrentErasureCausesRetainTheIssuedMediaTarget(t *testing.T) {
	ctx := context.Background()
	s, _ := callRoutingStore(t)
	const org = "00000000-0000-4000-8000-00000000006f"
	first, cs := seedCallRoom(t, s, org, "shared-epoch-room", "erased-first")
	second := &User{ID: "erased-second", Username: "erased-second", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "erased-second", Role: "user", Status: "active"}
	if err := s.Users().CreateUser(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().AddRoomMember(ctx, &RoomMember{TenantID: org, RoomID: cs.RoomID, UserID: second.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions().CreateSession(ctx, &Session{UserID: second.ID, TokenHash: "second-session", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}, second.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().PutCallSeat(ctx, cs, CallSeat{UserID: second.ID, PeerID: "second-peer", SessionHash: "second-session"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*User{first, second} {
		if _, err := s.Chat().EraseUser(ctx, org, u); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.Chat().PendingCallEvictions(ctx, org, "", 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("erasure causes lost: %+v %v", pending, err)
	}
	for _, p := range pending {
		if p.LiveKitRoom != cs.LiveKitRoom {
			t.Fatalf("cleanup used a later unissued target: %+v", p)
		}
	}
	if err := s.Chat().ClearPendingBlobDeletes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 0 {
		t.Fatalf("premature completion: %d %v", n, err)
	}
	for _, p := range pending {
		if err := s.Chat().ClearCallEviction(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 100, "sso.user_erased"); err != nil || n != 2 {
		t.Fatalf("missing completion: %d %v", n, err)
	}
}
