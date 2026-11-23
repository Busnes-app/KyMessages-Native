package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// seedGrants gives one user a session, an MFA challenge, a device pairing, an
// active call session, and an active bot agent.
func seedGrants(t *testing.T, st store.Store) (roomID, callID, agentID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	room := &store.Room{Kind: store.RoomKindChannel, Name: "restore-call-room", CreatedBy: "u"}
	for _, err := range []error{
		st.Users().CreateUser(ctx, &store.User{ID: "u", Username: "u", PasswordHash: "h", Role: "user", Status: "active", SSOProvider: "local"}),
		st.Users().CreateUser(ctx, &store.User{ID: "bot-u", Username: "bot_u", DisplayName: "Bot U", PasswordHash: "", Role: "bot", Status: "active", SSOProvider: "bot"}),
		st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "session", UserID: "u", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "h"),
		st.Sessions().CreateMFAChallenge(ctx, &store.MFAChallenge{TokenHash: "challenge", UserID: "u", ExpiresAt: now.Add(time.Hour)}, "h"),
		st.Devices().CreatePairing(ctx, &store.DevicePairing{Secret: "pair", UserID: "u", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, "h"),
		st.Chat().CreateRoom(ctx, room, []string{"u"}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	cs := &store.CallSession{RoomID: room.ID, Mode: store.CallModeP2PMesh, Epoch: 1, StartedBy: "u"}
	if err := st.Chat().CreateCallSession(ctx, cs); err != nil {
		t.Fatal(err)
	}
	agent := &store.Agent{
		ID:          "agent-1",
		UserID:      "bot-u",
		Username:    "bot_u",
		DisplayName: "Bot U",
		OwnerUserID: "u",
		TokenHash:   "agent-token-hash",
		TokenState:  store.AgentTokenActive,
		CreatedBy:   "u",
		CreatedAt:   now,
	}
	if err := st.Agents().CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().UpsertPushSubscription(ctx, "session", &store.PushSubscription{
		TenantID: store.DefaultTenantID, UserID: "u", Endpoint: "https://fcm.googleapis.com/fcm/send/restored", P256DH: "k", AuthSecret: "a",
	}, 20); err != nil {
		t.Fatal(err)
	}
	dev := &store.E2EEDevice{TenantID: store.DefaultTenantID, UserID: "u", DeviceID: "D1", Curve25519: "c", Ed25519: "e", Signature: "s"}
	if err := st.E2EE().UpsertDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().AddOneTimeKeys(ctx, "u", "D1", []store.E2EEOneTimeKey{
		{KeyID: "k1", Key: "spent-after-backup", Signature: "s"}, {KeyID: "fb", Key: "fallback", Signature: "s", Fallback: true},
	}, 100); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().SendToDevice(ctx, []store.E2EEToDevice{{TenantID: store.DefaultTenantID, RecipientUserID: "u", RecipientDeviceID: "D1", SenderUserID: "u", SenderDeviceID: "D1", Type: "olm.v1", Content: "already read"}}); err != nil {
		t.Fatal(err)
	}
	return room.ID, cs.ID, agent.ID
}

func TestRestoreInvalidatesGrants(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	roomID, _, agentID := seedGrants(t, st)
	for range 2 { // Repeating offline preparation is harmless.
		if err := st.InvalidateRestoredGrants(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Sessions().GetSession(ctx, "session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("session survived", err)
	}
	if n, _ := st.E2EE().CountOneTimeKeys(ctx, "u", "D1"); n != 0 {
		t.Fatalf("%d restored one-time keys survived", n)
	}
	// A device retrying its pre-backup upload must not revive the key either.
	if err := st.E2EE().AddOneTimeKeys(ctx, "u", "D1", []store.E2EEOneTimeKey{{KeyID: "k1", Key: "spent-after-backup", Signature: "s"}}, 100); err != nil {
		t.Fatal(err)
	}
	// The fallback key may have been rotated away after the backup, so it is retired too, and
	// retrying its upload cannot revive it: claims find nothing until the device uploads anew.
	if err := st.E2EE().AddOneTimeKeys(ctx, "u", "D1", []store.E2EEOneTimeKey{{KeyID: "fb", Key: "fallback", Signature: "s", Fallback: true}}, 100); err != nil {
		t.Fatal(err)
	}
	if has, err := st.E2EE().HasFallbackKey(ctx, "u", "D1"); err != nil || has {
		t.Fatalf("after restore has fallback = %v %v, want false", has, err)
	}
	if k, err := st.E2EE().ClaimOneTimeKey(ctx, "u", "D1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after restore the claim = %+v %v, want none", k, err)
	}
	if err := st.E2EE().AddOneTimeKeys(ctx, "u", "D1", []store.E2EEOneTimeKey{{KeyID: "fb2", Key: "fresh", Signature: "s", Fallback: true}}, 100); err != nil {
		t.Fatal(err)
	}
	if k, err := st.E2EE().ClaimOneTimeKey(ctx, "u", "D1"); err != nil || k.KeyID != "fb2" {
		t.Fatalf("claim after a new fallback = %+v %v", k, err)
	}
	if mail, _ := st.E2EE().ToDevice(ctx, "u", "D1", 10); len(mail) != 0 {
		t.Fatalf("restored to-device mail survived: %+v", mail)
	}
	if _, _, err := st.Sessions().ConsumeMFAChallenge(ctx, "challenge"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("challenge survived", err)
	}
	if _, err := st.Devices().GetPairingBySecret(ctx, "pair"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing survived", err)
	}
	if _, err := st.Chat().GetActiveCallSession(ctx, store.DefaultTenantID, roomID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("active call survived", err)
	}
	if subs, err := st.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, "u"); err != nil || len(subs) != 0 {
		t.Fatalf("push subscriptions survived restore: %d (err %v)", len(subs), err)
	}
	agent, err := st.Agents().GetAgent(ctx, agentID)
	if err != nil {
		t.Fatal("agent lookup failed", err)
	}
	if agent.TokenState != store.AgentTokenRevoked || agent.TokenHash != "" {
		t.Fatalf("agent token survived restore: state=%q hashLen=%d", agent.TokenState, len(agent.TokenHash))
	}
	if _, err := st.Audit().LatestAuditRecord(ctx, "restore.grants_invalidated"); err != nil {
		t.Fatal("no audit row", err)
	}
}

func TestRestoreGrantInvalidationRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restore.db")
	st, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roomID, callID, agentID := seedGrants(t, st)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER refuse_restore_audit BEFORE INSERT ON audit_records WHEN NEW.action = 'restore.grants_invalidated' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.InvalidateRestoredGrants(ctx); err == nil {
		t.Fatal("failed audit was ignored")
	}
	if _, err := st.Sessions().GetSession(ctx, "session"); err != nil {
		t.Fatal("partial session deletion", err)
	}
	if _, err := st.Chat().GetActiveCallSession(ctx, store.DefaultTenantID, roomID); err != nil {
		t.Fatal("partial call invalidation", err)
	}
	if agent, err := st.Agents().GetAgent(ctx, agentID); err != nil || agent.TokenState != store.AgentTokenActive {
		t.Fatalf("partial agent invalidation: err=%v state=%v", err, agent)
	}
	if _, err := db.Exec(`DROP TRIGGER refuse_restore_audit`); err != nil {
		t.Fatal(err)
	}
	if err := st.InvalidateRestoredGrants(ctx); err != nil {
		t.Fatal(err)
	}
	var endedType string
	var endedAt int64
	if err := db.QueryRow(`SELECT typeof(ended_at), ended_at FROM call_sessions WHERE id = ?`, callID).Scan(&endedType, &endedAt); err != nil {
		t.Fatal("ended_at query failed", err)
	}
	if endedType != "integer" || endedAt <= 0 {
		t.Fatalf("call_sessions.ended_at stored as %s (%d), want positive integer", endedType, endedAt)
	}
}
