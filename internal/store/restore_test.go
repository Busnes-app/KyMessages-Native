package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
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
	// E3: the identity and key backup are the point of a restore; a QR pairing is a grant.
	if err := st.E2EE().PutMasterKey(ctx, &store.E2EEMasterKey{TenantID: "t", UserID: "u", MasterKey: "mk", SelfSignature: "ss", BackupKey: "bk", BackupSignature: "bs", RecoveryMaster: "rm", RecoveryBackup: "rb"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().PutBackupSessions(ctx, "u", 1, []store.E2EEBackupSession{{RoomID: "r", SessionID: "s", Sealed: "x"}}, 10); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().CreatePairing(ctx, &store.E2EEPairing{ID: "qr", TenantID: "t", UserID: "u", InitiatorDevice: "D1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
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
	if _, err := st.E2EE().GetPairing(ctx, "t", "u", "qr", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("QR pairing survived restore", err)
	}
	if m, err := st.E2EE().GetMasterKey(ctx, "u"); err != nil || m.MasterKey != "mk" {
		t.Fatalf("master key lost in restore: %+v %v", m, err)
	}
	if rows, err := st.E2EE().ListBackupSessions(ctx, "u", 1, "", "", 10); err != nil || len(rows) != 1 {
		t.Fatalf("key backup lost in restore: %+v %v", rows, err)
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

// A restored admitted guest session would let a guest removed after the backup back in.
func TestRestoreInvalidatesGuestSessions(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	res, err := st.Chat().UpsertMeeting(ctx, store.UpsertMeetingParams{ID: "m", TenantID: store.DefaultTenantID, OrganizerSub: "s", Title: "T"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	gs := st.GuestSessions()
	if _, err := gs.Create(ctx, "restored-secret", store.GuestSession{GuestID: "g1", TenantID: store.DefaultTenantID, MeetingID: "m",
		RoomID: res.Meeting.RoomID, GuestKey: "k", InviteHash: storeInviteFixture(t, st, res.Meeting, "k"), DisplayName: "V", Status: "waiting", KnockedAt: now, SeenAt: now, ExpiresAt: now + 3600000}); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Admit(ctx, res.Meeting.RoomID, "g1", "host", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.InvalidateRestoredGrants(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.BySecret(ctx, "restored-secret", now, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BySecret after restore: %v", err)
	}
	if _, err := gs.ByID(ctx, "g1", now, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ByID after restore: %v", err)
	}
}

// Restoring a <24h backup must not trust its pre-restore KyIdentity sync timestamp,
// active customer org admission, or cached storage pool grant, while preserving
// tenancy.mode, tenancy.staff_org_id, the default/staff/deleted org states, pool_seq
// fences, and permanent erased_subjects tombstones.
func TestRestoreInvalidatesTenancySyncAndPoolGrants(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "restore-tenancy.db")
	st, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const (
		staffOrg    = "00000000-0000-4000-8000-000000000001"
		customerOrg = "00000000-0000-4000-8000-000000000002"
		deletedOrg  = "00000000-0000-4000-8000-000000000003"
	)
	nowSec := strconv.FormatInt(time.Now().Unix(), 10)
	for k, v := range map[string]string{
		store.TenancyModeSettingKey:     "multi",
		store.TenancyStaffOrgSettingKey: staffOrg,
		"tenancy.kyidentity_synced_at":  nowSec,
		"tenancy.full_sync_at":          nowSec,
		"tenancy.orgs_revision":         "42",
		"tenancy.erased_revision":       "7",
	} {
		if err := st.Settings().SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []store.TenantDirectoryEntry{
		{TenantID: staffOrg, Revision: 5, Status: store.TenantStatusActive, Enabled: true, Valid: true},
		{TenantID: customerOrg, Revision: 10, Status: store.TenantStatusActive, Enabled: true, Valid: true,
			Quotas: store.TenantQuotas{MaxUploadBytes: 4096, MaxPendingUserBytes: 8192}},
		{TenantID: deletedOrg, Revision: 12, Status: store.TenantStatusDeleted, Enabled: false, Valid: true},
	} {
		if _, err := st.Chat().EnsureTenant(ctx, entry.TenantID); err != nil {
			t.Fatal(err)
		}
		if err := st.Chat().ApplyTenantDirectory(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	seq, _, err := st.Chat().NextPoolReport(ctx, customerOrg)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().SetPoolGrant(ctx, customerOrg, seq, 128, 1<<20, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().RememberErasedSubject(ctx, "sub-erased-before-backup", customerOrg); err != nil {
		t.Fatal(err)
	}

	// Idempotent across repeated offline runs.
	for range 2 {
		if err := st.InvalidateRestoredGrants(ctx); err != nil {
			t.Fatal(err)
		}
	}

	for _, key := range []string{
		"tenancy.kyidentity_synced_at",
		"tenancy.full_sync_at",
		"tenancy.orgs_revision",
		"tenancy.erased_revision",
	} {
		if v, err := st.Settings().GetSetting(ctx, key); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("setting %s survived restore: %q %v", key, v, err)
		}
	}
	if mode, err := st.Settings().GetSetting(ctx, store.TenancyModeSettingKey); err != nil || mode != "multi" {
		t.Fatalf("tenancy.mode = %q %v, want multi", mode, err)
	}
	if staff, err := st.Settings().GetSetting(ctx, store.TenancyStaffOrgSettingKey); err != nil || staff != staffOrg {
		t.Fatalf("tenancy.staff_org_id = %q %v, want %s", staff, err, staffOrg)
	}

	for _, tc := range []struct {
		id   string
		want string
	}{
		{staffOrg, store.TenantStatusActive},
		{customerOrg, store.TenantStatusSuspended},
		{deletedOrg, store.TenantStatusDeleted},
	} {
		got, err := st.Chat().GetTenant(ctx, tc.id)
		if err != nil {
			t.Fatalf("GetTenant(%s): %v", tc.id, err)
		}
		if got.Status != tc.want {
			t.Fatalf("tenant %s status = %q, want %q", tc.id, got.Status, tc.want)
		}
	}

	// Stale customer org cannot reserve attachment quota before fresh sync, and its cached
	// pool grant is cleared independently of tenant status.
	if _, err := st.Chat().ReserveAttachmentQuota(ctx, customerOrg, "u1", 64, store.AttachmentQuotaLimits{Pool: true, ActiveUploader: true}, time.Minute); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("ReserveAttachmentQuota(ActiveUploader) on stale org = %v, want ErrForbidden", err)
	}
	if _, err := st.Chat().ReserveAttachmentQuota(ctx, customerOrg, "u1", 64, store.AttachmentQuotaLimits{Pool: true}, time.Minute); !errors.Is(err, store.ErrPoolUnavailable) {
		t.Fatalf("ReserveAttachmentQuota(Pool) on stale org = %v, want ErrPoolUnavailable", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var defaultStatus string
	if err := db.QueryRow(`SELECT status FROM tenants WHERE id = ?`, store.DefaultTenantID).Scan(&defaultStatus); err != nil {
		t.Fatal(err)
	}
	if defaultStatus != store.TenantStatusActive {
		t.Fatalf("default tenant stored status = %q, want active", defaultStatus)
	}
	var poolSeq int64
	var ceiling, expires, reported sql.NullInt64
	if err := db.QueryRow(`SELECT pool_seq, pool_ceiling_bytes, pool_expires_at, pool_reported_bytes FROM tenants WHERE id = ?`, customerOrg).
		Scan(&poolSeq, &ceiling, &expires, &reported); err != nil {
		t.Fatal(err)
	}
	if poolSeq != seq {
		t.Fatalf("pool_seq = %d, want preserved %d", poolSeq, seq)
	}
	if ceiling.Valid || expires.Valid || reported.Valid {
		t.Fatalf("cached pool grant survived restore: ceiling=%v expires=%v reported=%v", ceiling, expires, reported)
	}

	// Permanent erasure tombstone must remain intact and continue blocking re-provisioning.
	var erased int
	if err := db.QueryRow(`SELECT COUNT(*) FROM erased_subjects WHERE subject = ? AND org_id = ?`, "sub-erased-before-backup", customerOrg).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased != 1 {
		t.Fatalf("erased_subjects count = %d, want 1", erased)
	}
	if err := st.Users().CreateUser(ctx, &store.User{
		ID: "usr_revive", Username: "revive", Role: "user", Status: "active",
		SSOProvider: "kyidentity", SSOSubject: "sub-erased-before-backup", OrgID: customerOrg,
	}); !errors.Is(err, store.ErrSubjectErased) {
		t.Fatalf("CreateUser for erased subject after restore = %v, want ErrSubjectErased", err)
	}
}
