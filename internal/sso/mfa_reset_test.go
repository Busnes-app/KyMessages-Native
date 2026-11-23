package sso_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/sso"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestDirectoryResetAndDeleteOrgBinding(t *testing.T) {
	d := newDirectory(t)
	ctx := context.Background()
	const org = "00000000-0000-4000-8000-000000000001"
	const otherOrg = "00000000-0000-4000-8000-000000000002"
	d.client.SetTenancy(config.TenancyConfig{Mode: config.TenancyMulti, StaffOrgID: org})
	body := func(orgID string, rev int64) []byte {
		var user map[string]any
		if err := json.Unmarshal(scimUser("reset-sub", "user", true, rev), &user); err != nil {
			t.Fatal(err)
		}
		user["org_id"] = orgID
		b, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	d.must("user.created", body(org, 1))
	u := d.user("reset-sub")
	now := time.Now().UTC()
	if err := d.st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "reset-session", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err := d.st.Sessions().CreateMFAChallenge(ctx, &store.MFAChallenge{TokenHash: "reset-mfa", UserID: u.ID, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if err := d.st.Devices().CreatePairing(ctx, &store.DevicePairing{Secret: "reset-pair", UserID: u.ID, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := d.st.Chat().UpsertPushSubscription(ctx, "reset-session", &store.PushSubscription{TenantID: org, UserID: u.ID, Endpoint: "https://push.example/reset", P256DH: "key", AuthSecret: "secret"}, 20); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"user.mfa_reset", "user.deleted"} {
		if err := d.send(event, body(otherOrg, 2)); !errors.Is(err, sso.ErrSyncOrgMismatch) {
			t.Fatalf("%s: %v", event, err)
		}
		if _, err := d.st.Sessions().GetSession(ctx, "reset-session"); err != nil {
			t.Fatal("wrong org changed session", err)
		}
		if d.user("reset-sub") == nil {
			t.Fatal("wrong org deleted user")
		}
	}
	called := 0
	d.client.OnUserRevoked(func(context.Context, string) { called++ })
	d.must("user.mfa_reset", body(org, 2))
	if called != 1 {
		t.Fatalf("revocation notifications: %d", called)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "reset-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("session retained", err)
	}
	if _, err := d.st.Devices().GetPairingBySecret(ctx, "reset-pair"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing retained", err)
	}
	if _, _, err := d.st.Sessions().ConsumeMFAChallenge(ctx, "reset-mfa"); err == nil {
		t.Fatal("MFA retained")
	}
	if subs, err := d.st.Chat().ListPushSubscriptions(ctx, org, u.ID); err != nil || len(subs) != 0 {
		t.Fatal("push retained", err)
	}
	if got := d.user("reset-sub"); got.Status != "active" || got.Role != "user" || got.PasswordHash == u.PasswordHash {
		t.Fatalf("profile/fence: %+v", got)
	}
	if err := d.st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "stale", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err == nil {
		t.Fatal("stale snapshot issued session")
	}
	// New event ID but the same revision is superseded and cannot revoke a fresh sign-in.
	fresh := d.user("reset-sub")
	gen, err := d.st.Sessions().SSOGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.st.Sessions().CreateSession(ctx, &store.Session{SSOSession: store.SSOSession{SID: "fresh", IssuedAt: time.Now().Unix() + 1, Generation: gen}, TokenHash: "fresh", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, fresh.PasswordHash); err != nil {
		t.Fatal(err)
	}
	d.must("user.mfa_reset", body(org, 2))
	if _, err := d.st.Sessions().GetSession(ctx, "fresh"); err != nil {
		t.Fatal("duplicate reset revoked new session", err)
	}
	d.must("user.deleted", body(org, 3))
	if d.user("reset-sub") != nil {
		t.Fatal("correct-org deletion failed")
	}
}
