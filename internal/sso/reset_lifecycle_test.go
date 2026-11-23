package sso_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestMFAResetRevisionReuseAfterDirectoryRestore(t *testing.T) {
	d := newDirectory(t)
	ctx := context.Background()
	d.must("user.created", scimUser("restored-reset", "user", true, 1))
	d.must("user.mfa_reset", scimUser("restored-reset", "user", true, 2))
	d.must("user.updated", scimUser("restored-reset", "user", true, -1))
	freshSession := func(hash string) {
		u := d.user("restored-reset")
		generation, err := d.st.Sessions().SSOGeneration(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if err := d.st.Sessions().CreateSession(ctx, &store.Session{SSOSession: store.SSOSession{SID: hash, IssuedAt: now.Unix() + 1, Generation: generation}, TokenHash: hash, UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, u.PasswordHash); err != nil {
			t.Fatal(err)
		}
	}
	freshSession("after-restore")
	if err := d.sendID("restored-reset-event", "user.mfa_reset", scimUser("restored-reset", "user", true, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "after-restore"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("reused reset revision retained session", err)
	}
	freshSession("after-new-reset")
	if err := d.sendID("restored-reset-event", "user.mfa_reset", scimUser("restored-reset", "user", true, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "after-new-reset"); err != nil {
		t.Fatal("reset retry revoked fresh session", err)
	}
	// A retry of the restore resend cannot advance the restore generation again.
	if err := d.sendID("restore-once", "user.updated", scimUser("restored-reset", "user", true, -1)); err != nil {
		t.Fatal(err)
	}
	if err := d.sendID("restore-once", "user.updated", scimUser("restored-reset", "user", true, -1)); err != nil {
		t.Fatal(err)
	}
	if err := d.sendID("generation-two-reset", "user.mfa_reset", scimUser("restored-reset", "user", true, 2)); err != nil {
		t.Fatal(err)
	}
	freshSession("after-generation-two-reset")
	if err := d.sendID("restore-once", "user.updated", scimUser("restored-reset", "user", true, -1)); err != nil {
		t.Fatal(err)
	}
	if err := d.sendID("same-generation-new-delivery", "user.mfa_reset", scimUser("restored-reset", "user", true, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "after-generation-two-reset"); err != nil {
		t.Fatal("restore retry advanced reset generation", err)
	}
	// Event-ID replay protection survives every generation.
	if err := d.sendID("restored-reset-event", "user.mfa_reset", scimUser("restored-reset", "user", true, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "after-generation-two-reset"); err != nil {
		t.Fatal("old reset replay crossed generation", err)
	}
}

func TestDelayedMFAResetAfterDeletionIsAcknowledged(t *testing.T) {
	d := newDirectory(t)
	d.must("user.created", scimUser("deleted-reset", "user", true, 1))
	d.must("user.deleted", scimUser("deleted-reset", "user", false, 3))
	callbacks := 0
	d.client.OnUserRevoked(func(context.Context, string) { callbacks++ })
	for range 2 {
		if err := d.sendID("delayed-reset", "user.mfa_reset", scimUser("deleted-reset", "user", true, 2)); err != nil {
			t.Fatal("delayed reset refused", err)
		}
	}
	if d.user("deleted-reset") != nil || callbacks != 0 {
		t.Fatal("delayed reset changed deleted account")
	}
}
