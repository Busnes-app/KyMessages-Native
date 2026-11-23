package sso_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/sso"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

type flakySessions struct {
	store.SessionStore
	fail atomic.Bool
}

func (f *flakySessions) DeleteUserSessions(ctx context.Context, userID string) error {
	if f.fail.Load() {
		return errors.New("database unavailable")
	}
	return f.SessionStore.DeleteUserSessions(ctx, userID)
}

type flakyStore struct {
	store.Store
	sessions *flakySessions
}

func (s flakyStore) Sessions() store.SessionStore { return s.sessions }

// A suspension whose member revocation fails is not acknowledged, so KyIdentity redelivers it,
// and the retry sweeps the sessions the first attempt left.
func TestOrgSuspensionRetriesFailedRevocation(t *testing.T) {
	d := newDirectory(t)
	ctx := context.Background()
	sessions := &flakySessions{SessionStore: d.st.Sessions()}
	d.client = sso.NewKyIdentityClient(config.SSOConfig{KyIdentityHMACSecret: webhookSecret}, flakyStore{Store: d.st, sessions: sessions})
	d.client.SetTenancy(config.TenancyConfig{Mode: config.TenancyMulti})
	if _, err := d.st.Chat().EnsureTenant(ctx, "org-x"); err != nil {
		t.Fatal(err)
	}
	if err := d.st.Users().CreateUser(ctx, &store.User{ID: "u_x", Username: "ux", Role: "user", Status: "active", OrgID: "org-x"}); err != nil {
		t.Fatal(err)
	}
	if err := d.st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "sess-x", UserID: "u_x", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"org_id":"org-x","revision":1}`)

	sessions.fail.Store(true)
	if err := d.sendID("evt-suspend", "org.suspended", body); err == nil {
		t.Fatal("suspension acknowledged although a member's sessions were not revoked")
	}
	sessions.fail.Store(false)
	if err := d.sendID("evt-suspend", "org.suspended", body); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if _, err := d.st.Sessions().GetSession(ctx, "sess-x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session after the retried suspension: %v, want gone", err)
	}
}

// A suspension whose cross-pod revocation could not be published is not acknowledged either.
func TestOrgSuspensionRetriesFailedPublication(t *testing.T) {
	d := newDirectory(t)
	ctx := context.Background()
	d.client.SetTenancy(config.TenancyConfig{Mode: config.TenancyMulti})
	var down atomic.Bool
	published := 0
	d.client.OnTenantRevoked(func(context.Context, string) error {
		if down.Load() {
			return errors.New("bus unavailable")
		}
		published++
		return nil
	})
	if _, err := d.st.Chat().EnsureTenant(ctx, "org-y"); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"org_id":"org-y","revision":1}`)
	down.Store(true)
	if err := d.sendID("evt-y", "org.suspended", body); err == nil {
		t.Fatal("suspension acknowledged although its revocation was never published")
	}
	down.Store(false)
	if err := d.sendID("evt-y", "org.suspended", body); err != nil || published != 1 {
		t.Fatalf("redelivery = %v, published %d times, want nil and 1", err, published)
	}
}
