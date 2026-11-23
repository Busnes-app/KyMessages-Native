package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func TestSSOLogoutFencesAcrossConnections(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	first, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, sid := range []string{"sid-a", ""} {
		t.Run("scope="+sid, func(t *testing.T) {
			u := &store.User{ID: "u-" + sid, Username: "u-" + sid, SSOProvider: "kyidentity", SSOSubject: "sub-" + sid, Status: "active", Role: "user"}
			if err := first.Users().CreateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			generation, err := first.Sessions().SSOGeneration(ctx)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			binding := store.SSOSession{SID: "sid-a", IssuedAt: now.Unix(), Generation: generation}
			pairing := &store.DevicePairing{SSOSession: binding, Secret: u.ID, UserID: u.ID, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err := first.Devices().CreatePairing(ctx, pairing, ""); err != nil {
				t.Fatal(err)
			}
			// A pairing already consumed just before logout still carries the fence to issuance.
			if err := first.Devices().ConsumePairing(ctx, u.ID, "device", "pwa", ""); err != nil {
				t.Fatal(err)
			}
			sess := &store.Session{SSOSession: binding, TokenHash: u.ID, UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			var issueErr, logoutErr error
			go func() { defer wg.Done(); <-start; issueErr = first.Sessions().CreateSession(ctx, sess, "") }()
			go func() {
				defer wg.Done()
				<-start
				_, _, logoutErr = second.Sessions().ApplySSOLogout(ctx, "https://identity.example", u.SSOSubject, "", sid, u.ID, now.Unix())
			}()
			close(start)
			wg.Wait()
			if logoutErr != nil {
				t.Fatal(logoutErr)
			}
			if issueErr != nil && !errors.Is(issueErr, store.ErrNotFound) {
				t.Fatal(issueErr)
			}
			if _, err := first.Sessions().GetSession(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("concurrent session retained", err)
			}
			if err := first.Sessions().CreateSession(ctx, sess, ""); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("in-flight session resurrected", err)
			}
			// A newer token from an exchange begun before logout cannot bypass the generation.
			sess.IssuedAt = now.Unix() + 1
			if err := first.Sessions().CreateSession(ctx, sess, ""); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("in-flight new token bypassed fence", err)
			}
			if err := first.Devices().CreatePairing(ctx, pairing, ""); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("stale pairing recreated", err)
			}
			if _, err := first.Devices().GetPairingBySecret(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("pairing retained", err)
			}
			generation, err = first.Sessions().SSOGeneration(ctx)
			if err != nil {
				t.Fatal(err)
			}
			sess.SSOSession = store.SSOSession{SID: "sid-new", IssuedAt: now.Unix() + 1, Generation: generation}
			if err := first.Sessions().CreateSession(ctx, sess, ""); err != nil {
				t.Fatal("fresh session refused", err)
			}
			if _, _, err := first.Sessions().ApplySSOLogout(ctx, "https://identity.example", u.SSOSubject, "", sid, u.ID, now.Unix()); !errors.Is(err, store.ErrAlreadyExists) {
				t.Fatal("replay accepted", err)
			}
			if _, err := first.Sessions().GetSession(ctx, u.ID); err != nil {
				t.Fatal("replay changed fresh session", err)
			}
		})
	}
}
