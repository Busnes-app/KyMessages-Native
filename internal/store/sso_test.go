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

func TestSSOSIDLogoutCoversUnboundSessionsOnlyForSubjectAndOrg(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const orgA = "00000000-0000-4000-8000-000000000001"
	const orgB = "00000000-0000-4000-8000-000000000002"
	for _, org := range []string{orgA, orgB} {
		if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for _, item := range []struct{ id, org string }{{"a", orgA}, {"b", orgA}, {"c", orgB}} {
		u := &store.User{ID: item.id, Username: item.id, SSOProvider: "kyidentity", SSOSubject: "sub-" + item.id, OrgID: item.org, Status: "active", Role: "user"}
		if err := st.Users().CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		// Empty binding models a session retained by the additive upgrade.
		if err := st.Sessions().CreateSession(ctx, &store.Session{UserID: u.ID, TokenHash: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	pairing := &store.DevicePairing{Secret: "legacy-pair", UserID: "a", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.Devices().CreatePairing(ctx, pairing, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().UpsertPushSubscription(ctx, "a", &store.PushSubscription{TenantID: orgA, UserID: "a", Endpoint: "https://push.example/legacy", P256DH: "key", AuthSecret: "secret"}, 20); err != nil {
		t.Fatal(err)
	}
	live := func(id string) bool { _, err := st.Sessions().GetSession(ctx, id); return err == nil }
	// Another subject's logout cannot remove a's unbound session.
	if _, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity.example", "sub-b", orgA, "sid-a", "logout-b", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if !live("a") || live("b") || !live("c") {
		t.Fatal("another subject's logout changed unrelated sessions")
	}
	// The right subject with the wrong org cannot remove any of its sessions.
	if _, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity.example", "sub-a", orgB, "sid-a", "logout-a", now.Unix()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("wrong org accepted", err)
	}
	if !live("a") || !live("c") {
		t.Fatal("another org's logout changed sessions")
	}
	for _, sid := range []string{"sid-a", "sid-other"} {
		if err := st.Sessions().CreateSession(ctx, &store.Session{SSOSession: store.SSOSession{SID: sid, IssuedAt: now.Unix()}, UserID: "a", TokenHash: sid, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity.example", "sub-a", orgA, "sid-a", "logout-a", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if live("a") || live("sid-a") || !live("sid-other") || !live("c") {
		t.Fatal("sid logout did not narrow bound sessions and cover legacy sessions")
	}
	if _, err := st.Devices().GetPairingBySecret(ctx, "legacy-pair"); err != nil {
		t.Fatal("sid logout removed unbound pairing", err)
	}
	if subs, err := st.Chat().ListPushSubscriptions(ctx, orgA, "a"); err != nil || len(subs) != 1 {
		t.Fatal("sid logout removed legacy push", err)
	}
	// Even a pairing consumed before logout cannot reissue an unbound session afterward.
	if err := st.Sessions().CreateSession(ctx, &store.Session{UserID: "a", TokenHash: "legacy-derived", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unbound issuance passed sid fence", err)
	}
	if _, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity.example", "sub-a", orgA, "", "logout-sub-a", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if live("sid-other") {
		t.Fatal("subject logout retained session")
	}
	if _, err := st.Devices().GetPairingBySecret(ctx, "legacy-pair"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("subject logout retained legacy pairing", err)
	}
	if subs, err := st.Chat().ListPushSubscriptions(ctx, orgA, "a"); err != nil || len(subs) != 0 {
		t.Fatal("subject logout retained legacy push", err)
	}
}

func TestSSOSIDLogoutRemovesOnlyItsPushRecipients(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u := &store.User{ID: "sid-push", Username: "sid-push", SSOProvider: "kyidentity", SSOSubject: "sid-push", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{Kind: store.RoomKindChannel, Name: "push-sids", CreatedBy: u.ID}
	if err := st.Chat().CreateRoom(ctx, room, []string{u.ID}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, sid := range []string{"sid-a", "sid-b"} {
		if err := st.Sessions().CreateSession(ctx, &store.Session{SSOSession: store.SSOSession{SID: sid, IssuedAt: now.Unix()}, TokenHash: sid, UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Chat().UpsertPushSubscription(ctx, sid, &store.PushSubscription{TenantID: store.DefaultTenantID, UserID: u.ID, Endpoint: "https://push.example/" + sid, P256DH: "key", AuthSecret: "secret"}, 20); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity.example", u.SSOSubject, "", "sid-a", "push-logout", now.Unix()); err != nil {
		t.Fatal(err)
	}
	subs, err := st.Chat().ListPushRecipients(ctx, store.DefaultTenantID, room.ID, []string{u.ID})
	if err != nil || len(subs) != 1 || subs[0].Endpoint != "https://push.example/sid-b" {
		t.Fatalf("push recipients after sid logout: %+v (%v)", subs, err)
	}
}

func TestSSOPushRegistrationSerializesWithSIDLogout(t *testing.T) {
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
	u := &store.User{ID: "push-race", Username: "push-race", SSOProvider: "kyidentity", SSOSubject: "push-race", Role: "user", Status: "active"}
	if err := first.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"race-1", "race-2", "race-3", "race-4", "race-5"} {
		now := time.Now().UTC()
		if err := first.Sessions().CreateSession(ctx, &store.Session{SSOSession: store.SSOSession{SID: sid, IssuedAt: now.Unix()}, TokenHash: sid, UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var registerErr, logoutErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, registerErr = first.Chat().UpsertPushSubscription(ctx, sid, &store.PushSubscription{TenantID: store.DefaultTenantID, UserID: u.ID, Endpoint: "https://push.example/" + sid, P256DH: "key", AuthSecret: "secret"}, 20)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _, logoutErr = second.Sessions().ApplySSOLogout(ctx, "https://identity.example", u.SSOSubject, "", sid, sid, now.Unix())
		}()
		close(start)
		wg.Wait()
		if logoutErr != nil {
			t.Fatal(logoutErr)
		}
		if registerErr != nil && !errors.Is(registerErr, store.ErrNotFound) {
			t.Fatal(registerErr)
		}
		if subs, err := first.Chat().ListPushSubscriptions(ctx, store.DefaultTenantID, u.ID); err != nil || len(subs) != 0 {
			t.Fatalf("registration retained after sid logout: %+v (%v)", subs, err)
		}
	}
}

func TestUnprovisionedLogoutFenceRetainsIssuerScope(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	if user, _, err := st.Sessions().ApplySSOLogout(ctx, "https://identity-a.example", "new-sub", "", "new-sid", "before-provision", now.Unix()); err != nil || user != "" {
		t.Fatal("unprovisioned logout", user, err)
	}
	u := &store.User{ID: "new-user", Username: "new-user", SSOProvider: "kyidentity", SSOSubject: "new-sub", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	generation, err := st.Sessions().SSOGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sess := &store.Session{SSOSession: store.SSOSession{Issuer: "https://identity-a.example", SID: "new-sid", IssuedAt: now.Unix() + 1, Generation: generation}, UserID: u.ID, TokenHash: "new", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.Sessions().CreateSession(ctx, sess, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pre-provision sid fence ignored", err)
	}
	sess.Issuer = "https://identity-b.example"
	if err := st.Sessions().CreateSession(ctx, sess, ""); err != nil {
		t.Fatal("another issuer's fence applied", err)
	}
}

func TestFirstSessionIssuanceSerializesWithLogoutAcrossConnections(t *testing.T) {
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
	for _, scope := range []string{"first-sid", ""} {
		generation, err := first.Sessions().SSOGeneration(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		u := &store.User{ID: "first-" + scope, Username: "first-" + scope, SSOProvider: "kyidentity", SSOSubject: "first-" + scope, Role: "user", Status: "active"}
		sess := &store.Session{SSOSession: store.SSOSession{Issuer: "https://identity.example", SID: "first-sid", IssuedAt: now.Unix(), Generation: generation}, UserID: u.ID, TokenHash: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var issueErr, logoutErr error
		go func() {
			defer wg.Done()
			<-start
			if issueErr = first.Users().CreateUser(ctx, u); issueErr == nil {
				issueErr = first.Sessions().CreateSession(ctx, sess, "")
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _, logoutErr = second.Sessions().ApplySSOLogout(ctx, "https://identity.example", u.SSOSubject, "", scope, u.ID, now.Unix())
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
			t.Fatal("first session survived concurrent logout", err)
		}
	}
}
