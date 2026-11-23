package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestErasedSubjectBlocksProvisioningAndReactivation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000e5"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "fence-old", Username: "fence-old", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "fence-sub", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().RememberErasedSubject(ctx, u.SSOSubject, org); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().UpdateUser(ctx, u); err == nil {
		t.Fatal("stale full profile reactivated erased subject")
	}
	if err := st.Users().UpdateProfile(ctx, u); err == nil {
		t.Fatal("stale directory profile reactivated erased subject")
	}
	if _, err := st.Chat().EraseUser(ctx, org, u); err != nil {
		t.Fatal(err)
	}
	u.ID = "fence-new"
	u.Username = "fence-new"
	if err := st.Users().CreateUser(ctx, u); !errors.Is(err, store.ErrSubjectErased) {
		t.Fatalf("reprovision: %v", err)
	}
	for _, revision := range []int64{999, -1} {
		applied, err := st.Users().CreateDirectoryUser(ctx, u, store.DirectoryEvent{ID: fmt.Sprint("fence-event-", revision), Revision: revision})
		if err != nil || applied {
			t.Fatalf("directory replay revision %d: %v %v", revision, applied, err)
		}
	}
	if _, err := st.Users().GetUserBySSO(ctx, "kyidentity", u.SSOSubject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recreated account remains: %v", err)
	}
	if err := st.Chat().RememberErasedSubject(ctx, u.SSOSubject, org); err != nil {
		t.Fatalf("erasure replay: %v", err)
	}
	if _, err := st.Chat().ApplyTenantLifecycle(ctx, org, store.TenantStatusDeleted, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().PurgeTenantRows(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().MarkTenantPurged(ctx, org); err != nil {
		t.Fatal(err)
	}
	u.ID = "after-org-purge"
	u.Username = "after-org-purge"
	if err := st.Users().CreateUser(ctx, u); !errors.Is(err, store.ErrSubjectErased) {
		t.Fatalf("org purge lost permanent fence: %v", err)
	}
}

func TestErasureWrongOrgCannotFenceAnAccount(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000e6"
	u := &store.User{ID: "fence-bound", Username: "fence-bound", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "bound-sub", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().RememberErasedSubject(ctx, u.SSOSubject, "00000000-0000-4000-8000-0000000000e7"); !errors.Is(err, store.ErrErasureOrgMismatch) {
		t.Fatalf("wrong-org erasure: %v", err)
	}
	if err := st.Users().UpdateProfile(ctx, u); err != nil {
		t.Fatalf("wrong org left a fence: %v", err)
	}
	if got, err := st.Users().GetUserByID(ctx, u.ID); err != nil || got.Status != "active" {
		t.Fatalf("wrong org changed account: %+v %v", got, err)
	}
}

func TestErasureRacingFirstProvisionNeverLeavesAnActiveAccount(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000e8"
	for i := range 12 {
		sub := fmt.Sprint("racing-erasure-", i)
		u := &store.User{ID: sub, Username: sub, OrgID: org, SSOProvider: "kyidentity", SSOSubject: sub, Role: "user", Status: "active"}
		start := make(chan struct{})
		var createErr, eraseErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; createErr = st.Users().CreateUser(ctx, u) }()
		go func() { defer wg.Done(); <-start; eraseErr = st.Chat().RememberErasedSubject(ctx, sub, org) }()
		close(start)
		wg.Wait()
		if eraseErr != nil || createErr != nil && !errors.Is(createErr, store.ErrSubjectErased) {
			t.Fatalf("concurrent first provision: create=%v erase=%v", createErr, eraseErr)
		}
		got, err := st.Users().GetUserBySSO(ctx, "kyidentity", sub)
		if err == nil && got.Status == "active" || err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("erased account active after both commits: %+v %v", got, err)
		}
		u.ID += "-replay"
		u.Username += "-replay"
		if err := st.Users().CreateUser(ctx, u); !errors.Is(err, store.ErrSubjectErased) {
			t.Fatalf("post-race reprovision: %v", err)
		}
	}
}
