package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func e2eeUser(t *testing.T, st store.Store, id string) {
	t.Helper()
	if err := st.Users().CreateUser(context.Background(), &store.User{ID: id, Username: id, Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
		t.Fatal(err)
	}
}

func device(user, id, tenant string) *store.E2EEDevice {
	return &store.E2EEDevice{TenantID: tenant, UserID: user, DeviceID: id, Curve25519: "c-" + id, Ed25519: "e-" + id, Signature: "s-" + id}
}

func TestE2EEDevices(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	e2eeUser(t, st, "u-b")
	k := st.E2EE()
	if err := k.UpsertDevice(ctx, device("u-a", "D1", "t1")); err != nil {
		t.Fatal(err)
	}
	if err := k.UpsertDevice(ctx, device("u-a", "D1", "t1")); err != nil {
		t.Fatalf("identical re-upload: %v", err)
	}
	changed := device("u-a", "D1", "t1")
	changed.Curve25519 = "c-other"
	if err := k.UpsertDevice(ctx, changed); !errors.Is(err, store.ErrE2EEKeyMismatch) {
		t.Fatalf("changed identity keys: %v", err)
	}
	if err := k.UpsertDevice(ctx, device("u-a", "D1", "t2")); !errors.Is(err, store.ErrE2EEKeyMismatch) {
		t.Fatalf("same device in another tenant: %v", err)
	}
	if err := k.UpsertDevice(ctx, device("u-b", "D9", "t2")); err != nil {
		t.Fatal(err)
	}
	got, err := k.ListDevices(ctx, "t1", []string{"u-a", "u-b"})
	if err != nil || len(got) != 1 || got[0].DeviceID != "D1" || got[0].Curve25519 != "c-D1" {
		t.Fatalf("t1 devices = %+v %v (another tenant's device must not appear)", got, err)
	}
	if err := k.DeleteDevice(ctx, "u-a", "D1"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.GetDevice(ctx, "u-a", "D1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted device: %v", err)
	}
	// A user's deletion removes their devices.
	if err := st.Users().DeleteUser(ctx, "u-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.GetDevice(ctx, "u-b", "D9"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device outlived its user: %v", err)
	}
}

// One-time keys are claimed at most once, even when several replicas claim at the same time.
func TestE2EEOneTimeKeysClaimOnceAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	a, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	e2eeUser(t, a, "u-a")
	if err := a.E2EE().UpsertDevice(ctx, device("u-a", "D1", "t1")); err != nil {
		t.Fatal(err)
	}
	var keys []store.E2EEOneTimeKey
	for i := range 50 {
		keys = append(keys, store.E2EEOneTimeKey{KeyID: fmt.Sprintf("k%02d", i), Key: fmt.Sprintf("v%02d", i), Signature: "sig"})
	}
	keys = append(keys, store.E2EEOneTimeKey{KeyID: "fb1", Key: "fallback-1", Signature: "sig", Fallback: true})
	if err := a.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", keys, 100); err != nil {
		t.Fatal(err)
	}
	// A re-upload of a claimed-or-not key ID never changes its value.
	if err := a.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", []store.E2EEOneTimeKey{{KeyID: "k00", Key: "swapped", Signature: "sig"}}, 100); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := map[string]int{}
	fallbacks := 0
	var wg sync.WaitGroup
	// 200 claimants for 50 keys: a burst far larger than one round of claims can serve.
	for i := range 200 {
		st := a
		if i%2 == 1 {
			st = b
		}
		wg.Go(func() {
			k, err := st.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("claim: %v", err)
			case k.Fallback:
				fallbacks++
			default:
				seen[k.Key]++
			}
		})
	}
	wg.Wait()
	if len(seen) != 50 || fallbacks != 150 {
		t.Fatalf("claimed %d distinct keys and %d fallbacks, want 50 and 150: %v", len(seen), fallbacks, seen)
	}
	for key, n := range seen {
		if n != 1 || key == "swapped" {
			t.Fatalf("key %q claimed %d times", key, n)
		}
	}
	if n, _ := a.E2EE().CountOneTimeKeys(ctx, "u-a", "D1"); n != 0 {
		t.Fatalf("%d one-time keys left", n)
	}
	// vodozemac gives a device's first one-time key and first fallback key the same ID: both
	// must be stored and served.
	if err := a.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", []store.E2EEOneTimeKey{
		{KeyID: "AAAAAAAAAAA", Key: "otk-0", Signature: "sig"},
		{KeyID: "AAAAAAAAAAA", Key: "fallback-0", Signature: "sig", Fallback: true},
	}, 100); err != nil {
		t.Fatal(err)
	}
	if k, err := a.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1"); err != nil || k.Key != "otk-0" || k.Fallback {
		t.Fatalf("one-time key sharing the fallback's ID = %+v %v", k, err)
	}
	if k, err := a.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1"); err != nil || k.Key != "fallback-0" || !k.Fallback {
		t.Fatalf("fallback key sharing a one-time key's ID = %+v %v", k, err)
	}
	// A new fallback key replaces the old one.
	if err := a.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", []store.E2EEOneTimeKey{{KeyID: "fb2", Key: "fallback-2", Signature: "sig", Fallback: true}}, 100); err != nil {
		t.Fatal(err)
	}
	if k, err := a.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1"); err != nil || k.Key != "fallback-2" {
		t.Fatalf("after a new fallback key: %+v %v", k, err)
	}
	if err := a.E2EE().DeleteDevice(ctx, "u-a", "D1"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.E2EE().ClaimOneTimeKey(ctx, "u-a", "D1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim from a deleted device: %v", err)
	}
}

func TestE2EEToDeviceMailbox(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	e2eeUser(t, st, "u-b")
	k := st.E2EE()
	for _, d := range []*store.E2EEDevice{device("u-a", "A1", "t1"), device("u-b", "B1", "t1"), device("u-b", "B2", "t1")} {
		if err := k.UpsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	msg := func(to, content string) store.E2EEToDevice {
		return store.E2EEToDevice{TenantID: "t1", RecipientUserID: "u-b", RecipientDeviceID: to, SenderUserID: "u-a", SenderDeviceID: "A1", Type: "olm.v1", Content: content}
	}
	if err := k.SendToDevice(ctx, []store.E2EEToDevice{msg("B1", "one"), msg("B2", "other device"), msg("B1", "two"), msg("B1", "three")}); err != nil {
		t.Fatal(err)
	}
	got, err := k.ToDevice(ctx, "u-b", "B1", 2)
	if err != nil || len(got) != 2 || got[0].Content != "one" || got[1].Content != "two" || got[0].SenderDeviceID != "A1" {
		t.Fatalf("first page = %+v %v", got, err)
	}
	if err := k.AckToDevice(ctx, "u-b", "B1", []int64{got[0].ID, got[1].ID}); err != nil {
		t.Fatal(err)
	}
	rest, _ := k.ToDevice(ctx, "u-b", "B1", 10)
	if len(rest) != 1 || rest[0].Content != "three" {
		t.Fatalf("after ack = %+v", rest)
	}
	// Another device's ack never touches B2's mail, and B2 sees only its own.
	other, _ := k.ToDevice(ctx, "u-b", "B2", 10)
	if len(other) != 1 || other[0].Content != "other device" {
		t.Fatalf("B2 = %+v", other)
	}
	if err := k.PruneToDevice(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if left, _ := k.ToDevice(ctx, "u-b", "B2", 10); len(left) != 0 {
		t.Fatalf("pruned mail left: %+v", left)
	}
}

// Concurrent uploads for one device cannot together pass the one-time key cap.
func TestE2EEOneTimeKeyCapHoldsUnderConcurrentUploads(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	a, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	e2eeUser(t, a, "u-a")
	if err := a.E2EE().UpsertDevice(ctx, device("u-a", "D1", "t1")); err != nil {
		t.Fatal(err)
	}
	batch := func(prefix string) []store.E2EEOneTimeKey {
		var keys []store.E2EEOneTimeKey
		for i := range 60 {
			keys = append(keys, store.E2EEOneTimeKey{KeyID: fmt.Sprintf("%s%02d", prefix, i), Key: "k", Signature: "sig"})
		}
		return keys
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, st := range []store.Store{a, b} {
		wg.Go(func() { errs[i] = st.E2EE().AddOneTimeKeys(ctx, "u-a", "D1", batch(fmt.Sprintf("p%d-", i)), 100) })
	}
	wg.Wait()
	n, err := a.E2EE().CountOneTimeKeys(ctx, "u-a", "D1")
	if err != nil || n > 100 {
		t.Fatalf("device holds %d one-time keys (cap 100), upload errors %v, %v", n, errs[0], errs[1])
	}
	if refused := errors.Is(errs[0], store.ErrE2EETooManyKeys) != errors.Is(errs[1], store.ErrE2EETooManyKeys); !refused || n != 60 {
		t.Fatalf("want exactly one upload refused and 60 keys stored; got %d keys, errors %v, %v", n, errs[0], errs[1])
	}
}
