package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func master(user, tenant, tag string) *store.E2EEMasterKey {
	return &store.E2EEMasterKey{TenantID: tenant, UserID: user, MasterKey: "mk-" + tag, SelfSignature: "ss-" + tag,
		BackupKey: "bk-" + tag, BackupSignature: "bs-" + tag, RecoveryMaster: "rm-" + tag, RecoveryBackup: "rb-" + tag}
}

func TestE2EEMasterKeyVersions(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if _, err := k.GetMasterKey(ctx, "u-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 1); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("update of a missing identity: %v", err)
	}
	m := master("u-a", "t1", "1")
	if err := k.PutMasterKey(ctx, m, 0); err != nil || m.Version != 1 {
		t.Fatalf("first put: %v version %d", err, m.Version)
	}
	// A second first-device setup loses the race instead of overwriting.
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "x"), 0); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("second create: %v", err)
	}
	// Another org cannot replace it even with the right version.
	if err := k.PutMasterKey(ctx, master("u-a", "t2", "x"), 1); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("cross-org replace: %v", err)
	}

	if err := k.UpsertDevice(ctx, device("u-a", "D1", "t1")); err != nil {
		t.Fatal(err)
	}
	if err := k.SignDevice(ctx, "u-a", "D1", 2, "sig"); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("signature by a version that is not current: %v", err)
	}
	if err := k.SignDevice(ctx, "u-a", "D9", 1, "sig"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("signature for no device: %v", err)
	}
	if err := k.SignDevice(ctx, "u-a", "D1", 1, "sig-1"); err != nil {
		t.Fatal(err)
	}
	if err := k.PutPins(ctx, "u-a", 1, 0, "pins-1"); err != nil {
		t.Fatal(err)
	}
	if err := k.PutPins(ctx, "u-a", 1, 0, "pins-stale"); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("stale pin counter: %v", err)
	}
	if err := k.PutBackupSessions(ctx, "u-a", 1, []store.E2EEBackupSession{{RoomID: "r", SessionID: "s", FirstIndex: 0, Sealed: "x"}}, 10); err != nil {
		t.Fatal(err)
	}
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p1", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	// A reset: the new identity starts with no backup, pins, pairing or cross-signature.
	reset := master("u-a", "t1", "2")
	if err := k.PutMasterKey(ctx, reset, 1); err != nil || reset.Version != 2 {
		t.Fatalf("reset: %v %d", err, reset.Version)
	}
	got, err := k.GetMasterKey(ctx, "u-a")
	if err != nil || got.MasterKey != "mk-2" || got.Version != 2 || got.Pins != "" || got.PinsCounter != 0 {
		t.Fatalf("after reset: %+v %v", got, err)
	}
	d, _ := k.GetDevice(ctx, "u-a", "D1")
	if d.MasterSignature != "" || d.MasterVersion != 0 {
		t.Fatalf("cross-signature survived the reset: %+v", d)
	}
	if rows, _ := k.ListBackupSessions(ctx, "u-a", 1, "", "", 10); len(rows) != 0 {
		t.Fatalf("old backup survived: %+v", rows)
	}
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p1", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing survived the reset")
	}
	if err := k.PutBackupSessions(ctx, "u-a", 1, []store.E2EEBackupSession{{RoomID: "r", SessionID: "s", Sealed: "x"}}, 10); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("write to the old backup version: %v", err)
	}
	if list, _ := k.ListMasterKeys(ctx, "t2", []string{"u-a"}); len(list) != 0 {
		t.Fatal("master key listed in another org")
	}
}

func TestE2EEKeyBackupKeepsTheBestCopy(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 0); err != nil {
		t.Fatal(err)
	}
	put := func(idx int64, sealed string) {
		t.Helper()
		if err := k.PutBackupSessions(ctx, "u-a", 1, []store.E2EEBackupSession{{RoomID: "r1", SessionID: "s1", FirstIndex: idx, Sealed: sealed}}, 10); err != nil {
			t.Fatal(err)
		}
	}
	put(5, "from-5")
	put(9, "from-9") // reaches less far back: ignored
	put(2, "from-2") // reaches further back: replaces
	put(2, "again")  // equal: the first copy stays
	rows, err := k.ListBackupSessions(ctx, "u-a", 1, "", "", 10)
	if err != nil || len(rows) != 1 || rows[0].Sealed != "from-2" || rows[0].FirstIndex != 2 {
		t.Fatalf("rows = %+v %v", rows, err)
	}

	// Paging in (room, session) order, and the cap: a write past it stores nothing.
	var batch []store.E2EEBackupSession
	for i := range 9 {
		batch = append(batch, store.E2EEBackupSession{RoomID: fmt.Sprintf("r%d", i%3+2), SessionID: fmt.Sprintf("s%d", i), Sealed: "x"})
	}
	if err := k.PutBackupSessions(ctx, "u-a", 1, batch, 10); err != nil {
		t.Fatal(err)
	}
	if err := k.PutBackupSessions(ctx, "u-a", 1, []store.E2EEBackupSession{{RoomID: "r9", SessionID: "s", Sealed: "x"}}, 10); !errors.Is(err, store.ErrE2EEBackupFull) {
		t.Fatalf("past the cap: %v", err)
	}
	var seen []string
	afterRoom, afterSession := "", ""
	for {
		page, err := k.ListBackupSessions(ctx, "u-a", 1, afterRoom, afterSession, 4)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page {
			seen = append(seen, p.RoomID+"/"+p.SessionID)
		}
		if len(page) < 4 {
			break
		}
		afterRoom, afterSession = page[len(page)-1].RoomID, page[len(page)-1].SessionID
	}
	if len(seen) != 10 || seen[0] != "r1/s1" || seen[9] != "r4/s8" {
		t.Fatalf("paged %v", seen)
	}
	if err := k.DeleteBackup(ctx, "u-a", 2); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatal(err)
	}
	if err := k.DeleteBackup(ctx, "u-a", 1); err != nil {
		t.Fatal(err)
	}
	if rows, _ := k.ListBackupSessions(ctx, "u-a", 1, "", "", 10); len(rows) != 0 {
		t.Fatal("backup not deleted")
	}
}

func TestE2EEPairingIsOneTimeShortLivedAndScoped(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	e2eeUser(t, st, "u-b")
	k := st.E2EE()
	now := time.Now()
	open := func(id string) {
		t.Helper()
		if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: id, TenantID: "t1", UserID: "u-a", InitiatorDevice: "OLD", ExpiresAt: now.Add(3 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	open("p1")
	open("p2") // cancels p1
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a second pairing did not cancel the first")
	}
	for _, c := range []struct{ tenant, user string }{{"t2", "u-a"}, {"t1", "u-b"}} {
		if _, err := k.GetPairing(ctx, c.tenant, c.user, "p2", now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%v sees the pairing", c)
		}
		if err := k.JoinPairing(ctx, c.tenant, c.user, "p2", "NEW", "eph", now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%v joined", c)
		}
	}
	if err := k.SealPairing(ctx, "t1", "u-a", "p2", "OLD", "sealed", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("sealed before anyone joined")
	}
	if err := k.JoinPairing(ctx, "t1", "u-a", "p2", "OLD", "eph", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the initiator joined its own pairing")
	}
	if err := k.JoinPairing(ctx, "t1", "u-a", "p2", "NEW", "eph", now); err != nil {
		t.Fatal(err)
	}
	if err := k.JoinPairing(ctx, "t1", "u-a", "p2", "OTHER", "eph2", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("joined twice")
	}
	if _, err := k.ConsumePairing(ctx, "t1", "u-a", "p2", "NEW", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("consumed before the keys were sealed")
	}
	if err := k.SealPairing(ctx, "t1", "u-a", "p2", "NEW", "sealed", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the new device sealed keys")
	}
	if err := k.SealPairing(ctx, "t1", "u-a", "p2", "OLD", "sealed", now); err != nil {
		t.Fatal(err)
	}
	if err := k.SealPairing(ctx, "t1", "u-a", "p2", "OLD", "again", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("sealed twice")
	}
	if _, err := k.ConsumePairing(ctx, "t1", "u-a", "p2", "OTHER", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another device consumed the keys")
	}
	if _, err := k.ConsumePairing(ctx, "t1", "u-a", "p2", "NEW", now.Add(4*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("consumed after expiry")
	}
	p, err := k.ConsumePairing(ctx, "t1", "u-a", "p2", "NEW", now)
	if err != nil || p.Sealed != "sealed" || p.InitiatorDevice != "OLD" {
		t.Fatalf("consume: %+v %v", p, err)
	}
	if _, err := k.ConsumePairing(ctx, "t1", "u-a", "p2", "NEW", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("consumed twice")
	}

	// Expired pairings are unreadable at once and swept by the maintenance loop.
	open("p3")
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p3", now.Add(3*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("readable at expiry")
	}
	if err := k.PrunePairings(ctx, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := k.DeletePairing(ctx, "t1", "u-a", "p3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("swept pairing still stored")
	}
}

// Erasure and org purge delete a user's row; everything E3 keeps for them goes with it.
func TestE2EEIdentityGoesWithTheUser(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 0); err != nil {
		t.Fatal(err)
	}
	if err := k.PutBackupSessions(ctx, "u-a", 1, []store.E2EEBackupSession{{RoomID: "r", SessionID: "s", Sealed: "x"}}, 10); err != nil {
		t.Fatal(err)
	}
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().DeleteUser(ctx, "u-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.GetMasterKey(ctx, "u-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("master key survived the user")
	}
	if rows, _ := k.ListBackupSessions(ctx, "u-a", 1, "", "", 10); len(rows) != 0 {
		t.Fatal("key backup survived the user")
	}
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing survived the user")
	}
}
