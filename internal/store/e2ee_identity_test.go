package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// okProof and okDev accept any write: these tests cover the store's fencing, not signatures.
func okProof(string) error                  { return nil }
func okDev(string, *store.E2EEDevice) error { return nil }

// at is a clock stopped at t.
func at(t time.Time) func() time.Time { return func() time.Time { return t } }

func master(user, tenant, tag string) *store.E2EEMasterKey {
	return &store.E2EEMasterKey{TenantID: tenant, UserID: user, MasterKey: "mk-" + tag, SelfSignature: "ss-" + tag,
		BackupKey: "bk-" + tag, BackupSignature: "bs-" + tag, RecoveryMaster: "rm-" + tag, RecoveryBackup: "rb-" + tag}
}

// signedInitiator gives user an identity in tenant (if it has none) and a device signed by
// version 1, which a pairing needs.
func signedInitiator(t *testing.T, st store.Store, user, tenant, deviceID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.E2EE().GetMasterKey(ctx, user); errors.Is(err, store.ErrNotFound) {
		if err := st.E2EE().PutMasterKey(ctx, master(user, tenant, "1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.E2EE().UpsertDevice(ctx, device(user, deviceID, tenant)); err != nil {
		t.Fatal(err)
	}
	if err := st.E2EE().SignDevice(ctx, tenant, user, deviceID, 1, "sig", okDev); err != nil {
		t.Fatal(err)
	}
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
	if err := k.SignDevice(ctx, "t1", "u-a", "D1", 2, "sig", okDev); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("signature by a version that is not current: %v", err)
	}
	if err := k.SignDevice(ctx, "t1", "u-a", "D9", 1, "sig", okDev); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("signature for no device: %v", err)
	}
	if err := k.SignDevice(ctx, "t1", "u-a", "D1", 1, "sig-1", okDev); err != nil {
		t.Fatal(err)
	}
	if err := k.PutPins(ctx, "t1", "u-a", 1, 0, "pins-1", okProof); err != nil {
		t.Fatal(err)
	}
	if err := k.PutPins(ctx, "t1", "u-a", 1, 0, "pins-stale", okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("stale pin counter: %v", err)
	}
	if err := k.PutPins(ctx, "t2", "u-a", 1, 1, "pins-other-org", okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("pins written from another org: %v", err)
	}
	now := time.Now()
	if _, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-1", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["D1"]`, "dg-1", "list-sig", at(now), okProof); err != nil {
		t.Fatal(err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["D1","D9"]`, "dg-1", "stale", at(now), okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("stale device list epoch: %v", err)
	}
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r", SenderKey: "k", SessionID: "s", FirstIndex: 0, Sealed: "x"}}, 10, 1<<20, okProof); err != nil {
		t.Fatal(err)
	}
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p0", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D1", MasterVersion: 2, ExpiresAt: time.Now().Add(time.Minute)}); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("pairing fenced on a version that is not current: %v", err)
	}
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p1", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D1", MasterVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// A colleague's key query reads only the public half.
	pub, err := k.ListMasterKeys(ctx, "t1", []string{"u-a"})
	if err != nil || len(pub) != 1 || pub[0].MasterKey != "mk-1" || pub[0].DeviceListEpoch != 1 || pub[0].RecoveryMaster != "" || pub[0].RecoveryBackup != "" || pub[0].Pins != "" || pub[0].BackupKey != "" {
		t.Fatalf("public projection = %+v %v", pub, err)
	}

	// A reset: the new identity starts with no backup, pins, pairing or cross-signature.
	reset := master("u-a", "t1", "2")
	if err := k.PutMasterKey(ctx, reset, 1); err != nil || reset.Version != 2 {
		t.Fatalf("reset: %v %d", err, reset.Version)
	}
	got, err := k.GetMasterKey(ctx, "u-a")
	if err != nil || got.MasterKey != "mk-2" || got.Version != 2 || got.Pins != "" || got.PinsCounter != 0 || got.DeviceListEpoch != 0 || got.DeviceList != "" {
		t.Fatalf("after reset: %+v %v", got, err)
	}
	d, _ := k.GetDevice(ctx, "u-a", "D1")
	if d.MasterSignature != "" || d.MasterVersion != 0 {
		t.Fatalf("cross-signature survived the reset: %+v", d)
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 10); len(rows) != 0 {
		t.Fatalf("old backup survived: %+v", rows)
	}
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p1", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing survived the reset")
	}
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r", SenderKey: "k", SessionID: "s", Sealed: "x"}}, 10, 1<<20, okProof); !errors.Is(err, store.ErrE2EEVersion) {
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
	put := func(sender string, idx int64, sealed string) {
		t.Helper()
		if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r1", SenderKey: sender, SessionID: "s1", FirstIndex: idx, Sealed: sealed}}, 10, 1<<20, okProof); err != nil {
			t.Fatal(err)
		}
	}
	put("kA", 5, "from-5")
	put("kA", 9, "from-9") // reaches less far back: ignored
	put("kA", 2, "from-2") // reaches further back: replaces
	put("kA", 2, "again")  // equal: the first copy stays
	// Another sender re-sharing the same session ID gets its own row and displaces nothing.
	put("kB", 0, "impostor")
	rows, err := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 10)
	if err != nil || len(rows) != 2 || rows[0].SenderKey != "kA" || rows[0].Sealed != "from-2" || rows[0].FirstIndex != 2 || rows[1].SenderKey != "kB" {
		t.Fatalf("rows = %+v %v", rows, err)
	}

	// Paging in (room, sender, session) order, and both caps: past one, a new session is not
	// stored and the result says full, but an improvement to a stored one still lands.
	var batch []store.E2EEBackupSession
	for i := range 8 {
		batch = append(batch, store.E2EEBackupSession{RoomID: fmt.Sprintf("r%d", i%3+2), SenderKey: fmt.Sprintf("k%d", i%2), SessionID: fmt.Sprintf("s%d", i), Sealed: "x"})
	}
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, batch, 10, 1<<20, okProof); err != nil {
		t.Fatal(err)
	}
	res, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{
		{RoomID: "r9", SenderKey: "k", SessionID: "s", Sealed: "x"},                       // new: past the session cap
		{RoomID: "r1", SenderKey: "kA", SessionID: "s1", FirstIndex: 1, Sealed: "from-1"}, // better copy of a stored one
	}, 10, 1<<20, okProof)
	if err != nil || fmt.Sprint(res.Refused) != "[0]" || res.Stored != 1 {
		t.Fatalf("past the session cap: %+v %v", res, err)
	}
	stored := int64(len("from-1") + len("impostor") + 8)
	res, err = k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r8", SenderKey: "k", SessionID: "s", Sealed: "y"}}, 100, stored, okProof)
	if err != nil || fmt.Sprint(res.Refused) != "[0]" || res.Stored != 0 {
		t.Fatalf("past the byte cap: %+v %v", res, err)
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 1); rows[0].Sealed != "from-1" || rows[0].FirstIndex != 1 {
		t.Fatalf("the improvement did not land: %+v", rows)
	}
	// An improvement that would grow the backup past the byte cap is refused too; one that
	// fits in the same batch lands.
	res, err = k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{
		{RoomID: "r1", SenderKey: "kA", SessionID: "s1", FirstIndex: 0, Sealed: "from-0-but-much-longer"},
		{RoomID: "r1", SenderKey: "kB", SessionID: "s1", FirstIndex: 0, Sealed: "imposter"},
	}, 100, stored, okProof)
	if err != nil || fmt.Sprint(res.Refused) != "[0]" || res.Stored != 0 || res.Kept != 1 {
		t.Fatalf("an oversized improvement: %+v %v", res, err)
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 1); rows[0].Sealed != "from-1" {
		t.Fatalf("an oversized improvement landed: %+v", rows)
	}
	// A write whose proof fails stores nothing, inside the same transaction.
	refuse := errors.New("refused")
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r1", SenderKey: "kA", SessionID: "s1", FirstIndex: 0, Sealed: "forged"}}, 10, 1<<20, func(string) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("refused proof: %v", err)
	}
	if _, err := k.PutBackupSessions(ctx, "t2", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r1", SenderKey: "kA", SessionID: "s1", FirstIndex: 0, Sealed: "other-org"}}, 10, 1<<20, okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("write from another org: %v", err)
	}
	if rows, _ := k.ListBackupSessions(ctx, "t2", "u-a", 1, store.E2EEBackupCursor{}, 10); len(rows) != 0 {
		t.Fatal("another org reads the backup")
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 1); rows[0].Sealed != "from-1" {
		t.Fatal("a refused write changed a row")
	}
	var seen []string
	var after store.E2EEBackupCursor
	for {
		page, err := k.ListBackupSessions(ctx, "t1", "u-a", 1, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page {
			seen = append(seen, p.RoomID+"/"+p.SenderKey+"/"+p.SessionID)
		}
		if len(page) < 3 {
			break
		}
		l := page[len(page)-1]
		after = store.E2EEBackupCursor{RoomID: l.RoomID, SenderKey: l.SenderKey, SessionID: l.SessionID}
	}
	if len(seen) != 10 || seen[0] != "r1/kA/s1" || seen[1] != "r1/kB/s1" || seen[9] != "r4/k1/s5" {
		t.Fatalf("paged %v", seen)
	}
	if _, err := k.DeleteBackup(ctx, "t1", "u-a", 2); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatal(err)
	}
	if gen, err := k.DeleteBackup(ctx, "t1", "u-a", 1); err != nil || gen != 1 {
		t.Fatal(gen, err)
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 10); len(rows) != 0 {
		t.Fatal("backup not deleted")
	}
	// A write signed before the deletion cannot refill it; one for the new generation can.
	old := []store.E2EEBackupSession{{RoomID: "r1", SenderKey: "kA", SessionID: "s1", Sealed: "replayed"}}
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, old, 10, 1<<20, okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("replayed write after deletion: %v", err)
	}
	if res, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 1, old, 10, 1<<20, okProof); err != nil || res.Stored != 1 {
		t.Fatalf("write to the new generation: %+v %v", res, err)
	}
	if m, _ := k.GetMasterKey(ctx, "u-a"); m.BackupGeneration != 1 {
		t.Fatalf("generation %d", m.BackupGeneration)
	}
}

// A user's row left in another org (only a restore or a manual move makes one) must not block
// the first setup in their org.
func TestE2EEFirstSetupReplacesAnotherOrgsRow(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "old-org", "old"), 0); err != nil {
		t.Fatal(err)
	}
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "new"), 0); err != nil {
		t.Fatalf("first setup in the new org: %v", err)
	}
	if m, err := k.GetMasterKey(ctx, "u-a"); err != nil || m.TenantID != "t1" || m.MasterKey != "mk-new" {
		t.Fatalf("after = %+v %v", m, err)
	}
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "again"), 0); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("a second setup in the same org: %v", err)
	}
}

func TestE2EEPairingIsOneTimeShortLivedAndScoped(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	e2eeUser(t, st, "u-b")
	k := st.E2EE()
	now := time.Now()
	signedInitiator(t, st, "u-a", "t1", "OLD")
	open := func(id string) {
		t.Helper()
		if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: id, TenantID: "t1", UserID: "u-a", InitiatorDevice: "OLD", MasterVersion: 1, ExpiresAt: now.Add(3 * time.Minute)}); err != nil {
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
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, []store.E2EEBackupSession{{RoomID: "r", SenderKey: "k", SessionID: "s", Sealed: "x"}}, 10, 1<<20, okProof); err != nil {
		t.Fatal(err)
	}
	signedInitiator(t, st, "u-a", "t1", "D")
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D", MasterVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().DeleteUser(ctx, "u-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.GetMasterKey(ctx, "u-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("master key survived the user")
	}
	if rows, _ := k.ListBackupSessions(ctx, "t1", "u-a", 1, store.E2EEBackupCursor{}, 10); len(rows) != 0 {
		t.Fatal("key backup survived the user")
	}
	if _, err := k.GetPairing(ctx, "t1", "u-a", "p", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pairing survived the user")
	}
}

// The browser checks the backup cursor bytewise, so the server must page bytewise too, whatever
// the database's locale: under en_US.UTF-8 these room IDs sort rm_a, rm-b, rm.c, rmZ (letters
// first, punctuation ignored); bytewise they sort rm-b, rm.c, rmZ, rm_a. Run on PostgreSQL with
// a non-C default collation, this fails without COLLATE "C" on the key columns.
func TestE2EEKeyBackupPagesBytewise(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 0); err != nil {
		t.Fatal(err)
	}
	var batch []store.E2EEBackupSession
	for _, room := range []string{"rm_a", "rmZ", "rm.c", "rm-b"} {
		for _, sender := range []string{"k_x", "kY"} {
			batch = append(batch, store.E2EEBackupSession{RoomID: room, SenderKey: sender, SessionID: "s", Sealed: "x"})
		}
	}
	if _, err := k.PutBackupSessions(ctx, "t1", "u-a", 1, 0, batch, 100, 1<<20, okProof); err != nil {
		t.Fatal(err)
	}
	var got []string
	var after store.E2EEBackupCursor
	for {
		page, err := k.ListBackupSessions(ctx, "t1", "u-a", 1, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page {
			got = append(got, p.RoomID+"/"+p.SenderKey)
		}
		if len(page) < 3 {
			break
		}
		l := page[len(page)-1]
		after = store.E2EEBackupCursor{RoomID: l.RoomID, SenderKey: l.SenderKey, SessionID: l.SessionID}
	}
	want := []string{"rm-b/kY", "rm-b/k_x", "rm.c/kY", "rm.c/k_x", "rmZ/kY", "rmZ/k_x", "rm_a/kY", "rm_a/k_x"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("paged %v, want bytewise %v", got, want)
	}
}

// Two devices proposing different successors of one device list: only the first to reserve
// may publish, the other is refused before it signs (and told when the holder lapses), an honest
// retry keeps its epoch, and a different proposal replacing a lapsed one gets a higher epoch, so
// the two are never signable at one epoch.
func TestE2EEDeviceListReservation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	if r, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-a", now, time.Minute); err != nil || r.Epoch != 1 {
		t.Fatal(r, err)
	}
	// The losing proposal: refused while A's reservation is live, with its lapse, and unpublishable.
	r, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-b", now, time.Minute)
	if !errors.Is(err, store.ErrE2EEVersion) || !r.Until.Equal(now.Add(time.Minute)) {
		t.Fatalf("second reservation: %+v %v", r, err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["B"]`, "dg-b", "sig-b", at(now), okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("unreserved publish: %v", err)
	}
	// Wrong version, epoch or org reserve nothing, and name no holder.
	for _, c := range []struct {
		tenant            string
		version, expected int64
	}{{"t1", 2, 0}, {"t1", 1, 1}, {"t2", 1, 0}} {
		if r, err := k.ReserveDeviceList(ctx, c.tenant, "u-a", c.version, c.expected, "dg-a", now, time.Minute); !errors.Is(err, store.ErrE2EEVersion) || !r.Until.IsZero() {
			t.Fatalf("reservation %+v: %+v %v", c, r, err)
		}
	}
	// A's honest retry renews it at the same epoch; past its lapse A cannot publish.
	if r, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-a", now.Add(30*time.Second), time.Minute); err != nil || r.Epoch != 1 {
		t.Fatalf("renewal: %+v %v", r, err)
	}
	later := now.Add(2 * time.Minute)
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["A"]`, "dg-a", "sig-a", at(later), okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("publish after the reservation lapsed: %v", err)
	}
	// B replaces the lapsed reservation at a higher epoch: A may have signed epoch 1 already.
	r, err = k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-b", later, time.Minute)
	if err != nil || r.Epoch != 2 {
		t.Fatalf("reservation after a lapse: %+v %v", r, err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["B"]`, "dg-b", "sig-b", at(later), okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("published at an epoch other than the reserved one: %v", err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 2, `["B"]`, "dg-b", "sig-b", at(later), okProof); err != nil {
		t.Fatal(err)
	}
	// Publishing ends the reservation, and the next one starts above it.
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 2, 3, `["B"]`, "dg-b", "sig-b", at(later), okProof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("publish without a reservation of epoch 3: %v", err)
	}
	if r, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 2, "dg-c", later, time.Minute); err != nil || r.Epoch != 3 {
		t.Fatal(r, err)
	}
	m, _ := k.GetMasterKey(ctx, "u-a")
	if m.DeviceListEpoch != 2 || m.DeviceList != `["B"]` || m.DeviceListSignature != "sig-b" {
		t.Fatalf("published %+v", m)
	}
	// A reset clears a pending reservation with the list, and its epochs.
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "2"), 1); err != nil {
		t.Fatal(err)
	}
	if r, err := k.ReserveDeviceList(ctx, "t1", "u-a", 2, 0, "dg-d", later, time.Minute); err != nil || r.Epoch != 1 {
		t.Fatalf("reservation after a reset: %+v %v", r, err)
	}
}

// The verified device's cancel removes a pairing only while nothing was sealed to it.
func TestE2EEPairingUnsealedCancel(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	signedInitiator(t, st, "u-a", "t1", "D1")
	k := st.E2EE()
	now := time.Now()
	p := &store.E2EEPairing{ID: "p1", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D1", MasterVersion: 1, ExpiresAt: now.Add(time.Minute)}
	if err := k.CreatePairing(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := k.JoinPairing(ctx, "t1", "u-a", "p1", "D2", "eph", now); err != nil {
		t.Fatal(err)
	}
	if err := k.SealPairing(ctx, "t1", "u-a", "p1", "D1", "sealed", now); err != nil {
		t.Fatal(err)
	}
	if err := k.DeletePairingUnsealed(ctx, "t1", "u-a", "p1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cancel of a sealed pairing: %v", err)
	}
	if got, err := k.ConsumePairing(ctx, "t1", "u-a", "p1", "D2", now); err != nil || got.Sealed != "sealed" {
		t.Fatalf("the sealed keys did not survive: %+v %v", got, err)
	}
	if err := k.CreatePairing(ctx, &store.E2EEPairing{ID: "p2", TenantID: "t1", UserID: "u-a", InitiatorDevice: "D1", MasterVersion: 1, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := k.DeletePairingUnsealed(ctx, "t1", "u-a", "p2"); err != nil {
		t.Fatalf("cancel of an unsealed pairing: %v", err)
	}
}

// A list write judges its reservation's lease by the clock read once it holds the master row
// (after the proof ran in that transaction), not when the request arrived: one that waited on
// the lock past the lease is refused.
func TestE2EEDeviceListLeaseCheckedUnderTheLock(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	e2eeUser(t, st, "u-a")
	k := st.E2EE()
	if err := k.PutMasterKey(ctx, master("u-a", "t1", "1"), 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	if _, err := k.ReserveDeviceList(ctx, "t1", "u-a", 1, 0, "dg-a", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	locked := false
	proof := func(string) error { locked = true; return nil }
	clock := func() time.Time {
		if !locked {
			t.Fatal("the lease clock was read before the row was locked")
		}
		return now.Add(2 * time.Minute) // the write waited past the lease
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["A"]`, "dg-a", "sig", clock, proof); !errors.Is(err, store.ErrE2EEVersion) {
		t.Fatalf("a write past the lease: %v", err)
	}
	if err := k.PutDeviceList(ctx, "t1", "u-a", 1, 0, 1, `["A"]`, "dg-a", "sig", at(now.Add(30*time.Second)), okProof); err != nil {
		t.Fatalf("a write within the lease: %v", err)
	}
}
