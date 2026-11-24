package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

const retainedOrg = "00000000-0000-4000-8000-000000000071"
const retainedOtherOrg = "00000000-0000-4000-8000-000000000072"

const retainedVersion = "opaque/+&= original version"

// retainedFixture posts one object-store file (a version) in a message.
func retainedFixture(t *testing.T) (*SQLStore, Store, *User, *Attachment) {
	t.Helper()
	ctx := context.Background()
	cfg := testdb.Config(t)
	first, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })
	second, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	s := first.(*SQLStore)
	for _, org := range []string{retainedOrg, retainedOtherOrg} {
		if _, err := s.Chat().EnsureTenant(ctx, org); err != nil {
			t.Fatal(err)
		}
	}
	u := &User{ID: "original-uploader", Username: "original-uploader", OrgID: retainedOrg, SSOProvider: "kyidentity", SSOSubject: "immutable-original-subject", Role: "user", Status: "active"}
	if err := s.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	room := &Room{TenantID: retainedOrg, Kind: RoomKindChannel, CreatedBy: u.ID, Name: "shared"}
	if err := s.Chat().CreateRoom(ctx, room, nil); err != nil {
		t.Fatal(err)
	}
	a := &Attachment{ID: "retained-file", TenantID: retainedOrg, RoomID: room.ID, UploaderID: u.ID, BlobKey: "retained-key", Filename: "opaque.bin", MimeType: "application/octet-stream", SizeBytes: 700, SHA256Hex: strings.Repeat("a", 64), VersionID: retainedVersion}
	if err := s.Chat().CreateAttachment(ctx, a); err != nil {
		t.Fatal(err)
	}
	m, _, err := s.Chat().CreateMessage(ctx, CreateMessageParams{ID: "retained-msg", TenantID: retainedOrg, RoomID: room.ID, SenderID: u.ID, Body: "file", Encoding: MessageEncodingPlainV1, AttachmentIDs: []string{a.ID}})
	if err != nil {
		t.Fatal(err)
	}
	a.MessageID = m.ID
	return s, second, u, a
}

func deleteRetainedMessage(t *testing.T, st Store, a *Attachment) {
	t.Helper()
	if _, err := st.Chat().DeleteMessage(context.Background(), retainedOrg, a.RoomID, a.MessageID, a.UploaderID, false); err != nil {
		t.Fatal(err)
	}
}

func TestMessageDeleteRetainsVersionQuotaAndProvenance(t *testing.T) {
	s, replica, u, a := retainedFixture(t)
	ctx := context.Background()
	// A disk file (no version) in the same org retains nothing.
	disk := *a
	disk.ID, disk.BlobKey, disk.VersionID, disk.MessageID = "disk-file", "disk-key", "", ""
	if err := s.Chat().CreateAttachment(ctx, &disk); err != nil {
		t.Fatal(err)
	}
	dm, _, err := s.Chat().CreateMessage(ctx, CreateMessageParams{TenantID: retainedOrg, RoomID: a.RoomID, SenderID: u.ID, Body: "disk", Encoding: MessageEncodingPlainV1, AttachmentIDs: []string{disk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	disk.MessageID = dm.ID
	deleteRetainedMessage(t, s, &disk)
	// Real shared DB connections, simultaneous duplicate deletes, no polling/sleep.
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st := Store(s)
			if i%2 == 1 {
				st = replica
			}
			_, err := st.Chat().DeleteMessage(ctx, retainedOrg, a.RoomID, a.MessageID, u.ID, false)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Chat().GetAttachment(ctx, retainedOrg, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("live row survived: %v", err)
	}
	versions, err := replica.Chat().RetainedAttachmentVersions(ctx, retainedOrg, u.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("replay inventory: %+v %v", versions, err)
	}
	v := versions[0]
	if v.UploaderID != u.ID || v.UploaderSubject != u.SSOSubject || v.UploaderProvider != "kyidentity" || v.VersionID != retainedVersion || v.SizeBytes != a.SizeBytes || v.SHA256Hex != a.SHA256Hex {
		t.Fatalf("lost immutable provenance/receipt: %+v", v)
	}
	if other, err := s.Chat().RetainedAttachmentVersions(ctx, retainedOtherOrg, u.ID); err != nil || len(other) != 0 {
		t.Fatalf("foreign inventory leaked: %+v %v", other, err)
	}
	seq, used, err := s.Chat().NextPoolReport(ctx, retainedOrg)
	if err != nil || used != a.SizeBytes {
		t.Fatalf("retention freed/doubled pool: %d %v", used, err)
	}
	usages, err := s.Chat().PoolUsages(ctx, time.Now().UnixMilli(), retainedOrg)
	if err != nil || len(usages) != 1 || usages[0].UsedBytes != used {
		t.Fatalf("reporter disagrees: %+v %v", usages, err)
	}
	if err := s.Chat().SetPoolGrant(ctx, retainedOrg, seq, used, used, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Chat().ReserveAttachmentQuota(ctx, retainedOrg, u.ID, 1, AttachmentQuotaLimits{Pool: true}, time.Minute); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("retained bytes admitted new growth: %v", err)
	}
	// Retained files consume total storage, not the uploader's staged-file budget.
	if pending, err := s.Chat().SumPendingAttachmentBytesByUploader(ctx, retainedOrg, u.ID); err != nil || pending != 0 {
		t.Fatalf("retained file remained staged: %d %v", pending, err)
	}
}

// A retained file stays findable by erasure after its message and the account are gone, and
// erasure or purge (which erase every version first) clear its charge.
func TestRetainedVersionIsErasedAndPurged(t *testing.T) {
	s, _, u, a := retainedFixture(t)
	ctx := context.Background()
	other := &User{ID: "other-member", Username: "other-member", OrgID: retainedOrg, SSOProvider: "kyidentity", SSOSubject: "other-subject", Role: "user", Status: "active"}
	if err := s.Users().CreateUser(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().AddRoomMember(ctx, &RoomMember{TenantID: retainedOrg, RoomID: a.RoomID, UserID: other.ID, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	otherFile := *a
	otherFile.ID, otherFile.BlobKey, otherFile.UploaderID, otherFile.MessageID = "other-file", "other-key", other.ID, ""
	if err := s.Chat().CreateAttachment(ctx, &otherFile); err != nil {
		t.Fatal(err)
	}
	deleteRetainedMessage(t, s, a)
	if err := s.Chat().RememberErasedSubject(ctx, u.SSOSubject, retainedOrg); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().DeactivateForErasure(ctx, retainedOrg, u.ID); err != nil {
		t.Fatal(err)
	}
	refs, err := s.Chat().ErasureBlobs(ctx, retainedOrg, u.ID)
	if err != nil || len(refs) != 1 || refs[0].Key != a.BlobKey {
		t.Fatalf("deleted file lost erasure discovery: %+v %v", refs, err)
	}
	late, err := s.Chat().EraseUser(ctx, retainedOrg, u)
	if err != nil || len(late) != 1 || late[0].Key != a.BlobKey {
		t.Fatalf("retained cleanup was not queued: %+v %v", late, err)
	}
	if _, err := s.Users().GetUserByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("account not erased: %v", err)
	}
	versions, err := s.Chat().RetainedAttachmentVersions(ctx, retainedOrg, u.ID)
	if err != nil || len(versions) != 1 || versions[0].UploaderSubject != u.SSOSubject {
		t.Fatalf("account deletion lost uploader provenance: %+v %v", versions, err)
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 10, "sso.user_erased"); err != nil || n != 0 {
		t.Fatalf("erasure completed before its objects were erased: %d %v", n, err)
	}
	// The caller has erased every version: the charge, the queue entry and the erasure end.
	if err := s.Chat().ClearPendingBlobDeletes(ctx, late); err != nil {
		t.Fatal(err)
	}
	if versions, err := s.Chat().RetainedAttachmentVersions(ctx, retainedOrg, u.ID); err != nil || len(versions) != 0 {
		t.Fatalf("erased file still charged: %+v %v", versions, err)
	}
	if _, n, err := s.Audit().ListAuditRecords(ctx, 0, 10, "sso.user_erased"); err != nil || n != 1 {
		t.Fatalf("erasure did not complete once: %d %v", n, err)
	}
	if got, err := s.Chat().GetAttachment(ctx, retainedOrg, otherFile.ID); err != nil || got.UploaderID != other.ID {
		t.Fatalf("other member content changed: %+v %v", got, err)
	}
	// Purge: the other member's posted file is retained, then the purge clears it with the org.
	om, _, err := s.Chat().CreateMessage(ctx, CreateMessageParams{TenantID: retainedOrg, RoomID: a.RoomID, SenderID: other.ID, Body: "f", Encoding: MessageEncodingPlainV1, AttachmentIDs: []string{otherFile.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chat().DeleteMessage(ctx, retainedOrg, a.RoomID, om.ID, other.ID, false); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Chat().RetainedAttachmentVersions(ctx, retainedOrg, other.ID); err != nil || len(v) != 1 {
		t.Fatalf("other member's file not retained: %+v %v", v, err)
	}
	if _, err := s.Chat().ApplyTenantLifecycle(ctx, retainedOrg, TenantStatusDeleted, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Chat().PurgeTenantRows(ctx, retainedOrg); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Chat().RetainedAttachmentVersions(ctx, retainedOrg, other.ID); err != nil || len(v) != 0 {
		t.Fatalf("purge kept a retained charge: %+v %v", v, err)
	}
	if err := s.Chat().MarkTenantPurged(ctx, retainedOrg); err != nil {
		t.Fatal(err)
	}
}
