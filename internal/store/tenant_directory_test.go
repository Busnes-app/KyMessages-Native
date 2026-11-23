package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

func TestTenantDirectoryAdmissionAndOrdering(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Settings().SetSetting(ctx, "tenancy.mode", "multi"); err != nil {
		t.Fatal(err)
	}
	const org = "00000000-0000-4000-8000-0000000000d5"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "dir-user", Username: "directory", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "dir-sub", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	issue := func(hash string) error {
		return st.Sessions().CreateSession(ctx, &store.Session{UserID: u.ID, TokenHash: hash, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, "")
	}
	if err := issue("unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown org issued grant: %v", err)
	}
	e := store.TenantDirectoryEntry{TenantID: org, Revision: 10, Status: store.TenantStatusActive, Enabled: true, Valid: true, Quotas: store.TenantQuotas{MaxUploadBytes: 2048}}
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := issue("admitted"); err != nil {
		t.Fatal(err)
	}
	e.Revision = 11
	e.Enabled = false
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.Revision = 10
	e.Enabled = true
	e.Quotas.MaxUploadBytes = 8192
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := issue("stale"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale snapshot restored grant: %v", err)
	}
	e.Revision = 11 // same revision with different authority is not an idempotent replay
	if err := st.Chat().ApplyTenantDirectory(ctx, e); !errors.Is(err, store.ErrInvalidInput) {
		t.Fatalf("conflicting replay: %v", err)
	}
	e.Revision = 12
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := issue("pending-cleanup"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("restored access before cleanup: %v", err)
	}
	if err := st.Sessions().DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().CompleteTenantRevocation(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := issue("recovered"); err != nil {
		t.Fatal(err)
	}
	// A lifecycle event ahead of the directory cannot authorize a grant on old quotas.
	if _, err := st.Chat().ApplyTenantLifecycle(ctx, org, store.TenantStatusActive, 13); err != nil {
		t.Fatal(err)
	}
	if err := issue("ahead"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unmirrored lifecycle issued grant: %v", err)
	}
	e.Revision = 13
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	e.Status = store.TenantStatusDeleted
	e.Revision = 1
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.Status = store.TenantStatusActive
	e.Revision = 100
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := st.Chat().GetTenant(ctx, org)
	if err != nil || got.Status != store.TenantStatusDeleted {
		t.Fatalf("terminal deletion: %+v %v", got, err)
	}
}

func TestTenantDirectoryQuotasSerializeReservationsAndCommit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000d6"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "quota-user", Username: "quota-user", OrgID: org, SSOProvider: "kyidentity", SSOSubject: "quota-sub", Role: "user", Status: "active"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: org, Kind: store.RoomKindChannel, Name: "quota-room", CreatedBy: u.ID}
	if err := st.Chat().CreateRoom(ctx, room, []string{u.ID}); err != nil {
		t.Fatal(err)
	}
	e := store.TenantDirectoryEntry{TenantID: org, Revision: 1, Status: store.TenantStatusActive, Enabled: true, Valid: true, Quotas: store.TenantQuotas{MaxUploadBytes: 4096, MaxPendingUserBytes: 4096}}
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	limits := store.AttachmentQuotaLimits{ActiveUploader: true, MaxUploadBytes: 8192}
	start := make(chan struct{})
	results := make(chan *store.AttachmentQuotaReservation, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := st.Chat().ReserveAttachmentQuota(ctx, org, u.ID, 4096, limits, time.Minute)
			if err != nil && !errors.Is(err, store.ErrAttachmentPendingQuotaExceeded) {
				t.Error(err)
			}
			results <- r
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var reservation *store.AttachmentQuotaReservation
	for r := range results {
		if r != nil {
			if reservation != nil {
				t.Fatal("both replicas spent the same pending budget")
			}
			reservation = r
		}
	}
	if reservation == nil || reservation.ReservedBytes != 4096 {
		t.Fatalf("reservation: %+v", reservation)
	}
	// Narrow quotas while a previously reserved upload is in flight; commit must recheck.
	e.Revision = 2
	e.Quotas.MaxUploadBytes = 2048
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	a := &store.Attachment{ID: "att_quota_fence", TenantID: org, RoomID: room.ID, UploaderID: u.ID, Filename: "f", MimeType: "text/plain", SizeBytes: 4096, SHA256Hex: "h"}
	if err := st.Chat().CommitAttachmentWithQuota(ctx, reservation.ID, a, limits); !errors.Is(err, store.ErrAttachmentUploadQuotaExceeded) {
		t.Fatalf("old reservation bypassed new quota: %v", err)
	}
	a.SizeBytes = 2048
	if err := st.Chat().CommitAttachmentWithQuota(ctx, reservation.ID, a, limits); err != nil {
		t.Fatal(err)
	}
	// The same uploader may not commit an attachment into another org even if admitted there.
	other := "00000000-0000-4000-8000-0000000000d7"
	if _, err := st.Chat().EnsureTenant(ctx, other); err != nil {
		t.Fatal(err)
	}
	e.TenantID = other
	if err := st.Chat().ApplyTenantDirectory(ctx, e); err != nil {
		t.Fatal(err)
	}
	a.ID = "att_wrong_org"
	a.TenantID = other
	if err := st.Chat().CommitAttachmentWithQuota(ctx, "", a, limits); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("wrong-org commit: %v", err)
	}
}
