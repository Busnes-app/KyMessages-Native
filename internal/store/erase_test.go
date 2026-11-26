package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// An upload in flight when its person is erased cannot commit a row: ActiveUploader checks the
// account inside the commit's transaction.
func TestCommitRefusesAnInactiveUploader(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000d1"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().CreateUser(ctx, &store.User{ID: "u_up", Username: "up", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "s-up", OrgID: org}); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: org, Kind: store.RoomKindChannel, Name: "r", CreatedBy: "u_up"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u_up"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Chat().ApplyTenantDirectory(ctx, store.TenantDirectoryEntry{TenantID: org, Status: store.TenantStatusActive, Enabled: true, Valid: true}); err != nil {
		t.Fatal(err)
	}
	limits := store.AttachmentQuotaLimits{ActiveUploader: true}
	commit := func(id string) error {
		if err := st.Chat().QueueUploadIntent(ctx, org, id, time.Now().Add(time.Minute).UnixMilli()); err != nil {
			return err
		}
		return st.Chat().CommitAttachmentWithQuota(ctx, "", &store.Attachment{ID: id, TenantID: org, RoomID: room.ID, UploaderID: "u_up", Filename: "f", MimeType: "text/plain", SizeBytes: 1, SHA256Hex: "h"}, limits)
	}
	if err := commit("att_live_0001"); err != nil {
		t.Fatalf("active uploader: %v", err)
	}
	if err := st.Chat().DeactivateForErasure(ctx, org, "u_up"); err != nil {
		t.Fatal(err)
	}
	if err := commit("att_late_0001"); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("erased uploader: %v", err)
	}
}

// An upload in flight when its org is deleted commits nothing either.
func TestCommitRefusesADeletedOrg(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const org = "00000000-0000-4000-8000-0000000000d2"
	if _, err := st.Chat().EnsureTenant(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().CreateUser(ctx, &store.User{ID: "u_org", Username: "orguser", Role: "user", Status: "active", SSOProvider: "kyidentity", SSOSubject: "s-org", OrgID: org}); err != nil {
		t.Fatal(err)
	}
	room := &store.Room{TenantID: org, Kind: store.RoomKindChannel, Name: "r", CreatedBy: "u_org"}
	if err := st.Chat().CreateRoom(ctx, room, []string{"u_org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Chat().ApplyTenantLifecycle(ctx, org, store.TenantStatusDeleted, 1); err != nil {
		t.Fatal(err)
	}
	err := st.Chat().CommitAttachmentWithQuota(ctx, "", &store.Attachment{ID: "att_dead_0001", TenantID: org, RoomID: room.ID, UploaderID: "u_org", Filename: "f", MimeType: "text/plain", SizeBytes: 1, SHA256Hex: "h"}, store.AttachmentQuotaLimits{ActiveUploader: true})
	if !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("commit into a deleted org: %v", err)
	}
}
