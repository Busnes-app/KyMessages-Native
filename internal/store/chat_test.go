package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

func openTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestChatStoreDefaultTenantAndIsolation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()

	def, err := chat.GetTenant(ctx, store.DefaultTenantID)
	if err != nil {
		t.Fatalf("GetTenant(default): %v", err)
	}
	if def.P2PPolicy != store.P2PPolicyHybrid || def.P2PMaxVideo != 2 || def.P2PMaxAudio != 4 || !def.GuestForceSFU {
		t.Fatalf("unexpected default tenant policy: %+v", def)
	}

	other := &store.Tenant{ID: "tnt_acme", Slug: "acme", DisplayName: "Acme Corp", Plan: "business", GuestForceSFU: true}
	if err := chat.CreateTenant(ctx, other); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	room := &store.Room{TenantID: "tnt_acme", Kind: store.RoomKindChannel, Name: "general", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, []string{"u_bob"}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	// Default tenant must not see tnt_acme's room.
	if _, err := chat.GetRoom(ctx, store.DefaultTenantID, room.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant GetRoom returned %v, want ErrNotFound", err)
	}
	roomsDefault, err := chat.ListUserRooms(ctx, store.DefaultTenantID, "u_alice")
	if err != nil || len(roomsDefault) != 0 {
		t.Fatalf("cross-tenant ListUserRooms = (%d, %v), want (0, nil)", len(roomsDefault), err)
	}
	roomsAcme, err := chat.ListUserRooms(ctx, "tnt_acme", "u_alice")
	if err != nil || len(roomsAcme) != 1 || roomsAcme[0].ID != room.ID {
		t.Fatalf("acme ListUserRooms = (%+v, %v), want 1 room", roomsAcme, err)
	}
}

func TestChatStoreDMDeduplication(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()

	dm1, created, err := chat.GetOrCreateDM(ctx, store.DefaultTenantID, "u_alice", "u_bob")
	if err != nil || !created {
		t.Fatalf("first GetOrCreateDM: (%+v, created=%v, err=%v)", dm1, created, err)
	}
	dm2, created, err := chat.GetOrCreateDM(ctx, store.DefaultTenantID, "u_bob", "u_alice")
	if err != nil || created || dm2.ID != dm1.ID {
		t.Fatalf("reverse GetOrCreateDM: (%+v, created=%v, err=%v), want same ID %s", dm2, created, err, dm1.ID)
	}
	members, err := chat.ListRoomMembers(ctx, store.DefaultTenantID, dm1.ID)
	if err != nil || len(members) != 2 {
		t.Fatalf("DM members = (%d, %v), want 2", len(members), err)
	}
}

func TestChatStoreMessagesSeqIdempotencyPaginationAndReadCursor(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()

	room := &store.Room{Kind: store.RoomKindChannel, Name: "ops", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, []string{"u_bob"}); err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	// Non-member cannot post.
	if _, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: room.ID, SenderID: "u_eve", Body: "intruder",
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("non-member CreateMessage = %v, want ErrNotFound", err)
	}

	// Send 5 messages; retry message 2 with same idempotency key.
	var firstMsg *store.Message
	for i := 1; i <= 5; i++ {
		idem := ""
		if i == 2 {
			idem = "key-2"
		}
		m, created, err := chat.CreateMessage(ctx, store.CreateMessageParams{
			RoomID:         room.ID,
			SenderID:       "u_alice",
			SenderName:     "Alice",
			Body:           "msg",
			IdempotencyKey: idem,
		})
		if err != nil || !created {
			t.Fatalf("CreateMessage %d: (%v, created=%v)", i, err, created)
		}
		if m.Seq != int64(i) {
			t.Fatalf("msg %d seq = %d, want %d", i, m.Seq, i)
		}
		if i == 1 {
			firstMsg = m
		}
	}

	// Duplicate idempotency key returns original message without advancing seq.
	dup, created, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:         room.ID,
		SenderID:       "u_alice",
		Body:           "msg-different-body-ignored",
		IdempotencyKey: "key-2",
	})
	if err != nil || created || dup.Seq != 2 {
		t.Fatalf("idempotent retry = (%+v, created=%v, err=%v), want seq=2 created=false", dup, created, err)
	}

	// Next new message gets seq 6 (no gap).
	m6, created, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: room.ID, SenderID: "u_alice", Body: "sixth",
	})
	if err != nil || !created || m6.Seq != 6 {
		t.Fatalf("sixth message = (%+v, created=%v, err=%v), want seq=6", m6, created, err)
	}

	// Bob has 6 unreads; Alice (sender) has 0 unreads.
	bobRooms, err := chat.ListUserRooms(ctx, store.DefaultTenantID, "u_bob")
	if err != nil || len(bobRooms) != 1 || bobRooms[0].UnreadCount != 6 {
		t.Fatalf("bob unread = %+v (err=%v), want 6", bobRooms, err)
	}
	aliceRooms, err := chat.ListUserRooms(ctx, store.DefaultTenantID, "u_alice")
	if err != nil || len(aliceRooms) != 1 || aliceRooms[0].UnreadCount != 0 {
		t.Fatalf("alice unread = %+v (err=%v), want 0", aliceRooms, err)
	}

	// Read cursor is monotonic and clamped to room.last_seq (6).
	cur, err := chat.UpdateReadCursor(ctx, store.DefaultTenantID, room.ID, "u_bob", 999)
	if err != nil || cur != 6 {
		t.Fatalf("clamped UpdateReadCursor = (%d, %v), want 6", cur, err)
	}
	cur, err = chat.UpdateReadCursor(ctx, store.DefaultTenantID, room.ID, "u_bob", 2)
	if err != nil || cur != 6 {
		t.Fatalf("regressive UpdateReadCursor = (%d, %v), want 6", cur, err)
	}

	// Pagination: latest 3 -> seqs [4, 5, 6], hasMore=true.
	page1, hasMore, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: room.ID, Limit: 3})
	if err != nil || !hasMore || len(page1) != 3 || page1[0].Seq != 4 || page1[2].Seq != 6 {
		t.Fatalf("latest page = (len=%d, hasMore=%v, err=%v)", len(page1), hasMore, err)
	}
	// Before seq 4 -> seqs [1, 2, 3], hasMore=false.
	page2, hasMore, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: room.ID, BeforeSeq: 4, Limit: 3})
	if err != nil || hasMore || len(page2) != 3 || page2[0].Seq != 1 || page2[2].Seq != 3 {
		t.Fatalf("before page = (len=%d, hasMore=%v, err=%v)", len(page2), hasMore, err)
	}
	// After seq 4 -> seqs [5, 6], hasMore=false.
	catchup, hasMore, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: room.ID, AfterSeq: 4, Limit: 10})
	if err != nil || hasMore || len(catchup) != 2 || catchup[0].Seq != 5 || catchup[1].Seq != 6 {
		t.Fatalf("after page = (len=%d, hasMore=%v, err=%v)", len(catchup), hasMore, err)
	}

	// Reactions attach cleanly on ListMessages.
	if err := chat.AddReaction(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", "👍"); err != nil {
		t.Fatalf("AddReaction: %v", err)
	}
	if err := chat.AddReaction(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", "👍"); err != nil {
		t.Fatalf("duplicate AddReaction should be idempotent: %v", err)
	}
	got, err := chat.GetMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID)
	if err != nil || len(got.Reactions) != 1 || got.Reactions[0].Count != 1 || got.Reactions[0].Emoji != "👍" {
		t.Fatalf("reactions = %+v (err=%v)", got.Reactions, err)
	}
	if err := chat.RemoveReaction(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", "👍"); err != nil {
		t.Fatalf("RemoveReaction: %v", err)
	}

	// Edit/delete ownership checks.
	if _, err := chat.EditMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", "hijack", store.MessageEncodingPlainV1); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("non-sender EditMessage = %v, want ErrForbidden", err)
	}
	edited, err := chat.EditMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_alice", "edited text", store.MessageEncodingPlainV1)
	if err != nil || edited.Body != "edited text" || edited.EditedAt == nil {
		t.Fatalf("EditMessage = (%+v, %v)", edited, err)
	}
	if _, err := chat.DeleteMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", false); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("non-sender non-mod DeleteMessage = %v, want ErrForbidden", err)
	}
	deleted, err := chat.DeleteMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", true)
	if err != nil || deleted.Body != "" || deleted.DeletedAt == nil {
		t.Fatalf("moderator DeleteMessage = (%+v, %v)", deleted, err)
	}

	// Closed rooms reject new messages.
	if _, err := chat.CloseRoom(ctx, store.DefaultTenantID, room.ID); err != nil {
		t.Fatalf("CloseRoom: %v", err)
	}
	if _, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: room.ID, SenderID: "u_alice", Body: "after close",
	}); !errors.Is(err, store.ErrRoomClosed) {
		t.Fatalf("closed room CreateMessage = %v, want ErrRoomClosed", err)
	}
}

func TestChatStoreSearch(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()

	roomA := &store.Room{Kind: store.RoomKindChannel, Name: "public", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, roomA, []string{"u_bob"}); err != nil {
		t.Fatal(err)
	}
	roomB := &store.Room{Kind: store.RoomKindChannel, Name: "secret", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, roomB, nil); err != nil {
		t.Fatal(err)
	}

	_, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: roomA.ID, SenderID: "u_alice", Body: "deploy 100% done for invoice",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: roomA.ID, SenderID: "u_alice", Encoding: store.MessageEncodingE2EERoomV1, Body: "invoice ciphertext",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID: roomB.ID, SenderID: "u_alice", Body: "secret invoice details",
	})
	if err != nil {
		t.Fatal(err)
	}

}

func TestChatStoreAttachments(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	chat := st.Chat()

	roomA := &store.Room{Kind: store.RoomKindChannel, Name: "design", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, roomA, []string{"u_alice", "u_bob"}); err != nil {
		t.Fatal(err)
	}
	roomB := &store.Room{Kind: store.RoomKindChannel, Name: "other", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, roomB, []string{"u_alice"}); err != nil {
		t.Fatal(err)
	}

	attA := &store.Attachment{
		RoomID:     roomA.ID,
		UploaderID: "u_alice",
		Filename:   "diagram.png",
		MimeType:   "image/png",
		SizeBytes:  1024,
		SHA256Hex:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := chat.CreateAttachment(ctx, attA); err != nil {
		t.Fatalf("CreateAttachment: %v", err)
	}
	if attA.ID == "" || attA.BlobKey == "" || attA.CreatedAt == 0 {
		t.Fatalf("CreateAttachment did not populate defaults: %+v", attA)
	}

	// Bob cannot hijack Alice's staged attachment into his message.
	if _, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:        roomA.ID,
		SenderID:      "u_bob",
		Body:          "stealing file",
		AttachmentIDs: []string{attA.ID},
	}); !errors.Is(err, store.ErrAttachmentInvalid) {
		t.Fatalf("cross-uploader CreateMessage = %v, want ErrAttachmentInvalid", err)
	}

	// Alice cannot attach roomA's upload to a message in roomB.
	if _, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:        roomB.ID,
		SenderID:      "u_alice",
		Body:          "wrong room",
		AttachmentIDs: []string{attA.ID},
	}); !errors.Is(err, store.ErrAttachmentInvalid) {
		t.Fatalf("cross-room CreateMessage = %v, want ErrAttachmentInvalid", err)
	}

	// Rolled-back failures must not consume room sequence numbers.
	roomSnapshot, err := chat.GetRoom(ctx, store.DefaultTenantID, roomA.ID)
	if err != nil || roomSnapshot.LastSeq != 0 {
		t.Fatalf("roomA LastSeq after rollback = (%+v, %v), want 0", roomSnapshot, err)
	}

	// Valid attachment-only message with idempotency key.
	msg, created, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:         roomA.ID,
		SenderID:       "u_alice",
		SenderName:     "Alice",
		Body:           "architecture sketch",
		IdempotencyKey: "att-idem-1",
		AttachmentIDs:  []string{attA.ID, attA.ID}, // duplicates deduplicated
	})
	if err != nil || !created || len(msg.Attachments) != 1 || msg.Attachments[0].ID != attA.ID {
		t.Fatalf("CreateMessage with attachment = (%+v, created=%v, err=%v)", msg, created, err)
	}
	if msg.Attachments[0].MessageID != msg.ID {
		t.Errorf("linked attachment MessageID = %q, want %q", msg.Attachments[0].MessageID, msg.ID)
	}

	// Idempotency retry returns the same message with hydrated attachments.
	dup, createdDup, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:         roomA.ID,
		SenderID:       "u_alice",
		Body:           "architecture sketch",
		IdempotencyKey: "att-idem-1",
		AttachmentIDs:  []string{attA.ID},
	})
	if err != nil || createdDup || dup.ID != msg.ID || len(dup.Attachments) != 1 {
		t.Fatalf("idempotency retry = (%+v, created=%v, err=%v)", dup, createdDup, err)
	}

	// Cannot re-attach an already linked attachment to a second message.
	if _, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{
		RoomID:        roomA.ID,
		SenderID:      "u_alice",
		Body:          "reuse attempt",
		AttachmentIDs: []string{attA.ID},
	}); !errors.Is(err, store.ErrAttachmentInvalid) {
		t.Fatalf("reuse attachment CreateMessage = %v, want ErrAttachmentInvalid", err)
	}

	// ListMessages, GetMessage and EditMessage all hydrate attachments.
	listed, _, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: roomA.ID, Limit: 10})
	if err != nil || len(listed) != 1 || len(listed[0].Attachments) != 1 {
		t.Fatalf("ListMessages = (%+v, %v)", listed, err)
	}
	fetched, err := chat.GetMessage(ctx, store.DefaultTenantID, roomA.ID, msg.ID)
	if err != nil || len(fetched.Attachments) != 1 {
		t.Fatalf("GetMessage = (%+v, %v)", fetched, err)
	}
	edited, err := chat.EditMessage(ctx, store.DefaultTenantID, roomA.ID, msg.ID, "u_alice", "updated sketch caption", store.MessageEncodingPlainV1)
	if err != nil || len(edited.Attachments) != 1 {
		t.Fatalf("EditMessage = (%+v, %v)", edited, err)
	}

	// Deleting the message clears linked attachment rows.
	linked, err := chat.ListMessageAttachments(ctx, store.DefaultTenantID, roomA.ID, msg.ID)
	if err != nil || len(linked) != 1 {
		t.Fatalf("ListMessageAttachments = (%+v, %v)", linked, err)
	}
	deleted, err := chat.DeleteMessage(ctx, store.DefaultTenantID, roomA.ID, msg.ID, "u_alice", false)
	if err != nil || len(deleted.Attachments) != 0 {
		t.Fatalf("DeleteMessage = (%+v, %v)", deleted, err)
	}
	if _, err := chat.GetAttachment(ctx, store.DefaultTenantID, attA.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAttachment after DeleteMessage = %v, want ErrNotFound", err)
	}
}

func TestAttachmentQuotaAtomicConcurrencyAndReservationRelease(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	chat := st.Chat()

	room := &store.Room{Kind: store.RoomKindChannel, Name: "quota-race", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, []string{"u_alice", "u_bob", "u_carol", "u_dave"}); err != nil {
		t.Fatal(err)
	}

	// 1. Reservation blocks concurrent over-admission, and release immediately frees capacity.
	limits := store.AttachmentQuotaLimits{MaxTotalBytes: 2500, MaxPendingUserBytes: 1500}
	res1, err := chat.ReserveAttachmentQuota(ctx, store.DefaultTenantID, "u_alice", 1500, limits, time.Minute)
	if err != nil || res1.ReservedBytes != 1500 {
		t.Fatalf("ReserveAttachmentQuota res1 = (%+v, %v), want 1500", res1, err)
	}
	if _, err := chat.ReserveAttachmentQuota(ctx, store.DefaultTenantID, "u_alice", 100, limits, time.Minute); !errors.Is(err, store.ErrAttachmentPendingQuotaExceeded) {
		t.Fatalf("second alice reservation while full = %v, want ErrAttachmentPendingQuotaExceeded", err)
	}
	if err := chat.ReleaseAttachmentQuota(ctx, store.DefaultTenantID, res1.ID); err != nil {
		t.Fatalf("ReleaseAttachmentQuota: %v", err)
	}
	res2, err := chat.ReserveAttachmentQuota(ctx, store.DefaultTenantID, "u_alice", 1500, limits, 5*time.Millisecond)
	if err != nil || res2.ReservedBytes != 1500 {
		t.Fatalf("ReserveAttachmentQuota after release = (%+v, %v)", res2, err)
	}
	// Expired reservation is automatically reclaimed on the next admission check.
	time.Sleep(15 * time.Millisecond)
	res3, err := chat.ReserveAttachmentQuota(ctx, store.DefaultTenantID, "u_alice", 1500, limits, time.Minute)
	if err != nil || res3.ReservedBytes != 1500 {
		t.Fatalf("ReserveAttachmentQuota after expiry = (%+v, %v)", res3, err)
	}
	if err := chat.ReleaseAttachmentQuota(ctx, store.DefaultTenantID, res3.ID); err != nil {
		t.Fatalf("ReleaseAttachmentQuota res3: %v", err)
	}

	// 2. Direct concurrent CommitAttachmentWithQuota calls (even without pre-reservation)
	// must serialize atomically per tenant/uploader and never exceed MaxPendingUserBytes.
	t.Run("concurrent_commit_pending_quota", func(t *testing.T) {
		const (
			workers    = 20
			fileSize   = int64(400)
			pendingCap = int64(1500) // at most 3 * 400 = 1200 bytes
		)
		capLimits := store.AttachmentQuotaLimits{MaxTotalBytes: 100000, MaxPendingUserBytes: pendingCap}
		start := make(chan struct{})
		var accepted atomic.Int64
		var wg sync.WaitGroup
		errs := make(chan error, workers)

		for i := range workers {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				id := fmt.Sprintf("att_pending_%d", idx)
				if err := chat.QueueUploadIntent(ctx, "", id, time.Now().Add(time.Minute).UnixMilli()); err != nil {
					errs <- err
					return
				}
				att := &store.Attachment{
					ID:         id,
					RoomID:     room.ID,
					UploaderID: "u_alice",
					Filename:   fmt.Sprintf("p-%d.bin", idx),
					MimeType:   "application/octet-stream",
					SizeBytes:  fileSize,
					SHA256Hex:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				}
				err := chat.CommitAttachmentWithQuota(ctx, "", att, capLimits)
				if err == nil {
					accepted.Add(1)
				} else if !errors.Is(err, store.ErrAttachmentPendingQuotaExceeded) {
					errs <- err
				}
			}(i)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("unexpected commit error: %v", err)
		}

		used, err := chat.SumPendingAttachmentBytesByUploader(ctx, store.DefaultTenantID, "u_alice")
		if err != nil {
			t.Fatal(err)
		}
		if accepted.Load() != 3 || used != 3*fileSize || used > pendingCap {
			t.Fatalf("accepted=%d used=%d, want 3 uploads (1200 bytes <= %d)", accepted.Load(), used, pendingCap)
		}
	})

	// 3. Multi-user concurrent Reserve + Commit calls must never exceed MaxTotalBytes.
	t.Run("concurrent_multi_user_tenant_quota", func(t *testing.T) {
		const (
			fileSize  = int64(500)
			tenantCap = int64(3200) // alice already holds 1200 -> at most 4 more (2000 bytes)
		)
		capLimits := store.AttachmentQuotaLimits{MaxTotalBytes: tenantCap, MaxPendingUserBytes: 10000}
		users := []string{"u_alice", "u_bob", "u_carol", "u_dave"}
		start := make(chan struct{})
		var accepted atomic.Int64
		var wg sync.WaitGroup
		errs := make(chan error, len(users)*5)

		for _, uid := range users {
			for j := range 5 {
				wg.Add(1)
				go func(uploader string, idx int) {
					defer wg.Done()
					<-start
					res, err := chat.ReserveAttachmentQuota(ctx, store.DefaultTenantID, uploader, fileSize, capLimits, time.Minute)
					if err != nil {
						if !errors.Is(err, store.ErrAttachmentTenantQuotaExceeded) {
							errs <- fmt.Errorf("reserve: %w", err)
						}
						return
					}
					if res.ReservedBytes < fileSize {
						_ = chat.ReleaseAttachmentQuota(ctx, store.DefaultTenantID, res.ID)
						return
					}
					id := fmt.Sprintf("att_%s_%d", uploader, idx)
					if err := chat.QueueUploadIntent(ctx, "", id, time.Now().Add(time.Minute).UnixMilli()); err != nil {
						errs <- err
						return
					}
					att := &store.Attachment{
						ID:         id,
						RoomID:     room.ID,
						UploaderID: uploader,
						Filename:   fmt.Sprintf("t-%s-%d.bin", uploader, idx),
						MimeType:   "application/octet-stream",
						SizeBytes:  fileSize,
						SHA256Hex:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					}
					if err := chat.CommitAttachmentWithQuota(ctx, res.ID, att, capLimits); err != nil {
						_ = chat.ReleaseAttachmentQuota(ctx, store.DefaultTenantID, res.ID)
						if !errors.Is(err, store.ErrAttachmentTenantQuotaExceeded) {
							errs <- fmt.Errorf("commit: %w", err)
						}
						return
					}
					accepted.Add(1)
				}(uid, j)
			}
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("unexpected error: %v", err)
		}

		totalUsed, err := chat.SumAttachmentBytesByTenant(ctx, store.DefaultTenantID)
		if err != nil {
			t.Fatal(err)
		}
		if totalUsed > tenantCap {
			t.Fatalf("tenant totalUsed = %d exceeds cap %d (accepted=%d)", totalUsed, tenantCap, accepted.Load())
		}
		if accepted.Load() != 4 || totalUsed != 1200+4*fileSize {
			t.Fatalf("accepted=%d totalUsed=%d, want 4 new uploads (total 3200)", accepted.Load(), totalUsed)
		}
	})
}

// An edit never writes into a deleted message: deleted before, or concurrently, the row stays a
// tombstone with no body and no kept envelope.
func TestChatStoreEditNeverRevivesATombstone(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()
	room := &store.Room{Kind: store.RoomKindChannel, Name: "tomb", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, nil); err != nil {
		t.Fatal(err)
	}
	post := func(i int) *store.Message {
		m, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{RoomID: room.ID, SenderID: "u_alice", Encoding: store.MessageEncodingE2EERoomV1, Body: fmt.Sprintf("first %d", i)})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	gone := post(0)
	if _, err := chat.DeleteMessage(ctx, "", room.ID, gone.ID, "u_alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := chat.EditMessage(ctx, "", room.ID, gone.ID, "u_alice", "late edit", store.MessageEncodingE2EERoomV1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("edit of a deleted message = %v, want ErrNotFound", err)
	}
	for i := 1; i <= 20; i++ {
		m := post(i)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = chat.DeleteMessage(ctx, "", room.ID, m.ID, "u_alice", false)
		}()
		go func() {
			defer wg.Done()
			if _, err := chat.EditMessage(ctx, "", room.ID, m.ID, "u_alice", "racing edit", store.MessageEncodingE2EERoomV1); err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("racing edit: %v", err)
			}
		}()
		wg.Wait()
	}
	page, _, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: room.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range page {
		if m.DeletedAt == nil || m.Body != "" || m.OriginalBody != "" {
			t.Fatalf("message %s after delete/edit race: deleted=%v body=%q original=%q", m.ID, m.DeletedAt != nil, m.Body, m.OriginalBody)
		}
	}
}

// Every edit moves edited_at forward, even within one millisecond, so clients order versions.
func TestChatStoreEditsAreStrictlyOrdered(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()
	room := &store.Room{Kind: store.RoomKindChannel, Name: "order", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, []string{"u_bob"}); err != nil {
		t.Fatal(err)
	}
	m, _, err := chat.CreateMessage(ctx, store.CreateMessageParams{RoomID: room.ID, SenderID: "u_alice", Encoding: store.MessageEncodingE2EERoomV1, Body: "v0"})
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	for i := 1; i <= 5; i++ {
		e, err := chat.EditMessage(ctx, "", room.ID, m.ID, "u_alice", fmt.Sprintf("v%d", i), store.MessageEncodingE2EERoomV1)
		if err != nil || e.EditedAt == nil || *e.EditedAt <= last {
			t.Fatalf("edit %d: %v, edited_at %v after %d", i, err, e, last)
		}
		last = *e.EditedAt
	}
	if _, err := chat.EditMessage(ctx, "", room.ID, m.ID, "u_bob", "not mine", store.MessageEncodingE2EERoomV1); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("edit by another member = %v, want ErrForbidden", err)
	}
}

// An upload's intent goes with its commit; a sweep that leased it first makes the late commit
// refuse, so no row ever names a blob being erased. Staged removals are queued with the row.
func TestChatStoreUploadIntentsAndQueuedRemovals(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	chat := st.Chat()
	room := &store.Room{Kind: store.RoomKindChannel, Name: "intents", CreatedBy: "u_alice"}
	if err := chat.CreateRoom(ctx, room, nil); err != nil {
		t.Fatal(err)
	}
	att := func(key string) *store.Attachment {
		return &store.Attachment{ID: key, BlobKey: key, RoomID: room.ID, UploaderID: "u_alice", Filename: "encrypted.bin", MimeType: "application/octet-stream", SizeBytes: 10, SHA256Hex: strings.Repeat("a", 64)}
	}
	future := time.Now().Add(time.Hour).UnixMilli()
	past := time.Now().Add(-time.Second).UnixMilli()
	due := func() []string {
		t.Helper()
		refs, err := chat.DuePendingBlobDeletes(ctx, 100, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, r := range refs {
			keys = append(keys, r.Key)
		}
		return keys
	}

	// In flight: not due, and its commit removes it.
	if err := chat.QueueUploadIntent(ctx, "", "att_intent_ok", future); err != nil {
		t.Fatal(err)
	}
	if keys := due(); len(keys) != 0 {
		t.Fatalf("an in-flight intent is due: %v", keys)
	}
	if err := chat.CommitAttachmentWithQuota(ctx, "", att("att_intent_ok"), store.AttachmentQuotaLimits{}); err != nil {
		t.Fatal(err)
	}
	if queued, _ := chat.PendingBlobDeletes(ctx, 100); len(queued) != 0 {
		t.Fatalf("a committed upload is still queued: %v", queued)
	}

	// Crashed past its deadline: due, leased by the sweep, and a late commit refuses.
	if err := chat.QueueUploadIntent(ctx, "", "att_intent_late", past); err != nil {
		t.Fatal(err)
	}
	if keys := due(); len(keys) != 1 || keys[0] != "att_intent_late" {
		t.Fatalf("due = %v, want the late intent", keys)
	}
	if keys := due(); len(keys) != 0 {
		t.Fatalf("a leased intent was handed out twice: %v", keys)
	}
	if err := chat.CommitAttachmentWithQuota(ctx, "", att("att_intent_late"), store.AttachmentQuotaLimits{}); !errors.Is(err, store.ErrAttachmentInvalid) {
		t.Fatalf("late commit = %v, want ErrAttachmentInvalid", err)
	}

	if err := chat.ClearPendingBlobDeletes(ctx, []store.BlobRef{{TenantID: store.DefaultTenantID, Key: "att_intent_late"}}); err != nil {
		t.Fatal(err)
	}
	if err := chat.CommitAttachmentWithQuota(ctx, "", att("att_intent_late"), store.AttachmentQuotaLimits{}); !errors.Is(err, store.ErrAttachmentInvalid) {
		t.Fatalf("commit after completed cleanup = %v, want ErrAttachmentInvalid", err)
	}

	// A staged removal is queued with the row, due at once.
	if err := chat.QueueUploadIntent(ctx, "", "att_staged", future); err != nil {
		t.Fatal(err)
	}
	if err := chat.CommitAttachmentWithQuota(ctx, "", att("att_staged"), store.AttachmentQuotaLimits{}); err != nil {
		t.Fatal(err)
	}
	if key, err := chat.DeleteStagedAttachment(ctx, "", "att_staged", "u_alice"); err != nil || key != "att_staged" {
		t.Fatalf("delete staged = %q %v", key, err)
	}
	if keys := due(); len(keys) != 1 || keys[0] != "att_staged" {
		t.Fatalf("due = %v, want the staged removal", keys)
	}
	if err := chat.ClearPendingBlobDeletes(ctx, []store.BlobRef{{TenantID: store.DefaultTenantID, Key: "att_staged"}}); err != nil {
		t.Fatal(err)
	}
}
