package store_test

import (
	"context"
	"errors"
	"testing"

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
	if _, err := chat.EditMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_bob", "hijack"); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("non-sender EditMessage = %v, want ErrForbidden", err)
	}
	edited, err := chat.EditMessage(ctx, store.DefaultTenantID, room.ID, firstMsg.ID, "u_alice", "edited text")
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

func TestChatStoreSearchAndWebhooks(t *testing.T) {
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

	// Bob only sees plain_v1 messages from roomA, never roomB or e2ee_room_v1.
	hits, err := chat.SearchMessages(ctx, store.DefaultTenantID, "u_bob", "", "invoice", 20)
	if err != nil || len(hits) != 1 || hits[0].RoomID != roomA.ID {
		t.Fatalf("bob search = (%+v, %v), want 1 hit in roomA", hits, err)
	}

	// Wildcard '%' in SQLite LIKE must not match everything.
	pctHits, err := chat.SearchMessages(ctx, store.DefaultTenantID, "u_bob", "", "999%", 20)
	if err != nil || len(pctHits) != 0 {
		t.Fatalf("escaped wildcard search = (%d, %v), want 0", len(pctHits), err)
	}

	// Webhooks CRUD.
	wh := &store.RoomWebhook{
		RoomID:    roomA.ID,
		Name:      "CI Alerts",
		Direction: store.WebhookDirectionIncoming,
		TokenHash: "deadbeef",
		CreatedBy: "u_alice",
	}
	if err := chat.CreateRoomWebhook(ctx, wh); err != nil {
		t.Fatalf("CreateRoomWebhook: %v", err)
	}
	list, err := chat.ListRoomWebhooks(ctx, store.DefaultTenantID, roomA.ID)
	if err != nil || len(list) != 1 || list[0].ID != wh.ID {
		t.Fatalf("ListRoomWebhooks = (%+v, %v)", list, err)
	}
	if err := chat.RevokeRoomWebhook(ctx, store.DefaultTenantID, roomA.ID, wh.ID); err != nil {
		t.Fatalf("RevokeRoomWebhook: %v", err)
	}
	listAfter, err := chat.ListRoomWebhooks(ctx, store.DefaultTenantID, roomA.ID)
	if err != nil || len(listAfter) != 0 {
		t.Fatalf("ListRoomWebhooks after revoke = (%d, %v), want 0", len(listAfter), err)
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

	// ListMessages, GetMessage, EditMessage, and SearchMessages all hydrate attachments.
	listed, _, err := chat.ListMessages(ctx, store.MessagePageQuery{RoomID: roomA.ID, Limit: 10})
	if err != nil || len(listed) != 1 || len(listed[0].Attachments) != 1 {
		t.Fatalf("ListMessages = (%+v, %v)", listed, err)
	}
	fetched, err := chat.GetMessage(ctx, store.DefaultTenantID, roomA.ID, msg.ID)
	if err != nil || len(fetched.Attachments) != 1 {
		t.Fatalf("GetMessage = (%+v, %v)", fetched, err)
	}
	edited, err := chat.EditMessage(ctx, store.DefaultTenantID, roomA.ID, msg.ID, "u_alice", "updated sketch caption")
	if err != nil || len(edited.Attachments) != 1 {
		t.Fatalf("EditMessage = (%+v, %v)", edited, err)
	}
	hits, err := chat.SearchMessages(ctx, store.DefaultTenantID, "u_bob", roomA.ID, "sketch", 10)
	if err != nil || len(hits) != 1 || len(hits[0].Attachments) != 1 {
		t.Fatalf("SearchMessages = (%+v, %v)", hits, err)
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
