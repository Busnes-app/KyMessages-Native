package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

type chatStore struct {
	store *SQLStore
}

func nowMilli() int64 {
	return time.Now().UTC().UnixMilli()
}

func normalizeTenant(tenantID string) string {
	if tenantID == "" {
		return DefaultTenantID
	}
	return tenantID
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func dmPairKey(userA, userB string) string {
	if userA <= userB {
		return userA + "|" + userB
	}
	return userB + "|" + userA
}

// ---------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------

func (c *chatStore) CreateTenant(ctx context.Context, t *Tenant) error {
	if t.ID == "" {
		t.ID = "tnt_" + uuid.Must(uuid.NewV7()).String()
	}
	if t.Plan == "" {
		t.Plan = "business"
	}
	if t.P2PPolicy == "" {
		t.P2PPolicy = P2PPolicyHybrid
	}
	if t.P2PMaxVideo <= 0 {
		t.P2PMaxVideo = 2
	}
	if t.P2PMaxAudio <= 0 {
		t.P2PMaxAudio = 4
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = nowMilli()
	}
	q := c.store.rebind(`
		INSERT INTO tenants (id, slug, display_name, plan, p2p_policy, p2p_max_video, p2p_max_audio, guest_force_sfu, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := c.store.db.ExecContext(ctx, q,
		t.ID, t.Slug, t.DisplayName, t.Plan, t.P2PPolicy,
		t.P2PMaxVideo, t.P2PMaxAudio, boolToInt(t.GuestForceSFU), t.CreatedAt,
	)
	return uniqueError(err)
}

func (c *chatStore) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT id, slug, display_name, plan, p2p_policy, p2p_max_video, p2p_max_audio, guest_force_sfu, created_at
		FROM tenants WHERE id = ?`)
	var t Tenant
	var guestForce int
	err := c.store.read().QueryRowContext(ctx, q, tenantID).Scan(
		&t.ID, &t.Slug, &t.DisplayName, &t.Plan, &t.P2PPolicy,
		&t.P2PMaxVideo, &t.P2PMaxAudio, &guestForce, &t.CreatedAt,
	)
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.GuestForceSFU = guestForce != 0
	return &t, nil
}

// ---------------------------------------------------------------------
// Rooms & Membership
// ---------------------------------------------------------------------

const roomColumns = `id, tenant_id, kind, dm_pair_key, name, topic, is_private, last_seq, closed_at, created_by, created_at`

func scanRoom(row interface{ Scan(...any) error }) (*Room, error) {
	var r Room
	var pairKey sql.NullString
	var isPrivate int
	var closedAt sql.NullInt64
	err := row.Scan(
		&r.ID, &r.TenantID, &r.Kind, &pairKey, &r.Name, &r.Topic,
		&isPrivate, &r.LastSeq, &closedAt, &r.CreatedBy, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.DMPairKey = pairKey.String
	r.IsPrivate = isPrivate != 0
	if closedAt.Valid {
		v := closedAt.Int64
		r.ClosedAt = &v
	}
	return &r, nil
}

func (c *chatStore) CreateRoom(ctx context.Context, r *Room, initialMemberIDs []string) error {
	r.TenantID = normalizeTenant(r.TenantID)
	if r.ID == "" {
		r.ID = "rm_" + uuid.Must(uuid.NewV7()).String()
	}
	if r.Kind == "" {
		r.Kind = RoomKindChannel
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = nowMilli()
	}

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	qRoom := c.store.rebind(`
		INSERT INTO rooms (id, tenant_id, kind, dm_pair_key, name, topic, is_private, last_seq, closed_at, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	var closedAt any
	if r.ClosedAt != nil {
		closedAt = *r.ClosedAt
	}
	if _, err := tx.ExecContext(ctx, qRoom,
		r.ID, r.TenantID, r.Kind, nullString(r.DMPairKey), r.Name, r.Topic,
		boolToInt(r.IsPrivate), r.LastSeq, closedAt, r.CreatedBy, r.CreatedAt,
	); err != nil {
		return uniqueError(err)
	}

	seen := make(map[string]struct{}, len(initialMemberIDs)+1)
	qMember := c.store.rebind(`
		INSERT INTO room_members (tenant_id, room_id, user_id, role, last_read_seq, notify_mode, joined_at)
		VALUES (?, ?, ?, ?, 0, 'all', ?)`)

	if r.CreatedBy != "" {
		seen[r.CreatedBy] = struct{}{}
		role := RoomRoleOwner
		if r.Kind == RoomKindDM {
			role = RoomRoleMember
		}
		if _, err := tx.ExecContext(ctx, qMember, r.TenantID, r.ID, r.CreatedBy, role, r.CreatedAt); err != nil {
			return uniqueError(err)
		}
	}

	for _, uid := range initialMemberIDs {
		if uid == "" {
			continue
		}
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}
		if _, err := tx.ExecContext(ctx, qMember, r.TenantID, r.ID, uid, RoomRoleMember, r.CreatedAt); err != nil {
			return uniqueError(err)
		}
	}

	return tx.Commit()
}

func (c *chatStore) GetOrCreateDM(ctx context.Context, tenantID, userA, userB string) (*Room, bool, error) {
	tenantID = normalizeTenant(tenantID)
	pair := dmPairKey(userA, userB)

	getByPair := func() (*Room, error) {
		q := c.store.rebind(`SELECT ` + roomColumns + ` FROM rooms WHERE tenant_id = ? AND dm_pair_key = ?`)
		r, err := scanRoom(c.store.db.QueryRowContext(ctx, q, tenantID, pair))
		if errorsIs(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return r, err
	}

	if existing, err := getByPair(); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	room := &Room{
		TenantID:  tenantID,
		Kind:      RoomKindDM,
		DMPairKey: pair,
		IsPrivate: true,
		CreatedBy: userA,
		CreatedAt: nowMilli(),
	}
	err := c.CreateRoom(ctx, room, []string{userB})
	if errors.Is(err, ErrAlreadyExists) {
		existing, fetchErr := getByPair()
		if fetchErr != nil {
			return nil, false, fetchErr
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return room, true, nil
}

func (c *chatStore) GetRoom(ctx context.Context, tenantID, roomID string) (*Room, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT ` + roomColumns + ` FROM rooms WHERE tenant_id = ? AND id = ?`)
	r, err := scanRoom(c.store.db.QueryRowContext(ctx, q, tenantID, roomID))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (c *chatStore) ListUserRooms(ctx context.Context, tenantID, userID string) ([]*RoomSummary, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT r.id, r.tenant_id, r.kind, r.dm_pair_key, r.name, r.topic, r.is_private,
		       r.last_seq, r.closed_at, r.created_by, r.created_at,
		       rm.role, rm.last_read_seq, rm.notify_mode
		FROM rooms r
		INNER JOIN room_members rm ON rm.room_id = r.id AND rm.tenant_id = r.tenant_id
		WHERE rm.tenant_id = ? AND rm.user_id = ?
		ORDER BY r.created_at DESC, r.id ASC`)
	// The primary: the list decides which rooms a user sees, so replica lag must not keep
	// a removed member's room in it.
	rows, err := c.store.db.QueryContext(ctx, q, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*RoomSummary, 0)
	for rows.Next() {
		var rs RoomSummary
		var pairKey sql.NullString
		var isPrivate int
		var closedAt sql.NullInt64
		if err := rows.Scan(
			&rs.ID, &rs.TenantID, &rs.Kind, &pairKey, &rs.Name, &rs.Topic, &isPrivate,
			&rs.LastSeq, &closedAt, &rs.CreatedBy, &rs.CreatedAt,
			&rs.Role, &rs.LastReadSeq, &rs.NotifyMode,
		); err != nil {
			return nil, err
		}
		rs.DMPairKey = pairKey.String
		rs.IsPrivate = isPrivate != 0
		if closedAt.Valid {
			v := closedAt.Int64
			rs.ClosedAt = &v
		}
		if rs.LastSeq > rs.LastReadSeq {
			rs.UnreadCount = rs.LastSeq - rs.LastReadSeq
		}
		out = append(out, &rs)
	}
	return out, rows.Err()
}

func (c *chatStore) ListUserRoomIDs(ctx context.Context, tenantID, userID string) ([]string, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT room_id FROM room_members WHERE tenant_id = ? AND user_id = ? ORDER BY room_id`)
	rows, err := c.store.db.QueryContext(ctx, q, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (c *chatStore) UpdateRoom(ctx context.Context, tenantID, roomID, name, topic string) (*Room, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`UPDATE rooms SET name = ?, topic = ? WHERE tenant_id = ? AND id = ?`)
	res, err := c.store.db.ExecContext(ctx, q, name, topic, tenantID, roomID)
	if err := oneRow(res, err); err != nil {
		return nil, err
	}
	return c.GetRoom(ctx, tenantID, roomID)
}

func (c *chatStore) CloseRoom(ctx context.Context, tenantID, roomID string) (*Room, error) {
	tenantID = normalizeTenant(tenantID)
	ts := nowMilli()
	q := c.store.rebind(`UPDATE rooms SET closed_at = COALESCE(closed_at, ?) WHERE tenant_id = ? AND id = ?`)
	res, err := c.store.db.ExecContext(ctx, q, ts, tenantID, roomID)
	if err := oneRow(res, err); err != nil {
		return nil, err
	}
	return c.GetRoom(ctx, tenantID, roomID)
}

func (c *chatStore) AddRoomMember(ctx context.Context, m *RoomMember) error {
	m.TenantID = normalizeTenant(m.TenantID)
	if m.Role == "" {
		m.Role = RoomRoleMember
	}
	if m.NotifyMode == "" {
		m.NotifyMode = "all"
	}
	if m.JoinedAt == 0 {
		m.JoinedAt = nowMilli()
	}
	// Verify room exists in the same tenant before adding member.
	if _, err := c.GetRoom(ctx, m.TenantID, m.RoomID); err != nil {
		return err
	}
	q := c.store.rebind(`
		INSERT INTO room_members (tenant_id, room_id, user_id, role, last_read_seq, notify_mode, joined_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := c.store.db.ExecContext(ctx, q,
		m.TenantID, m.RoomID, m.UserID, m.Role, m.LastReadSeq, m.NotifyMode, m.JoinedAt,
	)
	return uniqueError(err)
}

func (c *chatStore) RemoveRoomMember(ctx context.Context, tenantID, roomID, userID string) (string, error) {
	tenantID = normalizeTenant(tenantID)
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	// Serializes concurrent removals, so two moderators leaving at once cannot both
	// see the other one stay.
	if c.store.driver == "postgres" {
		var id string
		err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT id FROM rooms WHERE tenant_id = ? AND id = ? FOR UPDATE`), tenantID, roomID).Scan(&id)
		if errorsIs(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		if err != nil {
			return "", err
		}
	}
	res, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM room_members WHERE tenant_id = ? AND room_id = ? AND user_id = ?`), tenantID, roomID, userID)
	if err := oneRow(res, err); err != nil {
		return "", err
	}

	// Only active accounts count: a suspended admin cannot moderate.
	var moderators int
	if err := tx.QueryRowContext(ctx, c.store.rebind(`
		SELECT COUNT(*) FROM room_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = ? AND m.room_id = ? AND m.role IN (?, ?) AND u.status = 'active'`),
		tenantID, roomID, RoomRoleOwner, RoomRoleAdmin,
	).Scan(&moderators); err != nil {
		return "", err
	}
	var promoted string
	if moderators == 0 {
		err := tx.QueryRowContext(ctx, c.store.rebind(`
			SELECT m.user_id FROM room_members m JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = ? AND m.room_id = ? AND u.status = 'active'
			ORDER BY m.joined_at, m.user_id LIMIT 1`),
			tenantID, roomID,
		).Scan(&promoted)
		if err != nil && !errorsIs(err, sql.ErrNoRows) {
			return "", err
		}
		if promoted != "" {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				UPDATE room_members SET role = ? WHERE tenant_id = ? AND room_id = ? AND user_id = ?`),
				RoomRoleOwner, tenantID, roomID, promoted,
			); err != nil {
				return "", err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return promoted, nil
}

func (c *chatStore) GetRoomMember(ctx context.Context, tenantID, roomID, userID string) (*RoomMember, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT tenant_id, room_id, user_id, role, last_read_seq, notify_mode, joined_at
		FROM room_members WHERE tenant_id = ? AND room_id = ? AND user_id = ?`)
	var m RoomMember
	err := c.store.db.QueryRowContext(ctx, q, tenantID, roomID, userID).Scan(
		&m.TenantID, &m.RoomID, &m.UserID, &m.Role, &m.LastReadSeq, &m.NotifyMode, &m.JoinedAt,
	)
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *chatStore) ListRoomMembers(ctx context.Context, tenantID, roomID string) ([]*RoomMember, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT tenant_id, room_id, user_id, role, last_read_seq, notify_mode, joined_at
		FROM room_members WHERE tenant_id = ? AND room_id = ?
		ORDER BY joined_at ASC, user_id ASC`)
	rows, err := c.store.read().QueryContext(ctx, q, tenantID, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*RoomMember, 0)
	for rows.Next() {
		var m RoomMember
		if err := rows.Scan(
			&m.TenantID, &m.RoomID, &m.UserID, &m.Role, &m.LastReadSeq, &m.NotifyMode, &m.JoinedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (c *chatStore) UpdateReadCursor(ctx context.Context, tenantID, roomID, userID string, seq int64) (int64, error) {
	tenantID = normalizeTenant(tenantID)
	if seq < 0 {
		seq = 0
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var roomLastSeq int64
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT last_seq FROM rooms WHERE tenant_id = ? AND id = ?`), tenantID, roomID).Scan(&roomLastSeq); err != nil {
		if errorsIs(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if seq > roomLastSeq {
		seq = roomLastSeq
	}

	var currentRead int64
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT last_read_seq FROM room_members WHERE tenant_id = ? AND room_id = ? AND user_id = ?`), tenantID, roomID, userID).Scan(&currentRead); err != nil {
		if errorsIs(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if seq > currentRead {
		q := c.store.rebind(`UPDATE room_members SET last_read_seq = ? WHERE tenant_id = ? AND room_id = ? AND user_id = ?`)
		if _, err := tx.ExecContext(ctx, q, seq, tenantID, roomID, userID); err != nil {
			return 0, err
		}
		currentRead = seq
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return currentRead, nil
}

// ---------------------------------------------------------------------
// Messages & Reactions
// ---------------------------------------------------------------------

const messageColumns = `id, tenant_id, room_id, seq, sender_id, sender_name, reply_to_id, encoding, body, edited_at, deleted_at, idempotency_key, created_at`

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	var m Message
	var replyTo, idemKey sql.NullString
	var editedAt, deletedAt sql.NullInt64
	err := row.Scan(
		&m.ID, &m.TenantID, &m.RoomID, &m.Seq, &m.SenderID, &m.SenderName,
		&replyTo, &m.Encoding, &m.Body, &editedAt, &deletedAt, &idemKey, &m.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	m.ReplyToID = replyTo.String
	m.IdempotencyKey = idemKey.String
	if editedAt.Valid {
		v := editedAt.Int64
		m.EditedAt = &v
	}
	if deletedAt.Valid {
		v := deletedAt.Int64
		m.DeletedAt = &v
	}
	return &m, nil
}

func (c *chatStore) CreateMessage(ctx context.Context, p CreateMessageParams) (*Message, bool, error) {
	tenantID := normalizeTenant(p.TenantID)
	encoding := p.Encoding
	if encoding == "" {
		encoding = MessageEncodingPlainV1
	}
	msgID := p.ID
	if msgID == "" {
		msgID = "msg_" + uuid.Must(uuid.NewV7()).String()
	}

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if !p.SkipMemberCheck {
		var role string
		err := tx.QueryRowContext(ctx,
			c.store.rebind(`SELECT role FROM room_members WHERE tenant_id = ? AND room_id = ? AND user_id = ?`),
			tenantID, p.RoomID, p.SenderID,
		).Scan(&role)
		if errorsIs(err, sql.ErrNoRows) {
			return nil, false, ErrNotFound
		}
		if err != nil {
			return nil, false, err
		}
	}

	roomLockSQL := `SELECT closed_at FROM rooms WHERE tenant_id = ? AND id = ?`
	if c.store.driver == "postgres" {
		roomLockSQL += ` FOR UPDATE`
	}
	var closedAt sql.NullInt64
	if err := tx.QueryRowContext(ctx, c.store.rebind(roomLockSQL), tenantID, p.RoomID).Scan(&closedAt); err != nil {
		if errorsIs(err, sql.ErrNoRows) {
			return nil, false, ErrNotFound
		}
		return nil, false, err
	}
	if closedAt.Valid {
		return nil, false, ErrRoomClosed
	}

	// Idempotency deduplication before incrementing room sequence number.
	if p.IdempotencyKey != "" {
		existing, err := scanMessage(tx.QueryRowContext(ctx,
			c.store.rebind(`SELECT `+messageColumns+` FROM messages WHERE tenant_id = ? AND room_id = ? AND sender_id = ? AND idempotency_key = ?`),
			tenantID, p.RoomID, p.SenderID, p.IdempotencyKey,
		))
		if err == nil {
			if err := c.attachReactions(ctx, tx, []*Message{existing}); err != nil {
				return nil, false, err
			}
			if err := c.attachAttachments(ctx, tx, []*Message{existing}); err != nil {
				return nil, false, err
			}
			return existing, false, nil
		}
		if !errorsIs(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}

	if p.ReplyToID != "" {
		var one int
		err := tx.QueryRowContext(ctx,
			c.store.rebind(`SELECT 1 FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`),
			tenantID, p.RoomID, p.ReplyToID,
		).Scan(&one)
		if errorsIs(err, sql.ErrNoRows) {
			return nil, false, ErrReplyNotFound
		}
		if err != nil {
			return nil, false, err
		}
	}

	// Deduplicate requested attachment IDs while preserving order.
	attIDs := make([]string, 0, len(p.AttachmentIDs))
	seenAtt := make(map[string]struct{}, len(p.AttachmentIDs))
	for _, rawID := range p.AttachmentIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, dup := seenAtt[id]; dup {
			continue
		}
		seenAtt[id] = struct{}{}
		attIDs = append(attIDs, id)
	}

	var seq int64
	if err := tx.QueryRowContext(ctx,
		c.store.rebind(`UPDATE rooms SET last_seq = last_seq + 1 WHERE tenant_id = ? AND id = ? RETURNING last_seq`),
		tenantID, p.RoomID,
	).Scan(&seq); err != nil {
		return nil, false, err
	}

	createdAt := nowMilli()
	qInsert := c.store.rebind(`
		INSERT INTO messages (id, tenant_id, room_id, seq, sender_id, sender_name, reply_to_id, encoding, body, idempotency_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, qInsert,
		msgID, tenantID, p.RoomID, seq, p.SenderID, p.SenderName,
		nullString(p.ReplyToID), encoding, p.Body, nullString(p.IdempotencyKey), createdAt,
	); err != nil {
		return nil, false, uniqueError(err)
	}

	var linkedAttachments []Attachment
	if len(attIDs) > 0 {
		qLink := c.store.rebind(`
			UPDATE attachments
			SET message_id = ?
			WHERE tenant_id = ? AND room_id = ? AND uploader_id = ? AND message_id IS NULL AND id = ?`)
		qFetch := c.store.rebind(`SELECT ` + attachmentColumns + ` FROM attachments WHERE tenant_id = ? AND id = ?`)
		linkedAttachments = make([]Attachment, 0, len(attIDs))
		for _, attID := range attIDs {
			res, err := tx.ExecContext(ctx, qLink, msgID, tenantID, p.RoomID, p.SenderID, attID)
			if err != nil {
				return nil, false, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return nil, false, err
			}
			if n != 1 {
				return nil, false, ErrAttachmentInvalid
			}
			att, err := scanAttachment(tx.QueryRowContext(ctx, qFetch, tenantID, attID))
			if err != nil {
				return nil, false, err
			}
			linkedAttachments = append(linkedAttachments, *att)
		}
	}

	// Advance sender's own read cursor to the message they just sent.
	if !p.SkipMemberCheck {
		_, _ = tx.ExecContext(ctx,
			c.store.rebind(`UPDATE room_members SET last_read_seq = CASE WHEN last_read_seq < ? THEN ? ELSE last_read_seq END WHERE tenant_id = ? AND room_id = ? AND user_id = ?`),
			seq, seq, tenantID, p.RoomID, p.SenderID,
		)
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	return &Message{
		ID:             msgID,
		TenantID:       tenantID,
		RoomID:         p.RoomID,
		Seq:            seq,
		SenderID:       p.SenderID,
		SenderName:     p.SenderName,
		ReplyToID:      p.ReplyToID,
		Encoding:       encoding,
		Body:           p.Body,
		IdempotencyKey: p.IdempotencyKey,
		CreatedAt:      createdAt,
		Attachments:    linkedAttachments,
	}, true, nil
}

func (c *chatStore) GetMessage(ctx context.Context, tenantID, roomID, messageID string) (*Message, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT ` + messageColumns + ` FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`)
	m, err := scanMessage(c.store.db.QueryRowContext(ctx, q, tenantID, roomID, messageID))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := c.attachReactions(ctx, c.store.db, []*Message{m}); err != nil {
		return nil, err
	}
	if err := c.attachAttachments(ctx, c.store.db, []*Message{m}); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *chatStore) ListMessages(ctx context.Context, q MessagePageQuery) ([]*Message, bool, error) {
	tenantID := normalizeTenant(q.TenantID)
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	fetchLimit := limit + 1

	var (
		db      *sql.DB
		sqlText string
		args    []any
		reverse bool
	)

	switch {
	case q.AfterSeq > 0:
		// Live reconnect catch-up hits the primary so replica lag never misses a just-notified message.
		db = c.store.db
		sqlText = `SELECT ` + messageColumns + ` FROM messages WHERE tenant_id = ? AND room_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?`
		args = []any{tenantID, q.RoomID, q.AfterSeq, fetchLimit}
	case q.BeforeSeq > 0:
		// Historical scrollback hits the read replica when configured.
		db = c.store.read()
		sqlText = `SELECT ` + messageColumns + ` FROM messages WHERE tenant_id = ? AND room_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?`
		args = []any{tenantID, q.RoomID, q.BeforeSeq, fetchLimit}
		reverse = true
	default:
		db = c.store.read()
		sqlText = `SELECT ` + messageColumns + ` FROM messages WHERE tenant_id = ? AND room_id = ? ORDER BY seq DESC LIMIT ?`
		args = []any{tenantID, q.RoomID, fetchLimit}
		reverse = true
	}

	rows, err := db.QueryContext(ctx, c.store.rebind(sqlText), args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	msgs := make([]*Message, 0, limit)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, false, err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(msgs) > limit
	if hasMore {
		msgs = msgs[:limit]
	}
	if reverse {
		slices.Reverse(msgs)
	}

	if err := c.attachReactions(ctx, db, msgs); err != nil {
		return nil, false, err
	}
	if err := c.attachAttachments(ctx, db, msgs); err != nil {
		return nil, false, err
	}
	return msgs, hasMore, nil
}

func (c *chatStore) EditMessage(ctx context.Context, tenantID, roomID, messageID, actorID, newBody string) (*Message, error) {
	tenantID = normalizeTenant(tenantID)
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	m, err := scanMessage(tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT `+messageColumns+` FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		tenantID, roomID, messageID,
	))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if m.SenderID != actorID {
		return nil, ErrForbidden
	}
	if m.DeletedAt != nil {
		return nil, ErrNotFound
	}

	editedAt := nowMilli()
	if _, err := tx.ExecContext(ctx,
		c.store.rebind(`UPDATE messages SET body = ?, edited_at = ? WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		newBody, editedAt, tenantID, roomID, messageID,
	); err != nil {
		return nil, err
	}
	if err := c.attachReactions(ctx, tx, []*Message{m}); err != nil {
		return nil, err
	}
	if err := c.attachAttachments(ctx, tx, []*Message{m}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	m.Body = newBody
	m.EditedAt = &editedAt
	return m, nil
}

func (c *chatStore) DeleteMessage(ctx context.Context, tenantID, roomID, messageID, actorID string, allowModerator bool) (*Message, error) {
	tenantID = normalizeTenant(tenantID)
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	m, err := scanMessage(tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT `+messageColumns+` FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		tenantID, roomID, messageID,
	))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if m.SenderID != actorID && !allowModerator {
		return nil, ErrForbidden
	}

	deletedAt := nowMilli()
	if m.DeletedAt != nil {
		deletedAt = *m.DeletedAt
	} else {
		if _, err := tx.ExecContext(ctx,
			c.store.rebind(`UPDATE messages SET body = '', deleted_at = ? WHERE tenant_id = ? AND room_id = ? AND id = ?`),
			deletedAt, tenantID, roomID, messageID,
		); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			c.store.rebind(`DELETE FROM attachments WHERE tenant_id = ? AND room_id = ? AND message_id = ?`),
			tenantID, roomID, messageID,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	m.Body = ""
	m.DeletedAt = &deletedAt
	m.Attachments = nil
	return m, nil
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (c *chatStore) SearchMessages(ctx context.Context, tenantID, userID, roomID, query string, limit int) ([]*Message, error) {
	tenantID = normalizeTenant(tenantID)
	query = strings.TrimSpace(query)
	if query == "" {
		return []*Message{}, nil
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 50 {
		limit = 50
	}

	// Membership comes from the primary; only the text search runs on the replica, so
	// replica lag never extends a removed member's access.
	rooms, err := c.ListUserRoomIDs(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if roomID != "" {
		if !slices.Contains(rooms, roomID) {
			return []*Message{}, nil
		}
		rooms = []string{roomID}
	}
	if len(rooms) == 0 {
		return []*Message{}, nil
	}

	var sqlText string
	args := []any{tenantID, MessageEncodingPlainV1}
	for _, id := range rooms {
		args = append(args, id)
	}
	baseSelect := `
		SELECT m.id, m.tenant_id, m.room_id, m.seq, m.sender_id, m.sender_name,
		       m.reply_to_id, m.encoding, m.body, m.edited_at, m.deleted_at, m.idempotency_key, m.created_at
		FROM messages m
		WHERE m.tenant_id = ? AND m.encoding = ? AND m.deleted_at IS NULL
		  AND m.room_id IN (?` + strings.Repeat(", ?", len(rooms)-1) + `)`

	if c.store.driver == "postgres" {
		sqlText = baseSelect + ` AND to_tsvector('simple', m.body) @@ plainto_tsquery('simple', ?) ORDER BY m.created_at DESC LIMIT ?`
		args = append(args, query, limit)
	} else {
		sqlText = baseSelect + ` AND LOWER(m.body) LIKE LOWER(?) ESCAPE '\' ORDER BY m.created_at DESC LIMIT ?`
		args = append(args, "%"+escapeLike(query)+"%", limit)
	}

	readDB := c.store.read()
	rows, err := readDB.QueryContext(ctx, c.store.rebind(sqlText), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*Message, 0)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := c.attachAttachments(ctx, readDB, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chatStore) AddReaction(ctx context.Context, tenantID, roomID, messageID, userID, emoji string) error {
	tenantID = normalizeTenant(tenantID)
	// Confirm message exists in this room & tenant and isn't deleted.
	var deletedAt sql.NullInt64
	err := c.store.db.QueryRowContext(ctx,
		c.store.rebind(`SELECT deleted_at FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		tenantID, roomID, messageID,
	).Scan(&deletedAt)
	if errorsIs(err, sql.ErrNoRows) || deletedAt.Valid {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	q := c.store.rebind(`
		INSERT INTO message_reactions (message_id, user_id, emoji, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (message_id, user_id, emoji) DO NOTHING`)
	_, err = c.store.db.ExecContext(ctx, q, messageID, userID, emoji, nowMilli())
	return err
}

func (c *chatStore) RemoveReaction(ctx context.Context, tenantID, roomID, messageID, userID, emoji string) error {
	tenantID = normalizeTenant(tenantID)
	// Verify message belongs to room & tenant.
	var exists int
	if err := c.store.db.QueryRowContext(ctx,
		c.store.rebind(`SELECT 1 FROM messages WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		tenantID, roomID, messageID,
	).Scan(&exists); err != nil {
		if errorsIs(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	q := c.store.rebind(`DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?`)
	_, err := c.store.db.ExecContext(ctx, q, messageID, userID, emoji)
	return err
}

type rowQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (c *chatStore) attachReactions(ctx context.Context, db rowQueryer, msgs []*Message) error {
	if len(msgs) == 0 {
		return nil
	}
	byID := make(map[string]*Message, len(msgs))
	placeholders := make([]string, len(msgs))
	args := make([]any, len(msgs))
	for i, m := range msgs {
		byID[m.ID] = m
		placeholders[i] = "?"
		args[i] = m.ID
	}

	sqlText := fmt.Sprintf(
		`SELECT message_id, emoji, user_id FROM message_reactions WHERE message_id IN (%s) ORDER BY created_at ASC`,
		strings.Join(placeholders, ","),
	)
	rows, err := db.QueryContext(ctx, c.store.rebind(sqlText), args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	// message_id -> emoji -> ordered userIDs
	type emojiEntry struct {
		emoji string
		users []string
	}
	grouped := make(map[string][]*emojiEntry, len(msgs))
	index := make(map[string]map[string]*emojiEntry, len(msgs))

	for rows.Next() {
		var msgID, emoji, userID string
		if err := rows.Scan(&msgID, &emoji, &userID); err != nil {
			return err
		}
		mIdx := index[msgID]
		if mIdx == nil {
			mIdx = make(map[string]*emojiEntry)
			index[msgID] = mIdx
		}
		entry := mIdx[emoji]
		if entry == nil {
			entry = &emojiEntry{emoji: emoji}
			mIdx[emoji] = entry
			grouped[msgID] = append(grouped[msgID], entry)
		}
		entry.users = append(entry.users, userID)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for msgID, entries := range grouped {
		m := byID[msgID]
		m.Reactions = make([]ReactionSummary, 0, len(entries))
		for _, e := range entries {
			m.Reactions = append(m.Reactions, ReactionSummary{
				Emoji:   e.emoji,
				UserIDs: e.users,
				Count:   len(e.users),
			})
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------

const attachmentColumns = `id, tenant_id, room_id, message_id, uploader_id, blob_key, filename, mime_type, size_bytes, sha256_hex, created_at`

func scanAttachment(row interface{ Scan(...any) error }) (*Attachment, error) {
	var (
		a     Attachment
		msgID sql.NullString
	)
	if err := row.Scan(
		&a.ID, &a.TenantID, &a.RoomID, &msgID, &a.UploaderID,
		&a.BlobKey, &a.Filename, &a.MimeType, &a.SizeBytes, &a.SHA256Hex, &a.CreatedAt,
	); err != nil {
		return nil, err
	}
	a.MessageID = msgID.String
	return &a, nil
}

func (c *chatStore) CreateAttachment(ctx context.Context, a *Attachment) error {
	a.TenantID = normalizeTenant(a.TenantID)
	if a.ID == "" {
		a.ID = "att_" + uuid.Must(uuid.NewV7()).String()
	}
	if a.BlobKey == "" {
		a.BlobKey = a.ID
	}
	if a.CreatedAt == 0 {
		a.CreatedAt = nowMilli()
	}
	q := c.store.rebind(`
		INSERT INTO attachments (id, tenant_id, room_id, message_id, uploader_id, blob_key, filename, mime_type, size_bytes, sha256_hex, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := c.store.db.ExecContext(ctx, q,
		a.ID, a.TenantID, a.RoomID, nullString(a.MessageID), a.UploaderID,
		a.BlobKey, a.Filename, a.MimeType, a.SizeBytes, a.SHA256Hex, a.CreatedAt,
	)
	return uniqueError(err)
}

func (c *chatStore) GetAttachment(ctx context.Context, tenantID, attachmentID string) (*Attachment, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT ` + attachmentColumns + ` FROM attachments WHERE tenant_id = ? AND id = ?`)
	a, err := scanAttachment(c.store.db.QueryRowContext(ctx, q, tenantID, attachmentID))
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (c *chatStore) ListMessageAttachments(ctx context.Context, tenantID, roomID, messageID string) ([]Attachment, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT ` + attachmentColumns + ` FROM attachments WHERE tenant_id = ? AND room_id = ? AND message_id = ? ORDER BY created_at ASC, id ASC`)
	rows, err := c.store.db.QueryContext(ctx, q, tenantID, roomID, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Attachment, 0)
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (c *chatStore) DeleteAttachment(ctx context.Context, tenantID, attachmentID string) error {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`DELETE FROM attachments WHERE tenant_id = ? AND id = ?`)
	_, err := c.store.db.ExecContext(ctx, q, tenantID, attachmentID)
	return err
}

func (c *chatStore) attachAttachments(ctx context.Context, db rowQueryer, msgs []*Message) error {
	if len(msgs) == 0 {
		return nil
	}
	byID := make(map[string]*Message, len(msgs))
	placeholders := make([]string, len(msgs))
	args := make([]any, len(msgs))
	for i, m := range msgs {
		byID[m.ID] = m
		placeholders[i] = "?"
		args[i] = m.ID
	}

	sqlText := fmt.Sprintf(
		`SELECT `+attachmentColumns+` FROM attachments WHERE message_id IN (%s) ORDER BY created_at ASC, id ASC`,
		strings.Join(placeholders, ","),
	)
	rows, err := db.QueryContext(ctx, c.store.rebind(sqlText), args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return err
		}
		if m := byID[a.MessageID]; m != nil {
			m.Attachments = append(m.Attachments, *a)
		}
	}
	return rows.Err()
}

// ---------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------

func (c *chatStore) CreateRoomWebhook(ctx context.Context, w *RoomWebhook) error {
	w.TenantID = normalizeTenant(w.TenantID)
	if w.ID == "" {
		w.ID = "wh_" + uuid.Must(uuid.NewV7()).String()
	}
	if w.Direction == "" {
		w.Direction = WebhookDirectionIncoming
	}
	if w.CreatedAt == 0 {
		w.CreatedAt = nowMilli()
	}
	q := c.store.rebind(`
		INSERT INTO room_webhooks (id, tenant_id, room_id, name, direction, token_hash, target_url, created_by, revoked_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	var revokedAt any
	if w.RevokedAt != nil {
		revokedAt = *w.RevokedAt
	}
	_, err := c.store.db.ExecContext(ctx, q,
		w.ID, w.TenantID, w.RoomID, w.Name, w.Direction, w.TokenHash,
		nullString(w.TargetURL), w.CreatedBy, revokedAt, w.CreatedAt,
	)
	return uniqueError(err)
}

func (c *chatStore) GetRoomWebhook(ctx context.Context, webhookID string) (*RoomWebhook, error) {
	q := c.store.rebind(`
		SELECT id, tenant_id, room_id, name, direction, token_hash, target_url, created_by, revoked_at, created_at
		FROM room_webhooks WHERE id = ?`)
	var w RoomWebhook
	var targetURL sql.NullString
	var revokedAt sql.NullInt64
	err := c.store.db.QueryRowContext(ctx, q, webhookID).Scan(
		&w.ID, &w.TenantID, &w.RoomID, &w.Name, &w.Direction, &w.TokenHash,
		&targetURL, &w.CreatedBy, &revokedAt, &w.CreatedAt,
	)
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	w.TargetURL = targetURL.String
	if revokedAt.Valid {
		v := revokedAt.Int64
		w.RevokedAt = &v
	}
	return &w, nil
}

func (c *chatStore) ListRoomWebhooks(ctx context.Context, tenantID, roomID string) ([]*RoomWebhook, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT id, tenant_id, room_id, name, direction, token_hash, target_url, created_by, revoked_at, created_at
		FROM room_webhooks WHERE tenant_id = ? AND room_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC, id ASC`)
	rows, err := c.store.read().QueryContext(ctx, q, tenantID, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*RoomWebhook, 0)
	for rows.Next() {
		var w RoomWebhook
		var targetURL sql.NullString
		var revokedAt sql.NullInt64
		if err := rows.Scan(
			&w.ID, &w.TenantID, &w.RoomID, &w.Name, &w.Direction, &w.TokenHash,
			&targetURL, &w.CreatedBy, &revokedAt, &w.CreatedAt,
		); err != nil {
			return nil, err
		}
		w.TargetURL = targetURL.String
		if revokedAt.Valid {
			v := revokedAt.Int64
			w.RevokedAt = &v
		}
		out = append(out, &w)
	}
	return out, rows.Err()
}

func (c *chatStore) RevokeRoomWebhook(ctx context.Context, tenantID, roomID, webhookID string) error {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		UPDATE room_webhooks SET revoked_at = COALESCE(revoked_at, ?)
		WHERE tenant_id = ? AND room_id = ? AND id = ? AND revoked_at IS NULL`)
	res, err := c.store.db.ExecContext(ctx, q, nowMilli(), tenantID, roomID, webhookID)
	return oneRow(res, err)
}
