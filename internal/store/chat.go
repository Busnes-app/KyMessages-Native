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
	if t.Status == "" {
		t.Status = TenantStatusActive
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
		INSERT INTO tenants (id, slug, display_name, plan, status, p2p_policy, p2p_max_video, p2p_max_audio, guest_force_sfu, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := c.store.db.ExecContext(ctx, q,
		t.ID, t.Slug, t.DisplayName, t.Plan, t.Status, t.P2PPolicy,
		t.P2PMaxVideo, t.P2PMaxAudio, boolToInt(t.GuestForceSFU), t.CreatedAt,
	)
	return uniqueError(err)
}

// EnsureTenant idempotently provisions a tenant row for a verified org_id and returns it.
func (c *chatStore) EnsureTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant id is required")
	}
	if existing, err := c.GetTenant(ctx, tenantID); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	t := &Tenant{
		ID:          tenantID,
		Slug:        tenantID,
		DisplayName: tenantID,
		Plan:        "business",
		Status:      TenantStatusActive,
		P2PPolicy:   P2PPolicyHybrid,
		P2PMaxVideo: 2,
		P2PMaxAudio: 4,
		CreatedAt:   nowMilli(),
	}
	if err := c.CreateTenant(ctx, t); err != nil && !errors.Is(err, ErrAlreadyExists) {
		return nil, err
	}
	return c.GetTenant(ctx, tenantID)
}

func (c *chatStore) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`
		SELECT id, slug, display_name, plan,
 CASE WHEN status = 'active' AND (EXISTS (SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id = tenants.id) OR (EXISTS (SELECT 1 FROM server_settings WHERE key = 'tenancy.mode' AND value = 'multi') AND NOT ` + directoryReadySQL + `)) THEN 'suspended' ELSE status END,
 p2p_policy, p2p_max_video, p2p_max_audio, guest_force_sfu, created_at, ` + directoryReadySQL + `
		FROM tenants WHERE id = ?`)
	var t Tenant
	var guestForce int
	// Tenant status gates access, so it is read from the primary, never a lagging replica.
	err := c.store.db.QueryRowContext(ctx, q, tenantID).Scan(
		&t.ID, &t.Slug, &t.DisplayName, &t.Plan, &t.Status, &t.P2PPolicy,
		&t.P2PMaxVideo, &t.P2PMaxAudio, &guestForce, &t.CreatedAt, &t.DirectoryReady,
	)
	if errorsIs(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.Status == "" {
		t.Status = TenantStatusActive
	}
	t.GuestForceSFU = guestForce != 0
	return &t, nil
}

func (c *chatStore) SetTenantStatus(ctx context.Context, tenantID, status string) error {
	tenantID = strings.TrimSpace(tenantID)
	switch status {
	case TenantStatusActive, TenantStatusSuspended, TenantStatusDeleted:
	default:
		return fmt.Errorf("invalid tenant status %q", status)
	}
	q := c.store.rebind(`UPDATE tenants SET status = ? WHERE id = ?`)
	return oneRow(c.store.db.ExecContext(ctx, q, status, tenantID))
}

// HoldsSingleTenantData reports whether the database already serves single-tenant use: any room,
// or any org-less account other than a local password one (directory-synced, SSO or bot). Local
// accounts are the bootstrap and recovery operators every fresh database has.
func (c *chatStore) HoldsSingleTenantData(ctx context.Context) (bool, error) {
	var one int
	err := c.store.db.QueryRowContext(ctx, `
		SELECT 1 WHERE EXISTS (SELECT 1 FROM rooms)
		   OR EXISTS (SELECT 1 FROM users WHERE org_id = '' AND sso_provider <> 'local')`).Scan(&one)
	if errorsIs(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (c *chatStore) OrgIDs(ctx context.Context) ([]string, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`
		SELECT org_id FROM users WHERE org_id <> ''
		UNION SELECT id FROM tenants WHERE id <> ?`), DefaultTenantID)
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

// ApplyTenantLifecycle sets an org's status from a KyIdentity lifecycle event carrying the org's
// revision. Only a revision above the last applied one changes status, so a delayed event never
// undoes a newer one; deletion applies whatever its revision and is never undone. It reports
// whether the status changed.
func (c *chatStore) ApplyTenantLifecycle(ctx context.Context, tenantID, status string, revision int64) (bool, error) {
	var q string
	var args []any
	switch status {
	case TenantStatusActive, TenantStatusSuspended:
		q = `UPDATE tenants SET status = ?, lifecycle_revision = ?, missing_since = NULL WHERE id = ? AND lifecycle_revision < ? AND status <> ?`
		args = []any{status, revision, strings.TrimSpace(tenantID), revision, TenantStatusDeleted}
	case TenantStatusDeleted:
		q = `UPDATE tenants SET status = ?, lifecycle_revision = CASE WHEN lifecycle_revision < ? THEN ? ELSE lifecycle_revision END, missing_since = NULL WHERE id = ? AND status <> ?`
		args = []any{status, revision, revision, strings.TrimSpace(tenantID), TenantStatusDeleted}
	default:
		return false, fmt.Errorf("invalid tenant status %q", status)
	}
	res, err := c.store.db.ExecContext(ctx, c.store.rebind(q), args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
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
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.tenant_id=? AND call_seats.room_id=? AND call_seats.user_id=?`, tenantID, roomID, userID); err != nil {
		return "", err
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

func (c *chatStore) MessageStates(ctx context.Context, tenantID, userID string, ids []string) ([]MessageState, error) {
	out := []MessageState{}
	if len(ids) == 0 {
		return out, nil
	}
	tenantID = normalizeTenant(tenantID)
	args := []any{tenantID, userID}
	for _, id := range ids {
		args = append(args, id)
	}
	q := c.store.rebind(`SELECT m.id, m.room_id, m.deleted_at, m.edited_at FROM messages m
		JOIN room_members rm ON rm.tenant_id = m.tenant_id AND rm.room_id = m.room_id
		WHERE m.tenant_id = ? AND rm.user_id = ? AND m.id IN (?` + strings.Repeat(", ?", len(ids)-1) + `)`)
	rows, err := c.store.db.QueryContext(ctx, q, args...) // the primary: a lagging replica could vouch for a deleted message
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s MessageState
		var deleted, edited sql.NullInt64
		if err := rows.Scan(&s.ID, &s.RoomID, &deleted, &edited); err != nil {
			return nil, err
		}
		s.Deleted, s.EditedAt = deleted.Valid, edited.Int64
		out = append(out, s)
	}
	return out, rows.Err()
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

// EditMessage replaces the sender's message body. An edit may change the encoding: a message
// sent before encryption is edited into an e2ee_room_v1 envelope.
func (c *chatStore) EditMessage(ctx context.Context, tenantID, roomID, messageID, actorID, newBody, encoding string) (*Message, error) {
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
		c.store.rebind(`UPDATE messages SET body = ?, encoding = ?, edited_at = ? WHERE tenant_id = ? AND room_id = ? AND id = ?`),
		newBody, encoding, editedAt, tenantID, roomID, messageID,
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
	m.Encoding = encoding
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
	return c.listAttachments(ctx, `message_id = ?`, normalizeTenant(tenantID), roomID, messageID)
}

// ListStagedAttachments lists uploaderID's unposted uploads in roomID, oldest first.
func (c *chatStore) ListStagedAttachments(ctx context.Context, tenantID, roomID, uploaderID string) ([]Attachment, error) {
	return c.listAttachments(ctx, `message_id IS NULL AND uploader_id = ?`, normalizeTenant(tenantID), roomID, uploaderID)
}

func (c *chatStore) listAttachments(ctx context.Context, where, tenantID, roomID, arg string) ([]Attachment, error) {
	q := c.store.rebind(`SELECT ` + attachmentColumns + ` FROM attachments WHERE tenant_id = ? AND room_id = ? AND ` + where + ` ORDER BY created_at ASC, id ASC`)
	rows, err := c.store.db.QueryContext(ctx, q, tenantID, roomID, arg)
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

func (c *chatStore) DeleteStagedAttachment(ctx context.Context, tenantID, attachmentID, uploaderID string) (string, error) {
	tenantID = normalizeTenant(tenantID)
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var msgID sql.NullString
	var owner, blobKey string
	selQ := c.store.rebind(`SELECT message_id, uploader_id, blob_key FROM attachments WHERE tenant_id = ? AND id = ?`)
	if err := tx.QueryRowContext(ctx, selQ, tenantID, attachmentID).Scan(&msgID, &owner, &blobKey); err != nil {
		if errorsIs(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if owner != uploaderID {
		return "", ErrNotFound
	}
	if msgID.Valid && msgID.String != "" {
		return "", ErrAttachmentInvalid
	}

	delQ := c.store.rebind(`DELETE FROM attachments WHERE tenant_id = ? AND id = ? AND uploader_id = ? AND message_id IS NULL`)
	res, err := tx.ExecContext(ctx, delQ, tenantID, attachmentID, uploaderID)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrAttachmentInvalid
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return blobKey, nil
}

func (c *chatStore) lockAttachmentQuotaTx(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if c.store.driver == "postgres" {
		// Transaction-scoped advisory lock isolates quota admission per schema and tenant
		// across all connections and replicas, releasing automatically on commit or rollback.
		_, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext('kymessages:attachment-quota:' || current_schema()), hashtext($1))`,
			tenantID,
		)
		return err
	}
	// Acquire SQLite's writer before any quota reads. Deferred read-to-write upgrades from
	// separate replica connections otherwise fail immediately with SQLITE_BUSY.
	_, err := tx.ExecContext(ctx, `UPDATE tenants SET id = id WHERE id = ?`, tenantID)
	return err
}

func (c *chatStore) attachmentQuotaUsageTx(ctx context.Context, tx *sql.Tx, tenantID, uploaderID string, nowMs int64) (tenantUsed, pendingUsed int64, err error) {
	pruneQ := c.store.rebind(`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND expires_at <= ?`)
	if _, err := tx.ExecContext(ctx, pruneQ, tenantID, nowMs); err != nil {
		return 0, 0, err
	}

	var tenantAtts, tenantRes, pendingAtts, pendingRes int64
	if err := tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM attachments WHERE tenant_id = ?`),
		tenantID,
	).Scan(&tenantAtts); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT COALESCE(SUM(reserved_bytes), 0) FROM attachment_upload_reservations WHERE tenant_id = ?`),
		tenantID,
	).Scan(&tenantRes); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM attachments WHERE tenant_id = ? AND uploader_id = ? AND message_id IS NULL`),
		tenantID, uploaderID,
	).Scan(&pendingAtts); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRowContext(ctx,
		c.store.rebind(`SELECT COALESCE(SUM(reserved_bytes), 0) FROM attachment_upload_reservations WHERE tenant_id = ? AND uploader_id = ?`),
		tenantID, uploaderID,
	).Scan(&pendingRes); err != nil {
		return 0, 0, err
	}
	return tenantAtts + tenantRes, pendingAtts + pendingRes, nil
}

func (c *chatStore) ReserveAttachmentQuota(ctx context.Context, tenantID, uploaderID string, requestedBytes int64, limits AttachmentQuotaLimits, ttl time.Duration) (*AttachmentQuotaReservation, error) {
	tenantID = normalizeTenant(tenantID)
	if requestedBytes <= 0 {
		return nil, fmt.Errorf("requestedBytes must be positive")
	}
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	if limits.ActiveUploader {
		limits, err = c.directoryQuotaTx(ctx, tx, tenantID, limits)
		if err != nil {
			return nil, err
		}
		if limits.MaxUploadBytes > 0 {
			requestedBytes = min(requestedBytes, limits.MaxUploadBytes)
		}
	}
	now := nowMilli()
	tenantUsed, pendingUsed, err := c.attachmentQuotaUsageTx(ctx, tx, tenantID, uploaderID, now)
	if err != nil {
		return nil, err
	}

	granted := requestedBytes
	limiting := AttachmentQuotaLimitUpload

	if limits.MaxTotalBytes > 0 {
		totalRem := limits.MaxTotalBytes - tenantUsed
		if totalRem <= 0 {
			return nil, ErrAttachmentTenantQuotaExceeded
		}
		if totalRem < granted {
			granted = totalRem
			limiting = AttachmentQuotaLimitTenant
		}
	}
	if limits.MaxPendingUserBytes > 0 {
		pendingRem := limits.MaxPendingUserBytes - pendingUsed
		if pendingRem <= 0 {
			return nil, ErrAttachmentPendingQuotaExceeded
		}
		if pendingRem < granted {
			granted = pendingRem
			limiting = AttachmentQuotaLimitPending
		}
	}
	if limits.Pool {
		ceiling, err := c.poolCeilingTx(ctx, tx, tenantID, now)
		if err != nil {
			return nil, err
		}
		poolRem := ceiling - tenantUsed
		if poolRem <= 0 {
			return nil, ErrPoolFull
		}
		if poolRem < granted {
			granted = poolRem
			limiting = AttachmentQuotaLimitPool
		}
	}

	resID := "res_" + uuid.Must(uuid.NewV7()).String()
	insQ := c.store.rebind(`
		INSERT INTO attachment_upload_reservations (id, tenant_id, uploader_id, reserved_bytes, expires_at)
		VALUES (?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insQ, resID, tenantID, uploaderID, granted, now+ttl.Milliseconds()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &AttachmentQuotaReservation{
		ID:            resID,
		ReservedBytes: granted,
		LimitingKind:  limiting,
	}, nil
}

func (c *chatStore) ReleaseAttachmentQuota(ctx context.Context, tenantID, reservationID string) error {
	if reservationID == "" {
		return nil
	}
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND id = ?`)
	_, err := c.store.db.ExecContext(ctx, q, tenantID, reservationID)
	return err
}

func (c *chatStore) CommitAttachmentWithQuota(ctx context.Context, reservationID string, a *Attachment, limits AttachmentQuotaLimits) error {
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

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := c.lockAttachmentQuotaTx(ctx, tx, a.TenantID); err != nil {
		return err
	}
	if limits.ActiveUploader {
		limits, err = c.directoryQuotaTx(ctx, tx, a.TenantID, limits)
		if err != nil {
			return err
		}
		if limits.MaxUploadBytes > 0 && a.SizeBytes > limits.MaxUploadBytes {
			return ErrAttachmentUploadQuotaExceeded
		}
	}
	if reservationID != "" {
		delResQ := c.store.rebind(`DELETE FROM attachment_upload_reservations WHERE tenant_id = ? AND id = ?`)
		if _, err := tx.ExecContext(ctx, delResQ, a.TenantID, reservationID); err != nil {
			return err
		}
	}
	tenantUsed, pendingUsed, err := c.attachmentQuotaUsageTx(ctx, tx, a.TenantID, a.UploaderID, nowMilli())
	if err != nil {
		return err
	}
	if limits.MaxTotalBytes > 0 && tenantUsed+a.SizeBytes > limits.MaxTotalBytes {
		return ErrAttachmentTenantQuotaExceeded
	}
	if limits.MaxPendingUserBytes > 0 && a.MessageID == "" && pendingUsed+a.SizeBytes > limits.MaxPendingUserBytes {
		return ErrAttachmentPendingQuotaExceeded
	}
	if limits.ActiveUploader {
		// Under the tenant lock the org purge also takes: an upload whose person was erased or
		// whose org was deleted while it was in flight commits nothing.
		var status, tenant string
		if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT u.status, t.status FROM users u JOIN tenants t ON t.id = ? WHERE u.id = ? AND u.org_id = t.id AND NOT EXISTS (SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id = t.id)`), a.TenantID, a.UploaderID).Scan(&status, &tenant); err != nil || status != "active" || tenant != TenantStatusActive {
			return ErrForbidden
		}
	}
	if limits.Pool {
		ceiling, err := c.poolCeilingTx(ctx, tx, a.TenantID, nowMilli())
		if err != nil {
			return err
		}
		if tenantUsed+a.SizeBytes > ceiling {
			return ErrPoolFull
		}
	}

	insQ := c.store.rebind(`
		INSERT INTO attachments (id, tenant_id, room_id, message_id, uploader_id, blob_key, filename, mime_type, size_bytes, sha256_hex, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insQ,
		a.ID, a.TenantID, a.RoomID, nullString(a.MessageID), a.UploaderID,
		a.BlobKey, a.Filename, a.MimeType, a.SizeBytes, a.SHA256Hex, a.CreatedAt,
	); err != nil {
		return uniqueError(err)
	}
	return tx.Commit()
}

func (c *chatStore) SumAttachmentBytesByTenant(ctx context.Context, tenantID string) (int64, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM attachments WHERE tenant_id = ?`)
	var total int64
	if err := c.store.db.QueryRowContext(ctx, q, tenantID).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (c *chatStore) SumPendingAttachmentBytesByUploader(ctx context.Context, tenantID, uploaderID string) (int64, error) {
	tenantID = normalizeTenant(tenantID)
	q := c.store.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM attachments WHERE tenant_id = ? AND uploader_id = ? AND message_id IS NULL`)
	var total int64
	if err := c.store.db.QueryRowContext(ctx, q, tenantID, uploaderID).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (c *chatStore) PurgeOrphanAttachments(ctx context.Context, olderThanMilli int64, limit int) ([]BlobRef, error) {
	if limit <= 0 {
		limit = 200
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM attachment_upload_reservations WHERE expires_at <= ?`), nowMilli()); err != nil {
		return nil, err
	}

	selQ := c.store.rebind(`
		SELECT id, tenant_id, blob_key FROM attachments
		WHERE message_id IS NULL AND created_at < ?
		ORDER BY created_at ASC, id ASC
		LIMIT ?`)
	rows, err := tx.QueryContext(ctx, selQ, olderThanMilli, limit)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id string
		BlobRef
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.TenantID, &item.Key); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	if len(candidates) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	delQ := c.store.rebind(`DELETE FROM attachments WHERE id = ? AND message_id IS NULL`)
	deletedKeys := make([]BlobRef, 0, len(candidates))
	for _, item := range candidates {
		res, err := tx.ExecContext(ctx, delQ, item.id)
		if err != nil {
			return nil, err
		}
		if n, err := res.RowsAffected(); err == nil && n == 1 {
			deletedKeys = append(deletedKeys, item.BlobRef)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deletedKeys, nil
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

// AttachmentTenant returns the org of the attachment stored under blobKey.
func (c *chatStore) AttachmentTenant(ctx context.Context, blobKey string) (string, error) {
	var t string
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`SELECT tenant_id FROM attachments WHERE blob_key = ?`), blobKey).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return t, err
}
