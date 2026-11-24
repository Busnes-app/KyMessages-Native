package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------
// Tenant Media Policy
// ---------------------------------------------------------------------

func (c *chatStore) UpdateTenantMediaPolicy(ctx context.Context, tenantID, policy string, maxVideo, maxAudio int, guestForceSFU bool) (*Tenant, error) {
	tenantID = normalizeTenant(tenantID)
	if policy != P2PPolicyHybrid && policy != P2PPolicySFUOnly {
		return nil, errors.New("p2p_policy must be hybrid or sfu_only")
	}
	if maxVideo < 2 {
		maxVideo = 2
	}
	if maxVideo > 6 {
		maxVideo = 6
	}
	if maxAudio < 2 {
		maxAudio = 2
	}
	if maxAudio > 8 {
		maxAudio = 8
	}
	res, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		UPDATE tenants
		SET p2p_policy = ?, p2p_max_video = ?, p2p_max_audio = ?, guest_force_sfu = ?
		WHERE id = ?`),
		policy, maxVideo, maxAudio, boolToInt(guestForceSFU), tenantID,
	)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return c.GetTenant(ctx, tenantID)
}

// ---------------------------------------------------------------------
// Call Sessions
// ---------------------------------------------------------------------

func (c *chatStore) CreateCallSession(ctx context.Context, cs *CallSession) error {
	cs.TenantID = normalizeTenant(cs.TenantID)
	if cs.ID == "" {
		cs.ID = "call_" + uuid.Must(uuid.NewV7()).String()
	}
	if cs.Mode == "" {
		cs.Mode = CallModeP2PMesh
	}
	if cs.Epoch <= 0 {
		cs.Epoch = 1
	}
	if cs.StartedAt == 0 {
		cs.StartedAt = nowMilli()
	}
	return c.withCallLease(ctx, cs, func(db execQuerier) error {
		_, err := db.ExecContext(ctx, c.store.rebind(`
		INSERT INTO call_sessions (id, tenant_id, room_id, mode, epoch, sfu_sticky, livekit_room, started_by, started_at, ended_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			cs.ID, cs.TenantID, cs.RoomID, cs.Mode, cs.Epoch, boolToInt(cs.SFUSticky),
			nullString(cs.LiveKitRoom), cs.StartedBy, cs.StartedAt, cs.EndedAt,
		)
		return err
	})
}

func (c *chatStore) GetActiveCallSession(ctx context.Context, tenantID, roomID string) (*CallSession, error) {
	tenantID = normalizeTenant(tenantID)
	row := c.store.db.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, mode, epoch, sfu_sticky, livekit_room, started_by, started_at, ended_at
		FROM call_sessions
		WHERE tenant_id = ? AND room_id = ? AND ended_at IS NULL
		ORDER BY started_at DESC
		LIMIT 1`),
		tenantID, roomID,
	)
	var cs CallSession
	var sticky int
	var lkRoom sql.NullString
	var endedAt sql.NullInt64
	if err := row.Scan(&cs.ID, &cs.TenantID, &cs.RoomID, &cs.Mode, &cs.Epoch, &sticky, &lkRoom, &cs.StartedBy, &cs.StartedAt, &endedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	cs.SFUSticky = sticky != 0
	if lkRoom.Valid {
		cs.LiveKitRoom = lkRoom.String
	}
	if endedAt.Valid {
		v := endedAt.Int64
		cs.EndedAt = &v
	}
	return &cs, nil
}

func (c *chatStore) UpdateCallSession(ctx context.Context, cs *CallSession) error {
	tenantID := normalizeTenant(cs.TenantID)
	return c.withCallLease(ctx, cs, func(db execQuerier) error {
		q := `UPDATE call_sessions SET mode=?,epoch=?,sfu_sticky=?,livekit_room=? WHERE tenant_id=? AND id=? AND ended_at IS NULL`
		args := []any{cs.Mode, cs.Epoch, boolToInt(cs.SFUSticky), nullString(cs.LiveKitRoom), tenantID, cs.ID}
		if cs.OwnerID != "" {
			q += ` AND room_id=? AND epoch<=?`
			args = append(args, cs.RoomID, cs.Epoch)
		}
		res, err := db.ExecContext(ctx, c.store.rebind(q), args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if cs.OwnerID != "" {
				return ErrCallStateStale
			}
			return ErrNotFound
		}
		return nil
	})
}

func (c *chatStore) EndCallSession(ctx context.Context, tenantID, callID string, endedAt int64) error {
	tenantID = normalizeTenant(tenantID)
	if endedAt == 0 {
		endedAt = nowMilli()
	}
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		UPDATE call_sessions
		SET ended_at = ?
		WHERE tenant_id = ? AND id = ? AND ended_at IS NULL`),
		endedAt, tenantID, callID,
	)
	return err
}

// ---------------------------------------------------------------------
// Native Meetings & External Guest Links
// ---------------------------------------------------------------------

func (c *chatStore) UpsertMeeting(ctx context.Context, p UpsertMeetingParams) (*UpsertMeetingResult, error) {
	tenantID := normalizeTenant(p.TenantID)
	now := nowMilli()

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if c.store.driver == "postgres" {
		// Serialise writers of one org's meeting across replicas, keyed like the row, before the
		// read below: two creates would otherwise both insert, and two updates both apply.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('kymessages:meeting:' || current_schema() || ':' || $1), hashtext($2))`, tenantID, p.ID); err != nil {
			return nil, err
		}
	}

	res := &UpsertMeetingResult{}

	// Check if meeting already exists.
	var existing Meeting
	var closedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at
		FROM meetings
		WHERE tenant_id = ? AND id = ?`),
		tenantID, p.ID,
	).Scan(&existing.ID, &existing.TenantID, &existing.RoomID, &existing.OrganizerSub, &existing.Title, &closedAt, &existing.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		res.Created = true
		roomID := p.RoomID
		if roomID == "" {
			roomID = "rm_" + uuid.Must(uuid.NewV7()).String()
		}
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			INSERT INTO rooms (id, tenant_id, kind, dm_pair_key, name, topic, is_private, last_seq, created_by, created_at)
			VALUES (?, ?, ?, NULL, ?, '', 1, 0, ?, ?)`),
			roomID, tenantID, RoomKindMeeting, p.Title, p.OrganizerID, now,
		); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			INSERT INTO meetings (id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at)
			VALUES (?, ?, ?, ?, ?, NULL, ?)`),
			p.ID, tenantID, roomID, p.OrganizerSub, p.Title, now,
		); err != nil {
			return nil, err
		}
		existing = Meeting{
			ID:           p.ID,
			TenantID:     tenantID,
			RoomID:       roomID,
			OrganizerSub: p.OrganizerSub,
			Title:        p.Title,
			UpdatedAt:    now,
		}
	} else if err != nil {
		return nil, err
	} else {
		if closedAt.Valid {
			v := closedAt.Int64
			existing.ClosedAt = &v
		}
		// Reopen/update title on active meeting.
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			UPDATE meetings SET organizer_sub = ?, title = ?, closed_at = NULL, updated_at = ?
			WHERE tenant_id = ? AND id = ?`),
			p.OrganizerSub, p.Title, now, tenantID, p.ID,
		); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			UPDATE rooms SET name = ?, closed_at = NULL WHERE tenant_id = ? AND id = ?`),
			p.Title, tenantID, existing.RoomID,
		); err != nil {
			return nil, err
		}
		existing.OrganizerSub = p.OrganizerSub
		existing.Title = p.Title
		existing.ClosedAt = nil
		existing.UpdatedAt = now
	}

	// Reconcile room members.
	desired := make(map[string]string, len(p.MemberUserIDs)+1)
	if p.OrganizerID != "" {
		desired[p.OrganizerID] = RoomRoleOwner
	}
	for _, uid := range p.MemberUserIDs {
		if uid == "" {
			continue
		}
		if _, ok := desired[uid]; !ok {
			desired[uid] = RoomRoleMember
		}
	}

	curMembers := make(map[string]string)
	mRows, err := tx.QueryContext(ctx, c.store.rebind(`
		SELECT user_id, role FROM room_members WHERE tenant_id = ? AND room_id = ?`),
		tenantID, existing.RoomID,
	)
	if err != nil {
		return nil, err
	}
	for mRows.Next() {
		var uid, role string
		if err := mRows.Scan(&uid, &role); err != nil {
			mRows.Close()
			return nil, err
		}
		curMembers[uid] = role
	}
	mRows.Close()

	for uid, role := range desired {
		if _, exists := curMembers[uid]; !exists {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				INSERT INTO room_members (tenant_id, room_id, user_id, role, last_read_seq, notify_mode, joined_at)
				VALUES (?, ?, ?, ?, 0, 'all', ?)`),
				tenantID, existing.RoomID, uid, role, now,
			); err != nil {
				return nil, err
			}
			res.AddedMemberIDs = append(res.AddedMemberIDs, uid)
		}
	}
	for uid := range curMembers {
		if _, keep := desired[uid]; !keep {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				DELETE FROM room_members WHERE tenant_id = ? AND room_id = ? AND user_id = ?`),
				tenantID, existing.RoomID, uid,
			); err != nil {
				return nil, err
			}
			res.RemovedMemberIDs = append(res.RemovedMemberIDs, uid)
		}
	}

	// Replace meeting windows.
	if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM meeting_windows WHERE tenant_id = ? AND meeting_id = ?`), tenantID, p.ID); err != nil {
		return nil, err
	}
	for _, w := range p.Windows {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			INSERT INTO meeting_windows (tenant_id, meeting_id, starts_at, ends_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT (tenant_id, meeting_id, starts_at, ends_at) DO NOTHING`),
			tenantID, p.ID, w.StartsAt, w.EndsAt,
		); err != nil {
			return nil, err
		}
	}

	// Reconcile guest links: keep active keys in KeepGuestKeys, revoke removed keys, insert or re-issue new keys.
	curGuests := make(map[string]*MeetingGuest)
	gRows, err := tx.QueryContext(ctx, c.store.rebind(`
		SELECT id, meeting_id, guest_key, token_hash, revoked_at, created_at
		FROM meeting_guests
		WHERE tenant_id = ? AND meeting_id = ?`),
		tenantID, p.ID,
	)
	if err != nil {
		return nil, err
	}
	for gRows.Next() {
		var g MeetingGuest
		var rev sql.NullInt64
		if err := gRows.Scan(&g.ID, &g.MeetingID, &g.GuestKey, &g.TokenHash, &rev, &g.CreatedAt); err != nil {
			gRows.Close()
			return nil, err
		}
		if rev.Valid {
			v := rev.Int64
			g.RevokedAt = &v
		}
		curGuests[g.GuestKey] = &g
	}
	gRows.Close()

	for key, g := range curGuests {
		if _, keep := p.KeepGuestKeys[key]; !keep && g.RevokedAt == nil {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				UPDATE meeting_guests SET revoked_at = ? WHERE id = ?`),
				now, g.ID,
			); err != nil {
				return nil, err
			}
			res.RevokedGuestKeys = append(res.RevokedGuestKeys, key)
		}
	}

	for key, cand := range p.NewGuestTokens {
		existingGuest, found := curGuests[key]
		if !found {
			if cand.ID == "" {
				cand.ID = "gst_" + uuid.Must(uuid.NewV7()).String()
			}
			if cand.CreatedAt == 0 {
				cand.CreatedAt = now
			}
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				INSERT INTO meeting_guests (id, tenant_id, meeting_id, guest_key, token_hash, revoked_at, created_at)
				VALUES (?, ?, ?, ?, ?, NULL, ?)`),
				cand.ID, tenantID, p.ID, key, cand.TokenHash, cand.CreatedAt,
			); err != nil {
				return nil, err
			}
			res.IssuedGuestKeys = append(res.IssuedGuestKeys, key)
		} else if existingGuest.RevokedAt != nil {
			// Key was previously revoked and is now re-invited: rotate token hash and clear revoked_at.
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				UPDATE meeting_guests SET token_hash = ?, revoked_at = NULL, created_at = ? WHERE id = ?`),
				cand.TokenHash, now, existingGuest.ID,
			); err != nil {
				return nil, err
			}
			res.IssuedGuestKeys = append(res.IssuedGuestKeys, key)
		}
	}

	room, err := scanRoom(tx.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, kind, dm_pair_key, name, topic, is_private, last_seq, closed_at, created_by, created_at
		FROM rooms WHERE tenant_id = ? AND id = ?`),
		tenantID, existing.RoomID,
	))
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	res.Meeting = &existing
	res.Room = room
	return res, nil
}

func (c *chatStore) GetMeeting(ctx context.Context, tenantID, meetingID string) (*Meeting, []MeetingWindow, []MeetingGuest, error) {
	tenantID = normalizeTenant(tenantID)
	var m Meeting
	var closedAt sql.NullInt64
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at
		FROM meetings WHERE tenant_id = ? AND id = ?`),
		tenantID, meetingID,
	).Scan(&m.ID, &m.TenantID, &m.RoomID, &m.OrganizerSub, &m.Title, &closedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if closedAt.Valid {
		v := closedAt.Int64
		m.ClosedAt = &v
	}

	windows, err := c.listMeetingWindows(ctx, m.TenantID, m.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	guests, err := c.listMeetingGuests(ctx, m.TenantID, m.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	return &m, windows, guests, nil
}

func (c *chatStore) GetMeetingByRoomID(ctx context.Context, tenantID, roomID string) (*Meeting, []MeetingWindow, error) {
	tenantID = normalizeTenant(tenantID)
	var m Meeting
	var closedAt sql.NullInt64
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at
		FROM meetings WHERE tenant_id = ? AND room_id = ?`),
		tenantID, roomID,
	).Scan(&m.ID, &m.TenantID, &m.RoomID, &m.OrganizerSub, &m.Title, &closedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if closedAt.Valid {
		v := closedAt.Int64
		m.ClosedAt = &v
	}
	windows, err := c.listMeetingWindows(ctx, m.TenantID, m.ID)
	if err != nil {
		return nil, nil, err
	}
	return &m, windows, nil
}

func (c *chatStore) CreateMeetingGuest(ctx context.Context, g *MeetingGuest) error {
	if g.ID == "" {
		g.ID = "gst_" + uuid.Must(uuid.NewV7()).String()
	}
	if g.CreatedAt == 0 {
		g.CreatedAt = nowMilli()
	}
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		INSERT INTO meeting_guests (id, tenant_id, meeting_id, guest_key, token_hash, revoked_at, created_at)
		VALUES (?, ?, ?, ?, ?, NULL, ?)`),
		g.ID, normalizeTenant(g.TenantID), g.MeetingID, g.GuestKey, g.TokenHash, g.CreatedAt,
	)
	return err
}

func (c *chatStore) GetMeetingGuestByTokenHash(ctx context.Context, tokenHash string) (*MeetingGuest, *Meeting, []MeetingWindow, error) {
	var g MeetingGuest
	var rev sql.NullInt64
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, meeting_id, guest_key, token_hash, revoked_at, created_at
		FROM meeting_guests WHERE token_hash = ?`),
		tokenHash,
	).Scan(&g.ID, &g.TenantID, &g.MeetingID, &g.GuestKey, &g.TokenHash, &rev, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if rev.Valid {
		v := rev.Int64
		g.RevokedAt = &v
	}

	var m Meeting
	var closedAt sql.NullInt64
	err = c.store.db.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at
		FROM meetings WHERE tenant_id = ? AND id = ?`),
		g.TenantID, g.MeetingID,
	).Scan(&m.ID, &m.TenantID, &m.RoomID, &m.OrganizerSub, &m.Title, &closedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if closedAt.Valid {
		v := closedAt.Int64
		m.ClosedAt = &v
	}

	windows, err := c.listMeetingWindows(ctx, m.TenantID, m.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	return &g, &m, windows, nil
}

func (c *chatStore) CloseMeeting(ctx context.Context, tenantID, meetingID string) (*Meeting, error) {
	tenantID = normalizeTenant(tenantID)
	now := nowMilli()

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var m Meeting
	var closedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at
		FROM meetings WHERE tenant_id = ? AND id = ?`),
		tenantID, meetingID,
	).Scan(&m.ID, &m.TenantID, &m.RoomID, &m.OrganizerSub, &m.Title, &closedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, c.store.rebind(`
		UPDATE meetings SET closed_at = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`),
		now, now, tenantID, meetingID,
	); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`
		UPDATE rooms SET closed_at = COALESCE(closed_at, ?) WHERE tenant_id = ? AND id = ?`),
		now, tenantID, m.RoomID,
	); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`
		UPDATE meeting_guests SET revoked_at = COALESCE(revoked_at, ?) WHERE tenant_id = ? AND meeting_id = ?`),
		now, tenantID, meetingID,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	m.ClosedAt = &now
	m.UpdatedAt = now
	return &m, nil
}

func (c *chatStore) listMeetingWindows(ctx context.Context, tenantID, meetingID string) ([]MeetingWindow, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`
		SELECT meeting_id, starts_at, ends_at FROM meeting_windows WHERE tenant_id = ? AND meeting_id = ? ORDER BY starts_at ASC`),
		tenantID, meetingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MeetingWindow, 0)
	for rows.Next() {
		var w MeetingWindow
		if err := rows.Scan(&w.MeetingID, &w.StartsAt, &w.EndsAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (c *chatStore) listMeetingGuests(ctx context.Context, tenantID, meetingID string) ([]MeetingGuest, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`
		SELECT id, meeting_id, guest_key, token_hash, revoked_at, created_at
		FROM meeting_guests WHERE tenant_id = ? AND meeting_id = ? ORDER BY created_at ASC`),
		tenantID, meetingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MeetingGuest, 0)
	for rows.Next() {
		var g MeetingGuest
		var rev sql.NullInt64
		if err := rows.Scan(&g.ID, &g.MeetingID, &g.GuestKey, &g.TokenHash, &rev, &g.CreatedAt); err != nil {
			return nil, err
		}
		if rev.Valid {
			v := rev.Int64
			g.RevokedAt = &v
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
