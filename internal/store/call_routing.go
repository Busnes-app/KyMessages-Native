package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AcquireCallRoom claims the room selected by edge affinity. A wrong replica cannot create
// another call. Every expired/released lease gets a new generation, even for the same holder.
func (c *chatStore) AcquireCallRoom(ctx context.Context, tenantID, roomID, holder string, ttl time.Duration) (CallLease, error) {
	lease := CallLease{TenantID: tenantID, RoomID: roomID, Holder: holder}
	if holder == "" || ttl < time.Millisecond || ttl > 5*time.Minute {
		return lease, ErrInvalidInput
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return lease, err
	}
	defer tx.Rollback()
	if err := c.lockAttachmentQuotaTx(ctx, tx, tenantID); err != nil {
		return lease, err
	}
	if _, err := c.directoryQuotaTx(ctx, tx, tenantID, AttachmentQuotaLimits{}); err != nil {
		return lease, err
	}
	now := c.store.dbNowMillis()
	err = tx.QueryRowContext(ctx, c.store.rebind(`INSERT INTO call_room_owners(room_id,tenant_id,holder,generation,expires_at)
 SELECT id,tenant_id,?,1,`+now+`+? FROM rooms WHERE tenant_id=? AND id=? AND closed_at IS NULL
 ON CONFLICT(room_id) DO UPDATE SET holder=excluded.holder,
 generation=CASE WHEN call_room_owners.expires_at<=`+now+` THEN call_room_owners.generation+1 ELSE call_room_owners.generation END,
 expires_at=excluded.expires_at WHERE call_room_owners.tenant_id=excluded.tenant_id
 AND (call_room_owners.expires_at<=`+now+` OR call_room_owners.holder=excluded.holder)
 RETURNING generation`), holder, ttl.Milliseconds(), tenantID, roomID).Scan(&lease.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return lease, ErrCallOwnerLost
	}
	if err != nil {
		return lease, err
	}
	return lease, tx.Commit()
}

func (c *chatStore) CallRoomHeld(ctx context.Context, l CallLease) (bool, error) {
	var held bool
	err := c.store.db.QueryRowContext(ctx, c.store.rebind(`SELECT EXISTS(SELECT 1 FROM call_room_owners WHERE tenant_id=? AND room_id=? AND holder=? AND generation=? AND expires_at>`+c.store.dbNowMillis()+`)`), l.TenantID, l.RoomID, l.Holder, l.Generation).Scan(&held)
	return held, err
}

func (c *chatStore) ReleaseCallRoom(ctx context.Context, l CallLease) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE call_room_owners SET expires_at=0 WHERE tenant_id=? AND room_id=? AND holder=? AND generation=?`), l.TenantID, l.RoomID, l.Holder, l.Generation)
	return err
}

func (c *chatStore) callLeaseTx(ctx context.Context, tx *sql.Tx, cs *CallSession) error {
	res, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE call_room_owners SET holder=holder WHERE tenant_id=? AND room_id=? AND holder=? AND generation=? AND expires_at>`+c.store.dbNowMillis()), cs.TenantID, cs.RoomID, cs.OwnerID, cs.OwnerGeneration)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCallOwnerLost
	}
	return nil
}

// PutCallSeat binds SFU credentials to a durable opaque account/peer link before they leave
// the server. User/guest locks serialize it with revocation; the owner generation fences it.
func (c *chatStore) PutCallSeat(ctx context.Context, cs *CallSession, userID, peerID string, guest bool) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var res sql.Result
	if guest {
		res, err = tx.ExecContext(ctx, c.store.rebind(`UPDATE meeting_guest_sessions SET guest_id=guest_id WHERE guest_id=? AND tenant_id=? AND room_id=? AND status='admitted' AND expires_at>`+c.store.dbNowMillis()), userID, cs.TenantID, cs.RoomID)
	} else {
		res, err = tx.ExecContext(ctx, c.store.rebind(`UPDATE users SET id=id WHERE id=? AND org_id=? AND status='active' AND role<>'bot'`), userID, cs.TenantID)
	}
	if err := oneRow(res, err); err != nil {
		return err
	}
	if err := c.lockAttachmentQuotaTx(ctx, tx, cs.TenantID); err != nil {
		return err
	}
	if _, err := c.directoryQuotaTx(ctx, tx, cs.TenantID, AttachmentQuotaLimits{}); err != nil {
		return err
	}
	if err := c.callLeaseTx(ctx, tx, cs); err != nil {
		return err
	}
	membership := `AND EXISTS(SELECT 1 FROM room_members m WHERE m.tenant_id=call_sessions.tenant_id AND m.room_id=call_sessions.room_id AND m.user_id=?)`
	args := []any{userID, peerID, cs.ID, cs.TenantID, cs.RoomID, userID}
	if guest {
		membership = ""
		args = args[:5]
	}
	res, err = tx.ExecContext(ctx, c.store.rebind(`INSERT INTO call_seats(room_id,tenant_id,user_id,peer_id,call_id)
 SELECT room_id,tenant_id,?,?,id FROM call_sessions WHERE id=? AND tenant_id=? AND room_id=? AND ended_at IS NULL `+membership+`
 ON CONFLICT(room_id,user_id) DO UPDATE SET peer_id=excluded.peer_id,call_id=excluded.call_id`), args...)
	if err := oneRow(res, err); err != nil {
		return err
	}
	return tx.Commit()
}

// queueCallSeatsTx retains cleanup before the seat/account/room can disappear. where is a
// fixed internal SQL predicate, never wire data. Empty SFU rooms need no external cleanup.
func queueCallSeatsTx(ctx context.Context, st *SQLStore, tx *sql.Tx, where string, args ...any) error {
	_, err := tx.ExecContext(ctx, st.rebind(`INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT call_seats.tenant_id,c.livekit_room,call_seats.peer_id,call_seats.user_id FROM call_seats
 JOIN call_sessions c ON c.id=call_seats.call_id AND c.tenant_id=call_seats.tenant_id AND c.room_id=call_seats.room_id
 WHERE `+where+` AND c.livekit_room IS NOT NULL AND c.livekit_room<>'' ON CONFLICT DO NOTHING`), args...)
	if err != nil {
		return err
	}
	// Retire the media address as well as the participant: a former bearer must never
	// reach the survivors' next media epoch by reconnecting with an old SFU token.
	if _, err := tx.ExecContext(ctx, st.rebind(`UPDATE call_sessions SET epoch=epoch+1,
 livekit_room='ky_' || id || '_e' || CAST(epoch+1 AS TEXT)
 WHERE ended_at IS NULL AND mode='sfu_livekit' AND livekit_room IS NOT NULL AND livekit_room<>''
 AND id IN(SELECT call_id FROM call_seats WHERE `+where+`)`), args...); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, st.rebind(`DELETE FROM call_seats WHERE `+where), args...)
	return err
}

func (c *chatStore) QueueCallSeatRemoval(ctx context.Context, roomID, userID string) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.room_id=? AND call_seats.user_id=?`, roomID, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *chatStore) QueueCallRoomRemoval(ctx context.Context, tenantID, livekitRoom string) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id)
 SELECT DISTINCT c.tenant_id,c.livekit_room,'','' FROM call_sessions c JOIN tenants t ON t.id=c.tenant_id
 WHERE c.tenant_id=? AND c.livekit_room=? AND t.purged_at IS NULL ON CONFLICT DO NOTHING`), tenantID, livekitRoom)
	return err
}

func (c *chatStore) PendingCallEvictions(ctx context.Context, tenantID, userID string, limit int) ([]CallEviction, error) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	q := `SELECT p.tenant_id,p.livekit_room,p.peer_id,p.user_id FROM pending_call_evictions p WHERE 1=1`
	var args []any
	if tenantID != "" {
		q += ` AND p.tenant_id=?`
		args = append(args, tenantID)
	}
	if userID != "" {
		q += ` AND (p.user_id=? OR p.user_id IN(SELECT a.user_id FROM user_erasure_actors a WHERE a.tenant_id=p.tenant_id AND a.owner_user_id=?))`
		args = append(args, userID, userID)
	}
	q += ` ORDER BY random() LIMIT ?`
	args = append(args, limit)
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CallEviction
	for rows.Next() {
		var e CallEviction
		if err := rows.Scan(&e.TenantID, &e.LiveKitRoom, &e.PeerID, &e.UserID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (c *chatStore) ClearCallEviction(ctx context.Context, e CallEviction) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`DELETE FROM pending_call_evictions WHERE tenant_id=? AND livekit_room=? AND peer_id=?`), e.TenantID, e.LiveKitRoom, e.PeerID)
	if err != nil {
		return err
	}
	return c.ClearPendingBlobDeletes(ctx, nil)
}

func (c *chatStore) EndOwnedCallSession(ctx context.Context, cs *CallSession, endedAt int64) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := c.callLeaseTx(ctx, tx, cs); err != nil {
		return err
	}
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.call_id=? AND call_seats.tenant_id=? AND call_seats.room_id=?`, cs.ID, cs.TenantID, cs.RoomID); err != nil {
		return err
	}
	if endedAt == 0 {
		endedAt = nowMilli()
	}
	if err := oneRow(tx.ExecContext(ctx, c.store.rebind(`UPDATE call_sessions SET ended_at=COALESCE(ended_at,?) WHERE tenant_id=? AND room_id=? AND id=?`), endedAt, cs.TenantID, cs.RoomID, cs.ID)); err != nil {
		return err
	}
	return tx.Commit()
}

// The empty owner keeps the original single-mode write path exactly as before.
func (c *chatStore) withCallLease(ctx context.Context, cs *CallSession, write func(execQuerier) error) error {
	if cs.OwnerID == "" {
		return write(c.store.db)
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := c.lockAttachmentQuotaTx(ctx, tx, cs.TenantID); err != nil {
		return err
	}
	if _, err := c.directoryQuotaTx(ctx, tx, cs.TenantID, AttachmentQuotaLimits{}); err != nil {
		return err
	}
	if err := c.callLeaseTx(ctx, tx, cs); err != nil {
		return err
	}
	if err := write(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// PruneCallSeats catches a notification missed while an owner was down. Polling/connected
// guests keep seen_at fresh; only a definite primary database answer queues their removal.
func (c *chatStore) PruneCallSeats(ctx context.Context, guestLive time.Duration) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	where := `NOT EXISTS(SELECT 1 FROM tenants WHERE id=call_seats.tenant_id AND status='active' AND ` + directoryReadySQL + ` AND NOT EXISTS(SELECT 1 FROM tenant_pending_revocations p WHERE p.tenant_id=tenants.id))
 OR (NOT EXISTS(SELECT 1 FROM users u JOIN room_members m ON m.user_id=u.id
 WHERE u.id=call_seats.user_id AND u.org_id=call_seats.tenant_id AND u.status='active' AND u.role<>'bot' AND m.tenant_id=call_seats.tenant_id AND m.room_id=call_seats.room_id)
 AND NOT EXISTS(SELECT 1 FROM meeting_guest_sessions g WHERE g.guest_id=call_seats.user_id AND g.tenant_id=call_seats.tenant_id AND g.room_id=call_seats.room_id AND g.status='admitted'
 AND g.expires_at>` + c.store.dbNowMillis() + ` AND g.seen_at>` + c.store.dbNowMillis() + `-?))`
	// Parenthesize the disjunction before the queue helper appends its SFU predicate.
	if err := queueCallSeatsTx(ctx, c.store, tx, `(`+where+`)`, guestLive.Milliseconds()); err != nil {
		return err
	}
	return tx.Commit()
}
