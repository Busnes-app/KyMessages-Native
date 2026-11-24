package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// RecoverCallSession preserves call identity and sticky policy while retiring media and
// opaque seats from a departed process. It runs once per new in-memory owner generation.
func (c *chatStore) RecoverCallSession(ctx context.Context, lease CallLease) (*CallSession, error) {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := c.lockAttachmentQuotaTx(ctx, tx, lease.TenantID); err != nil {
		return nil, err
	}
	if _, err := c.directoryQuotaTx(ctx, tx, lease.TenantID, AttachmentQuotaLimits{}); err != nil {
		return nil, err
	}
	cs := &CallSession{TenantID: lease.TenantID, RoomID: lease.RoomID, OwnerID: lease.Holder, OwnerGeneration: lease.Generation}
	if err := c.callLeaseTx(ctx, tx, cs); err != nil {
		return nil, err
	}
	var media sql.NullString
	var sticky int
	err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT id,mode,epoch,sfu_sticky,livekit_room,started_by,started_at FROM call_sessions WHERE tenant_id=? AND room_id=? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1`), lease.TenantID, lease.RoomID).Scan(&cs.ID, &cs.Mode, &cs.Epoch, &sticky, &media, &cs.StartedBy, &cs.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cs.SFUSticky = sticky != 0
	if media.Valid && media.String != "" {
		if _, err := tx.ExecContext(ctx, c.store.rebind(`INSERT INTO pending_call_evictions(tenant_id,livekit_room,peer_id,user_id) VALUES(?,?,'','') ON CONFLICT DO NOTHING`), cs.TenantID, media.String); err != nil {
			return nil, err
		}
	}
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.tenant_id=? AND call_seats.room_id=?`, cs.TenantID, cs.RoomID); err != nil {
		return nil, err
	}
	// Read after removal because revocation advances the current epoch in the same transaction.
	if err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT epoch FROM call_sessions WHERE id=?`), cs.ID).Scan(&cs.Epoch); err != nil {
		return nil, err
	}
	cs.Epoch++
	if cs.Mode == CallModeSFULiveKit {
		cs.LiveKitRoom = "ky_" + cs.ID + "_e" + strconv.Itoa(cs.Epoch)
	}
	if _, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE call_sessions SET epoch=?,livekit_room=? WHERE id=? AND tenant_id=? AND room_id=? AND ended_at IS NULL`), cs.Epoch, nullString(cs.LiveKitRoom), cs.ID, cs.TenantID, cs.RoomID); err != nil {
		return nil, err
	}
	return cs, tx.Commit()
}

func (c *chatStore) CallSeats(ctx context.Context, tenantID, roomID string) ([]CallSeat, error) {
	rows, err := c.store.db.QueryContext(ctx, c.store.rebind(`SELECT user_id,peer_id,session_hash FROM call_seats WHERE tenant_id=? AND room_id=?`), tenantID, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var seats []CallSeat
	for rows.Next() {
		var s CallSeat
		if err := rows.Scan(&s.UserID, &s.PeerID, &s.SessionHash); err != nil {
			return nil, err
		}
		s.Guest = s.SessionHash == ""
		seats = append(seats, s)
	}
	return seats, rows.Err()
}

// QueueOwnedCallSeatRemoval is rollback/departure by an ephemeral owner, rather than an
// authoritative principal revocation. Fence both ownership and the exact issued seat so
// late external work cannot retire a replacement session, peer or media epoch.
func (c *chatStore) QueueOwnedCallSeatRemoval(ctx context.Context, cs *CallSession, seat CallSeat) error {
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := c.callLeaseTx(ctx, tx, cs); err != nil {
		return err
	}
	if err := queueCallSeatsTx(ctx, c.store, tx, `call_seats.tenant_id=? AND call_seats.room_id=? AND call_seats.call_id=? AND call_seats.user_id=? AND call_seats.peer_id=? AND call_seats.session_hash=? AND call_seats.media_epoch=?`, cs.TenantID, cs.RoomID, cs.ID, seat.UserID, seat.PeerID, seat.SessionHash, cs.Epoch); err != nil {
		return err
	}
	return tx.Commit()
}
