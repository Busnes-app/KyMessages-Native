package store

import (
	"context"
	"database/sql"
	"errors"
)

// handoverErasureRooms runs before any actor membership disappears. All affected room locks
// are taken in ID order, also serializing with ordinary departures and concurrent erasures.
func (c *chatStore) handoverErasureRooms(ctx context.Context, tx *sql.Tx, tenantID, ownerID string) error {
	const actors = `SELECT user_id FROM user_erasure_actors WHERE tenant_id = ? AND owner_user_id = ?`
	q := `SELECT r.id, r.kind FROM rooms r WHERE r.tenant_id = ? AND (
 r.created_by IN (` + actors + `) OR EXISTS (SELECT 1 FROM room_members m
 WHERE m.tenant_id = r.tenant_id AND m.room_id = r.id AND m.user_id IN (` + actors + `))) ORDER BY r.id`
	if c.store.driver == "postgres" {
		q += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, c.store.rebind(q), tenantID, tenantID, ownerID, tenantID, ownerID)
	if err != nil {
		return err
	}
	type room struct{ id, kind string }
	var rooms []room
	for rows.Next() {
		var r room
		if err := rows.Scan(&r.id, &r.kind); err != nil {
			rows.Close()
			return err
		}
		rooms = append(rooms, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, r := range rooms {
		var owned bool
		err := tx.QueryRowContext(ctx, c.store.rebind(`SELECT EXISTS(SELECT 1 FROM rooms r
 WHERE r.tenant_id = ? AND r.id = ? AND (r.created_by IN (`+actors+`) OR EXISTS (
 SELECT 1 FROM room_members m WHERE m.tenant_id = r.tenant_id AND m.room_id = r.id
 AND m.role = 'owner' AND m.user_id IN (`+actors+`))))`), tenantID, r.id, tenantID, ownerID, tenantID, ownerID).Scan(&owned)
		if err != nil {
			return err
		}
		if !owned {
			continue
		}
		var successor string
		err = tx.QueryRowContext(ctx, c.store.rebind(`SELECT m.user_id FROM room_members m JOIN users u ON u.id = m.user_id
 WHERE m.tenant_id = ? AND m.room_id = ? AND u.status <> 'deleted'
 AND m.user_id NOT IN (`+actors+`) AND (u.org_id = ? OR (u.sso_provider = 'bot' AND u.org_id = ''
 AND EXISTS (SELECT 1 FROM agents a JOIN users o ON o.id = a.owner_user_id WHERE a.user_id = u.id AND o.org_id = ?)))
 ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.joined_at, m.user_id LIMIT 1`), tenantID, r.id, tenantID, ownerID, tenantID, tenantID).Scan(&successor)
		if errors.Is(err, sql.ErrNoRows) {
			// Solo rooms are removed with their blobs by eraseActorTx.
			continue
		}
		if err != nil {
			return err
		}
		if r.kind != RoomKindDM {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE room_members SET role = 'owner' WHERE tenant_id = ? AND room_id = ? AND user_id = ?`), tenantID, r.id, successor); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, c.store.rebind(`UPDATE rooms SET created_by = ? WHERE tenant_id = ? AND id = ?`), successor, tenantID, r.id); err != nil {
			return err
		}
	}
	return nil
}
