package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

func (s *e2eeStore) ListBotDevices(ctx context.Context, tenantID string, botIDs []string) ([]E2EEBotDevices, error) {
	if len(botIDs) == 0 {
		return nil, nil
	}
	args := []any{tenantID}
	for _, id := range botIDs {
		args = append(args, id)
	}
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT tenant_id, bot_user_id, owner_user_id, owner_version, epoch, devices, signature, updated_at
		FROM e2ee_bot_devices WHERE tenant_id = ? AND bot_user_id IN (?`+strings.Repeat(", ?", len(botIDs)-1)+`)`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEBotDevices
	for rows.Next() {
		var b E2EEBotDevices
		var updated int64
		if err := rows.Scan(&b.TenantID, &b.BotUserID, &b.OwnerUserID, &b.OwnerVersion, &b.Epoch, &b.Devices, &b.Signature, &updated); err != nil {
			return nil, err
		}
		b.UpdatedAt = time.Unix(updated, 0).UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *e2eeStore) PutBotDevices(ctx context.Context, b *E2EEBotDevices, expected int64, proof Proof) error {
	if b.Epoch <= expected {
		return ErrE2EEVersion
	}
	now := time.Now().Unix()
	// Holding the owner's master row keeps a reset from landing between the check and the write.
	return s.fenced(ctx, b.TenantID, b.OwnerUserID, b.OwnerVersion, proof, func(tx *sql.Tx) error {
		var res sql.Result
		var err error
		if expected == 0 {
			res, err = tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_bot_devices (bot_user_id, tenant_id, owner_user_id, owner_version, epoch, devices, signature, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (bot_user_id) DO NOTHING`),
				b.BotUserID, b.TenantID, b.OwnerUserID, b.OwnerVersion, b.Epoch, b.Devices, b.Signature, now)
		} else {
			res, err = tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_bot_devices SET owner_user_id = ?, owner_version = ?, epoch = ?, devices = ?, signature = ?, updated_at = ?
				WHERE bot_user_id = ? AND tenant_id = ? AND epoch = ?`),
				b.OwnerUserID, b.OwnerVersion, b.Epoch, b.Devices, b.Signature, now, b.BotUserID, b.TenantID, expected)
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrE2EEVersion
		}
		return nil
	})
}

func (s *e2eeStore) DeleteUserDevices(ctx context.Context, userID string) error {
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_devices WHERE user_id = ?`), userID)
	return err
}
