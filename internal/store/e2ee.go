package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type e2eeStore struct {
	store *SQLStore
}

// claimBudget bounds how long a claim keeps retrying while every remaining one-time key is
// locked by other in-flight claims (SKIP LOCKED on PostgreSQL). A round fails only then, and
// those claims finish within a statement, so a claim retries, with a short backoff, until it
// wins a key or none remain; the fallback key is handed out only when one-time keys are gone.
const claimBudget = 2 * time.Second

func (s *e2eeStore) UpsertDevice(ctx context.Context, d *E2EEDevice) error {
	now := time.Now().Unix()
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`
		INSERT INTO e2ee_devices (user_id, device_id, tenant_id, curve25519, ed25519, signature, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, device_id) DO NOTHING`),
		d.UserID, d.DeviceID, d.TenantID, d.Curve25519, d.Ed25519, d.Signature, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		d.CreatedAt = time.Unix(now, 0).UTC()
		return nil
	}
	// A device's identity keys never change: a different upload is a different device.
	cur, err := s.GetDevice(ctx, d.UserID, d.DeviceID)
	if err != nil {
		return err
	}
	if cur.TenantID != d.TenantID || cur.Curve25519 != d.Curve25519 || cur.Ed25519 != d.Ed25519 || cur.Signature != d.Signature {
		return ErrE2EEKeyMismatch
	}
	d.CreatedAt = cur.CreatedAt
	return nil
}

func scanDevice(sc interface{ Scan(...any) error }) (*E2EEDevice, error) {
	var d E2EEDevice
	var created int64
	if err := sc.Scan(&d.UserID, &d.DeviceID, &d.TenantID, &d.Curve25519, &d.Ed25519, &d.Signature, &created); err != nil {
		return nil, err
	}
	d.CreatedAt = time.Unix(created, 0).UTC()
	return &d, nil
}

const deviceColumns = `user_id, device_id, tenant_id, curve25519, ed25519, signature, created_at`

func (s *e2eeStore) GetDevice(ctx context.Context, userID, deviceID string) (*E2EEDevice, error) {
	d, err := scanDevice(s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT `+deviceColumns+` FROM e2ee_devices WHERE user_id = ? AND device_id = ?`), userID, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

func (s *e2eeStore) ListDevices(ctx context.Context, tenantID string, userIDs []string) ([]E2EEDevice, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	args := []any{tenantID}
	for _, id := range userIDs {
		args = append(args, id)
	}
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT `+deviceColumns+` FROM e2ee_devices WHERE tenant_id = ? AND user_id IN (?`+strings.Repeat(", ?", len(userIDs)-1)+`) ORDER BY user_id, device_id`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEDevice
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *e2eeStore) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_devices WHERE user_id = ? AND device_id = ?`), userID, deviceID))
}

func (s *e2eeStore) AddOneTimeKeys(ctx context.Context, userID, deviceID string, keys []E2EEOneTimeKey, max int) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Uploads for one device take turns, so the cap count below sees the other's rows. SQLite
	// already serializes writers; PostgreSQL's READ COMMITTED would let two both pass.
	if s.store.driver == "postgres" {
		if _, err := tx.ExecContext(ctx, s.store.rebind(`SELECT 1 FROM e2ee_devices WHERE user_id = ? AND device_id = ? FOR UPDATE`), userID, deviceID); err != nil {
			return err
		}
	}
	for _, k := range keys {
		if k.Fallback {
			// One live fallback key per device: a new one retires the old, which stays as a
			// tombstone so a stale retry of an older upload cannot bring it back.
			var seen int
			if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*) FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 1 AND key_id = ?`), userID, deviceID, k.KeyID).Scan(&seen); err != nil {
				return err
			}
			if seen > 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_one_time_keys SET claimed = 1 WHERE user_id = ? AND device_id = ? AND fallback = 1 AND claimed = 0`), userID, deviceID); err != nil {
				return err
			}
		}
		fallback := 0
		if k.Fallback {
			fallback = 1
		}
		// A key ID already uploaded keeps its first value, so a retried upload is harmless and
		// an upload cannot swap a key someone may already be using. Claimed keys stay as
		// tombstones, so a retry whose first response was lost cannot publish a spent key again.
		if _, err := tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_one_time_keys (user_id, device_id, key_id, key_value, signature, fallback) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, device_id, fallback, key_id) DO NOTHING`),
			userID, deviceID, k.KeyID, k.Key, k.Signature, fallback); err != nil {
			return err
		}
	}
	// The cap counts what is stored after the upload, so keys already present cost nothing.
	var n int
	if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*) FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 0 AND claimed = 0`), userID, deviceID).Scan(&n); err != nil {
		return err
	}
	if n > max {
		return ErrE2EETooManyKeys
	}
	return tx.Commit()
}

func (s *e2eeStore) CountOneTimeKeys(ctx context.Context, userID, deviceID string) (int, error) {
	var n int
	err := s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*) FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 0 AND claimed = 0`), userID, deviceID).Scan(&n)
	return n, err
}

func (s *e2eeStore) HasFallbackKey(ctx context.Context, userID, deviceID string) (bool, error) {
	var n int
	err := s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*) FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 1 AND claimed = 0`), userID, deviceID).Scan(&n)
	return n > 0, err
}

func (s *e2eeStore) ClaimOneTimeKey(ctx context.Context, userID, deviceID string) (*E2EEOneTimeKey, error) {
	// SQLite serializes writers; PostgreSQL must not send every claim at the same lowest key.
	lock := ""
	if s.store.driver == "postgres" {
		lock = " FOR UPDATE SKIP LOCKED"
	}
	claim := s.store.rebind(`
		UPDATE e2ee_one_time_keys SET claimed = 1
		WHERE user_id = ? AND device_id = ? AND fallback = 0 AND claimed = 0 AND key_id = (
			SELECT key_id FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 0 AND claimed = 0 ORDER BY key_id LIMIT 1` + lock + `)
		RETURNING key_id, key_value, signature`)
	deadline := time.Now().Add(claimBudget)
	for round := 0; ; round++ {
		var k E2EEOneTimeKey
		err := s.store.db.QueryRowContext(ctx, claim, userID, deviceID, userID, deviceID).Scan(&k.KeyID, &k.Key, &k.Signature)
		if err == nil {
			return &k, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		n, err := s.CountOneTimeKeys(ctx, userID, deviceID)
		if err != nil {
			return nil, err
		}
		if n == 0 || time.Now().After(deadline) {
			break // none left (or still contended past the budget): the fallback key
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(min(round+1, 20)) * time.Millisecond):
		}
	}
	k := E2EEOneTimeKey{Fallback: true}
	err := s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT key_id, key_value, signature FROM e2ee_one_time_keys WHERE user_id = ? AND device_id = ? AND fallback = 1 AND claimed = 0`), userID, deviceID).Scan(&k.KeyID, &k.Key, &k.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *e2eeStore) SendToDevice(ctx context.Context, msgs []E2EEToDevice) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	q := s.store.rebind(`INSERT INTO e2ee_to_device (tenant_id, recipient_user, recipient_device, sender_user, sender_device, type, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	for _, m := range msgs {
		if _, err := tx.ExecContext(ctx, q, m.TenantID, m.RecipientUserID, m.RecipientDeviceID, m.SenderUserID, m.SenderDeviceID, m.Type, m.Content, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *e2eeStore) ToDevice(ctx context.Context, userID, deviceID string, limit int) ([]E2EEToDevice, error) {
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`
		SELECT id, tenant_id, recipient_user, recipient_device, sender_user, sender_device, type, content, created_at
		FROM e2ee_to_device WHERE recipient_user = ? AND recipient_device = ? ORDER BY id LIMIT ?`), userID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEToDevice
	for rows.Next() {
		var m E2EEToDevice
		var created int64
		if err := rows.Scan(&m.ID, &m.TenantID, &m.RecipientUserID, &m.RecipientDeviceID, &m.SenderUserID, &m.SenderDeviceID, &m.Type, &m.Content, &created); err != nil {
			return nil, err
		}
		m.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *e2eeStore) AckToDevice(ctx context.Context, userID, deviceID string, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := []any{userID, deviceID}
	for _, id := range ids {
		args = append(args, id)
	}
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_to_device WHERE recipient_user = ? AND recipient_device = ? AND id IN (?`+strings.Repeat(", ?", len(ids)-1)+`)`), args...)
	return err
}

func (s *e2eeStore) PruneToDevice(ctx context.Context, before time.Time) error {
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_to_device WHERE created_at < ?`), before.Unix())
	return err
}
