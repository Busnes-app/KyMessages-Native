package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// E3 identity rows (migration 68). Every write that depends on the master key version checks
// it in the same statement or transaction, so a reset cannot interleave with a stale write.

const masterColumns = `user_id, tenant_id, version, master_key, self_signature, backup_key, backup_signature, recovery_master, recovery_backup, pins_counter, pins, updated_at`

func scanMaster(sc interface{ Scan(...any) error }) (*E2EEMasterKey, error) {
	var m E2EEMasterKey
	var updated int64
	if err := sc.Scan(&m.UserID, &m.TenantID, &m.Version, &m.MasterKey, &m.SelfSignature, &m.BackupKey, &m.BackupSignature, &m.RecoveryMaster, &m.RecoveryBackup, &m.PinsCounter, &m.Pins, &updated); err != nil {
		return nil, err
	}
	m.UpdatedAt = time.Unix(updated, 0).UTC()
	return &m, nil
}

func (s *e2eeStore) GetMasterKey(ctx context.Context, userID string) (*E2EEMasterKey, error) {
	m, err := scanMaster(s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT `+masterColumns+` FROM e2ee_master_keys WHERE user_id = ?`), userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

func (s *e2eeStore) ListMasterKeys(ctx context.Context, tenantID string, userIDs []string) ([]E2EEMasterKey, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	args := []any{tenantID}
	for _, id := range userIDs {
		args = append(args, id)
	}
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT `+masterColumns+` FROM e2ee_master_keys WHERE tenant_id = ? AND user_id IN (?`+strings.Repeat(", ?", len(userIDs)-1)+`) ORDER BY user_id`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEMasterKey
	for rows.Next() {
		m, err := scanMaster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *e2eeStore) PutMasterKey(ctx context.Context, m *E2EEMasterKey, expected int64) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	version := expected + 1
	var res sql.Result
	if expected == 0 {
		res, err = tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_master_keys (`+masterColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?) ON CONFLICT (user_id) DO NOTHING`),
			m.UserID, m.TenantID, version, m.MasterKey, m.SelfSignature, m.BackupKey, m.BackupSignature, m.RecoveryMaster, m.RecoveryBackup, now)
	} else {
		res, err = tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET version = ?, master_key = ?, self_signature = ?, backup_key = ?, backup_signature = ?, recovery_master = ?, recovery_backup = ?, pins_counter = 0, pins = '', updated_at = ? WHERE user_id = ? AND tenant_id = ? AND version = ?`),
			version, m.MasterKey, m.SelfSignature, m.BackupKey, m.BackupSignature, m.RecoveryMaster, m.RecoveryBackup, now, m.UserID, m.TenantID, expected)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrE2EEVersion
	}
	// A new identity: nothing the old master key vouched for or could open stays.
	for _, q := range []string{
		`DELETE FROM e2ee_key_backup WHERE user_id = ?`,
		`UPDATE e2ee_devices SET master_signature = '', master_version = 0 WHERE user_id = ?`,
		`DELETE FROM e2ee_pairings WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, s.store.rebind(q), m.UserID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.Version, m.PinsCounter, m.Pins, m.UpdatedAt = version, 0, "", time.Unix(now, 0).UTC()
	return nil
}

func (s *e2eeStore) SignDevice(ctx context.Context, userID, deviceID string, version int64, signature string) error {
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_devices SET master_signature = ?, master_version = ?
		WHERE user_id = ? AND device_id = ? AND EXISTS (SELECT 1 FROM e2ee_master_keys m WHERE m.user_id = ? AND m.version = ?)`),
		signature, version, userID, deviceID, userID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := s.GetDevice(ctx, userID, deviceID); err != nil {
		return err
	}
	return ErrE2EEVersion
}

func (s *e2eeStore) PutPins(ctx context.Context, userID string, version, expected int64, pins string) error {
	res, err := s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET pins = ?, pins_counter = ? WHERE user_id = ? AND version = ? AND pins_counter = ?`),
		pins, expected+1, userID, version, expected)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrE2EEVersion
	}
	return nil
}

// lockVersion reads the user's master key version inside tx, locking the row on PostgreSQL so
// a concurrent reset or backup write waits; ErrE2EEVersion unless it is version.
func (s *e2eeStore) lockVersion(ctx context.Context, tx *sql.Tx, userID string, version int64) error {
	lock := ""
	if s.store.driver == "postgres" {
		lock = " FOR UPDATE"
	}
	var cur int64
	err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT version FROM e2ee_master_keys WHERE user_id = ?`+lock), userID).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && cur != version) {
		return ErrE2EEVersion
	}
	return err
}

func (s *e2eeStore) PutBackupSessions(ctx context.Context, userID string, version int64, sessions []E2EEBackupSession, max int) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.lockVersion(ctx, tx, userID, version); err != nil {
		return err
	}
	now := time.Now().Unix()
	q := s.store.rebind(`INSERT INTO e2ee_key_backup (user_id, tenant_id, version, room_id, session_id, first_index, sealed, updated_at)
		SELECT user_id, tenant_id, version, ?, ?, ?, ?, ? FROM e2ee_master_keys WHERE user_id = ?
		ON CONFLICT (user_id, version, room_id, session_id) DO UPDATE SET first_index = excluded.first_index, sealed = excluded.sealed, updated_at = excluded.updated_at
		WHERE excluded.first_index < e2ee_key_backup.first_index`)
	for _, b := range sessions {
		if _, err := tx.ExecContext(ctx, q, b.RoomID, b.SessionID, b.FirstIndex, b.Sealed, now, userID); err != nil {
			return err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*) FROM e2ee_key_backup WHERE user_id = ? AND version = ?`), userID, version).Scan(&n); err != nil {
		return err
	}
	if n > max {
		return ErrE2EEBackupFull
	}
	return tx.Commit()
}

func (s *e2eeStore) ListBackupSessions(ctx context.Context, userID string, version int64, afterRoom, afterSession string, limit int) ([]E2EEBackupSession, error) {
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT room_id, session_id, first_index, sealed FROM e2ee_key_backup
		WHERE user_id = ? AND version = ? AND (room_id > ? OR (room_id = ? AND session_id > ?)) ORDER BY room_id, session_id LIMIT ?`),
		userID, version, afterRoom, afterRoom, afterSession, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEBackupSession
	for rows.Next() {
		var b E2EEBackupSession
		if err := rows.Scan(&b.RoomID, &b.SessionID, &b.FirstIndex, &b.Sealed); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *e2eeStore) DeleteBackup(ctx context.Context, userID string, version int64) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.lockVersion(ctx, tx, userID, version); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_key_backup WHERE user_id = ? AND version = ?`), userID, version); err != nil {
		return err
	}
	return tx.Commit()
}

// --- QR pairings ---

const pairingColumns = `id, tenant_id, user_id, initiator_device, new_device, ephemeral_key, sealed, expires_at`

func scanPairing(sc interface{ Scan(...any) error }) (*E2EEPairing, error) {
	var p E2EEPairing
	var exp int64
	if err := sc.Scan(&p.ID, &p.TenantID, &p.UserID, &p.InitiatorDevice, &p.NewDevice, &p.EphemeralKey, &p.Sealed, &exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.ExpiresAt = time.Unix(exp, 0).UTC()
	return &p, nil
}

func (s *e2eeStore) CreatePairing(ctx context.Context, p *E2EEPairing) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE user_id = ?`), p.UserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_pairings (`+pairingColumns+`) VALUES (?, ?, ?, ?, '', '', '', ?)`),
		p.ID, p.TenantID, p.UserID, p.InitiatorDevice, p.ExpiresAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *e2eeStore) GetPairing(ctx context.Context, tenantID, userID, id string, now time.Time) (*E2EEPairing, error) {
	return scanPairing(s.store.db.QueryRowContext(ctx, s.store.rebind(`SELECT `+pairingColumns+` FROM e2ee_pairings WHERE id = ? AND tenant_id = ? AND user_id = ? AND expires_at > ?`),
		id, tenantID, userID, now.Unix()))
}

func (s *e2eeStore) JoinPairing(ctx context.Context, tenantID, userID, id, newDevice, ephemeralKey string, now time.Time) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_pairings SET new_device = ?, ephemeral_key = ?
		WHERE id = ? AND tenant_id = ? AND user_id = ? AND new_device = '' AND initiator_device <> ? AND expires_at > ?`),
		newDevice, ephemeralKey, id, tenantID, userID, newDevice, now.Unix()))
}

func (s *e2eeStore) SealPairing(ctx context.Context, tenantID, userID, id, initiator, sealed string, now time.Time) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_pairings SET sealed = ?
		WHERE id = ? AND tenant_id = ? AND user_id = ? AND initiator_device = ? AND new_device <> '' AND sealed = '' AND expires_at > ?`),
		sealed, id, tenantID, userID, initiator, now.Unix()))
}

func (s *e2eeStore) ConsumePairing(ctx context.Context, tenantID, userID, id, newDevice string, now time.Time) (*E2EEPairing, error) {
	return scanPairing(s.store.db.QueryRowContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings
		WHERE id = ? AND tenant_id = ? AND user_id = ? AND new_device = ? AND sealed <> '' AND expires_at > ?
		RETURNING `+pairingColumns), id, tenantID, userID, newDevice, now.Unix()))
}

func (s *e2eeStore) DeletePairing(ctx context.Context, tenantID, userID, id string) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE id = ? AND tenant_id = ? AND user_id = ?`), id, tenantID, userID))
}

func (s *e2eeStore) PrunePairings(ctx context.Context, now time.Time) error {
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE expires_at <= ?`), now.Unix())
	return err
}
