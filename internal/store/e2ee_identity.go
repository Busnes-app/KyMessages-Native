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

const masterColumns = `user_id, tenant_id, version, master_key, self_signature, backup_key, backup_signature, recovery_master, recovery_backup, pins_counter, pins, device_list, device_list_epoch, device_list_signature, backup_generation, updated_at`

func scanMaster(sc interface{ Scan(...any) error }) (*E2EEMasterKey, error) {
	var m E2EEMasterKey
	var updated int64
	if err := sc.Scan(&m.UserID, &m.TenantID, &m.Version, &m.MasterKey, &m.SelfSignature, &m.BackupKey, &m.BackupSignature, &m.RecoveryMaster, &m.RecoveryBackup, &m.PinsCounter, &m.Pins, &m.DeviceList, &m.DeviceListEpoch, &m.DeviceListSignature, &m.BackupGeneration, &updated); err != nil {
		return nil, err
	}
	m.UpdatedAt = time.Unix(updated, 0).UTC()
	return &m, nil
}

// publicMasterColumns is what a key query needs of a colleague's identity: never the wraps,
// the pin set or the backup key.
const publicMasterColumns = `user_id, tenant_id, version, master_key, self_signature, device_list, device_list_epoch, device_list_signature`

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
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT `+publicMasterColumns+` FROM e2ee_master_keys WHERE tenant_id = ? AND user_id IN (?`+strings.Repeat(", ?", len(userIDs)-1)+`) ORDER BY user_id`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEMasterKey
	for rows.Next() {
		var m E2EEMasterKey
		if err := rows.Scan(&m.UserID, &m.TenantID, &m.Version, &m.MasterKey, &m.SelfSignature, &m.DeviceList, &m.DeviceListEpoch, &m.DeviceListSignature); err != nil {
			return nil, err
		}
		out = append(out, m)
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
		// A row this user left in another org (org IDs are immutable, so only a restore or a
		// manual move makes one) would block the first setup in this org forever: drop it.
		for _, q := range []string{
			`DELETE FROM e2ee_key_backup WHERE user_id = ? AND tenant_id <> ?`,
			`DELETE FROM e2ee_pairings WHERE user_id = ? AND tenant_id <> ?`,
			`DELETE FROM e2ee_master_keys WHERE user_id = ? AND tenant_id <> ?`,
		} {
			if _, err := tx.ExecContext(ctx, s.store.rebind(q), m.UserID, m.TenantID); err != nil {
				return err
			}
		}
		res, err = tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_master_keys (`+masterColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', 0, '', 0, ?) ON CONFLICT (user_id) DO NOTHING`),
			m.UserID, m.TenantID, version, m.MasterKey, m.SelfSignature, m.BackupKey, m.BackupSignature, m.RecoveryMaster, m.RecoveryBackup, now)
	} else {
		res, err = tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET version = ?, master_key = ?, self_signature = ?, backup_key = ?, backup_signature = ?, recovery_master = ?, recovery_backup = ?, pins_counter = 0, pins = '', device_list = '', device_list_epoch = 0, device_list_signature = '', device_list_reserved = '', device_list_reserved_until = 0, device_list_reserved_epoch = 0, backup_generation = 0, updated_at = ? WHERE user_id = ? AND tenant_id = ? AND version = ?`),
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
	m.DeviceList, m.DeviceListEpoch, m.DeviceListSignature, m.BackupGeneration = "", 0, "", 0
	return nil
}

// Proof checks a write's signature against the master key of the identity version the write
// names. Stores call it inside the write's transaction, with that master row locked, so the key
// that verified the proof is the key current when the write commits.
type Proof func(masterKey string) error

// lockMaster reads the master key of (tenant, user) at version inside tx, locking the row on
// PostgreSQL so a concurrent reset or other identity write waits; ErrE2EEVersion unless the row
// exists at exactly that version in that org. SQLite serializes writers.
func (s *e2eeStore) lockMaster(ctx context.Context, tx *sql.Tx, tenantID, userID string, version int64) (string, error) {
	lock := ""
	if s.store.driver == "postgres" {
		lock = " FOR UPDATE"
	}
	var key string
	err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT master_key FROM e2ee_master_keys WHERE user_id = ? AND tenant_id = ? AND version = ?`+lock), userID, tenantID, version).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrE2EEVersion
	}
	return key, err
}

// fenced runs fn in a transaction holding the master row at version, after proof verifies.
func (s *e2eeStore) fenced(ctx context.Context, tenantID, userID string, version int64, proof Proof, fn func(tx *sql.Tx) error) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	key, err := s.lockMaster(ctx, tx, tenantID, userID, version)
	if err != nil {
		return err
	}
	if err := proof(key); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *e2eeStore) SignDevice(ctx context.Context, tenantID, userID, deviceID string, version int64, signature string, proof func(masterKey string, d *E2EEDevice) error) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	key, err := s.lockMaster(ctx, tx, tenantID, userID, version)
	if err != nil {
		return err
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, s.store.rebind(`SELECT `+deviceColumns+` FROM e2ee_devices WHERE user_id = ? AND device_id = ? AND tenant_id = ?`), userID, deviceID, tenantID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := proof(key, d); err != nil {
		return err
	}
	// The reset that clears cross-signatures updates the master row this transaction holds, so
	// a signature by an older key cannot land after it.
	if err := oneRow(tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_devices SET master_signature = ?, master_version = ? WHERE user_id = ? AND device_id = ? AND tenant_id = ?`),
		signature, version, userID, deviceID, tenantID)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *e2eeStore) PutPins(ctx context.Context, tenantID, userID string, version, expected int64, pins string, proof Proof) error {
	return s.fenced(ctx, tenantID, userID, version, proof, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET pins = ?, pins_counter = ? WHERE user_id = ? AND tenant_id = ? AND version = ? AND pins_counter = ?`),
			pins, expected+1, userID, tenantID, version, expected)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrE2EEVersion
		}
		return nil
	})
}

// ReserveDeviceList is the device list's tentative state: one proposed successor at a time,
// which only its proposer signs. A proposal that loses the reservation is never signed, so it
// cannot later be shown as a signed successor.
func (s *e2eeStore) ReserveDeviceList(ctx context.Context, tenantID, userID string, version, expected int64, digest string, now time.Time, ttl time.Duration, proof Proof) (E2EEReservation, error) {
	until := now.Add(ttl).Unix()
	var res E2EEReservation
	refused := false
	err := s.fenced(ctx, tenantID, userID, version, proof, func(tx *sql.Tx) error {
		// Right-hand sides read the row as it was: the same digest keeps its epoch, another one
		// gets the next above both the list and every epoch granted before.
		var epoch int64
		err := tx.QueryRowContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET
				device_list_reserved_epoch = CASE WHEN device_list_reserved = ? AND device_list_reserved_epoch > device_list_epoch THEN device_list_reserved_epoch
					WHEN device_list_reserved_epoch > device_list_epoch THEN device_list_reserved_epoch + 1 ELSE device_list_epoch + 1 END,
				device_list_reserved = ?, device_list_reserved_until = ?
			WHERE user_id = ? AND tenant_id = ? AND version = ? AND device_list_epoch = ? AND (device_list_reserved = ? OR device_list_reserved_until <= ?)
			RETURNING device_list_reserved_epoch`),
			digest, digest, until, userID, tenantID, version, expected, digest, now.Unix()).Scan(&epoch)
		if err == nil {
			res = E2EEReservation{Epoch: epoch, Until: time.Unix(until, 0)}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// Refused: say when the holder's reservation lapses, if that is what is in the way.
		refused = true
		var listEpoch, held int64
		if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT device_list_epoch, device_list_reserved_until FROM e2ee_master_keys WHERE user_id = ? AND tenant_id = ? AND version = ?`),
			userID, tenantID, version).Scan(&listEpoch, &held); err != nil {
			return err
		}
		if listEpoch == expected && held > now.Unix() {
			res = E2EEReservation{Until: time.Unix(held, 0)}
		}
		return nil
	})
	if err != nil {
		return E2EEReservation{}, err
	}
	if refused {
		return res, ErrE2EEVersion
	}
	return res, nil
}

func (s *e2eeStore) PutDeviceList(ctx context.Context, tenantID, userID string, version, expected, epoch int64, list, digest, signature string, now func() time.Time, proof Proof) error {
	return s.fenced(ctx, tenantID, userID, version, proof, func(tx *sql.Tx) error {
		// The finalized state: published only under its own live reservation, at its epoch,
		// which it ends (the epoch stays granted). Live is judged now, holding the row lock, not
		// when the request arrived: a write that waited on the lock past the lease is refused.
		res, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET device_list = ?, device_list_signature = ?, device_list_epoch = ?, device_list_reserved = '', device_list_reserved_until = 0
			WHERE user_id = ? AND tenant_id = ? AND version = ? AND device_list_epoch = ? AND device_list_reserved = ? AND device_list_reserved_epoch = ? AND device_list_reserved_until > ?`),
			list, signature, epoch, userID, tenantID, version, expected, digest, epoch, now().Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrE2EEVersion
		}
		return nil
	})
}

func (s *e2eeStore) PutBackupSessions(ctx context.Context, tenantID, userID string, version, generation int64, sessions []E2EEBackupSession, maxSessions int, maxBytes int64, proof Proof) (E2EEBackupResult, error) {
	var out E2EEBackupResult
	err := s.fenced(ctx, tenantID, userID, version, proof, func(tx *sql.Tx) error {
		// The master row is locked, so a deletion cannot bump the generation meanwhile.
		var gen int64
		if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT backup_generation FROM e2ee_master_keys WHERE user_id = ?`), userID).Scan(&gen); err != nil {
			return err
		}
		if gen != generation {
			return ErrE2EEVersion
		}
		var n int
		var bytes int64
		if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*), COALESCE(SUM(LENGTH(sealed)), 0) FROM e2ee_key_backup WHERE user_id = ? AND tenant_id = ? AND version = ?`),
			userID, tenantID, version).Scan(&n, &bytes); err != nil {
			return err
		}
		now := time.Now().Unix()
		for i, b := range sessions {
			// A copy reaching further back replaces the stored one without taking a new row,
			// as long as its bytes fit.
			var cur int64
			var curLen int64
			err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT first_index, LENGTH(sealed) FROM e2ee_key_backup WHERE user_id = ? AND tenant_id = ? AND version = ? AND room_id = ? AND sender_key = ? AND session_id = ?`),
				userID, tenantID, version, b.RoomID, b.SenderKey, b.SessionID).Scan(&cur, &curLen)
			switch {
			case err == nil && b.FirstIndex < cur:
				if bytes-curLen+int64(len(b.Sealed)) > maxBytes {
					out.Refused = append(out.Refused, i)
					continue
				}
				if _, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_key_backup SET first_index = ?, sealed = ?, updated_at = ? WHERE user_id = ? AND tenant_id = ? AND version = ? AND room_id = ? AND sender_key = ? AND session_id = ?`),
					b.FirstIndex, b.Sealed, now, userID, tenantID, version, b.RoomID, b.SenderKey, b.SessionID); err != nil {
					return err
				}
				bytes += int64(len(b.Sealed)) - curLen
				out.Stored++
			case err == nil:
				out.Kept++
			case errors.Is(err, sql.ErrNoRows):
				if n+1 > maxSessions || bytes+int64(len(b.Sealed)) > maxBytes {
					out.Refused = append(out.Refused, i)
					continue
				}
				if _, err := tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_key_backup (user_id, tenant_id, version, room_id, sender_key, session_id, first_index, sealed, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
					userID, tenantID, version, b.RoomID, b.SenderKey, b.SessionID, b.FirstIndex, b.Sealed, now); err != nil {
					return err
				}
				n++
				bytes += int64(len(b.Sealed))
				out.Stored++
			default:
				return err
			}
		}
		return nil
	})
	return out, err
}

func (s *e2eeStore) ListBackupSessions(ctx context.Context, tenantID, userID string, version int64, after E2EEBackupCursor, limit int) ([]E2EEBackupSession, error) {
	// The key columns compare bytewise on both engines (COLLATE "C" on PostgreSQL), as the
	// client's cursor check does.
	rows, err := s.store.db.QueryContext(ctx, s.store.rebind(`SELECT room_id, sender_key, session_id, first_index, sealed FROM e2ee_key_backup
		WHERE user_id = ? AND tenant_id = ? AND version = ? AND (room_id > ? OR (room_id = ? AND (sender_key > ? OR (sender_key = ? AND session_id > ?))))
		ORDER BY room_id, sender_key, session_id LIMIT ?`),
		userID, tenantID, version, after.RoomID, after.RoomID, after.SenderKey, after.SenderKey, after.SessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EEBackupSession
	for rows.Next() {
		var b E2EEBackupSession
		if err := rows.Scan(&b.RoomID, &b.SenderKey, &b.SessionID, &b.FirstIndex, &b.Sealed); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *e2eeStore) DeleteBackup(ctx context.Context, tenantID, userID string, version int64) (int64, error) {
	var gen int64
	err := s.fenced(ctx, tenantID, userID, version, func(string) error { return nil }, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_key_backup WHERE user_id = ? AND tenant_id = ? AND version = ?`), userID, tenantID, version); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE e2ee_master_keys SET backup_generation = backup_generation + 1 WHERE user_id = ?`), userID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, s.store.rebind(`SELECT backup_generation FROM e2ee_master_keys WHERE user_id = ?`), userID).Scan(&gen)
	})
	return gen, err
}

// --- QR pairings ---

const pairingColumns = `id, tenant_id, user_id, initiator_device, master_version, new_device, ephemeral_key, sealed, expires_at`

func scanPairing(sc interface{ Scan(...any) error }) (*E2EEPairing, error) {
	var p E2EEPairing
	var exp int64
	if err := sc.Scan(&p.ID, &p.TenantID, &p.UserID, &p.InitiatorDevice, &p.MasterVersion, &p.NewDevice, &p.EphemeralKey, &p.Sealed, &exp); err != nil {
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
	// Fenced on the identity: a reset that commits first leaves this nothing to start from.
	if _, err := s.lockMaster(ctx, tx, p.TenantID, p.UserID, p.MasterVersion); err != nil {
		return err
	}
	var signed int64
	err = tx.QueryRowContext(ctx, s.store.rebind(`SELECT master_version FROM e2ee_devices WHERE user_id = ? AND device_id = ? AND tenant_id = ? AND master_signature <> ''`),
		p.UserID, p.InitiatorDevice, p.TenantID).Scan(&signed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && signed != p.MasterVersion) {
		return ErrE2EEVersion
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE user_id = ?`), p.UserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.store.rebind(`INSERT INTO e2ee_pairings (`+pairingColumns+`) VALUES (?, ?, ?, ?, ?, '', '', '', ?)`),
		p.ID, p.TenantID, p.UserID, p.InitiatorDevice, p.MasterVersion, p.ExpiresAt.Unix()); err != nil {
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

func (s *e2eeStore) DeletePairingUnsealed(ctx context.Context, tenantID, userID, id string) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE id = ? AND tenant_id = ? AND user_id = ? AND sealed = ''`), id, tenantID, userID))
}

func (s *e2eeStore) DeletePairing(ctx context.Context, tenantID, userID, id string) error {
	return oneRow(s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE id = ? AND tenant_id = ? AND user_id = ?`), id, tenantID, userID))
}

func (s *e2eeStore) PrunePairings(ctx context.Context, now time.Time) error {
	_, err := s.store.db.ExecContext(ctx, s.store.rebind(`DELETE FROM e2ee_pairings WHERE expires_at <= ?`), now.Unix())
	return err
}
