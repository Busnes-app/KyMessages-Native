package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"
)

func (s *sessionStore) SSOGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := s.store.db.QueryRowContext(ctx, "SELECT generation FROM sso_generation WHERE id = 1").Scan(&generation)
	return generation, err
}

// Every issuance holds the user row through its fence check and commit. Logout takes the
// same row, so either the new grant is swept or it observes the committed revocation.
func checkSSOFence(ctx context.Context, st *SQLStore, tx *sql.Tx, userID string, binding SSOSession) error {
	var count int
	err := tx.QueryRowContext(ctx, st.rebind(`SELECT COUNT(*) FROM sso_revocations WHERE user_id = ? AND
        ((sid <> '' AND (sid = ? OR ? = '')) OR (sid = '' AND (issued_before >= ? OR generation > ?)))`),
		userID, binding.SID, binding.SID, binding.IssuedAt, binding.Generation).Scan(&count)
	if err == nil && count > 0 {
		return ErrNotFound
	}
	return err
}

func recordSSOFence(ctx context.Context, st *SQLStore, tx *sql.Tx, userID, sid string, issuedAt int64) error {
	// A single counter orders callback starts against revocations across replicas without
	// relying on their wall clocks. Only revocations write it; sign-ins read the primary.
	if _, err := tx.ExecContext(ctx, "UPDATE sso_generation SET generation = generation + 1 WHERE id = 1"); err != nil {
		return err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM sso_generation WHERE id = 1").Scan(&generation); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, st.rebind(`INSERT INTO sso_revocations (user_id, sid, issued_before, generation) VALUES (?, ?, ?, ?)
        ON CONFLICT (user_id, sid) DO UPDATE SET
        issued_before = CASE WHEN sso_revocations.issued_before > excluded.issued_before THEN sso_revocations.issued_before ELSE excluded.issued_before END,
        generation = excluded.generation`), userID, sid, issuedAt, generation)
	return err
}

// Reset revisions have their own replay set; profile revisions cannot supersede them.
func recordMFAReset(ctx context.Context, st *SQLStore, tx *sql.Tx, provider, subject, key string) (bool, error) {
	res, err := tx.ExecContext(ctx, st.rebind(`INSERT INTO directory_mfa_resets (provider, subject, reset_key) VALUES (?, ?, ?) ON CONFLICT (provider, subject, reset_key) DO NOTHING`), provider, subject, key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// revokeSSOGrants runs inside the directory revision transaction, including its fence.
func revokeSSOGrants(ctx context.Context, st *SQLStore, tx *sql.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, st.rebind("UPDATE users SET password_hash = ? WHERE id = ?"), "revoked:"+rand.Text(), userID); err != nil {
		return err
	}
	if err := recordSSOFence(ctx, st, tx, userID, "", time.Now().Unix()); err != nil {
		return err
	}
	return deleteGrants(ctx, st, tx, userID)
}

// ApplySSOLogout checks the immutable subject/org binding before spending the jti. The
// replay record, fence and deletions commit together. Records are deliberately permanent.
func (s *sessionStore) ApplySSOLogout(ctx context.Context, issuer, subject, orgID, sid, jti string, issuedAt int64) (string, []string, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	// Lock by subject and org, never by sid alone. A mismatched event changes nothing.
	result, err := tx.ExecContext(ctx, s.store.rebind(`UPDATE users SET id = id
        WHERE sso_provider = 'kyidentity' AND sso_subject = ? AND org_id = ?`), subject, orgID)
	if err != nil {
		return "", nil, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return "", nil, err
	}
	if n != 1 {
		return "", nil, ErrNotFound
	}
	var userID string
	if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT id FROM users WHERE sso_provider = 'kyidentity' AND sso_subject = ? AND org_id = ?`), subject, orgID).Scan(&userID); err != nil {
		return "", nil, err
	}
	result, err = tx.ExecContext(ctx, s.store.rebind(`INSERT INTO sso_logout_events (issuer, jti) VALUES (?, ?) ON CONFLICT (issuer, jti) DO NOTHING`), issuer, jti)
	if err != nil {
		return "", nil, err
	}
	if n, err = result.RowsAffected(); err != nil {
		return "", nil, err
	} else if n != 1 {
		return "", nil, ErrAlreadyExists
	}
	if err := recordSSOFence(ctx, s.store, tx, userID, sid, issuedAt); err != nil {
		return "", nil, err
	}
	predicate := "user_id = ?"
	args := []any{userID}
	if sid != "" {
		// Unbound legacy sessions belong to this already-verified subject/org. With no
		// IdP sid to narrow them further, every logout of that subject must cover them.
		predicate += " AND (sso_sid = ? OR sso_sid = '')"
		args = append(args, sid)
	}
	rows, err := tx.QueryContext(ctx, s.store.rebind("SELECT token_hash FROM sessions WHERE "+predicate), args...)
	if err != nil {
		return "", nil, err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			return "", nil, err
		}
		hashes = append(hashes, hash)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", nil, err
	}
	if _, err := tx.ExecContext(ctx, s.store.rebind("DELETE FROM sessions WHERE "+predicate), args...); err != nil {
		return "", nil, err
	}
	if sid != "" {
		if _, err := tx.ExecContext(ctx, s.store.rebind("DELETE FROM device_pairings WHERE user_id = ? AND sso_sid = ?"), userID, sid); err != nil {
			return "", nil, err
		}
	}
	if sid != "" {
		// Delete after sessions: registration locks its session through commit, so a
		// concurrent registration is either refused or included in this sweep.
		if _, err := tx.ExecContext(ctx, s.store.rebind("DELETE FROM push_subscriptions WHERE user_id = ? AND sso_sid = ?"), userID, sid); err != nil {
			return "", nil, err
		}
	}
	if sid == "" {
		if err := deleteGrants(ctx, s.store, tx, userID); err != nil {
			return "", nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return userID, hashes, nil
}
