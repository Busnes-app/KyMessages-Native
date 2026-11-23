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
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrNotFound
	}
	err = tx.QueryRowContext(ctx, st.rebind(`SELECT COUNT(*) FROM sso_subject_revocations r JOIN users u ON u.id = ?
        WHERE u.sso_provider = 'kyidentity' AND r.subject = u.sso_subject AND r.org_id = u.org_id AND (r.issuer = ? OR ? = '')
        AND ((r.sid <> '' AND (r.sid = ? OR ? = '')) OR (r.sid = '' AND (r.issued_before >= ? OR r.generation > ?)))`),
		userID, binding.Issuer, binding.Issuer, binding.SID, binding.SID, binding.IssuedAt, binding.Generation).Scan(&count)
	if err == nil && count > 0 {
		return ErrNotFound
	}
	return err
}

// The identity row exists before an account does. Both logout and grant issuance lock it
// before the user row, so first-login provisioning cannot race past a logout fence.
func lockSSOIdentity(ctx context.Context, st *SQLStore, tx *sql.Tx, subject, orgID string) error {
	_, err := tx.ExecContext(ctx, st.rebind(`INSERT INTO sso_identities (subject,org_id) VALUES (?,?) ON CONFLICT (subject,org_id) DO UPDATE SET subject=excluded.subject`), subject, orgID)
	return err
}

func nextSSOGeneration(ctx context.Context, tx *sql.Tx) (int64, error) {
	// Only revocations advance this counter; ordinary callback starts read the primary.
	if _, err := tx.ExecContext(ctx, "UPDATE sso_generation SET generation = generation + 1 WHERE id = 1"); err != nil {
		return 0, err
	}
	var generation int64
	err := tx.QueryRowContext(ctx, "SELECT generation FROM sso_generation WHERE id = 1").Scan(&generation)
	return generation, err
}

func recordSSOFence(ctx context.Context, st *SQLStore, tx *sql.Tx, userID, sid string, issuedAt int64) error {
	generation, err := nextSSOGeneration(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, st.rebind(`INSERT INTO sso_revocations (user_id,sid,issued_before,generation) VALUES (?,?,?,?)
        ON CONFLICT (user_id,sid) DO UPDATE SET
        issued_before=CASE WHEN sso_revocations.issued_before>excluded.issued_before THEN sso_revocations.issued_before ELSE excluded.issued_before END,
        generation=excluded.generation`), userID, sid, issuedAt, generation)
	return err
}

func recordSubjectFence(ctx context.Context, st *SQLStore, tx *sql.Tx, issuer, subject, orgID, sid string, issuedAt int64) error {
	generation, err := nextSSOGeneration(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, st.rebind(`INSERT INTO sso_subject_revocations (issuer,subject,org_id,sid,issued_before,generation) VALUES (?,?,?,?,?,?)
        ON CONFLICT (issuer,subject,org_id,sid) DO UPDATE SET
        issued_before=CASE WHEN sso_subject_revocations.issued_before>excluded.issued_before THEN sso_subject_revocations.issued_before ELSE excluded.issued_before END,
        generation=excluded.generation`), issuer, subject, orgID, sid, issuedAt, generation)
	return err
}

// Reset revisions have their own replay set; profile revisions cannot supersede them.
func recordMFAReset(ctx context.Context, st *SQLStore, tx *sql.Tx, provider, subject, key string) (bool, error) {
	// Serialize reset admission with a restore resend's generation change. SQLite's
	// write transaction and PostgreSQL's row lock provide the same ordering.
	if _, err := tx.ExecContext(ctx, st.rebind(`UPDATE directory_sync_state SET restore_generation = restore_generation WHERE provider = ? AND subject = ?`), provider, subject); err != nil {
		return false, err
	}
	var generation int64
	err := tx.QueryRowContext(ctx, st.rebind(`SELECT restore_generation FROM directory_sync_state WHERE provider = ? AND subject = ?`), provider, subject).Scan(&generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	res, err := tx.ExecContext(ctx, st.rebind(`INSERT INTO directory_mfa_resets (provider, subject, restore_generation, reset_key) VALUES (?, ?, ?, ?) ON CONFLICT (provider, subject, restore_generation, reset_key) DO NOTHING`), provider, subject, generation, key)
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
	if err := lockSSOIdentity(ctx, s.store, tx, subject, orgID); err != nil {
		return "", nil, err
	}
	// Compare every existing binding before spending the jti or retaining any fence.
	// An absent account is allowed: the verified identity still owns a durable logout.
	var userID, accountOrg string
	var count int
	if err := tx.QueryRowContext(ctx, s.store.rebind(`SELECT COUNT(*),COALESCE(MAX(id),''),COALESCE(MAX(org_id),'') FROM users WHERE sso_provider='kyidentity' AND sso_subject=?`), subject).Scan(&count, &userID, &accountOrg); err != nil {
		return "", nil, err
	}
	if count > 1 || (count == 1 && accountOrg != orgID) {
		return "", nil, ErrNotFound
	}
	if count == 1 {
		if err := oneRow(tx.ExecContext(ctx, s.store.rebind(`UPDATE users SET id=id WHERE id=? AND sso_provider='kyidentity' AND sso_subject=? AND org_id=?`), userID, subject, orgID)); err != nil {
			return "", nil, err
		}
	}
	result, err := tx.ExecContext(ctx, s.store.rebind(`INSERT INTO sso_logout_events (issuer, jti) VALUES (?, ?) ON CONFLICT (issuer, jti) DO NOTHING`), issuer, jti)
	if err != nil {
		return "", nil, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return "", nil, err
	} else if n != 1 {
		return "", nil, ErrAlreadyExists
	}
	if err := recordSubjectFence(ctx, s.store, tx, issuer, subject, orgID, sid, issuedAt); err != nil {
		return "", nil, err
	}
	if userID == "" {
		return "", nil, tx.Commit()
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
