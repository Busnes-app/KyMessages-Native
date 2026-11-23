package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/ky-primitives/applysetup"
	"strconv"
	"time"
)

// ApplyInstallerDirectory receives authenticated, narrowed directory desired state.
// It updates only an owned subject and preserves role, local credentials and tickets.
// It returns the user ID whose access the event revokes, so callers can end live
// connections; "" when access stays, including a replayed MFA reset.
func (s *SQLStore) ApplyInstallerDirectory(ctx context.Context, issuer, subject, event, version, digest string, active, administrator bool, orgID string) (string, error) {
	revision, err := strconv.ParseUint(version, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != version {
		return "", errors.New("invalid directory revision")
	}
	rawConfig, e := s.Settings().GetSetting(ctx, InstallerConfigKey)
	var config applysetup.Common
	if e != nil || applysetup.DecodeRaw([]byte(rawConfig), &config) != nil || config.SSO == nil || config.SSO.IssuerURL != issuer {
		return "", errors.New("directory issuer not configured")
	}
	managed, _, err := s.InstallerIdentity(ctx, issuer, subject)
	if err != nil || !managed {
		return "", errors.New("directory issuer not configured")
	}
	hash := sha256.Sum256([]byte(issuer + "\x00" + subject))
	key := "installer.user." + hex.EncodeToString(hash[:])
	value, err := s.Settings().GetSetting(ctx, key)
	if err != nil {
		return "", errors.New("directory identity is not assigned")
	}
	var owned installerIdentity
	if json.Unmarshal([]byte(value), &owned) != nil || owned.Issuer != issuer || owned.Subject != subject {
		return "", errors.New("directory identity binding invalid")
	}
	status := "inactive"
	switch event {
	case "user.created", "user.updated", "user.mfa_reset":
		if active && (owned.Role != "admin" || administrator) {
			status = "active"
		}
	case "user.deleted":
		status = "deleted"
	case "user.deactivated":
	default:
		return "", errors.New("unsupported directory event")
	}
	revoked := ""
	if status != "active" || event == "user.mfa_reset" {
		revoked = owned.UserID
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Check binding inside the write transaction, before even accepting a duplicate.
	var storedOrg string
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT org_id FROM users WHERE id=? AND sso_provider='kyidentity' AND sso_subject=?"), owned.UserID, subject).Scan(&storedOrg); err != nil {
		return "", err
	}
	if storedOrg != orgID {
		return "", ErrForbidden
	}
	stateKey := "installer.directory." + hex.EncodeToString(hash[:])
	var prior string
	err = tx.QueryRowContext(ctx, s.rebind("SELECT value FROM server_settings WHERE key=?"), stateKey).Scan(&prior)
	if err == nil {
		var prev struct {
			Revision uint64
			Digest   string
		}
		if json.Unmarshal([]byte(prior), &prev) != nil {
			return "", errors.New("invalid retained directory state")
		}
		if prev.Revision > revision {
			return "", errors.New("stale directory event")
		}
		if prev.Revision == revision {
			if prev.Digest != digest {
				return "", errors.New("conflicting directory revision")
			}
			// A replayed MFA reset must not end sessions signed in since the first
			// delivery; the per-ping check already covers the sessions it deleted.
			if status == "active" {
				return "", nil
			}
			return revoked, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var previousStatus string
	if err = tx.QueryRowContext(ctx, s.rebind("SELECT status FROM users WHERE id=?"), owned.UserID).Scan(&previousStatus); err != nil {
		return "", err
	}
	if previousStatus == "deleted" && status == "active" {
		return "", errors.New("deleted directory identity cannot be reactivated")
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, s.rebind("UPDATE users SET status=?,updated_at=? WHERE id=? AND sso_provider=? AND sso_subject=? AND role=?"), status, now, owned.UserID, "kyidentity", subject, owned.Role)
	if err != nil {
		return "", err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", errors.New("directory identity drifted")
	}
	if revoked != "" {
		if err = revokeSSOGrants(ctx, s, tx, owned.UserID); err != nil {
			return "", err
		}
	}
	next, _ := json.Marshal(struct {
		Revision uint64
		Digest   string
	}{revision, digest})
	if _, err = tx.ExecContext(ctx, s.rebind("INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at"), stateKey, string(next), now); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, s.rebind("INSERT INTO audit_records(user_id,action,resource,details,ip_address,created_at) VALUES(?,?,?,?,?,?)"), owned.UserID, "installer.directory_applied", subject, version, "kyidentity", now); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return revoked, nil
}

func (s *SQLStore) InstallerUserAllowed(ctx context.Context, u *User) (bool, error) {
	if u.SSOProvider != "kyidentity" {
		return true, nil
	}
	raw, err := s.Settings().GetSetting(ctx, InstallerConfigKey)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	var cfg struct {
		SSO struct {
			IssuerURL string `json:"issuerUrl"`
		} `json:"sso"`
	}
	if json.Unmarshal([]byte(raw), &cfg) != nil {
		return false, errors.New("invalid owned issuer")
	}
	hash := sha256.Sum256([]byte(cfg.SSO.IssuerURL + "\x00" + u.SSOSubject))
	value, err := s.Settings().GetSetting(ctx, "installer.user."+hex.EncodeToString(hash[:]))
	if err != nil {
		return false, err
	}
	var owned installerIdentity
	if json.Unmarshal([]byte(value), &owned) != nil || owned.UserID != u.ID || owned.Role != u.Role {
		return false, errors.New("owned identity does not match session")
	}
	_, allowed, err := s.InstallerIdentity(ctx, cfg.SSO.IssuerURL, u.SSOSubject)
	return allowed, err
}
