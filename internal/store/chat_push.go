package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// ErrInvalidInput indicates a caller supplied invalid store arguments.
var ErrInvalidInput = errors.New("invalid input")

// ValidNotifyMode reports whether mode is a recognized room notification mode.
func ValidNotifyMode(mode string) bool {
	switch mode {
	case NotifyModeAll, NotifyModeMentions, NotifyModeMute:
		return true
	default:
		return false
	}
}

// UpdateRoomNotifyMode updates a member's notification preference for a room.
func (c *chatStore) UpdateRoomNotifyMode(ctx context.Context, tenantID, roomID, userID, mode string) error {
	tenantID = normalizeTenant(tenantID)
	if !ValidNotifyMode(mode) {
		return ErrInvalidInput
	}
	res, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		UPDATE room_members
		SET notify_mode = ?
		WHERE tenant_id = ? AND room_id = ? AND user_id = ?
	`), mode, tenantID, roomID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertPushSubscription stores or updates a Web Push subscription owned by (sub.TenantID, sub.UserID),
// enforcing maxPerUser by evicting the oldest subscriptions for that user when the cap is exceeded.
func (c *chatStore) UpsertPushSubscription(ctx context.Context, sub *PushSubscription, maxPerUser int) (*PushSubscription, error) {
	if sub == nil || sub.UserID == "" || sub.Endpoint == "" || sub.P256DH == "" || sub.AuthSecret == "" {
		return nil, ErrInvalidInput
	}
	tenantID := normalizeTenant(sub.TenantID)
	now := nowMilli()
	ua := sub.UserAgent
	if len(ua) > 255 {
		ua = ua[:255]
	}

	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var existingID, existingTenant, existingUser string
	var existingCreated, existingUsed int64
	err = tx.QueryRowContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, user_id, created_at, last_used_at
		FROM push_subscriptions
		WHERE endpoint = ?
	`), sub.Endpoint).Scan(&existingID, &existingTenant, &existingUser, &existingCreated, &existingUsed)

	out := &PushSubscription{
		TenantID:   tenantID,
		UserID:     sub.UserID,
		Endpoint:   sub.Endpoint,
		P256DH:     sub.P256DH,
		AuthSecret: sub.AuthSecret,
		UserAgent:  ua,
	}

	switch {
	case err == nil && existingTenant == tenantID && existingUser == sub.UserID:
		out.ID = existingID
		out.CreatedAt = existingCreated
		out.LastUsedAt = existingUsed
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			UPDATE push_subscriptions
			SET p256dh = ?, auth_secret = ?, user_agent = ?
			WHERE id = ?
		`), out.P256DH, out.AuthSecret, out.UserAgent, out.ID); err != nil {
			return nil, err
		}
	case err == nil || errors.Is(err, sql.ErrNoRows):
		// Transfer endpoint ownership atomically when a shared browser switches accounts:
		// delete the prior owner's row and insert a fresh ID so in-flight delivery handles
		// for the previous owner cannot touch the new owner's subscription.
		if err == nil {
			if _, err := tx.ExecContext(ctx, c.store.rebind(`
				DELETE FROM push_subscriptions WHERE endpoint = ?
			`), sub.Endpoint); err != nil {
				return nil, err
			}
		}
		out.ID = "ps_" + uuid.Must(uuid.NewV7()).String()
		out.CreatedAt = now
		out.LastUsedAt = 0
		if _, err := tx.ExecContext(ctx, c.store.rebind(`
			INSERT INTO push_subscriptions
				(id, tenant_id, user_id, endpoint, p256dh, auth_secret, user_agent, created_at, last_used_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
		`), out.ID, out.TenantID, out.UserID, out.Endpoint, out.P256DH, out.AuthSecret, out.UserAgent, out.CreatedAt); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if maxPerUser > 0 {
		rows, err := tx.QueryContext(ctx, c.store.rebind(`
			SELECT id FROM push_subscriptions
			WHERE tenant_id = ? AND user_id = ?
			ORDER BY created_at DESC, id DESC
		`), tenantID, sub.UserID)
		if err != nil {
			return nil, err
		}
		var allIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return nil, err
			}
			allIDs = append(allIDs, id)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(allIDs) > maxPerUser {
			for _, staleID := range allIDs[maxPerUser:] {
				if _, err := tx.ExecContext(ctx, c.store.rebind(`DELETE FROM push_subscriptions WHERE id = ?`), staleID); err != nil {
					return nil, err
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPushSubscriptions returns all push subscriptions owned by (tenantID, userID).
func (c *chatStore) ListPushSubscriptions(ctx context.Context, tenantID, userID string) ([]*PushSubscription, error) {
	tenantID = normalizeTenant(tenantID)
	rows, err := c.store.readDB.QueryContext(ctx, c.store.rebind(`
		SELECT id, tenant_id, user_id, endpoint, p256dh, auth_secret, user_agent, created_at, last_used_at
		FROM push_subscriptions
		WHERE tenant_id = ? AND user_id = ?
		ORDER BY created_at DESC
	`), tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPushSubscriptions(rows)
}

// ListPushSubscriptionsForUsers batch-loads active-account push subscriptions for userIDs in tenantID.
func (c *chatStore) ListPushSubscriptionsForUsers(ctx context.Context, tenantID string, userIDs []string) ([]*PushSubscription, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	tenantID = normalizeTenant(tenantID)
	placeholders := strings.Repeat("?,", len(userIDs))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, 1+len(userIDs))
	args = append(args, tenantID)
	for _, uid := range userIDs {
		args = append(args, uid)
	}
	q := c.store.rebind(`
		SELECT ps.id, ps.tenant_id, ps.user_id, ps.endpoint, ps.p256dh, ps.auth_secret, ps.user_agent, ps.created_at, ps.last_used_at
		FROM push_subscriptions ps
		INNER JOIN users u ON u.id = ps.user_id
		WHERE ps.tenant_id = ? AND ps.user_id IN (` + placeholders + `) AND u.status = 'active'
		ORDER BY ps.created_at DESC
	`)
	rows, err := c.store.readDB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPushSubscriptions(rows)
}

// DeletePushSubscriptionByEndpoint removes one push subscription owned by (tenantID, userID).
func (c *chatStore) DeletePushSubscriptionByEndpoint(ctx context.Context, tenantID, userID, endpoint string) error {
	tenantID = normalizeTenant(tenantID)
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		DELETE FROM push_subscriptions
		WHERE tenant_id = ? AND user_id = ? AND endpoint = ?
	`), tenantID, userID, endpoint)
	return err
}

// DeletePushSubscriptionByID removes one push subscription by ID owned by (tenantID, userID).
func (c *chatStore) DeletePushSubscriptionByID(ctx context.Context, tenantID, userID, id string) error {
	tenantID = normalizeTenant(tenantID)
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`
		DELETE FROM push_subscriptions
		WHERE tenant_id = ? AND user_id = ? AND id = ?
	`), tenantID, userID, id)
	return err
}

// DeletePushSubscriptionInternal removes a subscription by ID (used when a push service returns 404/410).
func (c *chatStore) DeletePushSubscriptionInternal(ctx context.Context, id string) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`DELETE FROM push_subscriptions WHERE id = ?`), id)
	return err
}

// TouchPushSubscription records the last successful delivery time (Unix milliseconds).
func (c *chatStore) TouchPushSubscription(ctx context.Context, id string, usedAt int64) error {
	_, err := c.store.db.ExecContext(ctx, c.store.rebind(`UPDATE push_subscriptions SET last_used_at = ? WHERE id = ?`), usedAt, id)
	return err
}

func scanPushSubscriptions(rows *sql.Rows) ([]*PushSubscription, error) {
	var out []*PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.UserID, &s.Endpoint,
			&s.P256DH, &s.AuthSecret, &s.UserAgent, &s.CreatedAt, &s.LastUsedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
