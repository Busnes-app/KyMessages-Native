package chat

import (
	"context"
	"errors"
)

// SetCleanupLease elects one multi-mode replica to reconcile opaque call cleanup.
func (m *CallManager) SetCleanupLease(fn func(context.Context) (bool, error)) { m.cleanupLease = fn }

// DrainCleanup keeps failed SFU work durable. Targeted erasure/purge drains its complete
// queue before acknowledging; the leased shared sweep takes one bounded fair batch.
func (m *CallManager) DrainCleanup(ctx context.Context, tenantID, userID string) error {
	for {
		pending, err := m.chatStore.PendingCallEvictions(ctx, tenantID, userID, 200)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return m.chatStore.ClearPendingBlobDeletes(ctx, nil)
		}
		if m.livekit == nil {
			return ErrSFUUnavailable
		}
		var failed []error
		for _, e := range pending {
			// Revocation retires the old media epoch, not only one current connection.
			err = m.livekit.DeleteRoom(ctx, e.LiveKitRoom)
			if err == nil {
				err = m.chatStore.ClearCallEviction(ctx, e)
			}
			if err != nil {
				failed = append(failed, err)
			}
		}
		if err := errors.Join(failed...); err != nil {
			return err
		}
		if tenantID == "" && userID == "" {
			return m.chatStore.ClearPendingBlobDeletes(ctx, nil)
		}
	}
}
