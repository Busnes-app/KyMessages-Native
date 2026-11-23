package main

import (
	"context"
	"log"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// maintenanceLoop deletes expired QR pairings and suite replay IDs once a minute. done closes between ticks,
// so shutdown can wait for it before the store closes.
func maintenanceLoop(ctx context.Context, st store.Store, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepPairings(ctx, st)
			sweepSuiteReplay(ctx, st)
			sweepE2EEMailbox(ctx, st)
		}
	}
}

func sweepPairings(ctx context.Context, st store.Store) {
	run, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.Devices().CleanExpiredPairings(run); err != nil && ctx.Err() == nil {
		log.Printf("[DEVICES] expired pairing sweep failed: %v", err)
	}
}

func sweepSuiteReplay(ctx context.Context, st store.Store) {
	run, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.SuiteReplay().Prune(run, time.Now().Unix()); err != nil && ctx.Err() == nil {
		log.Printf("[SUITE] replay ledger sweep failed: %v", err)
	}
}

func sweepE2EEMailbox(ctx context.Context, st store.Store) {
	run, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.E2EE().PruneToDevice(run, time.Now().Add(-api.E2EEMailboxTTL)); err != nil && ctx.Err() == nil {
		log.Printf("[E2EE] to-device mailbox sweep failed: %v", err)
	}
}

// agentExpiryLoop revokes idle (90d) and inactive-owner bot tokens (api.Server.ExpireIdleAgents)
// at its start and hourly. done closes between runs, so shutdown can wait before the store closes.
func agentExpiryLoop(ctx context.Context, expire func(context.Context, time.Time) error, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		run, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := expire(run, time.Now())
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("[AGENTS] idle token expiry incomplete (retrying hourly): %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// attachmentSweepLoop expires abandoned unposted (staged) attachments at start and every
// 15 minutes. done closes between runs so shutdown waits cleanly before the store closes.
func attachmentSweepLoop(ctx context.Context, sweep func(context.Context, time.Time) (int, error), done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		run, cancel := context.WithTimeout(ctx, 2*time.Minute)
		removed, err := sweep(run, time.Now())
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("[ATTACHMENTS] orphan sweep failed: %v", err)
		} else if removed > 0 {
			log.Printf("[ATTACHMENTS] purged %d expired staged attachment(s)", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
