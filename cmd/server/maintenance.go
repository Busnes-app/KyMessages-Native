package main

import (
	"context"
	"log"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// jobGate reports whether this replica runs one tick of job, which runs every interval.
type jobGate func(ctx context.Context, job string, every time.Duration) bool

// everyReplica is single mode: every job runs in the one process, as it always has.
func everyReplica(context.Context, string, time.Duration) bool { return true }

// leasedJobs is multi mode: a tick runs only on the replica holding the job's lease. The lease
// lasts three ticks and each tick renews it, so a dead replica's jobs move within three ticks.
func leasedJobs(st store.Store) jobGate {
	holder := crypto.RandomHex(16)
	return func(ctx context.Context, job string, every time.Duration) bool {
		ok, err := st.AcquireLease(ctx, job, holder, 3*every)
		if err != nil && ctx.Err() == nil {
			log.Printf("[JOBS] %s lease unavailable: %v", job, err)
		}
		return ok
	}
}

// maintenanceLoop deletes expired QR pairings, suite replay IDs and stale end-to-end encryption
// mail once a minute. done closes between ticks,
// so shutdown can wait for it before the store closes.
// In multi mode (shared) it also prunes the shared limits, spent challenges and lobby sessions.
func maintenanceLoop(ctx context.Context, st store.Store, gate jobGate, shared bool, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if gate(ctx, "maintenance", time.Minute) {
				sweepPairings(ctx, st)
				sweepSuiteReplay(ctx, st)
				sweepE2EEMailbox(ctx, st)
				if shared {
					sweepShared(ctx, st)
				}
			}
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

func sweepShared(ctx context.Context, st store.Store) {
	run, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.PruneShared(run); err != nil && ctx.Err() == nil {
		log.Printf("[JOBS] shared limit sweep failed: %v", err)
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
func agentExpiryLoop(ctx context.Context, expire func(context.Context, time.Time) error, gate jobGate, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if gate(ctx, "agent_expiry", time.Hour) {
			run, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := expire(run, time.Now())
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Printf("[AGENTS] idle token expiry incomplete (retrying hourly): %v", err)
			}
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
func attachmentSweepLoop(ctx context.Context, sweep func(context.Context, time.Time) (int, error), gate jobGate, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		if gate(ctx, "attachment_sweep", 15*time.Minute) {
			run, cancel := context.WithTimeout(ctx, 2*time.Minute)
			removed, err := sweep(run, time.Now())
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Printf("[ATTACHMENTS] orphan sweep failed: %v", err)
			} else if removed > 0 {
				log.Printf("[ATTACHMENTS] purged %d expired staged attachment(s)", removed)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
