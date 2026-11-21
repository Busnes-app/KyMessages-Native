package main

import (
	"context"
	"log"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
)

// maintenanceLoop deletes expired QR pairings once a minute. done closes between ticks,
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
