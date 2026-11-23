package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// A sweep deletes expired pairings and leaves live ones.
func TestSweepPairingsDropsOnlyExpired(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Users().CreateUser(ctx, &store.User{ID: "u", Username: "u", PasswordHash: "h", Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for secret, expires := range map[string]time.Time{"old": now.Add(-time.Minute), "live": now.Add(time.Minute)} {
		if err := st.Devices().CreatePairing(ctx, &store.DevicePairing{Secret: secret, UserID: "u", Status: "pending", CreatedAt: now, ExpiresAt: expires}, "h"); err != nil {
			t.Fatal(err)
		}
	}
	sweepPairings(ctx, st)
	if _, err := st.Devices().GetPairingBySecret(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired pairing survived", err)
	}
	if _, err := st.Devices().GetPairingBySecret(ctx, "live"); err != nil {
		t.Fatal("live pairing swept", err)
	}
}

// Shutdown waits on done before the store closes, so the loop must close it on cancel.
func TestMaintenanceLoopClosesDoneOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go maintenanceLoop(ctx, nil, everyReplica, false, done)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenanceLoop did not close done after its context was cancelled")
	}
}

// Expiry runs at start under a deadline, survives a failure, and closes done on cancel.
func TestAgentExpiryLoopRunsAtStartAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go agentExpiryLoop(ctx, func(ctx context.Context, now time.Time) error {
		if _, ok := ctx.Deadline(); !ok || now.IsZero() {
			t.Error("expiry runs without a deadline or a time")
		}
		called <- struct{}{}
		return errors.New("store unavailable")
	}, everyReplica, done)
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("expiry did not run at start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agentExpiryLoop did not close done after cancel")
	}
}

func TestAttachmentSweepLoopRunsAtStartAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go attachmentSweepLoop(ctx, func(ctx context.Context, now time.Time) (int, error) {
		if _, ok := ctx.Deadline(); !ok || now.IsZero() {
			t.Error("attachment sweep runs without a deadline or a time")
		}
		called <- struct{}{}
		return 1, nil
	}, everyReplica, done)
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("attachment sweep did not run at start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("attachmentSweepLoop did not close done after cancel")
	}
}

// Two replicas on one database: only the lease holder runs a tick, per job.
func TestLeasedJobsRunOnOneReplica(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, b := leasedJobs(st), leasedJobs(st)
	if !a(ctx, "agent_expiry", time.Hour) || b(ctx, "agent_expiry", time.Hour) {
		t.Fatal("agent_expiry must run on exactly one replica")
	}
	if !a(ctx, "agent_expiry", time.Hour) {
		t.Fatal("the holder must keep its lease from tick to tick")
	}
	if !b(ctx, "maintenance", time.Minute) || a(ctx, "maintenance", time.Minute) {
		t.Fatal("each job has its own lease")
	}
}

// A replica without the lease skips the work and still stops cleanly.
func TestLoopsSkipWithoutTheLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	never := func(context.Context, string, time.Duration) bool { return false }
	done1, done2 := make(chan struct{}), make(chan struct{})
	go agentExpiryLoop(ctx, func(context.Context, time.Time) error { t.Error("expiry ran without the lease"); return nil }, never, done1)
	go attachmentSweepLoop(ctx, func(context.Context, time.Time) (int, error) { t.Error("sweep ran without the lease"); return 0, nil }, never, done2)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done1
	<-done2
}

func TestPoolLoopRunsUnderItsLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan string, 1)
	done := make(chan struct{})
	gate := func(_ context.Context, job string, every time.Duration) bool {
		called <- job
		return false
	}
	go poolLoop(ctx, func(context.Context, time.Time) error { t.Error("report ran without the lease"); return nil }, gate, done)
	if job := <-called; job != "pool_report" {
		t.Fatalf("lease %q", job)
	}
	cancel()
	<-done
}

// leasedLoop runs only under its lease, and the held func it passes renews that lease.
func TestLeasedLoopHeldRenewsTheLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan string, 4)
	gate := func(_ context.Context, job string, _ time.Duration) bool { calls <- job; return true }
	done := make(chan struct{})
	ran := make(chan bool, 1)
	go leasedLoop(ctx, "org_purge", time.Hour, gate, func(ctx context.Context, held func() bool) error {
		ran <- held()
		return nil
	}, done)
	if !<-ran {
		t.Fatal("held reported a lost lease")
	}
	if a, b := <-calls, <-calls; a != "org_purge" || b != "org_purge" {
		t.Fatalf("lease calls %q %q", a, b)
	}
	cancel()
	<-done
}
