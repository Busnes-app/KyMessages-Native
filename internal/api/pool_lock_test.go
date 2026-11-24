package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/internal/testdb"
)

type cancelContendedPoolStore struct {
	store.Store
	cancel context.CancelFunc
}

func (s *cancelContendedPoolStore) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	ok, err := s.Store.AcquireLease(ctx, name, holder, ttl)
	if !ok && err == nil {
		s.cancel()
	}
	return ok, err
}

func TestPoolReportWaitHonorsCancellation(t *testing.T) {
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if ok, err := st.AcquireLease(context.Background(), "pool-report:held", "owner", time.Minute); err != nil || !ok {
		t.Fatalf("held exchange: %v %v", ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &cancelContendedPoolStore{Store: st, cancel: cancel}
	srv := &Server{store: observed}
	if err := srv.lockPoolReport(ctx, "pool-report:held", "waiter", true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
	if ok, err := st.AcquireLease(context.Background(), "pool-report:held", "stranger", time.Minute); err != nil || ok {
		t.Fatalf("waiter disturbed owner: %v %v", ok, err)
	}
}
