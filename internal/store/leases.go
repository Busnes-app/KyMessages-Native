package store

import (
	"context"
	"time"
)

// dbNowMillis is the database clock in Unix milliseconds. Leases compare against it, never a
// replica's clock, so skew between hosts cannot give two replicas one lease.
func (s *SQLStore) dbNowMillis() string {
	if s.driver == "postgres" {
		return `CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT)`
	}
	return `CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)`
}

// AcquireLease takes or renews the named job lease for holder until ttl from now. It wins
// only if the lease is free, expired or already holder's; exactly one row changes then.
func (s *SQLStore) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	now := s.dbNowMillis()
	res, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO job_leases (name, holder, expires_at) VALUES (?, ?, `+now+` + ?)
ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
WHERE job_leases.expires_at < `+now+` OR job_leases.holder = excluded.holder`), name, holder, ttl.Milliseconds())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
