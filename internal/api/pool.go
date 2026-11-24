package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/google/uuid"
)

// The org storage pool (multi mode): KyIdentity's POST /api/suite/storage takes each org's
// absolute attachment bytes and answers with a grant, a ceiling this app may fill until it
// expires (KyIdentity docs/SUITE-DIRECTORY.md, "Storage pool"). The upload path checks the grant
// under the tenant lock; this file fetches and refreshes it.

const (
	// poolWantBytes is the headroom asked for beyond current usage.
	poolWantBytes = 256 << 20
	// poolReportBatch is KyIdentity's per-request maximum.
	poolReportBatch = 500
	// poolRefreshBefore reports again while this much of a grant's lifetime is left, so a
	// grant (15 minutes) is renewed about every 5 minutes even for an idle org.
	poolRefreshBefore = 10 * time.Minute
	// poolSyncTimeout bounds the report an upload makes when its org has no usable grant.
	poolSyncTimeout = 5 * time.Second
	// maxPoolTTL caps the grant lifetime this app accepts.
	maxPoolTTL = 15 * time.Minute
)

type poolReport struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

type poolResult struct {
	OrgID        string `json:"org_id"`
	Result       string `json:"result"`
	Seq          int64  `json:"seq"`
	CeilingBytes int64  `json:"ceiling_bytes"`
	TTLSeconds   int64  `json:"ttl_seconds"`
}

// poolActive reports whether tenantID's writes are checked against the pool: customer orgs in
// multi mode. The staff org and org-less operators are not in any pool.
func (s *Server) poolActive(tenantID string) bool {
	return s.config.Tenancy.IsMultiTenant() && tenantID != store.DefaultTenantID && tenantID != s.config.Tenancy.StaffOrgID &&
		config.IsCanonicalUUID(tenantID)
}

// postPoolReports sends one batch to KyIdentity and returns the results by org.
func (s *Server) postPoolReports(ctx context.Context, reports []poolReport) (map[string]poolResult, error) {
	var out struct {
		Results []poolResult `json:"results"`
	}
	if err := s.kyidentity.SuiteRequest(ctx, http.MethodPost, "storage", nil, map[string]any{"reports": reports}, &out, 1<<20); err != nil {
		return nil, err
	}
	sent := make(map[string]bool, len(reports))
	for _, r := range reports {
		sent[r.OrgID] = true
	}
	byOrg := make(map[string]poolResult, len(out.Results))
	for _, r := range out.Results {
		if sent[r.OrgID] { // an answer about an org we did not report is ignored
			byOrg[r.OrgID] = r
		}
	}
	return byOrg, nil
}

// lockPoolReport serializes exchanges for the one shared org/app grant across
// replicas. Sequence fencing alone cannot make an older cold response usable while
// a newer request is still in flight. Wait only within the report's deadline.
func (s *Server) lockPoolReport(ctx context.Context, name, holder string) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, err := s.store.AcquireLease(ctx, name, holder, 2*poolSyncTimeout)
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// reportPool sends usages and stores each org's answer. PoolUsages returns orgs in
// ID order, so overlapping batches take their per-org leases in the same order.
func (s *Server) reportPool(ctx context.Context, usages []store.PoolUsage) error {
	var blocked []error
	for len(usages) > 0 {
		batch := usages[:min(len(usages), poolReportBatch)]
		usages = usages[len(batch):]
		if err := s.reportPoolBatch(ctx, batch); err != nil {
			if !errors.Is(err, store.ErrPoolUnavailable) {
				return err
			}
			blocked = append(blocked, err)
		}
	}
	return errors.Join(blocked...)
}

func (s *Server) reportPoolBatch(ctx context.Context, batch []store.PoolUsage) error {
	ctx, cancel := context.WithTimeout(ctx, poolSyncTimeout)
	defer cancel()
	holder := uuid.NewString()
	var held []string
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer releaseCancel()
		for _, name := range held {
			if err := s.store.ReleaseLease(releaseCtx, name, holder); err != nil {
				log.Printf("[POOL] report lease release failed (expires automatically): %v", err)
			}
		}
	}()
	chat := s.store.Chat()
	reports := make([]poolReport, 0, len(batch))
	used := make(map[string]int64, len(batch))
	var blocked []error
	for _, u := range batch {
		name := "pool-report:" + u.TenantID
		if err := s.lockPoolReport(ctx, name, holder); err != nil {
			return err
		}
		held = append(held, name)
		seq, now, err := chat.NextPoolReport(ctx, u.TenantID)
		if errors.Is(err, store.ErrPoolUnavailable) {
			blocked = append(blocked, err)
			continue
		}
		if err != nil {
			return err
		}
		reports = append(reports, poolReport{OrgID: u.TenantID, UsedBytes: now, Seq: seq, WantBytes: poolWantBytes})
		used[u.TenantID] = now
	}
	if len(reports) == 0 {
		return errors.Join(blocked...)
	}
	sentAt := time.Now() // KyIdentity requires the grant's lifetime to start here.
	results, err := s.postPoolReports(ctx, reports)
	if err != nil {
		return err
	}
	for _, rep := range reports {
		r, ok := results[rep.OrgID]
		if !ok {
			continue
		}
		switch r.Result {
		case "ok":
			ttl := time.Duration(r.TTLSeconds) * time.Second
			if r.Seq != rep.Seq || r.CeilingBytes < 0 || ttl <= 0 || ttl > maxPoolTTL {
				continue // not an answer to this report
			}
			err = chat.SetPoolGrant(ctx, rep.OrgID, rep.Seq, used[rep.OrgID], r.CeilingBytes, sentAt.Add(ttl).UnixMilli())
		case "stale":
			// A newer writer or restored database needs explicit operator reconciliation.
			// Never jump past that writer automatically or keep a restored grant usable.
			err = chat.RecordStalePoolReport(ctx, rep.OrgID, rep.Seq, r.Seq)
			log.Printf("[POOL] ALERT: report sequence requires offline operator reconciliation")
		case "unknown_org":
			// Not a pool member KyIdentity knows: nothing may be added until it is.
			err = chat.SetPoolGrant(ctx, rep.OrgID, rep.Seq, used[rep.OrgID], 0, sentAt.Add(15*time.Minute).UnixMilli())
		}
		if err != nil {
			return err
		}
	}
	return errors.Join(blocked...)
}

// RefreshPool is the leased reporter's tick: it reports each customer org whose usage changed,
// which has used half its grant, or whose grant is missing or nears expiry. Totals are absolute,
// so a lost or repeated report never drifts, and a restored database's true total goes out
// within one grant lifetime.
func (s *Server) RefreshPool(ctx context.Context, now time.Time) error {
	if !s.config.Tenancy.IsMultiTenant() || s.store == nil {
		return nil
	}
	all, err := s.store.Chat().PoolUsages(ctx, now.UnixMilli(), "")
	if err != nil {
		return err
	}
	var due []store.PoolUsage
	for _, u := range all {
		if !s.poolActive(u.TenantID) {
			continue
		}
		switch {
		case u.CeilingBytes == nil || u.ExpiresAt == nil || u.ReportedBytes == nil,
			*u.ExpiresAt-now.UnixMilli() < poolRefreshBefore.Milliseconds(),
			u.UsedBytes != *u.ReportedBytes,
			u.UsedBytes-*u.ReportedBytes >= (*u.CeilingBytes-*u.ReportedBytes)/2:
			due = append(due, u)
		}
	}
	return s.reportPool(ctx, due)
}

// refreshOrgPool reports one org at once, for an upload that found no usable grant.
func (s *Server) refreshOrgPool(ctx context.Context, tenantID string) error {
	ctx, cancel := context.WithTimeout(ctx, poolSyncTimeout)
	defer cancel()
	usage, err := s.store.Chat().PoolUsages(ctx, time.Now().UnixMilli(), tenantID)
	if err != nil {
		return err
	}
	if err := s.reportPool(ctx, usage); err != nil {
		log.Printf("[POOL] storage report failed: %v", err)
		return err
	}
	return nil
}

// writePoolError answers a pool refusal: full is 413 org_storage_full, unknown is 503.
// Neither names another app or its usage.
func (s *Server) writePoolError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, store.ErrPoolFull):
		s.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "Your plan's storage is full. Free up space, or manage your plan in your account.",
			"code":  "org_storage_full",
		})
	case errors.Is(err, store.ErrPoolUnavailable):
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Storage is temporarily unavailable. Try again shortly.",
			"code":  "pool_unavailable",
		})
	default:
		return false
	}
	return true
}
