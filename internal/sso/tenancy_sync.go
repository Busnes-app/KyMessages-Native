package sso

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// Tenancy sync (multi mode, spec §7.4). KyIdentity's org list and erased list are the authority:
// a restore rewinds this database but not them. The leased sync job reads both incrementally
// every few minutes, from the revisions stored here (so a restore replays what it undid), and
// in full from zero once a day and at every start. Only an explicit deletion purges anything.

const (
	settingOrgsRevision   = "tenancy.orgs_revision"
	settingErasedRevision = "tenancy.erased_revision"
	// SettingSyncedAt is the Unix second of the last complete sync, incremental or full.
	SettingSyncedAt = "tenancy.kyidentity_synced_at"
	// SettingFullSyncAt is the Unix second of the last complete full read.
	SettingFullSyncAt = "tenancy.full_sync_at"
	// StartupSyncMaxAge is how old the last sync may be for a replica to serve while KyIdentity
	// cannot be reached at its start.
	StartupSyncMaxAge = 24 * time.Hour
)

// listedStatus maps KyIdentity's org status to the tenant status this app enforces.
func listedStatus(s string) string {
	switch s {
	case suitedir.OrgActive:
		return store.TenantStatusActive
	case suitedir.OrgDeleted:
		return store.TenantStatusDeleted
	default: // suspended, deletion_scheduled: stop serving, keep the data
		return store.TenantStatusSuspended
	}
}

// SyncTenancy reads both lists and applies them. full reads from zero and holds offline any
// active org a complete read does not list (within the guard); startup never holds one offline.
func (k *KyIdentityClient) SyncTenancy(ctx context.Context, full, startup bool) error {
	if !k.tenancy.IsMultiTenant() {
		return nil
	}
	dir, err := k.SuiteDirectory()
	if err != nil {
		return err
	}
	if dir == nil {
		return ErrSuiteOff
	}
	settings := k.store.Settings()
	since := int64(0)
	if !full {
		since = k.storedRevision(ctx, settingOrgsRevision)
	}
	// suitedir.Orgs stops at its page bound with a revision below the last listed; continue from
	// there until a call ends on its own, so a full read is complete before anything is decided.
	var orgs []suitedir.Org
	next := since
	for {
		page, n, err := dir.Orgs(ctx, next)
		if err != nil {
			return err
		}
		orgs = append(orgs, page...)
		done := len(page) == 0 || n >= page[len(page)-1].Revision
		if !done && n <= next {
			return errors.New("sso: org list did not advance")
		}
		next = n
		if done {
			break
		}
	}
	for _, o := range orgs {
		if err := k.applyListedOrg(ctx, o); err != nil {
			return err // the revision stays, so the next run applies it again
		}
	}
	if full {
		if err := k.checkMissing(ctx, orgs, startup); err != nil {
			return err
		}
	}
	if err := settings.SetSetting(ctx, settingOrgsRevision, strconv.FormatInt(next, 10)); err != nil {
		return err
	}
	if err := k.syncErased(ctx, full); err != nil {
		return err
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	if full {
		if err := settings.SetSetting(ctx, SettingFullSyncAt, now); err != nil {
			return err
		}
	}
	return settings.SetSetting(ctx, SettingSyncedAt, now)
}

func (k *KyIdentityClient) storedRevision(ctx context.Context, key string) int64 {
	v, err := k.store.Settings().GetSetting(ctx, key)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return max(n, 0)
}

// applyListedOrg applies one org as KyIdentity lists it.
func (k *KyIdentityClient) applyListedOrg(ctx context.Context, o suitedir.Org) error {
	if !config.IsCanonicalUUID(o.ID) {
		return nil // never an org of ours
	}
	status := listedStatus(o.Status)
	chat := k.store.Chat()
	if status == store.TenantStatusDeleted {
		if _, err := chat.GetTenant(ctx, o.ID); errors.Is(err, store.ErrNotFound) {
			return nil // nothing held: nothing to delete
		} else if err != nil {
			return err
		}
	} else if _, err := chat.EnsureTenant(ctx, o.ID); err != nil {
		return err
	}
	missing, err := chat.TenantMissing(ctx, o.ID)
	if err != nil {
		return err
	}
	if missing && status == store.TenantStatusActive {
		if found, err := chat.ClearTenantMissing(ctx, o.ID, o.Revision); err != nil {
			return err
		} else if found {
			k.auditSync(ctx, "tenancy.org_found", o.ID, "")
		}
	} else if missing {
		if err := chat.ForgetTenantMissing(ctx, o.ID); err != nil {
			return err
		}
	}
	if _, err := chat.ApplyTenantLifecycle(ctx, o.ID, status, o.Revision); err != nil {
		return err
	}
	// Revoke from the resulting state, not from whether this read changed it: a revocation that
	// failed last time (the revision then stays unstored) is retried. Revoking an org with no
	// grants is a no-op.
	tenant, err := chat.GetTenant(ctx, o.ID)
	if err != nil {
		return err
	}
	if tenant.Status != store.TenantStatusActive {
		return k.revokeTenant(ctx, o.ID)
	}
	return nil
}

// checkMissing holds offline each active org a complete full read did not list, unless more
// are missing than max(5% of active orgs, 3): then it holds none and audits the abort, since a
// wrong issuer, a paging bug or an empty answer must not take every org offline.
func (k *KyIdentityClient) checkMissing(ctx context.Context, listed []suitedir.Org, startup bool) error {
	active, err := k.store.Chat().ActiveTenantIDs(ctx)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(listed))
	for _, o := range listed {
		seen[o.ID] = true
	}
	var missing []string
	for _, id := range active {
		if !seen[id] && id != k.tenancy.StaffOrgID {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if len(missing) > max(len(active)*5/100, 3) {
		log.Printf("[TENANCY] ALERT: %d of %d active orgs missing from KyIdentity's list; holding none offline", len(missing), len(active))
		k.auditSync(ctx, "tenancy.sync_aborted", "", fmt.Sprintf("missing=%d active=%d", len(missing), len(active)))
		return nil
	}
	if startup {
		log.Printf("[TENANCY] ALERT: %d active org(s) missing from KyIdentity's list at start; the next full read decides", len(missing))
		return nil
	}
	for _, id := range missing {
		marked, err := k.store.Chat().MarkTenantMissing(ctx, id, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		if marked {
			log.Printf("[TENANCY] ALERT: an org is missing from KyIdentity's list and is held offline")
			k.auditSync(ctx, "tenancy.org_missing", id, "")
			if err := k.revokeTenant(ctx, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// syncErased erases every subject KyIdentity lists after the stored revision (all, when full).
func (k *KyIdentityClient) syncErased(ctx context.Context, full bool) error {
	since := int64(0)
	if !full {
		since = k.storedRevision(ctx, settingErasedRevision)
	}
	stored := since
	// No page cap: each entry must advance the revision, so the walk ends; stopping early would
	// record a sync that left erased subjects unerased.
	for {
		var body struct {
			Subjects []struct {
				Sub      string `json:"sub"`
				OrgID    string `json:"org_id"`
				Revision int64  `json:"revision"`
			} `json:"subjects"`
			Next string `json:"next"`
		}
		q := url.Values{"since": {strconv.FormatInt(since, 10)}, "limit": {"500"}}
		if err := k.SuiteRequest(ctx, http.MethodGet, "erased", q, nil, &body, 1<<20); err != nil {
			return err
		}
		for _, s := range body.Subjects {
			if s.Sub == "" || s.Revision <= since {
				return errors.New("sso: erased list: malformed entry")
			}
			if err := k.eraseSubject(ctx, s.Sub, strings.TrimSpace(s.OrgID)); err != nil {
				return err
			}
			since = s.Revision
		}
		if body.Next == "" || len(body.Subjects) == 0 {
			break
		}
	}
	if since == stored && !full {
		return nil
	}
	return k.store.Settings().SetSetting(ctx, settingErasedRevision, strconv.FormatInt(since, 10))
}

// revokeTenant ends every grant of an org that stopped serving.
func (k *KyIdentityClient) revokeTenant(ctx context.Context, orgID string) error {
	var failed []error
	if k.onTenantRevoked != nil {
		if err := k.onTenantRevoked(ctx, orgID); err != nil {
			failed = append(failed, err)
		}
	}
	const pageSize = 1000
	for offset := 0; ; offset += pageSize {
		users, total, err := k.store.Users().ListUsers(ctx, offset, pageSize, store.UserFilter{OrgID: orgID})
		if err != nil {
			return err
		}
		for _, u := range users {
			if err := k.store.Sessions().DeleteUserSessions(ctx, u.ID); err != nil {
				failed = append(failed, err)
			}
			if k.onUserRevoked != nil {
				k.onUserRevoked(ctx, u.ID)
			}
		}
		if len(users) == 0 || offset+len(users) >= total {
			break
		}
	}
	return errors.Join(failed...)
}

func (k *KyIdentityClient) auditSync(ctx context.Context, action, orgID, details string) {
	resource := ""
	if orgID != "" {
		resource = "tenant:" + orgID
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := k.store.Audit().LogAudit(actx, &store.AuditRecord{UserID: "system", Action: action, Resource: resource, Details: details}); err != nil {
		log.Printf("[AUDIT] %s not recorded: %v", action, err)
	}
}

// StartupSync is every multi-mode replica's start: a full read before serving. If KyIdentity
// cannot answer, the replica may still serve while the database records a sync younger than
// StartupSyncMaxAge; otherwise (a fresh install, or a restore of an older backup) it must not.
func (k *KyIdentityClient) StartupSync(ctx context.Context) error {
	err := k.SyncTenancy(ctx, true, true)
	if err == nil {
		return nil
	}
	if v, gerr := k.store.Settings().GetSetting(ctx, SettingSyncedAt); gerr == nil {
		if at, perr := strconv.ParseInt(v, 10, 64); perr == nil && time.Since(time.Unix(at, 0)) < StartupSyncMaxAge {
			log.Printf("[TENANCY] KyIdentity unreachable at start (%v); serving on the last sync and retrying", err)
			return nil
		}
	}
	return fmt.Errorf("tenancy: no KyIdentity sync within %s and KyIdentity unreachable: %w", StartupSyncMaxAge, err)
}

// FullSyncDue reports whether the daily full read is due.
func (k *KyIdentityClient) FullSyncDue(ctx context.Context) bool {
	return time.Since(time.Unix(k.storedRevision(ctx, SettingFullSyncAt), 0)) >= StartupSyncMaxAge
}
