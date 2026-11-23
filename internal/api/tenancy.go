package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/store"
)

// EnsureTenancyMode locks the database's tenancy mode on first start and refuses to boot if an
// existing database was initialized in a different mode (single vs. multi). A database from
// before the lock that holds rooms or org-less directory accounts is single-tenant: those
// accounts have no org, so locking it to multi would shut every one of them out for good.
func EnsureTenancyMode(ctx context.Context, st store.Store, cfg config.TenancyConfig) error {
	if st == nil {
		return nil
	}
	want := cfg.EffectiveMode()
	if want == config.TenancyMulti {
		if !config.IsCanonicalUUID(strings.TrimSpace(cfg.StaffOrgID)) {
			return fmt.Errorf("KY_STAFF_ORG_ID must be a canonical lowercase UUID when KY_TENANCY_MODE=multi")
		}
	}
	stored, err := st.Settings().GetSetting(ctx, store.TenancyModeSettingKey)
	if errors.Is(err, store.ErrNotFound) {
		if want == config.TenancyMulti {
			used, err := st.Chat().HoldsSingleTenantData(ctx)
			if err != nil {
				return fmt.Errorf("check for existing chat data: %w", err)
			}
			if used {
				return fmt.Errorf("this database already holds single-tenant rooms or accounts; refusing to lock it to KY_TENANCY_MODE=multi (start it with single, or use a fresh database)")
			}
		}
		if err := st.Settings().SetSetting(ctx, store.TenancyModeSettingKey, want); err != nil {
			return err
		}
		if want == config.TenancyMulti {
			return st.Settings().SetSetting(ctx, store.TenancyStaffOrgSettingKey, strings.TrimSpace(cfg.StaffOrgID))
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", store.TenancyModeSettingKey, err)
	}
	stored = strings.ToLower(strings.TrimSpace(stored))
	if stored != want {
		return fmt.Errorf("database tenancy mode is %q; refusing to start with KY_TENANCY_MODE=%q", stored, want)
	}
	if want == config.TenancyMulti {
		wantStaff := strings.TrimSpace(cfg.StaffOrgID)
		storedStaff, err := st.Settings().GetSetting(ctx, store.TenancyStaffOrgSettingKey)
		if errors.Is(err, store.ErrNotFound) {
			return st.Settings().SetSetting(ctx, store.TenancyStaffOrgSettingKey, wantStaff)
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", store.TenancyStaffOrgSettingKey, err)
		}
		if strings.TrimSpace(storedStaff) != wantStaff {
			return fmt.Errorf("database staff org is %q; refusing to start with KY_STAFF_ORG_ID=%q", storedStaff, wantStaff)
		}
	}
	return nil
}

// requireUserTenant resolves the authenticated user's authoritative tenant ID.
// In single-tenant mode it always returns store.DefaultTenantID so self-hosted behavior is
// unchanged. In multi-tenant mode it derives the tenant strictly from the verified user record's
// immutable org_id and refuses accounts with no org or a non-active organization.
func (s *Server) requireUserTenant(w http.ResponseWriter, r *http.Request, user *store.User) (string, bool) {
	if !s.config.Tenancy.IsMultiTenant() {
		return store.DefaultTenantID, true
	}
	orgID := strings.TrimSpace(user.OrgID)
	if orgID == "" {
		s.writeError(w, http.StatusForbidden, "Account is not bound to an organization")
		return "", false
	}
	tenant, err := s.store.Chat().GetTenant(r.Context(), orgID)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusForbidden, "Organization is not provisioned")
		return "", false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to verify organization")
		return "", false
	}
	if tenant.Status != store.TenantStatusActive {
		s.writeError(w, http.StatusForbidden, "Organization is suspended or inactive")
		return "", false
	}
	return orgID, true
}

// isTenantActive reports whether tenantID is currently permitted to serve traffic.
func (s *Server) isTenantActive(ctx context.Context, tenantID string) (bool, error) {
	if !s.config.Tenancy.IsMultiTenant() {
		return true, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false, nil
	}
	tenant, err := s.store.Chat().GetTenant(ctx, tenantID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return tenant.Status == store.TenantStatusActive, nil
}
