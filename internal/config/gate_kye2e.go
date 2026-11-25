//go:build kye2e

package config

// multiTenantBuild opens multi mode for the cross-app e2e run only (KyCalendar
// docs/superpowers/specs/2026-11-24-multi-tenant-e2e-design.md). Such a binary also refuses
// any issuer outside the reserved .test domain.
const multiTenantBuild = true
