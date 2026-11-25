//go:build !kye2e

package config_test

// wantMultiTenantBuild is set by build tag, not read from the gate, so editing a gate file fails.
const wantMultiTenantBuild = false
