//go:build !kye2e

package config

// multiTenantBuild is false in every shipped binary: LoadFromEnv refuses multi mode.
const multiTenantBuild = false
