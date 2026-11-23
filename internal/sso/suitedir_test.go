package sso_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/applysetup"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/sso"
)

// A managed console pairs through its installer's KyIdentity even when the environment names
// no issuer.
func TestSuiteDirectoryPrefersInstaller(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client.secret")
	if err := os.WriteFile(secret, []byte("installer-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := sso.NewKyIdentityClient(config.SSOConfig{
		KyIdentityIssuer: "https://env.example",
		Installer:        &applysetup.SSO{IssuerURL: "https://identity.example", ClientID: "message", ClientSecretFile: secret},
	}, nil)
	c, err := k.SuiteDirectory()
	if err != nil || c == nil || c.Issuer != "https://identity.example" || c.ClientID != "message" || c.ClientSecret != "installer-secret" {
		t.Fatalf("installer directory = %+v, %v", c, err)
	}
	if c, err := sso.NewKyIdentityClient(config.SSOConfig{}, nil).SuiteDirectory(); c != nil || err != nil {
		t.Fatalf("unconfigured = %+v, %v", c, err)
	}
}
