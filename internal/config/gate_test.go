package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky_server_base/internal/config"
)

// completeMultiEnv sets every requirement of multi mode, so only the build gate can refuse it.
func completeMultiEnv(t *testing.T) {
	dir := t.TempDir()
	seal := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(seal, []byte(strings.Repeat("ef", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"KY_TENANCY_MODE":                 "multi",
		"KY_DATA_DIR":                     dir,
		"KY_DB_DRIVER":                    "postgres",
		"KY_DB_DSN":                       "postgres://user:pass@localhost:5432/testdb",
		"KY_STAFF_ORG_ID":                 "00000000-0000-4000-8000-000000000001",
		"KY_SESSION_SECRET":               "multi-session-secret-0123456789abcdef",
		"KY_ENCRYPTION_KEY":               strings.Repeat("ab", 32),
		"KY_PUSH_ENABLED":                 "false",
		"KY_CELLS":                        "e2e-1,e2e-2",
		"KY_KYIDENTITY_ISSUER":            "https://id.e2e.test",
		"KY_ATTACHMENTS_S3_ENDPOINT":      "https://objects.e2e.test",
		"KY_ATTACHMENTS_S3_REGION":        "us-east-2",
		"KY_ATTACHMENTS_S3_BUCKET":        "kymessages",
		"KY_ATTACHMENTS_S3_ACCESS_KEY":    "access-id",
		"KY_ATTACHMENTS_S3_SECRET":        "s3-secret",
		"KY_ATTACHMENTS_S3_SEAL_KEY_FILE": seal,
	} {
		t.Setenv(k, v)
	}
}

// A release build refuses a complete multi config with the release message; a test build serves it.
func TestBuildGateMultiTenant(t *testing.T) {
	completeMultiEnv(t)
	cfg, err := config.LoadFromEnv()
	if !wantMultiTenantBuild {
		if !errors.Is(err, config.ErrMultiTenantRelease) || err.Error() != "KY_TENANCY_MODE=multi: multi-tenant mode is unavailable in this release" {
			t.Fatalf("release build: want the release refusal, got %v", err)
		}
		return
	}
	if err != nil || !cfg.Tenancy.IsMultiTenant() || cfg.Attachments.ObjectStore == nil {
		t.Fatalf("test build: complete multi config refused: %v", err)
	}
}

// Multi mode needs object storage in both builds, checked before the release refusal.
func TestBuildGateMultiRequiresObjectStorage(t *testing.T) {
	completeMultiEnv(t)
	for _, k := range []string{"ENDPOINT", "REGION", "BUCKET", "ACCESS_KEY", "SECRET", "SEAL_KEY_FILE"} {
		t.Setenv("KY_ATTACHMENTS_S3_"+k, "")
	}
	if _, err := config.LoadFromEnv(); err == nil || err.Error() != "KY_TENANCY_MODE=multi requires object storage (KY_ATTACHMENTS_S3_*)" {
		t.Fatalf("multi without KY_ATTACHMENTS_S3_*: %v", err)
	}
}

// A test build takes only an https issuer under .test, in either mode; a release build any.
func TestBuildGateTestIssuer(t *testing.T) {
	for _, mode := range []string{"multi", "single"} {
		for _, iss := range []string{"", "https://id.example.com", "https://id.test.example.com", "http://id.e2e.test", "https://id.e2e.test.", "https://test", "not a url"} {
			completeMultiEnv(t)
			t.Setenv("KY_TENANCY_MODE", mode)
			t.Setenv("KY_KYIDENTITY_ISSUER", iss)
			if mode == "single" {
				t.Setenv("KY_DB_DRIVER", "sqlite")
				t.Setenv("KY_CELLS", "")
				for _, k := range []string{"ENDPOINT", "REGION", "BUCKET", "ACCESS_KEY", "SECRET", "SEAL_KEY_FILE"} {
					t.Setenv("KY_ATTACHMENTS_S3_"+k, "")
				}
			}
			_, err := config.LoadFromEnv()
			refused := err != nil && strings.Contains(err.Error(), "accepts only an https issuer under .test")
			if refused != wantMultiTenantBuild {
				t.Errorf("%s issuer %q: %v", mode, iss, err)
			}
		}
	}
	t.Setenv("KY_KYIDENTITY_ISSUER", "https://ID.E2E.TEST:8443")
	if _, err := config.LoadFromEnv(); err != nil {
		t.Fatalf("single with a .test issuer: %v", err)
	}
}
