package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
)

func TestConfigLoadDefaults(t *testing.T) {
	t.Setenv("KY_APP_NAME", "")
	t.Setenv("KY_DATA_DIR", t.TempDir())
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.AppName != "KyMessages" {
		t.Errorf("expected KyMessages service name, got %q", cfg.Server.AppName)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("expected default driver sqlite, got %s", cfg.Database.Driver)
	}
	if cfg.Captcha.Provider != "pow" {
		t.Errorf("expected default captcha provider pow, got %s", cfg.Captcha.Provider)
	}
	if cfg.Backup.Dir != "" {
		t.Errorf("expected empty default backup dir (sealed local copies off), got %q", cfg.Backup.Dir)
	}
}

// Postgres has no default DSN: a guessed postgres:postgres@localhost would connect to whatever
// answers there, in any environment.
func TestPostgresRequiresAnExplicitDSN(t *testing.T) {
	for _, driver := range []string{"postgres", "postgresql", "PostgreSQL"} {
		for _, env := range []string{"development", "production"} {
			t.Setenv("KY_DATA_DIR", t.TempDir())
			t.Setenv("KY_ENV", env)
			t.Setenv("KY_SESSION_SECRET", "s")
			t.Setenv("KY_DB_DRIVER", driver)
			t.Setenv("KY_DB_DSN", "")
			_, err := config.LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), "KY_DB_DSN is required") {
				t.Errorf("%s/%s without KY_DB_DSN: %v", driver, env, err)
			}
		}
	}
}

func TestConfigLoadFromEnvOverrides(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_PORT", "9090")
	t.Setenv("KY_DB_DRIVER", "postgres")
	t.Setenv("KY_DB_DSN", "postgres://user:pass@localhost:5432/testdb")
	t.Setenv("KY_APP_NAME", "CustomBusnesApp")
	t.Setenv("KY_CAPTCHA_PROVIDER", "none")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("expected driver postgres, got %s", cfg.Database.Driver)
	}
	if cfg.Database.DSN != "postgres://user:pass@localhost:5432/testdb" {
		t.Errorf("expected custom DSN, got %s", cfg.Database.DSN)
	}
	if cfg.Server.AppName != "CustomBusnesApp" {
		t.Errorf("expected custom app name, got %s", cfg.Server.AppName)
	}
	if cfg.Captcha.Provider != "none" {
		t.Errorf("expected captcha provider none, got %s", cfg.Captcha.Provider)
	}
}

// Login verifies only proof-of-work, so any other provider name would silently turn the
// check off. Startup must refuse it instead.
func TestUnverifiedCaptchaProviderFailsStartup(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	for _, provider := range []string{"turnstile", "friendly", "POW"} {
		t.Setenv("KY_CAPTCHA_PROVIDER", provider)
		if _, err := config.LoadFromEnv(); err == nil {
			t.Errorf("provider %q loaded; want a startup error", provider)
		}
	}
}

func TestEncryptionKeyPersistsAcrossLoads(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_ENCRYPTION_KEY", "")
	a, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Security.EncryptionKey) != 32 || !bytes.Equal(a.Security.EncryptionKey, b.Security.EncryptionKey) {
		t.Fatal("encryption key was not persisted between loads")
	}
}

func TestEncryptionKeyFromEnvMustBe32Bytes(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_ENCRYPTION_KEY", "deadbeef")
	if _, err := config.LoadFromEnv(); err == nil {
		t.Fatal("8-byte key accepted")
	}
}

func TestDepositIntervalFromEnv(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 24 * time.Hour, true},
		{"90m", 90 * time.Minute, true},
		{"15m", 15 * time.Minute, true},
		{"0", 0, true},
		{"1s", 0, false},
		{"14m", 0, false},
		{"-1h", 0, false},
		{"daily", 0, false},
	} {
		t.Setenv("KY_BACKUP_DEPOSIT_INTERVAL", tc.in)
		cfg, err := config.LoadFromEnv()
		if (err == nil) != tc.ok {
			t.Errorf("%q: err=%v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && cfg.Backup.DepositInterval != tc.want {
			t.Errorf("%q: got %v, want %v", tc.in, cfg.Backup.DepositInterval, tc.want)
		}
	}
}

func TestBackupConfigFromEnv(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_BACKUP_DIR", "/tmp/x")
	t.Setenv("KY_BACKUP_KEEP", "3")
	t.Setenv("KY_BACKUP_ALLOW_PRIVATE_RECOVERY", "true")
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backup.Dir != "/tmp/x" || cfg.Backup.Keep != 3 || !cfg.Backup.AllowPrivateRecovery {
		t.Fatalf("%+v", cfg.Backup)
	}
}

func TestBackupKeepBelowOneIsRefused(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_BACKUP_KEEP", "0")
	if _, err := config.LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "KY_BACKUP_KEEP") {
		t.Fatalf("want KY_BACKUP_KEEP error, got %v", err)
	}
}

// Operators often set an https app URL behind a TLS proxy and never touch KY_ENV. Cookies must
// still be Secure there, and production must not silently run insecure over plain HTTP.
func TestCookieSecureFollowsTheAppURL(t *testing.T) {
	for _, tc := range []struct {
		env, url, secure string
		want, fails      bool
	}{
		{"", "https://chat.example.com", "", true, false},
		{"", "http://localhost:8080", "", false, false},
		{"production", "https://chat.example.com", "", true, false},
		{"production", "http://chat.lan", "", false, true},
		{"production", "http://chat.lan", "false", false, false},
		{"", "https://chat.example.com", "false", false, false},
	} {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_SESSION_SECRET", "a-durable-secret-for-this-test")
		t.Setenv("KY_ENV", tc.env)
		t.Setenv("KY_APP_URL", tc.url)
		t.Setenv("KY_COOKIE_SECURE", tc.secure)
		cfg, err := config.LoadFromEnv()
		if tc.fails {
			if err == nil {
				t.Errorf("%+v: loaded, want a startup error", tc)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		if cfg.Security.CookieSecure != tc.want {
			t.Errorf("%+v: CookieSecure=%v, want %v", tc, cfg.Security.CookieSecure, tc.want)
		}
	}
}

// A secret left under its pre-rename name must stop startup, not leave sign-in unconfigured.
func TestLegacyKySignOnEnvironmentFailsStartup(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	for _, suffix := range []string{"ISSUER", "CLIENT_ID", "SECRET", "HMAC_SECRET"} {
		t.Run(suffix, func(t *testing.T) {
			t.Setenv("KY_KYSIGNON_"+suffix, "set")
			_, err := config.LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), "KY_KYSIGNON_"+suffix) || !strings.Contains(err.Error(), "KY_KYIDENTITY_"+suffix) {
				t.Fatalf("legacy KY_KYSIGNON_%s: err = %v, want one naming both variables", suffix, err)
			}
		})
	}
}

// Compose passes unset variables as empty strings; an empty legacy name is not a misconfiguration.
func TestEmptyLegacyKySignOnEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_KYSIGNON_SECRET", " ")
	t.Setenv("KY_KYIDENTITY_ISSUER", "https://id.example.test")
	t.Setenv("KY_KYIDENTITY_CLIENT_ID", "client")
	t.Setenv("KY_KYIDENTITY_SECRET", "secret")
	t.Setenv("KY_KYIDENTITY_HMAC_SECRET", "hmac")
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.SSO; s.KyIdentityIssuer != "https://id.example.test" || s.KyIdentityClientID != "client" || s.KyIdentitySecret != "secret" || s.KyIdentityHMACSecret != "hmac" {
		t.Fatalf("KY_KYIDENTITY_* not loaded: %+v", s)
	}
}

func TestRTCConfigFromEnv(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_LIVEKIT_URL", "wss://sfu.example.com")
	t.Setenv("KY_LIVEKIT_API_KEY", "devkey")
	t.Setenv("KY_LIVEKIT_API_SECRET", "devsecret")
	t.Setenv("KY_STUN_URLS", "stun:stun.example.com:3478,stuns:stun.example.com:5349")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RTC.LiveKitEnabled() || cfg.RTC.LiveKitURL != "https://sfu.example.com" {
		t.Fatalf("unexpected RTC config: %+v", cfg.RTC)
	}
	raw, err := json.Marshal(cfg.RTC)
	if err != nil || bytes.Contains(raw, []byte("devsecret")) {
		t.Fatal("LiveKit secret serialized into JSON")
	}
	if len(cfg.RTC.STUNURLs) != 2 {
		t.Fatalf("unexpected STUN URLs: %v", cfg.RTC.STUNURLs)
	}

	t.Setenv("KY_LIVEKIT_API_SECRET", "")
	if _, err := config.LoadFromEnv(); err == nil {
		t.Fatal("partial LiveKit config accepted")
	}
}

// KY_ADMIN_USERNAME names the bootstrap admin, so a KyIdentity user called admin can sync.
func TestAdminUsernameFromEnv(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_ADMIN_USERNAME", "")
	cfg, err := config.LoadFromEnv()
	if err != nil || cfg.Security.AdminUsername != "admin" {
		t.Fatalf("default: %v %+v", err, cfg)
	}
	t.Setenv("KY_ADMIN_USERNAME", "ky.local-admin_1")
	if cfg, err = config.LoadFromEnv(); err != nil || cfg.Security.AdminUsername != "ky.local-admin_1" {
		t.Fatalf("override: %v %+v", err, cfg)
	}
	for _, bad := range []string{"ab", "local admin", "ad\x01min", "ädmin", "a/b", strings.Repeat("a", 65)} {
		t.Setenv("KY_ADMIN_USERNAME", bad)
		if _, err := config.LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "KY_ADMIN_USERNAME") {
			t.Errorf("%q: got %v, want a KY_ADMIN_USERNAME error", bad, err)
		}
	}
}

// Every attachment upload is staged first, so KY_MAX_UPLOAD_BYTES above either the pending
// per-user quota or the workspace total quota would advertise an unreachable maximum.
func TestAttachmentLimitsConsistency(t *testing.T) {
	t.Run("max_upload_above_default_pending_quota_fails", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_MAX_UPLOAD_BYTES", "104857600") // 100 MiB > 50 MiB default pending cap
		t.Setenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", "")
		t.Setenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES", "")
		_, err := config.LoadFromEnv()
		if err == nil || !strings.Contains(err.Error(), "KY_MAX_UPLOAD_BYTES") || !strings.Contains(err.Error(), "KY_ATTACHMENTS_MAX_PENDING_USER_BYTES") {
			t.Fatalf("got %v, want error naming KY_MAX_UPLOAD_BYTES and KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", err)
		}
	})

	t.Run("max_upload_matching_raised_pending_quota_succeeds", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_MAX_UPLOAD_BYTES", "104857600")
		t.Setenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", "104857600")
		t.Setenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES", "")
		cfg, err := config.LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Attachments.MaxUploadBytes != 104857600 || cfg.Attachments.MaxPendingUserBytes != 104857600 {
			t.Fatalf("unexpected attachment limits: %+v", cfg.Attachments)
		}
	})

	t.Run("lowered_pending_quota_below_default_upload_fails", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_MAX_UPLOAD_BYTES", "")
		t.Setenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", "10485760") // 10 MiB < 25 MiB default max upload
		t.Setenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES", "")
		_, err := config.LoadFromEnv()
		if err == nil || !strings.Contains(err.Error(), "KY_ATTACHMENTS_MAX_PENDING_USER_BYTES") {
			t.Fatalf("got %v, want error naming KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", err)
		}
	})

	t.Run("lowered_total_quota_below_default_upload_fails", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_MAX_UPLOAD_BYTES", "")
		t.Setenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", "")
		t.Setenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES", "10485760") // 10 MiB < 25 MiB default max upload
		_, err := config.LoadFromEnv()
		if err == nil || !strings.Contains(err.Error(), "KY_ATTACHMENTS_MAX_TOTAL_BYTES") {
			t.Fatalf("got %v, want error naming KY_ATTACHMENTS_MAX_TOTAL_BYTES", err)
		}
	})

	t.Run("consistent_lowered_limits_succeed", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_MAX_UPLOAD_BYTES", "10485760")
		t.Setenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES", "10485760")
		t.Setenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES", "10485760")
		cfg, err := config.LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Attachments.MaxUploadBytes != 10485760 || cfg.Attachments.MaxTotalBytes != 10485760 {
			t.Fatalf("unexpected attachment limits: %+v", cfg.Attachments)
		}
	})
}

func TestTenancyModeFromEnv(t *testing.T) {
	for _, mode := range []string{"", "single"} {
		t.Run("single/"+mode, func(t *testing.T) {
			t.Setenv("KY_DATA_DIR", t.TempDir())
			t.Setenv("KY_TENANCY_MODE", mode)
			cfg, err := config.LoadFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Tenancy.Mode != config.TenancySingle {
				t.Fatalf("tenancy mode = %q, want single", cfg.Tenancy.Mode)
			}
		})
	}

	for _, mode := range []string{"multi", " MuLtI "} {
		t.Run("unavailable/"+mode, func(t *testing.T) {
			t.Setenv("KY_DATA_DIR", t.TempDir())
			t.Setenv("KY_TENANCY_MODE", mode)
			if _, err := config.LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "KY_TENANCY_MODE=multi: multi-tenant mode is unavailable in this release") {
				t.Fatalf("want multi-tenant release refusal, got %v", err)
			}
		})
	}

	multiEnv := func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_DB_DRIVER", "postgres")
		t.Setenv("KY_DB_DSN", "postgres://user:pass@localhost:5432/testdb")
		t.Setenv("KY_STAFF_ORG_ID", "00000000-0000-4000-8000-000000000001")
		t.Setenv("KY_SESSION_SECRET", "multi-session-secret-0123456789abcdef")
		t.Setenv("KY_ENCRYPTION_KEY", strings.Repeat("ab", 32))
		t.Setenv("KY_VAPID_PRIVATE_KEY", "unchecked-here")
	}

	// Replicas must share every secret: none may be minted per process or per data directory.
	t.Run("multi_requires_shared_secrets", func(t *testing.T) {
		for _, tc := range []struct{ unset, want string }{
			{"KY_SESSION_SECRET", "KY_SESSION_SECRET"},
			{"KY_ENCRYPTION_KEY", "KY_ENCRYPTION_KEY"},
			{"KY_VAPID_PRIVATE_KEY", "KY_VAPID_PRIVATE_KEY"},
		} {
			multiEnv(t)
			dir := os.Getenv("KY_DATA_DIR")
			t.Setenv(tc.unset, "")
			if _, err := config.LoadForTenancy(config.TenancyMulti); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("multi without %s: %v", tc.unset, err)
			}
			for _, f := range []string{"encryption.key", "vapid.key"} {
				if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
					t.Errorf("multi mode minted %s", f)
				}
			}
		}
	})

	t.Run("multi_accepts_shared_files", func(t *testing.T) {
		multiEnv(t)
		dir := os.Getenv("KY_DATA_DIR")
		t.Setenv("KY_ENCRYPTION_KEY", "")
		t.Setenv("KY_VAPID_PRIVATE_KEY", "")
		if err := os.WriteFile(filepath.Join(dir, "encryption.key"), []byte(strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vapid.key"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadForTenancy(config.TenancyMulti); err != nil {
			t.Fatalf("shared files: %v", err)
		}
		t.Setenv("KY_PUSH_ENABLED", "false")
		if err := os.Remove(filepath.Join(dir, "vapid.key")); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadForTenancy(config.TenancyMulti); err != nil {
			t.Fatalf("push off needs no VAPID key: %v", err)
		}
	})

	// Object storage: all of KY_ATTACHMENTS_S3_* or none, multi mode only, no secret in errors.
	t.Run("object_store", func(t *testing.T) {
		const secret = "s3-secret-never-printed"
		s3Env := func(t *testing.T) {
			multiEnv(t)
			dir := os.Getenv("KY_DATA_DIR")
			seal := filepath.Join(dir, "seal.key")
			if err := os.WriteFile(seal, []byte(strings.Repeat("ef", 32)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			secretFile := filepath.Join(dir, "s3.secret")
			if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("KY_ATTACHMENTS_S3_ENDPOINT", "https://objects.example.test")
			t.Setenv("KY_ATTACHMENTS_S3_REGION", "us-east-2")
			t.Setenv("KY_ATTACHMENTS_S3_BUCKET", "kymessages")
			t.Setenv("KY_ATTACHMENTS_S3_ACCESS_KEY", "access-id")
			t.Setenv("KY_ATTACHMENTS_S3_SECRET_FILE", secretFile)
			t.Setenv("KY_ATTACHMENTS_S3_SECRET", "") // each case starts from the same valid set
			t.Setenv("KY_ATTACHMENTS_S3_ACCESS_KEY_FILE", "")
			t.Setenv("KY_ATTACHMENTS_S3_SEAL_KEY_FILE", seal)
		}
		s3Env(t)
		cfg, err := config.LoadForTenancy(config.TenancyMulti)
		if err != nil {
			t.Fatal(err)
		}
		obj := cfg.Attachments.ObjectStore
		if obj == nil || obj.S3.SecretKey != secret || obj.S3.Bucket != "kymessages" || len(obj.SealKey) != 32 {
			t.Fatalf("object store: %+v", obj)
		}
		if printed := fmt.Sprintf("%v %+v %#v", obj, *obj, cfg.Attachments); strings.Contains(printed, secret) || strings.Contains(printed, "efef") {
			t.Fatal("a secret is printable")
		}
		for _, tc := range []struct{ name, value string }{
			{"KY_ATTACHMENTS_S3_ENDPOINT", "http://objects.example.test"},
			{"KY_ATTACHMENTS_S3_ENDPOINT", "https://user:" + secret + "@objects.example.test"},
			{"KY_ATTACHMENTS_S3_ENDPOINT", ""},
			{"KY_ATTACHMENTS_S3_REGION", ""},
			{"KY_ATTACHMENTS_S3_BUCKET", "a/b"},
			{"KY_ATTACHMENTS_S3_SECRET_FILE", ""},
			{"KY_ATTACHMENTS_S3_SECRET", secret}, // with the file too: ambiguous
			{"KY_ATTACHMENTS_S3_SEAL_KEY_FILE", ""},
			{"KY_ATTACHMENTS_S3_SEAL_KEY_FILE", os.Getenv("KY_ATTACHMENTS_S3_SECRET_FILE")},
		} {
			s3Env(t)
			t.Setenv(tc.name, tc.value)
			_, err := config.LoadForTenancy(config.TenancyMulti)
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Errorf("%s=%q: %v", tc.name, tc.value, err)
			}
		}
		// Single mode never takes object storage, even fully configured.
		s3Env(t)
		t.Setenv("KY_DB_DRIVER", "sqlite")
		if _, err := config.LoadForTenancy(config.TenancySingle); err == nil || !strings.Contains(err.Error(), "multi only") {
			t.Fatalf("single mode accepted object storage: %v", err)
		}
		t.Setenv("KY_ATTACHMENTS_S3_SEAL_KEY_FILE", "")
		t.Setenv("KY_ATTACHMENTS_S3_ENDPOINT", "")
		if _, err := config.LoadForTenancy(config.TenancySingle); err == nil {
			t.Fatal("single mode accepted a partial object store setting")
		}
	})

	t.Run("single_still_mints_keys", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("KY_DATA_DIR", dir)
		t.Setenv("KY_TENANCY_MODE", "")
		t.Setenv("KY_SESSION_SECRET", "")
		t.Setenv("KY_ENCRYPTION_KEY", "")
		if _, err := config.LoadFromEnv(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "encryption.key")); err != nil {
			t.Fatalf("single mode must keep minting its key file: %v", err)
		}
	})

	t.Run("multi_requires_postgres", func(t *testing.T) {
		multiEnv(t)
		t.Setenv("KY_DB_DRIVER", "sqlite")
		if _, err := config.LoadForTenancy(config.TenancyMulti); err == nil || !strings.Contains(err.Error(), "requires KY_DB_DRIVER=postgres") {
			t.Fatalf("multi on sqlite: %v", err)
		}
	})

	t.Run("multi_requires_canonical_staff_org", func(t *testing.T) {
		for _, staff := range []string{"", "org-staff", "00000000-0000-4000-8000-00000000000A", "{00000000-0000-4000-8000-000000000001}"} {
			multiEnv(t)
			t.Setenv("KY_STAFF_ORG_ID", staff)
			if _, err := config.LoadForTenancy(config.TenancyMulti); err == nil || !strings.Contains(err.Error(), "KY_STAFF_ORG_ID") {
				t.Errorf("KY_STAFF_ORG_ID=%q: %v", staff, err)
			}
		}
	})

	t.Run("multi_forces_scim_off", func(t *testing.T) {
		multiEnv(t)
		t.Setenv("KY_SCIM_ENABLED", "true")
		cfg, err := config.LoadForTenancy(config.TenancyMulti)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Tenancy.IsMultiTenant() || cfg.Tenancy.EffectiveMode() != config.TenancyMulti {
			t.Fatalf("unexpected multi tenancy: %+v", cfg.Tenancy)
		}
		if cfg.SCIM.Enabled {
			t.Fatal("expected KY_TENANCY_MODE=multi to force SCIM.Enabled=false")
		}
		if cfg.Tenancy.MayAdminister("00000000-0000-4000-8000-0000000000aa") {
			t.Fatal("only the staff org may administer in multi-tenant mode")
		}
	})

	t.Run("staff_org_administers", func(t *testing.T) {
		multiEnv(t)
		t.Setenv("KY_STAFF_ORG_ID", " 00000000-0000-4000-8000-000000000001 ")
		cfg, err := config.LoadForTenancy(config.TenancyMulti)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Tenancy.MayAdminister("00000000-0000-4000-8000-000000000001") || cfg.Tenancy.MayAdminister("00000000-0000-4000-8000-0000000000aa") || cfg.Tenancy.MayAdminister("") {
			t.Fatalf("MayAdminister wrong for staff org %q", cfg.Tenancy.StaffOrgID)
		}
		single := config.TenancyConfig{Mode: config.TenancySingle}
		if !single.MayAdminister("00000000-0000-4000-8000-0000000000aa") {
			t.Fatal("single-tenant mode must keep every org's admins")
		}
	})

	t.Run("invalid_mode_fails", func(t *testing.T) {
		t.Setenv("KY_DATA_DIR", t.TempDir())
		t.Setenv("KY_TENANCY_MODE", "hybrid")
		if _, err := config.LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "KY_TENANCY_MODE") {
			t.Fatalf("want KY_TENANCY_MODE error, got %v", err)
		}
	})
}

func TestMaintenanceLoaderKeepsServerGate(t *testing.T) {
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_TENANCY_MODE", "multi")
	t.Setenv("KY_DB_DRIVER", "postgres")
	t.Setenv("KY_DB_DSN", "postgres://unused/maintenance")
	t.Setenv("KY_STAFF_ORG_ID", "00000000-0000-4000-8000-000000000001")
	t.Setenv("KY_SESSION_SECRET", "maintenance-session-secret-0123456789")
	t.Setenv("KY_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	t.Setenv("KY_PUSH_ENABLED", "false")
	if cfg, err := config.LoadForMaintenance(); err != nil || !cfg.Tenancy.IsMultiTenant() {
		t.Fatalf("offline multi config: %+v %v", cfg, err)
	}
	if _, err := config.LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "unavailable in this release") {
		t.Fatalf("server gate lost: %v", err)
	}
	t.Setenv("KY_TENANCY_MODE", "invalid")
	if _, err := config.LoadForMaintenance(); err == nil {
		t.Fatal("maintenance accepted invalid tenancy mode")
	}
}
