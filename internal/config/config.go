package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky-primitives/applysetup"
	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/s3"
	"github.com/google/uuid"
)

// Config encapsulates all runtime configuration for KyMessages.
type Config struct {
	InstallerSSO *applysetup.SSO   `json:"-"`
	Tenancy      TenancyConfig     `json:"tenancy"`
	Server       ServerConfig      `json:"server"`
	Database     DatabaseConfig    `json:"database"`
	Security     SecurityConfig    `json:"security"`
	SSO          SSOConfig         `json:"sso"`
	SCIM         SCIMConfig        `json:"scim"`
	Backup       BackupConfig      `json:"backup"`
	Captcha      CaptchaConfig     `json:"captcha"`
	RTC          RTCConfig         `json:"rtc"`
	Attachments  AttachmentsConfig `json:"attachments"`
	Push         PushConfig        `json:"push"`
	KyPost       PairConfig        `json:"kypost"`
	KyCalendar   PairConfig        `json:"kycalendar"`
}

// PairConfig holds an explicit suite peer configuration (KY_<PEER>_URL and _SECRET_FILE).
// When unset, the peer may be fetched automatically from KyIdentity's suite directory.
type PairConfig struct {
	URL    string `json:"url"`
	Secret []byte `json:"-"`
}

// IsCanonicalUUID reports whether s is a canonical 36-character lowercase hyphenated UUID.
func IsCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	u, err := uuid.Parse(s)
	return err == nil && s == u.String()
}

// Tenancy modes for KY_TENANCY_MODE. Single is the default and preserves existing self-hosted
// single-organization behavior unchanged.
const (
	TenancySingle = "single"
	TenancyMulti  = "multi"
)

// TenancyConfig controls whether the server operates as a single-organization deployment or
// isolates multiple KyIdentity organizations by org_id.
type TenancyConfig struct {
	Mode string `json:"mode"` // "single" (default) or "multi"
	// StaffOrgID is KyIdentity's staff org (KY_STAFF_ORG_ID). In multi-tenant mode only its
	// accounts may be administrators; customer orgs have none.
	StaffOrgID string `json:"staff_org_id"`
	// Cells are the KyIdentity home regions this deployment serves (KY_CELLS, multi mode).
	// Every org whose home_region is another cell is refused on every way in.
	Cells []string `json:"cells,omitempty"`
}

// MaxCells is KyIdentity's region-map cap per app.
const MaxCells = 32

var validCell = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidCell reports whether s is a KyIdentity home-region slug.
func ValidCell(s string) bool { return validCell.MatchString(s) }

// parseCells reads KY_CELLS: comma-separated home-region slugs, at most MaxCells, no repeats.
func parseCells(raw string) ([]string, error) {
	var cells []string
	seen := map[string]bool{}
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if !ValidCell(c) || seen[c] {
			return nil, errors.New("KY_CELLS: comma-separated home-region slugs (^[a-z][a-z0-9-]{1,31}$), each once")
		}
		seen[c] = true
		cells = append(cells, c)
	}
	if len(cells) > MaxCells {
		return nil, fmt.Errorf("KY_CELLS: at most %d cells", MaxCells)
	}
	return cells, nil
}

// MayAdminister reports whether an account bound to orgID may hold the install-wide admin role.
func (t TenancyConfig) MayAdminister(orgID string) bool {
	return !t.IsMultiTenant() || (t.StaffOrgID != "" && orgID == t.StaffOrgID)
}

// EffectiveMode returns the normalized tenancy mode, defaulting to single-tenant.
func (t TenancyConfig) EffectiveMode() string {
	if strings.EqualFold(strings.TrimSpace(t.Mode), TenancyMulti) {
		return TenancyMulti
	}
	return TenancySingle
}

// IsMultiTenant reports whether multi-tenant org_id isolation is active.
func (t TenancyConfig) IsMultiTenant() bool {
	return t.EffectiveMode() == TenancyMulti
}

// DefaultMaxUploadBytes is the default per-attachment upload size limit (25 MiB).
const DefaultMaxUploadBytes int64 = 25 << 20

// MaxAllowedUploadBytes caps KY_MAX_UPLOAD_BYTES at 100 MiB so single uploads stay bounded.
const MaxAllowedUploadBytes int64 = 100 << 20

// DefaultMaxTotalAttachmentBytes caps aggregate stored attachment bytes per tenant (1 GiB).
const DefaultMaxTotalAttachmentBytes int64 = 1 << 30

// DefaultMaxPendingUserBytes caps unposted staged attachment bytes per uploader (50 MiB).
const DefaultMaxPendingUserBytes int64 = 50 << 20

// DefaultPendingAttachmentTTL is how long unposted staged attachments survive before expiry.
const DefaultPendingAttachmentTTL = 24 * time.Hour

// AttachmentsConfig configures local blob storage for chat file and image attachments.
type AttachmentsConfig struct {
	Dir                 string        `json:"dir"`
	MaxUploadBytes      int64         `json:"max_upload_bytes"`
	MaxTotalBytes       int64         `json:"max_total_bytes"`
	MaxPendingUserBytes int64         `json:"max_pending_user_bytes"`
	PendingTTL          time.Duration `json:"pending_ttl"`
	// ObjectStore is the multi-mode S3 backend (KY_ATTACHMENTS_S3_*); nil keeps disk.
	ObjectStore *ObjectStoreConfig `json:"-"`
}

// ObjectStoreConfig is the attachment bucket and the key that seals every object in it.
// Neither secret is printable: s3.Config hides its keys and SealKey is never logged.
type ObjectStoreConfig struct {
	S3      s3.Config
	SealKey []byte
}

func (ObjectStoreConfig) String() string   { return "config.ObjectStoreConfig" }
func (ObjectStoreConfig) GoString() string { return "config.ObjectStoreConfig" }

// PushConfig configures RFC 8291/8292 Web Push notifications (VAPID).
type PushConfig struct {
	Disabled        bool   `json:"disabled"`
	VAPIDPrivateKey string `json:"-"` // Optional base64url 32-byte P-256 scalar; defaults to <DataDir>/vapid.key
	VAPIDSubject    string `json:"vapid_subject"`
	AllowPrivate    bool   `json:"-"` // Tests only
}

// RTCConfig holds native hybrid P2P + LiveKit SFU calling and KyCalendar meeting settings.
// LiveKit is optional: when unset, P2P WebRTC calls still work directly over /api/v1/ws.
type RTCConfig struct {
	LiveKitURL        string   `json:"livekit_url"`
	LiveKitAPIKey     string   `json:"-"`
	LiveKitAPISecret  string   `json:"-"`
	STUNURLs          []string `json:"stun_urls"`
	MeetingSyncSecret string   `json:"-"`
}

// LiveKitEnabled reports whether LiveKit SFU credentials and endpoint are configured.
func (r RTCConfig) LiveKitEnabled() bool {
	return r.LiveKitURL != "" && r.LiveKitAPIKey != "" && r.LiveKitAPISecret != ""
}

// ServerConfig defines HTTP and network settings.
type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	AppURL       string        `json:"app_url"`
	AppName      string        `json:"app_name"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	Environment  string        `json:"environment"`
}

// DatabaseConfig holds connection settings for pluggable storage (SQLite, PostgreSQL, MySQL).
type DatabaseConfig struct {
	Driver          string        `json:"driver"` // "sqlite", "postgres", "mysql"
	DSN             string        `json:"dsn"`    // Connection string or file path
	ReadReplicaDSN  string        `json:"-"`      // Optional read-only PostgreSQL replica DSN
	DataDir         string        `json:"data_dir"`
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
}

// SecurityConfig holds encryption keys, cookie secrets, and session settings.
type SecurityConfig struct {
	SessionSecret string `json:"session_secret"`
	EncryptionKey []byte `json:"-"` // 32 bytes for AES-256-GCM; never serialised
	CookieSecure  bool   `json:"cookie_secure"`
	CookieDomain  string `json:"cookie_domain"`
	SessionTTL    time.Duration
	// TrustedProxies is the parsed KY_TRUSTED_PROXIES allowlist. Only a request whose peer
	// address falls inside it may speak for a client other than itself.
	TrustedProxies []netip.Prefix `json:"-"`
	// AdminUsername names the local admin created on an empty database (KY_ADMIN_USERNAME).
	AdminUsername string `json:"admin_username"`
}

// usernamePattern is the account username rule; auth.ValidateUsername applies it too.
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{3,64}$`)

// ValidUsername reports whether s is a valid account username.
func ValidUsername(s string) bool { return usernamePattern.MatchString(s) }

// SSOConfig holds identity provider and federation parameters.
type SSOConfig struct {
	Installer            *applysetup.SSO `json:"-"`
	Enabled              bool            `json:"enabled"`
	KyIdentityIssuer     string          `json:"kyidentity_issuer"`
	KyIdentityClientID   string          `json:"kyidentity_client_id"`
	KyIdentitySecret     string          `json:"kyidentity_secret"`
	KyIdentityHMACSecret string          `json:"kyidentity_hmac_secret"`
	AutoProvision        bool            `json:"auto_provision"`
}

// SCIMConfig holds settings for RFC 7643/7644 inbound user provisioning.
type SCIMConfig struct {
	Enabled     bool   `json:"enabled"`
	BearerToken string `json:"bearer_token"`
	// TokenSet is true when KY_SCIM_TOKEN is set; otherwise the token is random per start.
	TokenSet bool `json:"-"`
}

// BackupConfig holds parameters for KyBackup capsules & recovery drills.
type BackupConfig struct {
	Dir string `json:"dir"`
	// Keep is how many capsule generations recoveryclient retains; it refuses values below 1.
	Keep int `json:"keep"`
	// DepositInterval is how often a paired instance seals and deposits a capsule to
	// KyRecovery. Zero disables the schedule; deposits then happen only on request.
	DepositInterval time.Duration `json:"deposit_interval"`
	// AllowPrivateRecovery admits private and CGNAT KyRecovery destinations (HTTPS still
	// required). Off by default: KyRecovery destinations must be public.
	AllowPrivateRecovery bool `json:"allow_private_recovery"`
}

// CaptchaConfig holds anti-abuse settings for password login.
type CaptchaConfig struct {
	Provider      string `json:"provider"` // "pow" or "none"
	DifficultyPoW int    `json:"difficulty_pow"`
}

// MinDepositInterval is the shortest schedule accepted: each run snapshots the whole database
// and uploads it, and KyRecovery admits 60 deposits per token per 15 minutes.
const MinDepositInterval = 15 * time.Minute

// DefaultAppName is the service name an unconfigured instance runs under. Capsules are sealed
// under it, so the restore CLI has to agree with it without loading a whole Config.
const DefaultAppName = "KyMessages"

// AppVersion is shared by the CLI and every capsule-producing path.
const AppVersion = "0.4.2"

// ErrMultiTenantRelease is the refusal every release build gives a complete multi-tenant config.
var ErrMultiTenantRelease = errors.New("KY_TENANCY_MODE=multi: multi-tenant mode is unavailable in this release")

// LoadFromEnv initializes a Config struct populated from environment variables with sensible defaults.
func LoadFromEnv() (*Config, error) {
	mode := strings.ToLower(getEnv("KY_TENANCY_MODE", TenancySingle))
	if mode != TenancySingle && mode != TenancyMulti {
		return nil, fmt.Errorf("KY_TENANCY_MODE: only single is available in this release, got %q", mode)
	}
	// A test build must never take tokens from a real issuer (RFC 2606 reserves .test).
	if multiTenantBuild && !testIssuer(getEnv("KY_KYIDENTITY_ISSUER", "")) {
		return nil, errors.New("KY_KYIDENTITY_ISSUER: this test build accepts only an https issuer under .test")
	}
	if mode == TenancySingle {
		return loadFromEnv(mode)
	}
	// Every multi requirement is checked in both builds; only then does a release build refuse.
	cfg, err := loadFromEnv(mode)
	if err != nil {
		return nil, err
	}
	if cfg.Attachments.ObjectStore == nil {
		// Spec §9.1: no attachment disk volume in hosted multi mode.
		return nil, errors.New("KY_TENANCY_MODE=multi requires object storage (KY_ATTACHMENTS_S3_*)")
	}
	if !multiTenantBuild {
		return nil, ErrMultiTenantRelease
	}
	return cfg, nil
}

func testIssuer(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.HasSuffix(strings.ToLower(u.Hostname()), ".test")
}

// LoadForMaintenance reads deployment configuration for offline grant invalidation only.
// Server startup must use LoadFromEnv, which retains the multi-tenant release gate.
func LoadForMaintenance() (*Config, error) {
	return loadFromEnv(strings.ToLower(getEnv("KY_TENANCY_MODE", TenancySingle)))
}

func loadFromEnv(tenancyMode string) (*Config, error) {
	if err := rejectLegacyEnvironment(); err != nil {
		return nil, err
	}
	port := getEnvInt("KY_PORT", getEnvInt("PORT", 8080))
	host := getEnv("KY_HOST", "0.0.0.0")
	appURL := getEnv("KY_APP_URL", fmt.Sprintf("http://localhost:%d", port))
	appName := getEnv("KY_APP_NAME", DefaultAppName)
	env := getEnv("KY_ENV", "development")

	driver := strings.ToLower(getEnv("KY_DB_DRIVER", "sqlite"))
	dataDir := getEnv("KY_DATA_DIR", "./data")
	dsn := getEnv("KY_DB_DSN", fmt.Sprintf("%s/ky_server.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dataDir))
	if driver == "postgres" || driver == "postgresql" {
		driver = "postgres"
		// No default: a guessed postgres:postgres@localhost would connect to whatever answers.
		if dsn = getEnv("KY_DB_DSN", ""); dsn == "" {
			return nil, errors.New("KY_DB_DSN is required with KY_DB_DRIVER=postgres")
		}
	}

	if tenancyMode != TenancySingle && tenancyMode != TenancyMulti {
		return nil, fmt.Errorf("KY_TENANCY_MODE: must be %q or %q, got %q", TenancySingle, TenancyMulti, tenancyMode)
	}
	multi := tenancyMode == TenancyMulti

	// Multi mode runs several replicas: each secret below must be the same on all of them, so
	// none may be minted per process or per data directory.
	sessionSecret := getEnv("KY_SESSION_SECRET", "")
	if env == "production" && sessionSecret == "" {
		return nil, fmt.Errorf("KY_SESSION_SECRET is required in production")
	}
	if multi && sessionSecret == "" {
		return nil, errors.New("KY_SESSION_SECRET is required when KY_TENANCY_MODE=multi (every replica must verify the others' challenges)")
	}
	if sessionSecret == "" {
		sessionSecret = generateRandomHex(32)
	}

	encryptionKey, ok, err := keyfile.FromEnv("KY_ENCRYPTION_KEY", 32)
	if err != nil {
		return nil, fmt.Errorf("KY_ENCRYPTION_KEY: %w", err)
	}
	if !ok && multi {
		// A shared file is fine; a key minted here would differ from the other replicas'.
		if encryptionKey, err = keyfile.Load(filepath.Join(dataDir, "encryption.key"), 32); err != nil {
			return nil, fmt.Errorf("KY_TENANCY_MODE=multi requires KY_ENCRYPTION_KEY or a shared %s: %w", filepath.Join(dataDir, "encryption.key"), err)
		}
	} else if !ok {
		encryptionKey, err = keyfile.LoadOrCreate(filepath.Join(dataDir, "encryption.key"), 32)
		if err != nil {
			return nil, fmt.Errorf("encryption key: %w", err)
		}
	}

	depositInterval, err := getEnvDuration("KY_BACKUP_DEPOSIT_INTERVAL", 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("KY_BACKUP_DEPOSIT_INTERVAL: %w", err)
	}
	if depositInterval != 0 && depositInterval < MinDepositInterval {
		return nil, fmt.Errorf("KY_BACKUP_DEPOSIT_INTERVAL: %s is below the %s minimum (0 disables)", depositInterval, MinDepositInterval)
	}

	backupKeep := getEnvInt("KY_BACKUP_KEEP", 7)
	if backupKeep < 1 {
		return nil, fmt.Errorf("KY_BACKUP_KEEP: must be at least 1, got %d", backupKeep)
	}

	// An https app URL means browsers reach it over TLS, so cookies are Secure (and HSTS sent)
	// whatever KY_ENV says. Production over plain HTTP must be an explicit choice.
	https := strings.HasPrefix(strings.ToLower(appURL), "https://")
	cookieSecure := getEnvBool("KY_COOKIE_SECURE", env == "production" || https)
	if env == "production" && !https && cookieSecure {
		return nil, fmt.Errorf("KY_APP_URL must be https in production (set KY_COOKIE_SECURE=false to serve plain HTTP deliberately)")
	}

	trustedProxies, err := ParseTrustedProxies(getEnv("KY_TRUSTED_PROXIES", ""))
	if err != nil {
		return nil, fmt.Errorf("KY_TRUSTED_PROXIES: %w", err)
	}

	kyIdentityHMAC := getEnv("KY_KYIDENTITY_HMAC_SECRET", "")
	rtcCfg, err := rtcFromEnv(kyIdentityHMAC)
	if err != nil {
		return nil, err
	}

	adminUsername := getEnv("KY_ADMIN_USERNAME", "admin")
	if !ValidUsername(adminUsername) {
		return nil, errors.New("KY_ADMIN_USERNAME: must be 3-64 characters of letters, digits, '.', '_' or '-'")
	}

	staffOrgID := strings.TrimSpace(os.Getenv("KY_STAFF_ORG_ID"))
	var cells []string
	if tenancyMode != TenancyMulti && strings.TrimSpace(os.Getenv("KY_CELLS")) != "" {
		return nil, errors.New("KY_CELLS is for KY_TENANCY_MODE=multi only")
	}
	scimEnabled := getEnvBool("KY_SCIM_ENABLED", true)
	if tenancyMode == TenancyMulti {
		if driver != "postgres" {
			return nil, errors.New("KY_TENANCY_MODE=multi requires KY_DB_DRIVER=postgres")
		}
		if !IsCanonicalUUID(staffOrgID) {
			return nil, errors.New("KY_STAFF_ORG_ID is required and must be a canonical lowercase UUID when KY_TENANCY_MODE=multi")
		}
		if cells, err = parseCells(os.Getenv("KY_CELLS")); err != nil {
			return nil, fmt.Errorf("%w (required when KY_TENANCY_MODE=multi)", err)
		}
		scimEnabled = false
		if getEnvBool("KY_PUSH_ENABLED", true) && strings.TrimSpace(os.Getenv("KY_VAPID_PRIVATE_KEY")) == "" {
			// A shared file is fine; push.LoadOrCreateVAPIDKey must never mint one per replica.
			if _, err := os.Stat(filepath.Join(dataDir, "vapid.key")); err != nil {
				return nil, fmt.Errorf("KY_TENANCY_MODE=multi requires KY_VAPID_PRIVATE_KEY or a shared %s (or KY_PUSH_ENABLED=false)", filepath.Join(dataDir, "vapid.key"))
			}
		}
	}

	kypostPair, err := pairFromEnv("KY_KYPOST")
	if err != nil {
		return nil, err
	}
	kycalendarPair, err := pairFromEnv("KY_KYCALENDAR")
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Tenancy: TenancyConfig{
			Mode:       tenancyMode,
			StaffOrgID: staffOrgID,
			Cells:      cells,
		},
		Server: ServerConfig{
			Host:         host,
			Port:         port,
			AppURL:       strings.TrimRight(appURL, "/"),
			AppName:      appName,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			Environment:  env,
		},
		Database: DatabaseConfig{
			Driver:          driver,
			DSN:             dsn,
			ReadReplicaDSN:  getEnv("KY_DB_READ_REPLICA_DSN", ""),
			DataDir:         dataDir,
			MaxOpenConns:    getEnvInt("KY_DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("KY_DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: 15 * time.Minute,
		},
		Security: SecurityConfig{
			SessionSecret:  sessionSecret,
			EncryptionKey:  encryptionKey,
			CookieSecure:   cookieSecure,
			CookieDomain:   getEnv("KY_COOKIE_DOMAIN", ""),
			SessionTTL:     7 * 24 * time.Hour,
			TrustedProxies: trustedProxies,
			AdminUsername:  adminUsername,
		},
		SSO: SSOConfig{
			Enabled:              getEnvBool("KY_SSO_ENABLED", true),
			KyIdentityIssuer:     getEnv("KY_KYIDENTITY_ISSUER", ""),
			KyIdentityClientID:   getEnv("KY_KYIDENTITY_CLIENT_ID", ""),
			KyIdentitySecret:     getEnv("KY_KYIDENTITY_SECRET", ""),
			KyIdentityHMACSecret: kyIdentityHMAC,
			AutoProvision:        getEnvBool("KY_SSO_AUTO_PROVISION", true),
		},
		SCIM: SCIMConfig{
			Enabled:     scimEnabled,
			BearerToken: getEnv("KY_SCIM_TOKEN", generateRandomHex(24)),
			TokenSet:    getEnv("KY_SCIM_TOKEN", "") != "",
		},
		Backup: BackupConfig{
			Dir:                  getEnv("KY_BACKUP_DIR", ""),
			Keep:                 backupKeep,
			DepositInterval:      depositInterval,
			AllowPrivateRecovery: getEnvBool("KY_BACKUP_ALLOW_PRIVATE_RECOVERY", false),
		},
		Captcha: CaptchaConfig{
			Provider:      getEnv("KY_CAPTCHA_PROVIDER", "pow"),
			DifficultyPoW: getEnvInt("KY_CAPTCHA_POW_DIFFICULTY", 50000),
		},
		RTC: rtcCfg,
		Attachments: AttachmentsConfig{
			Dir:                 getEnv("KY_ATTACHMENTS_DIR", filepath.Join(dataDir, "attachments")),
			MaxUploadBytes:      DefaultMaxUploadBytes,
			MaxTotalBytes:       DefaultMaxTotalAttachmentBytes,
			MaxPendingUserBytes: DefaultMaxPendingUserBytes,
			PendingTTL:          DefaultPendingAttachmentTTL,
		},
		Push: PushConfig{
			Disabled:        !getEnvBool("KY_PUSH_ENABLED", true),
			VAPIDPrivateKey: strings.TrimSpace(os.Getenv("KY_VAPID_PRIVATE_KEY")),
			VAPIDSubject:    strings.TrimSpace(os.Getenv("KY_VAPID_SUBJECT")),
		},
		KyPost:     kypostPair,
		KyCalendar: kycalendarPair,
	}
	if rawMax := strings.TrimSpace(os.Getenv("KY_MAX_UPLOAD_BYTES")); rawMax != "" {
		n, err := strconv.ParseInt(rawMax, 10, 64)
		if err != nil || n < 1024 || n > MaxAllowedUploadBytes {
			return nil, fmt.Errorf("KY_MAX_UPLOAD_BYTES: must be between 1024 and %d bytes", MaxAllowedUploadBytes)
		}
		cfg.Attachments.MaxUploadBytes = n
	}
	if rawTotal := strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES")); rawTotal != "" {
		n, err := strconv.ParseInt(rawTotal, 10, 64)
		if err != nil || n < 1024 {
			return nil, errors.New("KY_ATTACHMENTS_MAX_TOTAL_BYTES: must be at least 1024 bytes")
		}
		cfg.Attachments.MaxTotalBytes = n
	}
	if rawPending := strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES")); rawPending != "" {
		n, err := strconv.ParseInt(rawPending, 10, 64)
		if err != nil || n < 1024 {
			return nil, errors.New("KY_ATTACHMENTS_MAX_PENDING_USER_BYTES: must be at least 1024 bytes")
		}
		cfg.Attachments.MaxPendingUserBytes = n
	}
	if rawTTL := strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_PENDING_TTL")); rawTTL != "" {
		d, err := time.ParseDuration(rawTTL)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			return nil, errors.New("KY_ATTACHMENTS_PENDING_TTL: must be a duration between 1m and 720h")
		}
		cfg.Attachments.PendingTTL = d
	}
	if cfg.Attachments.ObjectStore, err = objectStoreFromEnv(multi); err != nil {
		return nil, err
	}
	// Every upload is staged before it can be attached to a message, so a single-file limit
	// above the pending or total quota would advertise an unreachable maximum to clients.
	if cfg.Attachments.MaxUploadBytes > cfg.Attachments.MaxPendingUserBytes {
		return nil, fmt.Errorf("KY_MAX_UPLOAD_BYTES (%d) cannot exceed KY_ATTACHMENTS_MAX_PENDING_USER_BYTES (%d)", cfg.Attachments.MaxUploadBytes, cfg.Attachments.MaxPendingUserBytes)
	}
	if cfg.Attachments.MaxUploadBytes > cfg.Attachments.MaxTotalBytes {
		return nil, fmt.Errorf("KY_MAX_UPLOAD_BYTES (%d) cannot exceed KY_ATTACHMENTS_MAX_TOTAL_BYTES (%d)", cfg.Attachments.MaxUploadBytes, cfg.Attachments.MaxTotalBytes)
	}
	// Login verifies only proof-of-work. Accepting another name would silently disable it.
	if p := cfg.Captcha.Provider; p != "pow" && p != "none" {
		return nil, fmt.Errorf("KY_CAPTCHA_PROVIDER: %q is not supported (use pow or none)", p)
	}

	return cfg, nil
}

// rtcFromEnv parses native hybrid P2P + LiveKit SFU settings.
func rtcFromEnv(fallbackSyncSecret string) (RTCConfig, error) {
	rawURL := strings.TrimSpace(getEnv("KY_LIVEKIT_URL", ""))
	apiKey := strings.TrimSpace(getEnv("KY_LIVEKIT_API_KEY", ""))
	apiSecret := strings.TrimSpace(getEnv("KY_LIVEKIT_API_SECRET", ""))

	if keyFile := strings.TrimSpace(getEnv("KY_LIVEKIT_API_KEY_FILE", "")); keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return RTCConfig{}, fmt.Errorf("KY_LIVEKIT_API_KEY_FILE: %w", err)
		}
		apiKey = strings.TrimSpace(string(b))
	}
	if secretFile := strings.TrimSpace(getEnv("KY_LIVEKIT_API_SECRET_FILE", "")); secretFile != "" {
		b, err := os.ReadFile(secretFile)
		if err != nil {
			return RTCConfig{}, fmt.Errorf("KY_LIVEKIT_API_SECRET_FILE: %w", err)
		}
		apiSecret = strings.TrimSpace(string(b))
	}

	var lkURL string
	if rawURL != "" || apiKey != "" || apiSecret != "" {
		if rawURL == "" || apiKey == "" || apiSecret == "" {
			return RTCConfig{}, errors.New("KY_LIVEKIT_URL, KY_LIVEKIT_API_KEY, and KY_LIVEKIT_API_SECRET must all be set together")
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return RTCConfig{}, errors.New("KY_LIVEKIT_URL must be a valid http(s) or ws(s) origin")
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "wss":
			lkURL = "https://" + u.Host
		case "http", "ws":
			lkURL = "http://" + u.Host
		default:
			return RTCConfig{}, errors.New("KY_LIVEKIT_URL scheme must be http, https, ws, or wss")
		}
		if strings.ContainsFunc(apiKey, unicode.IsControl) || strings.ContainsFunc(apiSecret, unicode.IsControl) {
			return RTCConfig{}, errors.New("LiveKit API credentials must not contain control characters")
		}
	}

	var stunURLs []string
	rawStun := strings.TrimSpace(getEnv("KY_STUN_URLS", "stun:stun.l.google.com:19302"))
	if rawStun != "" && strings.ToLower(rawStun) != "none" {
		for _, part := range strings.Split(rawStun, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				continue
			}
			lower := strings.ToLower(s)
			if !strings.HasPrefix(lower, "stun:") && !strings.HasPrefix(lower, "stuns:") {
				return RTCConfig{}, fmt.Errorf("KY_STUN_URLS: %q must start with stun: or stuns:", s)
			}
			stunURLs = append(stunURLs, s)
		}
	}

	syncSecret := strings.TrimSpace(getEnv("KY_MEETING_SYNC_SECRET", fallbackSyncSecret))
	return RTCConfig{
		LiveKitURL:        lkURL,
		LiveKitAPIKey:     apiKey,
		LiveKitAPISecret:  apiSecret,
		STUNURLs:          stunURLs,
		MeetingSyncSecret: syncSecret,
	}, nil
}

// rejectLegacyEnvironment refuses the pre-rename KY_KYSIGNON_* names: ignoring a set one
// would silently leave suite sign-in unconfigured.
func rejectLegacyEnvironment() error {
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if rest, ok := strings.CutPrefix(name, "KY_KYSIGNON_"); ok && strings.TrimSpace(value) != "" {
			return fmt.Errorf("legacy environment variable %s is set; use KY_KYIDENTITY_%s instead", name, rest)
		}
		if name == "KY_REGION" && strings.TrimSpace(value) != "" {
			return errors.New("KY_REGION is replaced by KY_CELLS, the list of cells this deployment serves")
		}
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if intVal, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return intVal
		}
	}
	return defaultVal
}

// getEnvBool treats an empty value as unset, like getEnv: a compose file's `${X:-}` must not
// silently turn off a security default such as Secure cookies.
func getEnvBool(key string, defaultVal bool) bool {
	lower := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if lower == "" {
		return defaultVal
	}
	return lower == "true" || lower == "1" || lower == "yes" || lower == "on"
}

// getEnvDuration parses a Go duration such as "24h" or "90m". Negative is refused; "0" disables.
func getEnvDuration(key string, defaultVal time.Duration) (time.Duration, error) {
	val, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(val) == "" {
		return defaultVal, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(val))
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("%s is negative", val)
	}
	return d, nil
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ParseTrustedProxies parses a comma-separated list of IPs and CIDR blocks into prefixes.
// A bare IP becomes a single-address prefix. An unparsable entry is a startup error: a
// silently dropped proxy would make the server ignore its X-Forwarded-For and lump every
// client behind it into one rate-limit bucket.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if strings.Contains(field, "/") {
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", field, err)
			}
			// Checked after unmapping: a mapped form like ::ffff:0.0.0.0/96 has Bits() == 96
			// here but means 0.0.0.0/0 once rewritten, and would otherwise slip the guard.
			masked := unmapPrefix(prefix).Masked()
			if masked.Bits() == 0 {
				return nil, fmt.Errorf("trusted proxy %q trusts every address; list the proxy's own address or subnet instead", field)
			}
			out = append(out, masked)
			continue
		}
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q: %w", field, err)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// unmapPrefix rewrites an IPv4-mapped IPv6 prefix as the plain IPv4 one it means. Peers are
// unmapped before the allowlist is consulted, and netip.Prefix.Contains never matches across
// families, so a mapped entry would otherwise match nothing at all.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() || p.Bits() < 96 {
		return p
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
}

// pairFromEnv reads an explicit suite pair, <prefix>_URL and <prefix>_SECRET_FILE: both or
// neither. The secret is at least 32 bytes and never echoed.
func pairFromEnv(prefix string) (PairConfig, error) {
	raw, file := getEnv(prefix+"_URL", ""), getEnv(prefix+"_SECRET_FILE", "")
	if raw == "" && file == "" {
		return PairConfig{}, nil
	}
	if raw == "" || file == "" {
		return PairConfig{}, fmt.Errorf("%s_URL and %s_SECRET_FILE are set together or not at all", prefix, prefix)
	}
	u, err := PeerOrigin(raw)
	if err != nil {
		return PairConfig{}, fmt.Errorf("%s_URL: %w", prefix, err)
	}
	b, err := os.ReadFile(file)
	secret := []byte(strings.TrimSpace(string(b)))
	if err != nil || len(secret) < 32 {
		return PairConfig{}, fmt.Errorf("%s_SECRET_FILE %q must name a readable file of at least 32 bytes", prefix, file)
	}
	return PairConfig{URL: u, Secret: secret}, nil
}

// PeerOrigin checks that raw is an https origin (host and optional port only, not loopback)
// and returns it without a trailing slash.
func PeerOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil:
		return "", err
	case u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return "", errors.New("must be an https origin such as https://host[:port]")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return "", errors.New("must not be a loopback address")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return "", errors.New("must not be a loopback address")
	}
	return "https://" + u.Host, nil
}

// objectStoreFromEnv reads KY_ATTACHMENTS_S3_*: all of them or none, and only in multi mode,
// so a single-mode server can never move off its disk store by accident. Errors name the
// variable, never its value.
func objectStoreFromEnv(multi bool) (*ObjectStoreConfig, error) {
	names := []string{"ENDPOINT", "REGION", "BUCKET", "ACCESS_KEY", "ACCESS_KEY_FILE", "SECRET", "SECRET_FILE", "SEAL_KEY_FILE"}
	set := false
	for _, n := range names {
		set = set || strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_S3_"+n)) != ""
	}
	if !set {
		return nil, nil
	}
	if !multi {
		return nil, errors.New("KY_ATTACHMENTS_S3_*: object storage is for KY_TENANCY_MODE=multi only")
	}
	secret := func(name string) (string, error) {
		v, file := strings.TrimSpace(os.Getenv(name)), strings.TrimSpace(os.Getenv(name+"_FILE"))
		if (v == "") == (file == "") {
			return "", fmt.Errorf("%s or %s_FILE is required (not both)", name, name)
		}
		if file != "" {
			b, err := os.ReadFile(file)
			if err != nil {
				return "", fmt.Errorf("%s_FILE: unreadable", name)
			}
			v = strings.TrimSpace(string(b))
		}
		return v, nil
	}
	access, err := secret("KY_ATTACHMENTS_S3_ACCESS_KEY")
	if err != nil {
		return nil, err
	}
	secretKey, err := secret("KY_ATTACHMENTS_S3_SECRET")
	if err != nil {
		return nil, err
	}
	sealFile := strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_S3_SEAL_KEY_FILE"))
	if sealFile == "" {
		return nil, errors.New("KY_ATTACHMENTS_S3_SEAL_KEY_FILE is required with object storage")
	}
	sealKey, err := keyfile.Load(sealFile, 32)
	if err != nil {
		return nil, errors.New("KY_ATTACHMENTS_S3_SEAL_KEY_FILE: must hold a 32-byte hex key")
	}
	cfg := s3.Config{
		Endpoint:  strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_S3_ENDPOINT")),
		Region:    strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_S3_REGION")),
		Bucket:    strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_S3_BUCKET")),
		AccessKey: access,
		SecretKey: secretKey,
	}
	if cfg.Region == "" {
		return nil, errors.New("KY_ATTACHMENTS_S3_REGION is required with object storage")
	}
	// s3.New refuses non-HTTPS endpoints, credentials or a query in the URL, and bad names.
	if _, err := s3.New(cfg); err != nil {
		return nil, errors.New("KY_ATTACHMENTS_S3_ENDPOINT/BUCKET/ACCESS_KEY: invalid (HTTPS endpoint without credentials, plain bucket name)")
	}
	return &ObjectStoreConfig{S3: cfg, SealKey: sealKey}, nil
}
