package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/auth"
	"github.com/Busnes-app/ky_server_base/internal/blobs"
	"github.com/Busnes-app/ky_server_base/internal/chat"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/devices"
	"github.com/Busnes-app/ky_server_base/internal/health"
	"github.com/Busnes-app/ky_server_base/internal/push"
	"github.com/Busnes-app/ky_server_base/internal/rtc"
	"github.com/Busnes-app/ky_server_base/internal/scim"
	"github.com/Busnes-app/ky_server_base/internal/sso"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"github.com/Busnes-app/ky_server_base/web"
)

// recoveryClient is the KyRecovery client as the handlers use it, narrowed so tests can stand
// in a fake without reaching the network.
type recoveryClient interface {
	ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (recoveryclient.PairingResult, error)
	recoveryclient.Depositor
}

type Server struct {
	config           *config.Config
	store            store.Store
	blobs            *blobs.Store
	blobsErr         error
	push             *push.Dispatcher
	sessions         *auth.SessionManager
	pairing          *devices.PairingService
	kyidentity       *sso.KyIdentityClient
	directoryChanged func()
	scim             *scim.Server
	chatHub          *chat.Hub
	calls            *chat.CallManager
	lobby            *chat.LobbyManager
	recovery         recoveryClient
	kypost           *suitePair
	kycal            *suitePair
	probeHTTP        *http.Client
	mux              *http.ServeMux
	cspHeader        string
	// clientAttempts throttles anonymous callers by address; accountAttempts throttles by
	// user ID. Separate maps, so anonymous traffic filling one cannot evict the other.
	clientAttempts  attemptLimiter
	accountAttempts attemptLimiter
	pow             auth.PoWSpender
	// detached counts the requests running on a context deliberately separated from their
	// connection. http.Server.Shutdown does not know about them, so runServer waits on this
	// before the store closes.
	detached detachedCounter
}

// BlobsError returns any initialization error encountered while opening the attachment blob store.
func (s *Server) BlobsError() error {
	return s.blobsErr
}

// detachedCounter is a WaitGroup that tolerates a registration arriving while the wait is
// already running. sync.WaitGroup panics on an Add from zero concurrent with Wait, and there is
// no barrier that rules that out here: Shutdown returns when its own timeout expires, with
// requests still in flight, so a second admin request can register just as the first finishes
// and drops the count to zero. A counter under a condition variable has no such rule.
type detachedCounter struct {
	once sync.Once
	mu   sync.Mutex
	cond *sync.Cond
	n    int
}

// signal builds the condition variable on first use, so the zero value of Server works.
func (d *detachedCounter) signal() *sync.Cond {
	d.once.Do(func() { d.cond = sync.NewCond(&d.mu) })
	return d.cond
}

func (d *detachedCounter) add() {
	c := d.signal()
	c.L.Lock()
	d.n++
	c.L.Unlock()
}

func (d *detachedCounter) done() {
	c := d.signal()
	c.L.Lock()
	d.n--
	c.L.Unlock()
	c.Broadcast()
}

// tracked counts a request as detached for as long as h runs. It wraps the auth middleware
// rather than the handler: requireAdmin authenticates against the store before the handler is
// reached, ReadTimeout (15s) outlasts cmd/server's shutdownTimeout (5s), and a SIGTERM landing
// during that lookup would otherwise leave the counter at zero, WaitDetached returning and the
// store closing under a request about to pin a key.
//
// The window before ServeHTTP is entered -- while net/http is still reading the request line
// and headers -- cannot be covered by any counter: there is no handler goroutine to register
// yet. Shutdown's own drain is all that covers it, which is why shutdownTimeout is spent first.
func (s *Server) tracked(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.detached.add()
		defer s.detached.done()
		h(w, r)
	}
}

// WaitDetached blocks until every request that detached from its connection has finished. It is
// called after http.Server.Shutdown and before the store is closed: pairing, the key pin and a
// deposit all keep writing after their connection is gone, and a closed store under them leaves
// a key pinned on disk with no row recording it.
func (s *Server) WaitDetached() {
	c := s.detached.signal()
	c.L.Lock()
	for s.detached.n > 0 {
		c.Wait()
	}
	c.L.Unlock()
	if s.push != nil {
		s.push.Close()
	}
}

type attemptWindow struct {
	count int
	reset time.Time
}

type attemptLimiter struct {
	mu sync.Mutex
	m  map[string]attemptWindow
	// cap bounds the map when callers influence the keys; zero means unbounded.
	cap int
}

// attemptsCap bounds the client limiter. Unauthenticated callers influence its keys, so the
// map is itself attack surface. At the cap we evict, never refuse: refusing every unknown key
// would let one caller fill the map and lock every new client out of login.
//
// The trade-off: memory is bounded, but an attacker who fills the map shortens other clients'
// windows, since an evicted counter starts again from zero. Per-account windows live in the
// separate, uncapped account limiter, whose keys are existing user IDs, so no flood of
// anonymous keys can reset them.
//
// Eviction is deliberately blind to how much of a window is left. Picking the entry nearest to
// expiry would always sacrifice the shortest windows first, so a caller minting keys with a
// long window could keep the one-minute login counter from ever reaching its limit. Every key
// is therefore equally likely to go. No key carries caller-supplied bytes, and IPv6 clients
// share one key per /64, so filling the map costs an attacker a distinct IPv4 address or /64.
const attemptsCap = 10000

// OnDirectoryChange registers fn to run after each applied-or-acknowledged directory event.
// fn must not block: the webhook's sender is waiting.
func (s *Server) OnDirectoryChange(fn func()) { s.directoryChanged = fn }

func NewServer(cfg *config.Config, st store.Store) *Server {
	sessions := auth.NewSessionManager(st, cfg.Security)
	pairing := devices.NewPairingService(st, cfg.Server.AppName, cfg.Server.AppURL)
	kyidentity := sso.NewKyIdentityClient(cfg.SSO, st)
	kyidentity.SetTenancy(cfg.Tenancy)
	scimSrv := scim.NewServer(st, cfg.SCIM, cfg.Server.AppURL)
	recovery := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})

	var bus chat.EventBus = chat.NewMemoryBus()
	if st != nil && st.Driver() == "postgres" && cfg.Database.DSN != "" {
		bus = chat.NewPostgresBus(cfg.Database.DSN, st)
	}
	chatHub := chat.NewHub(bus)
	if st != nil {
		chatHub.SetSessionCheck(func(ctx context.Context, userID, sessionHash string) (bool, error) {
			return chatSessionValid(ctx, st, userID, sessionHash)
		})
		chatHub.SetRoomSource(st.Chat().ListUserRoomIDs)
	}
	var chatStore store.ChatStore
	if st != nil {
		chatStore = st.Chat()
	}
	var nativeLK *rtc.Client
	if cfg.RTC.LiveKitEnabled() {
		nativeLK = rtc.NewClient(cfg.RTC.LiveKitURL, cfg.RTC.LiveKitAPIKey, cfg.RTC.LiveKitAPISecret)
	}
	callMgr := chat.NewCallManager(chatStore, chatHub, nativeLK, cfg.RTC.STUNURLs)
	lobbyMgr := chat.NewLobbyManager(chatHub, callMgr)
	chatHub.SetDisconnectHandler(func(userID string, isGuest bool, remainingConns int) {
		callMgr.HandleDisconnect(userID, remainingConns)
		if isGuest {
			lobbyMgr.HandleDisconnect(userID, remainingConns)
		}
	})

	var blobStore *blobs.Store
	var blobsErr error
	attDir := strings.TrimSpace(cfg.Attachments.Dir)
	if attDir == "" && strings.TrimSpace(cfg.Database.DataDir) != "" {
		attDir = filepath.Join(cfg.Database.DataDir, "attachments")
	}
	if attDir != "" {
		bs, err := blobs.NewStore(attDir)
		if err != nil {
			blobsErr = err
			log.Printf("[ATTACHMENTS] failed to initialize attachment storage at %q: %v", attDir, err)
		} else {
			blobStore = bs
		}
	}

	s := &Server{
		config:          cfg,
		store:           st,
		blobs:           blobStore,
		blobsErr:        blobsErr,
		push:            initPushDispatcher(cfg, st),
		sessions:        sessions,
		pairing:         pairing,
		kyidentity:      kyidentity,
		scim:            scimSrv,
		chatHub:         chatHub,
		calls:           callMgr,
		lobby:           lobbyMgr,
		recovery:        recovery,
		kypost:          newSuitePair("kypost", cfg.KyPost),
		kycal:           newSuitePair("kycalendar", cfg.KyCalendar),
		probeHTTP:       health.NewHTTPClient(),
		mux:             http.NewServeMux(),
		cspHeader:       buildCSP(cfg),
		clientAttempts:  attemptLimiter{m: make(map[string]attemptWindow), cap: attemptsCap},
		accountAttempts: attemptLimiter{m: make(map[string]attemptWindow)},
	}

	revokeUser := func(ctx context.Context, userID string) {
		callMgr.HandleDisconnect(userID, 0)
		_ = chatHub.RevokeUser(ctx, userID)
		s.revokeAgentsForOwner(ctx, userID)
	}
	kyidentity.OnUserRevoked(revokeUser)
	chatHub.SetGuestCheck(lobbyMgr.GuestCheck(s.isTenantActive))
	chatHub.SetTenantRevokeHandler(func(tenantID string) {
		lobbyMgr.RevokeTenant(context.Background(), tenantID)
		callMgr.RevokeTenant(context.Background(), tenantID)
	})
	kyidentity.OnTenantRevoked(chatHub.RevokeTenant)
	scimSrv.OnUserRevoked(revokeUser)

	s.routes()
	return s
}

func buildCSP(cfg *config.Config) string {
	connectSrc := "'self'"
	if cfg != nil && cfg.RTC.LiveKitEnabled() {
		if u, err := url.Parse(cfg.RTC.LiveKitURL); err == nil && u.Host != "" {
			if u.Scheme == "http" || u.Scheme == "ws" {
				connectSrc += " http://" + u.Host + " ws://" + u.Host
			} else {
				connectSrc += " https://" + u.Host + " wss://" + u.Host
			}
		}
	}
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src " + connectSrc + "; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
}

func (l *attemptLimiter) allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, known := l.m[key]; !known && l.cap > 0 && len(l.m) >= l.cap {
		l.makeRoom(now)
	}
	entry := bumpWindow(l.m[key], now, window)
	l.m[key] = entry
	return entry.count <= limit
}

// makeRoom frees a slot for a new key: it drops every expired window, and if the map is still
// full it drops one live entry chosen at random, never the one nearest expiry. Caller holds
// mu. The scan is O(cap) and only runs for a new key while the map is full; 10 000 entries is
// microseconds.
func (l *attemptLimiter) makeRoom(now time.Time) {
	for candidate, w := range l.m {
		if now.After(w.reset) {
			delete(l.m, candidate)
		}
	}
	if len(l.m) >= l.cap {
		// Go randomises map iteration, so the first entry is an unbiased victim.
		for candidate := range l.m {
			delete(l.m, candidate)
			break
		}
	}
}

// resetIn is how long until key's current window ends.
func (l *attemptLimiter) resetIn(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return max(time.Until(l.m[key].reset), 0)
}

// blocked reports whether key has used up limit in its current window, without counting.
func (l *attemptLimiter) blocked(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.m[key]
	return ok && time.Now().Before(entry.reset) && entry.count >= limit
}

// clientKey is the limiter's name for the caller. An IPv6 client is keyed by its /64: a single
// subscriber usually holds at least that much, and one key per address would let it mint a
// fresh window for every request.
func (s *Server) clientKey(r *http.Request) string {
	client := s.requestIP(r)
	if addr, err := netip.ParseAddr(client); err == nil && addr.Is6() {
		client = netip.PrefixFrom(addr, 64).Masked().String()
	}
	return client
}

// allowClientAttempt throttles an anonymous route per client.
func (s *Server) allowClientAttempt(scope string, r *http.Request, limit int, window time.Duration) bool {
	return s.clientAttempts.allow(scope+":"+s.clientKey(r), limit, window)
}

// allowAccountAttempt throttles by an existing user's ID. Callers must never pass a
// caller-supplied string: this map is unbounded because its keys are not attacker-minted.
func (s *Server) allowAccountAttempt(key string, limit int, window time.Duration) bool {
	return s.accountAttempts.allow(key, limit, window)
}

func bumpWindow(entry attemptWindow, now time.Time, window time.Duration) attemptWindow {
	if now.After(entry.reset) {
		entry = attemptWindow{reset: now.Add(window)}
	}
	entry.count++
	return entry
}

// requestIP is the client address behind the limiter keys and audit rows. It resolves to the
// same address a session is bound to, and honours X-Forwarded-For only from a configured
// trusted proxy: keying on a caller-supplied header would make every limit here bypassable.
func (s *Server) requestIP(r *http.Request) string {
	return auth.ClientIP(r, s.config.Security.TrustedProxies)
}

func (s *Server) routes() {
	// Deliberate public, narrow forwarded-header self-check. Directory verifies HMAC itself.
	s.mux.HandleFunc("GET /api/installer/network", s.handleInstallerNetwork)
	s.mux.HandleFunc("POST /api/installer/directory", s.handleInstallerDirectory)
	// Auth
	s.mux.HandleFunc("/api/auth/pow-challenge", s.handlePoWChallenge)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/mfa/totp", s.handleMFATOTP)
	s.mux.HandleFunc("/api/auth/mfa/recovery-code", s.handleMFARecovery)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/me", s.handleMe)
	s.mux.HandleFunc("/api/auth/change-password", s.handleChangePassword)
	// TOTP enrolment for the signed-in local admin; each step needs a recent sign-in.
	s.mux.HandleFunc("POST /api/auth/totp/begin", s.requireFreshAdmin(s.handleTOTPBegin))
	s.mux.HandleFunc("POST /api/auth/totp/confirm", s.requireFreshAdmin(s.handleTOTPConfirm))
	s.mux.HandleFunc("POST /api/auth/totp/disable", s.requireFreshAdmin(s.handleTOTPDisable))

	// SSO
	s.mux.HandleFunc("/api/sso/kyidentity/login", s.handleKyIdentityLogin)
	s.mux.HandleFunc("/api/sso/kyidentity/callback", s.handleKyIdentityCallback)
	s.mux.HandleFunc("/api/sso/kyidentity/sync", s.handleKyIdentitySyncWebhook)
	s.mux.HandleFunc("POST /api/sso/kyidentity/logout", s.handleKyIdentityLogout)

	// Devices & Ephemeral QR Pairing
	s.mux.HandleFunc("/api/devices/pair/init", s.requireAuthenticated(s.handlePairInit))
	s.mux.HandleFunc("/api/devices/pair/verify", s.handlePairVerify)
	s.mux.HandleFunc("POST /api/devices/pair/poll", s.handlePairPoll)
	// The old GET carried the secret in its query string; refuse it loudly.
	s.mux.HandleFunc("GET /api/devices/pair/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		s.writeError(w, http.StatusMethodNotAllowed, "Use POST with the secret in a JSON body")
	})

	// Feature 0 KyBackup & Restore Drills. Capsules carry site data and keys: admins only.
	// Method patterns: only the declared method reaches a handler. Export is a POST so the
	// CSRF check covers a download that carries the whole instance.
	// Routes that move, pin, disable or export the recovery trust root also need a recent
	// sign-in, so a stolen or long-lived session cannot redirect every future capsule.
	s.mux.HandleFunc("POST /api/backup/drill", s.tracked(s.requireAdmin(s.handleBackupDrill)))
	s.mux.HandleFunc("POST /api/backup/export-capsule", s.tracked(s.requireFreshAdmin(s.handleExportCapsule)))
	s.mux.HandleFunc("POST /api/backup/pair-remote", s.tracked(s.requireFreshAdmin(s.handlePairRemoteRecovery)))
	s.mux.HandleFunc("POST /api/backup/deposit", s.tracked(s.requireFreshAdmin(s.handleRunBackup)))
	s.mux.HandleFunc("DELETE /api/backup/pairing", s.tracked(s.requireFreshAdmin(s.handleUnpair)))
	s.mux.HandleFunc("POST /api/backup/pin-key", s.tracked(s.requireFreshAdmin(s.handlePinKey)))
	s.mux.HandleFunc("PUT /api/backup/schedule", s.requireFreshAdmin(s.handleSetSchedule))
	s.mux.HandleFunc("GET /api/backup/status", s.requireAdmin(s.handleBackupStatus))
	s.mux.HandleFunc("GET /api/admin/network-check", s.requireAdmin(s.handleNetworkCheck))
	s.mux.HandleFunc("GET /api/admin/scim/users", s.requireAdmin(s.handleSCIMUsers))

	// Console.
	s.mux.HandleFunc("GET /api/admin/health", s.requireAdmin(s.handleHealth))
	s.mux.HandleFunc("GET /api/admin/kypost", s.requireAdmin(s.handlePairStatus(s.kypost)))
	s.mux.HandleFunc("GET /api/admin/kycalendar", s.requireAdmin(s.handlePairStatus(s.kycal)))
	s.mux.HandleFunc("GET /api/admin/audit", s.requireAdmin(s.handleAudit))

	// Native Bot & Agent accounts.
	s.mux.HandleFunc("GET /api/admin/agents", s.requireAdmin(s.handleAgents))
	s.mux.HandleFunc("GET /api/admin/agents/skill", s.requireAdmin(s.handleAgentSkill))
	s.mux.HandleFunc("POST /api/admin/agents", s.tracked(s.requireFreshAdmin(s.handleAgentCreate)))
	s.mux.HandleFunc("POST /api/admin/agents/{id}/rotate", s.tracked(s.requireFreshAdmin(s.handleAgentRotate)))
	// Revoke cuts access immediately in one click.
	s.mux.HandleFunc("POST /api/admin/agents/{id}/revoke", s.tracked(s.requireAdmin(s.handleAgentRevoke)))
	s.mux.HandleFunc("DELETE /api/admin/agents/{id}", s.tracked(s.requireFreshAdmin(s.handleAgentDelete)))

	// Settings & Theme. The read endpoint tiers its own payload by role.
	s.mux.HandleFunc("/api/settings", s.handleGetSettings)
	s.mux.HandleFunc("/api/settings/theme", s.requireAdmin(s.handleSetTheme))

	// Branding. Any admin reads it; changes need a recent sign-in, run detached and are audited.
	s.mux.HandleFunc("GET /api/admin/branding", s.requireAdmin(s.handleBranding))
	s.mux.HandleFunc("PUT /api/admin/branding/name", s.tracked(s.requireFreshAdmin(s.handleBrandName)))
	s.mux.HandleFunc("PUT /api/admin/branding/logo", s.tracked(s.requireFreshAdmin(s.handleBrandLogo)))
	s.mux.HandleFunc("DELETE /api/admin/branding/logo", s.tracked(s.requireFreshAdmin(s.handleBrandLogoReset)))

	// Native KyMessages v1 Chat & Real-Time API
	s.mux.HandleFunc("GET /api/v1/bootstrap", s.requireAuthenticated(s.handleChatBootstrap))
	s.mux.HandleFunc("GET /api/v1/users", s.requireAuthenticated(s.handleChatListUsers))
	s.mux.HandleFunc("GET /api/v1/rooms", s.requireAuthenticated(s.handleChatListRooms))
	s.mux.HandleFunc("POST /api/v1/rooms", s.requireAuthenticated(s.handleChatCreateRoom))
	s.mux.HandleFunc("GET /api/v1/rooms/{id}", s.requireAuthenticated(s.handleChatGetRoom))
	s.mux.HandleFunc("PATCH /api/v1/rooms/{id}", s.requireAuthenticated(s.handleChatUpdateRoom))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/members", s.requireAuthenticated(s.handleChatAddMember))
	s.mux.HandleFunc("DELETE /api/v1/rooms/{id}/members/{uid}", s.requireAuthenticated(s.handleChatRemoveMember))
	s.mux.HandleFunc("GET /api/v1/rooms/{id}/messages", s.requireAuthenticated(s.handleChatListMessages))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/messages", s.requireAuthenticated(s.handleChatSendMessage))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/attachments", s.requireAuthenticated(s.handleChatUploadAttachment))
	s.mux.HandleFunc("GET /api/v1/rooms/{id}/attachments", s.requireAuthenticated(s.handleChatListStagedAttachments))
	s.mux.HandleFunc("GET /api/v1/attachments/{id}", s.requireAuthenticated(s.handleChatDownloadAttachment))
	s.mux.HandleFunc("DELETE /api/v1/attachments/{id}", s.requireAuthenticated(s.handleChatDeleteAttachment))
	s.mux.HandleFunc("PATCH /api/v1/rooms/{id}/messages/{mid}", s.requireAuthenticated(s.handleChatEditMessage))
	s.mux.HandleFunc("DELETE /api/v1/rooms/{id}/messages/{mid}", s.requireAuthenticated(s.handleChatDeleteMessage))
	s.mux.HandleFunc("PUT /api/v1/rooms/{id}/messages/{mid}/reactions/{emoji}", s.requireAuthenticated(s.handleChatAddReaction))
	s.mux.HandleFunc("DELETE /api/v1/rooms/{id}/messages/{mid}/reactions/{emoji}", s.requireAuthenticated(s.handleChatRemoveReaction))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/read", s.requireAuthenticated(s.handleChatMarkRead))
	s.mux.HandleFunc("PUT /api/v1/rooms/{id}/notifications", s.requireAuthenticated(s.handleUpdateRoomNotifications))
	s.mux.HandleFunc("GET /api/v1/push/subscriptions", s.requireAuthenticated(s.handleListPushSubscriptions))
	s.mux.HandleFunc("POST /api/v1/push/subscriptions", s.requireAuthenticated(s.handleRegisterPushSubscription))
	s.mux.HandleFunc("DELETE /api/v1/push/subscriptions", s.requireAuthenticated(s.handleDeletePushSubscription))
	s.mux.HandleFunc("POST /api/v1/keys/upload", s.handleE2EEUpload)
	s.mux.HandleFunc("POST /api/v1/keys/query", s.handleE2EEQuery)
	s.mux.HandleFunc("POST /api/v1/keys/claim", s.handleE2EEClaim)
	s.mux.HandleFunc("DELETE /api/v1/keys/devices/{id}", s.handleE2EEDeleteDevice)
	s.mux.HandleFunc("PUT /api/v1/to-device", s.handleE2EESendToDevice)
	s.mux.HandleFunc("GET /api/v1/to-device", s.handleE2EEToDevice)
	s.mux.HandleFunc("POST /api/v1/to-device/ack", s.handleE2EEAck)
	s.mux.HandleFunc("POST /api/v1/webhooks/in/{id}", s.handleChatIncomingWebhook)
	s.mux.HandleFunc("GET /api/v1/ws", s.handleChatWS)

	// Hybrid P2P-first / LiveKit SFU Calling & Meeting Waiting Rooms
	s.mux.HandleFunc("GET /api/v1/rooms/{id}/calls/state", s.requireAuthenticated(s.handleCallState))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/calls/join", s.requireAuthenticated(s.handleCallJoin))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/calls/leave", s.requireAuthenticated(s.handleCallLeave))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/calls/escalate", s.requireAuthenticated(s.handleCallEscalate))
	s.mux.HandleFunc("GET /api/v1/rooms/{id}/lobby", s.requireAuthenticated(s.handleRoomLobbyList))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/lobby/{gid}/admit", s.requireAuthenticated(s.handleRoomLobbyAdmit))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/lobby/{gid}/deny", s.requireAuthenticated(s.handleRoomLobbyDeny))
	s.mux.HandleFunc("POST /api/v1/rooms/{id}/meeting/guest-link", s.requireAuthenticated(s.handleCreateRoomGuestLink))
	s.mux.HandleFunc("POST /api/v1/meetings", s.requireAuthenticated(s.handleCreateInstantMeeting))
	s.mux.HandleFunc("GET /api/admin/media-policy", s.requireAdmin(s.handleAdminGetMediaPolicy))
	s.mux.HandleFunc("PUT /api/admin/media-policy", s.requireAdmin(s.handleAdminUpdateMediaPolicy))

	// KyCalendar signed meeting sync
	s.mux.HandleFunc("PUT /api/meetings/{id}", s.handleKyCalendarUpsertMeeting)
	s.mux.HandleFunc("POST /api/suite/chat", s.handleSuiteChat)
	s.mux.HandleFunc("POST /api/suite/presence/lookup", s.handlePresenceLookup)
	s.mux.HandleFunc("POST /api/suite/presence/out-of-office", s.handlePresenceOOO)
	s.mux.HandleFunc("POST /api/suite/presence/calendar", s.handlePresenceCalendar)
	s.mux.HandleFunc("POST /api/suite/presence/me", s.handlePresenceMe)
	s.mux.HandleFunc("DELETE /api/meetings/{id}", s.handleKyCalendarCloseMeeting)

	// Confined external guest waiting room & meeting endpoints
	s.mux.HandleFunc("GET /api/meet/{token}", s.handleGuestMeetInfo)
	s.mux.HandleFunc("POST /api/meet/{token}/knock", s.handleGuestMeetKnock)
	s.mux.HandleFunc("GET /api/meet/{token}/ws", s.handleGuestMeetWS)
	s.mux.HandleFunc("POST /api/meet/{token}/call/join", s.handleGuestCallJoin)
	s.mux.HandleFunc("POST /api/meet/{token}/call/leave", s.handleGuestCallLeave)
	s.mux.HandleFunc("GET /api/meet/{token}/messages", s.handleGuestListMessages)
	s.mux.HandleFunc("POST /api/meet/{token}/messages", s.handleGuestSendMessage)

	// SCIM 2.0 routes (disabled in multi-tenant mode; provisioning arrives via signed KyIdentity webhooks).
	if !s.config.Tenancy.IsMultiTenant() {
		s.scim.RegisterRoutes(s.mux)
	}

	// Unmatched API paths fail instead of falling through to the SPA's 200: a webhook sender
	// on a retired or mistyped route must see an error and retry, never a false acknowledgement.
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, http.StatusNotFound, "Unknown API endpoint")
	})

	// Embedded React PWA Frontend. /app-icon.png is the admin's logo when one is set; public.
	static := web.Handler()
	s.mux.HandleFunc("GET /app-icon.png", s.appIcon(static))
	s.mux.Handle("/", static)
}

// stepUpWindow is how recent a sign-in must be for requireFreshAdmin. Signing in again is the
// step-up: it repeats the password and TOTP, or the suite login, the session was issued on.
const stepUpWindow = 10 * time.Minute

// reauthURL forces a KyIdentity credential prompt (prompt=login, max_age=0) for step-up.
const reauthURL = "/api/sso/kyidentity/login?fresh=1"

// requireAdmin rejects requests without a valid session, or with a non-admin one.
func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc { return s.admin(h, false) }

// requireFreshAdmin is requireAdmin with step-up: the session must be younger than stepUpWindow.
func (s *Server) requireFreshAdmin(h http.HandlerFunc) http.HandlerFunc { return s.admin(h, true) }

func (s *Server) admin(h http.HandlerFunc, fresh bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sess, err := s.sessions.AuthenticateRequest(r)
		if err != nil {
			if errors.Is(err, auth.ErrPasswordChangeRequired) {
				s.writeJSON(w, http.StatusForbidden, map[string]string{"error": "Change your password before continuing", "code": "password_change_required"})
			} else {
				s.writeError(w, http.StatusUnauthorized, "Authentication required")
			}
			return
		}
		// A customer org's account never administers the install, whatever its stored role.
		if user.Role != "admin" || (user.OrgID != "" && !s.config.Tenancy.MayAdminister(user.OrgID)) {
			s.writeError(w, http.StatusForbidden, "Administrator role required")
			return
		}
		if user.OrgID != "" {
			if active, err := s.isTenantActive(r.Context(), user.OrgID); err != nil || !active {
				s.writeError(w, http.StatusForbidden, "Organization is suspended or inactive")
				return
			}
		}
		if fresh && time.Since(sess.CreatedAt) > stepUpWindow {
			s.writeStepUp(w, user)
			return
		}
		h(w, r)
	}
}

// writeStepUp is the one refusal every step-up check sends.
func (s *Server) writeStepUp(w http.ResponseWriter, user *store.User) {
	body := map[string]string{"error": "Confirm it's you: this change needs a sign-in from the last 10 minutes", "code": "reauthentication_required"}
	if user.SSOProvider == "kyidentity" {
		// A plain SSO login may silently reuse the IdP session; this one forces credentials.
		body["reauth_url"] = reauthURL
	}
	s.writeJSON(w, http.StatusForbidden, body)
}

func (s *Server) requireAuthenticated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := s.sessions.AuthenticateRequest(r); err != nil {
			if errors.Is(err, auth.ErrPasswordChangeRequired) {
				s.writeJSON(w, http.StatusForbidden, map[string]string{"error": "Change your password before continuing", "code": "password_change_required"})
			} else {
				s.writeError(w, http.StatusUnauthorized, "Authentication required")
			}
			return
		}
		h(w, r)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", s.cspHeader)
	if app, err := url.Parse(s.config.Server.AppURL); s.config.Security.CookieSecure && err == nil && hostMatches(r.Host, app) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	origin := r.Header.Get("Origin")
	if origin != "" && sameOrigin(origin, s.config.Server.AppURL) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Guest-Session, Idempotency-Key, "+syncauth.HeaderSignature)

	if r.Method == http.MethodOptions {
		if origin != "" && !sameOrigin(origin, s.config.Server.AppURL) {
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Routes that mint a session carry no CSRF token. Requiring a JSON body forces a CORS
	// preflight, which foreign origins fail, so a cross-site form cannot log a victim into
	// the attacker's account.
	if r.Method == http.MethodPost && mintsSession(r.URL.Path) && !jsonRequest(r) {
		s.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if isUnsafeMethod(r.Method) && s.sessions.HasSessionCookie(r) && !csrfExempt(r.URL.Path) && !s.sessions.ValidateCSRF(r) {
		s.writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}
	if r.Body != nil && !(r.Method == http.MethodPost && isAttachmentUploadPath(r.URL.Path)) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}

	// SCIM middleware (inbound SCIM is disabled in multi-tenant mode).
	if strings.HasPrefix(r.URL.Path, "/scim/v2") {
		if s.config.Tenancy.IsMultiTenant() {
			s.writeError(w, http.StatusNotFound, "SCIM is disabled in multi-tenant mode")
			return
		}
		s.scim.AuthMiddleware(s.mux).ServeHTTP(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && dec.Decode(&struct{}{}) == io.EOF
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func csrfExempt(path string) bool {
	return path == "/api/auth/login" ||
		strings.HasPrefix(path, "/api/auth/mfa/") ||
		path == "/api/sso/kyidentity/sync" ||
		path == "/api/sso/kyidentity/logout" ||
		strings.HasPrefix(path, "/api/v1/webhooks/in/") ||
		strings.HasPrefix(path, "/api/meetings/") ||
		strings.HasPrefix(path, "/api/suite/") ||
		strings.HasPrefix(path, "/api/meet/")
}

func mintsSession(path string) bool {
	return path == "/api/auth/login" || strings.HasPrefix(path, "/api/auth/mfa/") || path == "/api/devices/pair/verify"
}

func jsonRequest(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func sameOrigin(origin, appURL string) bool {
	a, err := url.Parse(appURL)
	if err != nil || a.Scheme == "" || a.Host == "" {
		return false
	}
	o, err := url.Parse(origin)
	return err == nil && o.Scheme == a.Scheme && o.Host == a.Host
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
