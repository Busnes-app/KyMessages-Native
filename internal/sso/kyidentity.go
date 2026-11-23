package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/applysetup"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"golang.org/x/oauth2"
)

// KyIdentityClient manages interactions with the suite KyIdentity identity provider.
type KyIdentityClient struct {
	config  config.SSOConfig
	store   store.Store
	flow    *oauthFlow
	tenancy config.TenancyConfig

	// syncMu applies directory updates one at a time, so a read and its conditional write
	// see the same row. Ordering itself is persisted per subject (directory_sync_state).
	syncMu sync.Mutex
	// rejects counts refused deliveries since start, in memory only.
	rejects rejectCounter
	// onUserRevoked fires after a user's sessions are revoked (deactivation, role change, deletion).
	onUserRevoked func(ctx context.Context, userID string)
	// onTenantRevoked fires when an org is suspended or deleted, before its members are revoked.
	onTenantRevoked func(ctx context.Context, orgID string) error
	// onUserErased deletes one person's data (user.erased, multi mode); its error fails the
	// delivery so KyIdentity retries.
	onUserErased func(ctx context.Context, user *store.User) error
}

func NewKyIdentityClient(cfg config.SSOConfig, st store.Store) *KyIdentityClient {
	return &KyIdentityClient{
		config: cfg,
		store:  st,
		flow:   newOAuthFlow(cfg.KyIdentityIssuer, cfg.KyIdentityClientID, cfg.KyIdentitySecret),
	}
}

// SetTenancy enables strict org_id binding on directory webhooks in multi-tenant mode, and
// limits the admin role to the staff org.
func (k *KyIdentityClient) SetTenancy(t config.TenancyConfig) {
	k.tenancy = t
}

// OnTenantRevoked registers a callback invoked when an org is suspended or deleted.
func (k *KyIdentityClient) OnTenantRevoked(fn func(ctx context.Context, orgID string) error) {
	k.onTenantRevoked = fn
}

// OnUserErased registers what deletes a person's data on user.erased (multi mode).
func (k *KyIdentityClient) OnUserErased(fn func(ctx context.Context, user *store.User) error) {
	k.onUserErased = fn
}

// OnUserRevoked registers a callback invoked immediately when directory sync revokes or deletes a user.
func (k *KyIdentityClient) OnUserRevoked(fn func(ctx context.Context, userID string)) {
	k.onUserRevoked = fn
}

// BuildAuthURL generates the authorization code URL with PKCE for KyIdentity.
// fresh asks the IdP for a new credential interaction instead of reusing its own session.
func (k *KyIdentityClient) BuildAuthURL(ctx context.Context, redirectURI, state, verifier, nonce string, fresh bool) (string, error) {
	if fresh {
		flow, err := k.currentFlow(ctx)
		if err != nil {
			return "", err
		}
		return flow.authCodeURL(ctx, redirectURI, state, verifier, nonce,
			oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	flow, err := k.currentFlow(ctx)
	if err != nil {
		return "", err
	}
	return flow.authCodeURL(ctx, redirectURI, state, verifier, nonce)
}

// ExchangeCode exchanges the authorization code and verifier for identity claims.
func (k *KyIdentityClient) ExchangeCode(ctx context.Context, code, verifier, redirectURI, expectedNonce string) (*IdentityClaims, error) {
	flow, err := k.currentFlow(ctx)
	if err != nil {
		return nil, err
	}
	claims, err := flow.exchange(ctx, code, verifier, redirectURI, expectedNonce)
	if err != nil {
		return nil, err
	}
	claims.Provider = "kyidentity"
	return claims, nil
}

// DirectoryUser is the SCIM 2.0 User resource KyIdentity sends to a suite webhook. The event
// type and ID travel in the signed headers, not the body.
type DirectoryUser struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id,omitempty"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Name        *struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Emails []scimValue `json:"emails"`
	Roles  []scimValue `json:"roles"`
	Active bool        `json:"active"`
	Meta   *struct {
		Version string `json:"version"`
	} `json:"meta"`
}

type scimValue struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

// primaryValue is the value marked primary, else the first, else "".
func primaryValue(values []scimValue) string {
	for _, v := range values {
		if v.Primary {
			return v.Value
		}
	}
	if len(values) > 0 {
		return values[0].Value
	}
	return ""
}

var (
	// ErrSyncUnauthorized covers a missing secret or a failed signature, timestamp or event check.
	ErrSyncUnauthorized = errors.New("directory webhook not authenticated")
	// ErrSyncMalformed is an authenticated body that is not a usable SCIM User.
	ErrSyncMalformed = errors.New("directory webhook body is not a usable SCIM user")
	// ErrSyncUsernameConflict is an authenticated user whose username another account holds.
	ErrSyncUsernameConflict = errors.New("directory username is held by another KyMessages account")
	// ErrSyncOrgMismatch is an authenticated user whose org_id disagrees with the existing account.
	ErrSyncOrgMismatch = errors.New("directory user org_id does not match existing KyMessages account")
	// errNoSecret: the receiver has no key, so nothing can be verified.
	errNoSecret = errors.New("KY_KYIDENTITY_HMAC_SECRET is not set")
)

// revisionPattern matches KyIdentity's meta.version, W/"<n>": a per-user counter that rises on
// every change. -1 marks state resent after a KyIdentity restore.
var revisionPattern = regexp.MustCompile(`^W/"(-1|0|[1-9][0-9]{0,17})"$`)

// HandleSyncWebhook applies one signed directory event from KyIdentity. Superseded and
// duplicate events succeed without effect, so the sender's outbox stops retrying them. An
// acknowledged delivery is recorded under WebhookRecordKey; a refused one is only counted, in
// memory (Rejections).
func (k *KyIdentityClient) HandleSyncWebhook(ctx context.Context, headers syncauth.Headers, body []byte) error {
	kind, err := k.applySyncWebhook(ctx, headers, body)
	switch {
	case err == nil:
		k.recordDelivery(ctx, kind)
	case errors.Is(err, ErrSyncUnauthorized), errors.Is(err, ErrSyncMalformed), errors.Is(err, ErrSyncUsernameConflict), errors.Is(err, ErrSyncOrgMismatch):
		k.reject(err)
	}
	return err
}

// auditUsernameConflict records a directory username another account holds; merging the two
// would hand that account to whoever KyIdentity names alike. The delivery is authenticated, so
// unlike other refusals it is logged and audited. kept is the username retained, if any.
func (k *KyIdentityClient) auditUsernameConflict(ctx context.Context, in DirectoryUser, kept string) {
	details := fmt.Sprintf("subject=%q", in.ID)
	if kept != "" {
		details += fmt.Sprintf(" kept=%q", kept)
	}
	log.Printf("[SSO] directory username %q refused for %s: held by another KyMessages account", in.UserName, details)
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := k.store.Audit().LogAudit(actx, &store.AuditRecord{
		Action:   "sso.sync_conflict",
		Resource: recoveryclient.AuditSafe(in.UserName),
		Details:  recoveryclient.AuditSafe(details),
	}); err != nil {
		log.Printf("[AUDIT] sso.sync_conflict not recorded: %v", err)
	}
}

func (k *KyIdentityClient) auditOrgMismatch(ctx context.Context, subject, expectedOrg, gotOrg string) {
	details := fmt.Sprintf("subject=%q expected=%q got=%q", subject, expectedOrg, gotOrg)
	log.Printf("[SSO] directory org_id mismatch refused: %s", details)
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := k.store.Audit().LogAudit(actx, &store.AuditRecord{
		Action:   "sso.org_mismatch",
		Resource: recoveryclient.AuditSafe(subject),
		Details:  recoveryclient.AuditSafe(details),
	}); err != nil {
		log.Printf("[AUDIT] sso.org_mismatch not recorded: %v", err)
	}
}

// applySyncWebhook verifies and applies one event and returns its signed type. The cause of
// ErrSyncUnauthorized stays reachable with errors.Is, so refusals can be told apart.
func (k *KyIdentityClient) applySyncWebhook(ctx context.Context, headers syncauth.Headers, body []byte) (string, error) {
	if k.config.KyIdentityHMACSecret == "" {
		return "", fmt.Errorf("%w: %w", ErrSyncUnauthorized, errNoSecret)
	}
	event, err := syncauth.Verify([]byte(k.config.KyIdentityHMACSecret), headers, body, syncauth.Options{})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSyncUnauthorized, err)
	}

	switch event.Type {
	case "org.suspended", "org.unsuspended", "org.resumed", "org.deleted":
		return event.Type, k.applyOrgLifecycle(ctx, event.Type, body)
	case "user.erased":
		return event.Type, k.applyErasure(ctx, body)
	}

	var user DirectoryUser
	if err := json.Unmarshal(body, &user); err != nil || user.ID == "" || user.Meta == nil {
		return "", ErrSyncMalformed
	}
	match := revisionPattern.FindStringSubmatch(user.Meta.Version)
	if match == nil {
		return "", ErrSyncMalformed
	}
	orgID, err := DirectoryOrg(body, k.tenancy)
	if err != nil {
		return event.Type, err
	}
	revision, _ := strconv.ParseInt(match[1], 10, 64)
	ev := store.DirectoryEvent{ID: event.ID, Revision: revision}

	k.syncMu.Lock()
	defer k.syncMu.Unlock()
	switch event.Type {
	case "user.created", "user.updated":
		return event.Type, k.upsertDirectoryUser(ctx, user, ev)
	case "user.mfa_reset":
		existing, err := k.store.Users().GetUserBySSO(ctx, "kyidentity", user.ID)
		if errors.Is(err, store.ErrNotFound) {
			existing, err = &store.User{SSOProvider: "kyidentity", SSOSubject: user.ID}, nil
		}
		if err != nil {
			return event.Type, err
		}
		if k.tenancy.IsMultiTenant() && existing.ID != "" && existing.OrgID != orgID {
			k.auditOrgMismatch(ctx, user.ID, existing.OrgID, orgID)
			return event.Type, ErrSyncOrgMismatch
		}
		applied, err := k.store.Users().ResetDirectoryMFA(ctx, existing, ev)
		if err == nil && applied && k.onUserRevoked != nil {
			k.onUserRevoked(ctx, existing.ID)
		}
		return event.Type, err
	case "user.deleted":
		existing, err := k.store.Users().GetUserBySSO(ctx, "kyidentity", user.ID)
		if errors.Is(err, store.ErrNotFound) {
			// Record the deletion anyway, so an older creation delivered later cannot
			// bring the account into existence. The delete matches no row.
			existing, err = &store.User{SSOProvider: "kyidentity", SSOSubject: user.ID}, nil
		}
		if err != nil {
			return event.Type, err
		}
		if k.tenancy.IsMultiTenant() && existing.ID != "" && existing.OrgID != orgID {
			k.auditOrgMismatch(ctx, user.ID, existing.OrgID, orgID)
			return event.Type, ErrSyncOrgMismatch
		}
		applied, err := k.store.Users().DeleteDirectoryUser(ctx, existing, ev)
		if err == nil && applied && existing.ID != "" && k.onUserRevoked != nil {
			k.onUserRevoked(ctx, existing.ID)
		}
		return event.Type, err
	}
	return event.Type, nil // other event types (groups) are not for this product
}

// applyErasure deletes the data of one person who used Delete everything (multi mode). The body
// is the bare inactive SCIM user with org_id. A person this install never held, or holds in
// another org, is acknowledged without effect; a repeat finds no one and is acknowledged too.
// Single mode acknowledges it unchanged, as before.
func (k *KyIdentityClient) applyErasure(ctx context.Context, body []byte) error {
	if !k.tenancy.IsMultiTenant() {
		return nil
	}
	var in struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.ID == "" || !config.IsCanonicalUUID(strings.TrimSpace(in.OrgID)) {
		return ErrSyncMalformed
	}
	k.syncMu.Lock()
	defer k.syncMu.Unlock()
	user, err := k.store.Users().GetUserBySSO(ctx, "kyidentity", in.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if user.OrgID != strings.TrimSpace(in.OrgID) {
		k.auditOrgMismatch(ctx, in.ID, user.OrgID, in.OrgID)
		return nil
	}
	if k.onUserErased == nil {
		return errors.New("sso: user.erased has no handler")
	}
	return k.onUserErased(ctx, user)
}

func (k *KyIdentityClient) applyOrgLifecycle(ctx context.Context, eventType string, body []byte) error {
	if !k.tenancy.IsMultiTenant() {
		return nil
	}
	var payload struct {
		ID       string `json:"id"`
		OrgID    string `json:"org_id"`
		Revision int64  `json:"revision"` // KyIdentity's per-org lifecycle counter
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Revision <= 0 {
		return ErrSyncMalformed
	}
	orgID := strings.TrimSpace(payload.OrgID)
	if orgID == "" {
		orgID = strings.TrimSpace(payload.ID)
	}
	if !config.IsCanonicalUUID(orgID) {
		return ErrSyncMalformed
	}
	if _, err := k.store.Chat().EnsureTenant(ctx, orgID); err != nil {
		return err
	}
	var nextStatus string
	switch eventType {
	case "org.suspended":
		nextStatus = store.TenantStatusSuspended
	case "org.unsuspended", "org.resumed":
		nextStatus = store.TenantStatusActive
	case "org.deleted":
		nextStatus = store.TenantStatusDeleted
	default:
		return nil
	}
	if _, err := k.store.Chat().ApplyTenantLifecycle(ctx, orgID, nextStatus, payload.Revision); err != nil {
		return err
	}
	// Revoke from the resulting state, so a retry of a delivery that died mid-revocation, or a
	// stale event, still leaves an inactive org with no grants.
	tenant, err := k.store.Chat().GetTenant(ctx, orgID)
	if err != nil {
		return err
	}
	if tenant.Status != store.TenantStatusActive {
		// Revoke every member, then fail the delivery if any revocation failed, so KyIdentity
		// redelivers and the retry sweeps what is left.
		var failed []error
		if k.onTenantRevoked != nil {
			if err := k.onTenantRevoked(ctx, orgID); err != nil {
				failed = append(failed, fmt.Errorf("publish tenant revocation: %w", err))
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
					failed = append(failed, fmt.Errorf("revoke %s: %w", u.ID, err))
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
	return nil
}

func (k *KyIdentityClient) auditCustomerAdminIgnored(ctx context.Context, subject, orgID string) {
	details := fmt.Sprintf("subject=%q org_id=%q", subject, orgID)
	log.Printf("[SSO] customer org admin role downgraded to user: %s", details)
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := k.store.Audit().LogAudit(actx, &store.AuditRecord{
		Action:   "sso.customer_admin_ignored",
		Resource: recoveryclient.AuditSafe(subject),
		Details:  recoveryclient.AuditSafe(details),
	}); err != nil {
		log.Printf("[AUDIT] sso.customer_admin_ignored not recorded: %v", err)
	}
}

func (k *KyIdentityClient) upsertDirectoryUser(ctx context.Context, in DirectoryUser, ev store.DirectoryEvent) error {
	// KyIdentity sends this app's roles when it defines any, else the user's global role.
	orgID := strings.TrimSpace(in.OrgID)
	if k.tenancy.IsMultiTenant() {
		if !config.IsCanonicalUUID(orgID) {
			return ErrSyncMalformed
		}
		if _, err := k.store.Chat().EnsureTenant(ctx, orgID); err != nil {
			return err
		}
	}
	role := "user"
	if primaryValue(in.Roles) == "admin" {
		if k.tenancy.MayAdminister(orgID) {
			role = "admin"
		} else if k.tenancy.IsMultiTenant() {
			k.auditCustomerAdminIgnored(ctx, in.ID, orgID)
		}
	}
	status := "inactive"
	if in.Active {
		status = "active"
	}
	email := primaryValue(in.Emails)
	displayName := in.DisplayName
	if displayName == "" && in.Name != nil {
		displayName = in.Name.Formatted
	}

	existing, err := k.store.Users().GetUserBySSO(ctx, "kyidentity", in.ID)
	if errors.Is(err, store.ErrNotFound) {
		newUser := &store.User{
			ID: fmt.Sprintf("usr_%s", crypto.RandomHex(12)), Username: in.UserName, Email: email,
			DisplayName: displayName, Role: role, Status: status, SSOProvider: "kyidentity", SSOSubject: in.ID,
		}
		if k.tenancy.IsMultiTenant() {
			newUser.OrgID = orgID
		}
		_, err = k.store.Users().CreateDirectoryUser(ctx, newUser, ev)
		if errors.Is(err, store.ErrUsernameTaken) {
			k.auditUsernameConflict(ctx, in, "")
			return fmt.Errorf("%w: %q", ErrSyncUsernameConflict, in.UserName)
		}
		return err
	}
	if err != nil {
		return err
	}
	if k.tenancy.IsMultiTenant() && existing.OrgID != orgID {
		k.auditOrgMismatch(ctx, in.ID, existing.OrgID, orgID)
		return fmt.Errorf("%w: subject %q", ErrSyncOrgMismatch, in.ID)
	}
	updated := *existing
	updated.Username, updated.Email, updated.DisplayName, updated.Role, updated.Status = in.UserName, email, displayName, role, status
	applied, err := k.store.Users().ApplyDirectoryProfile(ctx, &updated, ev)
	if errors.Is(err, store.ErrUsernameTaken) {
		// Refuse only the rename: the same event may deactivate or downgrade, which must land.
		// The failed write rolled back with its event ID, so it applies again under the old name.
		k.auditUsernameConflict(ctx, in, existing.Username)
		updated.Username = existing.Username
		applied, err = k.store.Users().ApplyDirectoryProfile(ctx, &updated, ev)
	}
	if err != nil || !applied {
		return err
	}
	if existing.Role != role || existing.Status != status {
		if err := k.store.Sessions().DeleteUserSessions(ctx, existing.ID); err != nil {
			return err
		}
		if k.onUserRevoked != nil {
			k.onUserRevoked(ctx, existing.ID)
		}
	}
	return nil
}

// SuiteDirectory returns a client for KyIdentity's suite directory using this app's own OAuth
// client credentials, or nil when KyIdentity is not configured.
func (k *KyIdentityClient) SuiteDirectory() (*suitedir.Client, error) {
	if m := k.config.Installer; m != nil && m.IssuerURL != "" {
		secret, err := applysetup.Secret(m.ClientSecretFile)
		if err != nil {
			return nil, err
		}
		return &suitedir.Client{Issuer: m.IssuerURL, ClientID: m.ClientID, ClientSecret: secret}, nil
	}
	if !k.config.Enabled || k.config.KyIdentityIssuer == "" {
		return nil, nil
	}
	return &suitedir.Client{
		Issuer:       k.config.KyIdentityIssuer,
		ClientID:     k.config.KyIdentityClientID,
		ClientSecret: k.config.KyIdentitySecret,
	}, nil
}

// EffectiveIssuer returns the canonical KyIdentity issuer URL configured for this server, by the
// same installer-first rule as SuiteDirectory.
func (k *KyIdentityClient) EffectiveIssuer() string {
	if m := k.config.Installer; m != nil && m.IssuerURL != "" {
		return strings.TrimRight(strings.TrimSpace(m.IssuerURL), "/")
	}
	if !k.config.Enabled {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(k.config.KyIdentityIssuer), "/")
}

// Owned runtime credentials are private target references; missing files fail closed.
func (k *KyIdentityClient) currentFlow(ctx context.Context) (*oauthFlow, error) {
	if k.config.Installer == nil {
		return k.flow, nil
	}
	managed := k.config.Installer
	secret, err := applysetup.Secret(managed.ClientSecretFile)
	if err != nil {
		return nil, err
	}
	return newOAuthFlow(managed.IssuerURL, managed.ClientID, secret), nil
}
