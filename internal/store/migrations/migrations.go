package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Migration represents an incremental schema change step.
type Migration struct {
	Version  int
	Name     string
	SQLite   string
	Postgres string
}

var registry = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQLite: `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    sso_provider TEXT NOT NULL DEFAULT 'local',
    sso_subject TEXT NOT NULL DEFAULT '',
    totp_secret_enc TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    recovery_codes_hash TEXT NOT NULL DEFAULT '[]',
    push_device_id TEXT NOT NULL DEFAULT '',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    last_login_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS device_pairings (
    secret TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    push_token TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairings_code ON device_pairings(code);
CREATE INDEX IF NOT EXISTS idx_pairings_expires ON device_pairings(expires_at);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    external_id TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_records(user_id, created_at);

CREATE TABLE IF NOT EXISTS server_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL
);
`,
		Postgres: `
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL DEFAULT '',
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    sso_provider VARCHAR(32) NOT NULL DEFAULT 'local',
    sso_subject VARCHAR(255) NOT NULL DEFAULT '',
    totp_secret_enc TEXT NOT NULL DEFAULT '',
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_codes_hash TEXT NOT NULL DEFAULT '[]',
    push_device_id VARCHAR(255) NOT NULL DEFAULT '',
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent TEXT NOT NULL DEFAULT '',
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS device_pairings (
    secret VARCHAR(64) PRIMARY KEY,
    code VARCHAR(16) NOT NULL UNIQUE,
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    device_name VARCHAR(255) NOT NULL DEFAULT '',
    platform VARCHAR(32) NOT NULL DEFAULT '',
    push_token TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pairings_code ON device_pairings(code);
CREATE INDEX IF NOT EXISTS idx_pairings_expires ON device_pairings(expires_at);

CREATE TABLE IF NOT EXISTS groups (
    id VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL UNIQUE,
    external_id VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id VARCHAR(64) NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_records (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(255) NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_records(user_id, created_at);

CREATE TABLE IF NOT EXISTS server_settings (
    key VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);
`,
	},
	{
		Version: 2,
		Name:    "one_time_auth_challenges",
		SQLite: `
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
`,
		Postgres: `
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
`,
	},
	{
		Version:  3,
		Name:     "totp_last_counter",
		SQLite:   `ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0;`,
		Postgres: `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_counter BIGINT NOT NULL DEFAULT 0;`,
	},
	{
		Version: 4,
		Name:    "mfa_credential_snapshot",
		SQLite: `DELETE FROM mfa_challenges;
ALTER TABLE mfa_challenges ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';`,
		Postgres: `DELETE FROM mfa_challenges;
ALTER TABLE mfa_challenges ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';`,
	},
	{Version: 5, Name: "messaging_devices_and_rooms", SQLite: messagingSchema, Postgres: messagingSchema},
	{Version: 6, Name: "messaging_delivery", SQLite: messagingDeliverySchema, Postgres: messagingDeliverySchema},
	{Version: 7, Name: "messaging_key_packages", SQLite: messagingKeyPackageSchema, Postgres: messagingKeyPackageSchema},
	{Version: 8, Name: "messaging_recovery_auth", SQLite: messagingRecoveryAuthSchema, Postgres: messagingRecoveryAuthSchema},
	{Version: 9, Name: "messaging_identity_generations", SQLite: messagingIdentitySchema, Postgres: messagingIdentitySchema},
	{Version: 10, Name: "messaging_scoped_packages", SQLite: messagingScopedPackageSchema, Postgres: messagingScopedPackageSchema},
	{Version: 11, Name: "messaging_direct_rooms", SQLite: messagingDirectRoomSchema, Postgres: messagingDirectRoomSchema},
	{Version: 12, Name: "messaging_retention", SQLite: messagingRetentionSchema, Postgres: messagingRetentionSchema},
	{Version: 13, Name: "audit_latest_action", SQLite: `CREATE INDEX idx_audit_action_id ON audit_records(action, id);`, Postgres: `CREATE INDEX idx_audit_action_id ON audit_records(action, id);`},
	{Version: 14, Name: "pairing_secret_only", SQLite: pairingSecretOnlySQLite, Postgres: pairingSecretOnlyPostgres},
	// The newest directory-webhook update applied per subject. It is not a users column: it
	// must survive deletion, or a replayed older update could recreate the account.
	{Version: 15, Name: "directory_sync_order", SQLite: directorySyncStateSchema, Postgres: directorySyncStateSchema},
	// KyIdentity orders directory updates by a per-user revision, not a timestamp. Stored
	// timestamps would outrank every revision, so they are discarded. directory_sync_events
	// keeps every delivered event ID: a -1 resend resets the order, so revision alone cannot
	// stop an earlier event applying twice.
	{Version: 16, Name: "directory_sync_revision", SQLite: directorySyncRevision, Postgres: directorySyncRevision},
	// Retention becomes owner-mutable and may be Off (0) or 90 days, and purging deletes
	// events outright, so expiry derives from created_at instead of a stored column.
	// Column-level CHECKs drop with their column; a table rebuild would cascade-delete rooms.
	{Version: 17, Name: "thread_auto_purge", SQLite: threadAutoPurgeSQLite, Postgres: threadAutoPurgePostgres},
	// A suspended device's proposed credential waits here until its key signature verifies.
	{Version: 18, Name: "messaging_device_resume", SQLite: messagingDeviceResume, Postgres: messagingDeviceResume},
	// When a device was suspended (unix seconds, 0 when not suspended); it is revoked 30 days
	// later. Devices already suspended start their 30 days at upgrade.
	{Version: 19, Name: "messaging_device_suspended_at", SQLite: suspendedAt + `CAST(strftime('%s', 'now') AS INTEGER)` + suspendedWhere, Postgres: suspendedAt + `CAST(FLOOR(EXTRACT(EPOCH FROM now())) AS BIGINT)` + suspendedWhere},
	// The suite identity provider was renamed from KySignOn to KyIdentity.
	{Version: 20, Name: "kyidentity_provider", SQLite: kyIdentityProvider, Postgres: kyIdentityProvider},
	{Version: 21, Name: "drop_messaging", SQLite: dropMessaging, Postgres: dropMessaging},
	// Chat agent accounts (legacy MAS-backed table replaced in migration 24).
	{Version: 22, Name: "agents", SQLite: agentsSchema("DATETIME"), Postgres: agentsSchema("TIMESTAMPTZ")},
	// Native multi-tenant chat, calls, meetings, and webhooks schema.
	{Version: 23, Name: "native_chat", SQLite: nativeChatSchemaSQLite, Postgres: nativeChatSchemaPostgres},
	// Native chat bot/agent accounts backed directly by users and hashed bearer tokens.
	{Version: 24, Name: "native_agents", SQLite: nativeAgentsSchema("DATETIME"), Postgres: nativeAgentsSchema("TIMESTAMPTZ")},
	// Index attachments by message_id and quota columns, and track in-flight upload quota reservations.
	{Version: 25, Name: "attachments_message_index", SQLite: attachmentsQuotaSchema, Postgres: attachmentsQuotaSchema},
	// Web Push (RFC 8291/8292) per-user browser subscriptions.
	{Version: 26, Name: "web_push_subscriptions", SQLite: pushSubscriptionsSchema, Postgres: pushSubscriptionsSchema},
	// Multi-tenancy alignment: immutable org_id binding on users and tenant lifecycle status.
	{Version: 27, Name: "users_org_id_and_tenant_status", SQLite: multiTenancySchemaSQLite, Postgres: multiTenancySchemaPostgres},
	// Org lifecycle events apply in KyIdentity's per-org revision order.
	{Version: 28, Name: "tenant_lifecycle_revision", SQLite: tenantLifecycleRevisionSchema, Postgres: tenantLifecycleRevisionSchema},
	// Durable replay ledger shared across signed /api/suite/* and /api/meetings/* requests.
	{Version: 29, Name: "suite_replay_events", SQLite: suiteReplayEventsSchema, Postgres: suiteReplayEventsSchema},
	// Coarse suite status inputs (KyCalendar busy blocks, KyPost out-of-office, manual status).
	{Version: 30, Name: "suite_presence", SQLite: presenceSchema, Postgres: presenceSchema},
	// End-to-end encryption key server: public device keys, one-time keys, to-device mailbox.
	{Version: 31, Name: "e2ee_keys", SQLite: e2eeSchema + e2eeToDeviceSQLite, Postgres: e2eeSchema + e2eeToDevicePostgres},
	{Version: 51, Name: "sso_session_lifecycle", SQLite: ssoLifecycleSchema, Postgres: ssoLifecycleSchema},
	// Incoming webhooks are removed for end-to-end encryption; each live one leaves an audit row.
	{Version: 52, Name: "remove_room_webhooks", SQLite: removeRoomWebhooksSchema, Postgres: removeRoomWebhooksSchema},
	// Search runs on the device; the server's full-text index has no reader left.
	{Version: 53, Name: "drop_message_search_index", SQLite: `SELECT 1;`, Postgres: `DROP INDEX IF EXISTS idx_messages_body_fts;`},
	// The sender device's self-signed keys at send time, so mail from a device deleted since stays
	// verifiable. Rows from before carry none and are refused by clients, as unverifiable.
	{Version: 54, Name: "e2ee_mail_sender_keys", SQLite: e2eeMailSenderKeysSchema, Postgres: e2eeMailSenderKeysSchema},

	// Tenancy migrations follow the merged webhook removal and E2EE slots 53–54.
	{Version: 55, Name: "job_leases", SQLite: jobLeasesSchema, Postgres: jobLeasesSchema},
	// Each org has its own meeting ID space: meetings key on (tenant_id, id), and their
	// windows and guests carry tenant_id. Rebuilt and renamed, which works on both engines.
	{Version: 56, Name: "meetings_per_tenant_key", SQLite: meetingsPerTenantKey, Postgres: meetingsPerTenantKey},
	// Sign-in limits and spent proof-of-work challenges shared by every replica (multi mode).
	{Version: 57, Name: "shared_limits", SQLite: sharedLimitsSchema, Postgres: sharedLimitsSchema},
	// Meeting guest lobby sessions shared by every replica (multi mode).
	{Version: 58, Name: "meeting_guest_sessions", SQLite: guestSessionsSchema, Postgres: guestSessionsSchema},
	// The org storage pool (multi mode): each org's report sequence and KyIdentity's latest grant.
	{Version: 59, Name: "tenant_storage_pool", SQLite: tenantPoolSchema, Postgres: tenantPoolSchema},
	// Erasure state: which local account a KyIdentity subject was, kept after the account row
	// goes (so an erasure after user.deleted, or a repeat, still finds the data), and blob
	// deletes an erasure committed but has not finished.
	{Version: 60, Name: "erasure_state", SQLite: userSubjectsSchema, Postgres: userSubjectsSchema},
	// Tenancy sync and purge (multi mode): an org a full KyIdentity read did not list, and when
	// a deleted org's data was purged.
	{Version: 61, Name: "tenant_missing_and_purge", SQLite: tenantMissingSchema, Postgres: tenantMissingSchema},
	{Version: 62, Name: "tenant_directory", SQLite: tenantDirectorySchema, Postgres: tenantDirectorySchema},
	{Version: 63, Name: "erased_subjects", SQLite: erasedSubjectsSQLite, Postgres: erasedSubjectsPostgres},
	{Version: 64, Name: "call_routing", SQLite: callRoutingSQLite, Postgres: callRoutingPostgres},
	{Version: 65, Name: "guest_invite_binding", SQLite: guestInviteBindingSchema, Postgres: guestInviteBindingSchema},
	{Version: 66, Name: "retained_attachment_versions", SQLite: retainedAttachmentVersionsSchema, Postgres: retainedAttachmentVersionsSchema},
	{Version: 67, Name: "cells", SQLite: cellsSchema, Postgres: cellsSchema},
	{Version: 68, Name: "message_original_body", SQLite: originalBodySchema, Postgres: originalBodySchema},
}

const tenantDirectorySchema = `
CREATE TABLE tenant_directory (
 tenant_id VARCHAR(64) PRIMARY KEY REFERENCES tenants(id),
 revision BIGINT NOT NULL,
 status VARCHAR(32) NOT NULL,
 enabled INTEGER NOT NULL,
 valid INTEGER NOT NULL,
 max_upload_bytes BIGINT NOT NULL DEFAULT 0,
 max_pending_user_bytes BIGINT NOT NULL DEFAULT 0
);
`

const userSubjectsSchema = `
CREATE TABLE user_subjects (
    provider VARCHAR(32) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    PRIMARY KEY (provider, subject, user_id)
);
CREATE TABLE pending_blob_deletes (
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    tenant_id VARCHAR(64) NOT NULL,
    blob_key VARCHAR(512) NOT NULL,
    PRIMARY KEY (tenant_id, blob_key)
);
CREATE TABLE user_erasure_state (
    user_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    completed_at BIGINT
);
CREATE TABLE user_erasure_actors (
 owner_user_id VARCHAR(64) NOT NULL,
 tenant_id VARCHAR(64) NOT NULL,
 user_id VARCHAR(64) NOT NULL,
 PRIMARY KEY (owner_user_id, tenant_id, user_id)
);
`

const tenantMissingSchema = `
ALTER TABLE tenants ADD COLUMN missing_since BIGINT;
ALTER TABLE tenants ADD COLUMN purged_at BIGINT;
CREATE TABLE tenant_pending_revocations (
    tenant_id VARCHAR(64) PRIMARY KEY REFERENCES tenants(id)
);
`

const tenantPoolSchema = `
ALTER TABLE tenants ADD COLUMN pool_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN pool_required_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN pool_ceiling_bytes BIGINT;
ALTER TABLE tenants ADD COLUMN pool_expires_at BIGINT;
ALTER TABLE tenants ADD COLUMN pool_reported_bytes BIGINT;
`

const sharedLimitsSchema = `
CREATE TABLE attempt_counters (
    key_hash VARCHAR(64) PRIMARY KEY,
    count BIGINT NOT NULL,
    reset_at BIGINT NOT NULL
);
CREATE INDEX idx_attempt_counters_reset ON attempt_counters(reset_at);
CREATE TABLE pow_spent (
    sig_hash VARCHAR(64) PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX idx_pow_spent_expires ON pow_spent(expires_at);
`

const guestSessionsSchema = `
CREATE TABLE meeting_guest_sessions (
    secret_hash VARCHAR(64) PRIMARY KEY,
    guest_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL,
    meeting_id VARCHAR(128) NOT NULL,
    room_id VARCHAR(64) NOT NULL,
    guest_key VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(16) NOT NULL,
    knocked_at BIGINT NOT NULL,
    decided_by VARCHAR(64) NOT NULL DEFAULT '',
    seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    UNIQUE (tenant_id, meeting_id, guest_key),
    FOREIGN KEY (tenant_id, meeting_id) REFERENCES meetings(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_guest_sessions_room ON meeting_guest_sessions(room_id);
CREATE INDEX idx_guest_sessions_tenant ON meeting_guest_sessions(tenant_id);
CREATE INDEX idx_guest_sessions_expires ON meeting_guest_sessions(expires_at);
`

const meetingsPerTenantKey = `
CREATE TABLE meetings_v41 (
    id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    room_id VARCHAR(64) NOT NULL UNIQUE REFERENCES rooms(id) ON DELETE CASCADE,
    organizer_sub VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    closed_at BIGINT,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE meeting_windows_v41 (
    tenant_id VARCHAR(64) NOT NULL,
    meeting_id VARCHAR(128) NOT NULL,
    starts_at BIGINT NOT NULL,
    ends_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, meeting_id, starts_at, ends_at),
    FOREIGN KEY (tenant_id, meeting_id) REFERENCES meetings_v41(tenant_id, id) ON DELETE CASCADE
);
CREATE TABLE meeting_guests_v41 (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    meeting_id VARCHAR(128) NOT NULL,
    guest_key VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_id, meeting_id, guest_key),
    FOREIGN KEY (tenant_id, meeting_id) REFERENCES meetings_v41(tenant_id, id) ON DELETE CASCADE
);
INSERT INTO meetings_v41 (id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at)
    SELECT id, tenant_id, room_id, organizer_sub, title, closed_at, updated_at FROM meetings;
INSERT INTO meeting_windows_v41 (tenant_id, meeting_id, starts_at, ends_at)
    SELECT m.tenant_id, w.meeting_id, w.starts_at, w.ends_at FROM meeting_windows w JOIN meetings m ON m.id = w.meeting_id;
INSERT INTO meeting_guests_v41 (id, tenant_id, meeting_id, guest_key, token_hash, revoked_at, created_at)
    SELECT g.id, m.tenant_id, g.meeting_id, g.guest_key, g.token_hash, g.revoked_at, g.created_at FROM meeting_guests g JOIN meetings m ON m.id = g.meeting_id;
DROP TABLE meeting_guests;
DROP TABLE meeting_windows;
DROP TABLE meetings;
ALTER TABLE meetings_v41 RENAME TO meetings;
ALTER TABLE meeting_windows_v41 RENAME TO meeting_windows;
ALTER TABLE meeting_guests_v41 RENAME TO meeting_guests;
`

const jobLeasesSchema = `
CREATE TABLE IF NOT EXISTS job_leases (
	name TEXT PRIMARY KEY,
	holder TEXT NOT NULL,
	expires_at BIGINT NOT NULL
);
`

const multiTenancySchemaSQLite = `
ALTER TABLE users ADD COLUMN org_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
ALTER TABLE tenants ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
`

const multiTenancySchemaPostgres = `
ALTER TABLE users ADD COLUMN org_id VARCHAR(64) NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
ALTER TABLE tenants ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active';
`

const tenantLifecycleRevisionSchema = `
ALTER TABLE tenants ADD COLUMN lifecycle_revision BIGINT NOT NULL DEFAULT 0;
`

// Event IDs are TEXT on both engines: syncauth bounds them only by header size, and an ID the
// column cannot hold would fail every retry with 503.
const suiteReplayEventsSchema = `
CREATE TABLE IF NOT EXISTS suite_replay_events (
	event_id TEXT PRIMARY KEY,
	seen_at BIGINT NOT NULL,
	expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suite_replay_events_expires_at ON suite_replay_events(expires_at);
`

const presenceSchema = `
CREATE TABLE IF NOT EXISTS presence (
	tenant_id VARCHAR(64) NOT NULL,
	user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	share_off INTEGER NOT NULL DEFAULT 0,
	manual_state VARCHAR(16) NOT NULL DEFAULT '',
	manual_until BIGINT NOT NULL DEFAULT 0,
	ooo_revision BIGINT NOT NULL DEFAULT 0,
	ooo_start BIGINT NOT NULL DEFAULT 0,
	ooo_end BIGINT NOT NULL DEFAULT 0,
	cal_revision BIGINT NOT NULL DEFAULT 0,
	cal_at BIGINT NOT NULL DEFAULT 0,
	busy TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (tenant_id, user_id)
);
`

// Only public keys and ciphertext live here (docs/superpowers/specs/2026-11-22-e2ee-design.md).
const e2eeSchema = `
CREATE TABLE IF NOT EXISTS e2ee_devices (
	user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	device_id VARCHAR(64) NOT NULL,
	tenant_id VARCHAR(64) NOT NULL,
	curve25519 VARCHAR(64) NOT NULL,
	ed25519 VARCHAR(64) NOT NULL,
	signature VARCHAR(128) NOT NULL,
	created_at BIGINT NOT NULL,
	PRIMARY KEY (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_e2ee_devices_tenant ON e2ee_devices(tenant_id, user_id);
CREATE TABLE IF NOT EXISTS e2ee_one_time_keys (
	user_id VARCHAR(64) NOT NULL,
	device_id VARCHAR(64) NOT NULL,
	key_id VARCHAR(64) NOT NULL,
	key_value VARCHAR(64) NOT NULL,
	signature VARCHAR(128) NOT NULL,
	fallback INTEGER NOT NULL DEFAULT 0,
	-- A claimed key stays as a tombstone, so a retried upload cannot publish it again.
	claimed INTEGER NOT NULL DEFAULT 0,
	-- vodozemac numbers one-time and fallback keys with separate counters, so IDs collide.
	PRIMARY KEY (user_id, device_id, fallback, key_id),
	FOREIGN KEY (user_id, device_id) REFERENCES e2ee_devices(user_id, device_id) ON DELETE CASCADE
);
`

const e2eeToDeviceSQLite = `
CREATE TABLE IF NOT EXISTS e2ee_to_device (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id VARCHAR(64) NOT NULL,
	recipient_user VARCHAR(64) NOT NULL,
	recipient_device VARCHAR(64) NOT NULL,
	sender_user VARCHAR(64) NOT NULL,
	sender_device VARCHAR(64) NOT NULL,
	type VARCHAR(64) NOT NULL,
	content TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	FOREIGN KEY (recipient_user, recipient_device) REFERENCES e2ee_devices(user_id, device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_e2ee_to_device_recipient ON e2ee_to_device(recipient_user, recipient_device, id);
CREATE INDEX IF NOT EXISTS idx_e2ee_to_device_created ON e2ee_to_device(created_at);
`

const e2eeMailSenderKeysSchema = `
ALTER TABLE e2ee_to_device ADD COLUMN sender_curve25519 VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE e2ee_to_device ADD COLUMN sender_ed25519 VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE e2ee_to_device ADD COLUMN sender_signature VARCHAR(128) NOT NULL DEFAULT '';
`

const e2eeToDevicePostgres = `
CREATE TABLE IF NOT EXISTS e2ee_to_device (
	id BIGSERIAL PRIMARY KEY,
	tenant_id VARCHAR(64) NOT NULL,
	recipient_user VARCHAR(64) NOT NULL,
	recipient_device VARCHAR(64) NOT NULL,
	sender_user VARCHAR(64) NOT NULL,
	sender_device VARCHAR(64) NOT NULL,
	type VARCHAR(64) NOT NULL,
	content TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	FOREIGN KEY (recipient_user, recipient_device) REFERENCES e2ee_devices(user_id, device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_e2ee_to_device_recipient ON e2ee_to_device(recipient_user, recipient_device, id);
CREATE INDEX IF NOT EXISTS idx_e2ee_to_device_created ON e2ee_to_device(created_at);
`

const removeRoomWebhooksSchema = `
INSERT INTO audit_records (user_id, action, resource, details, created_at)
SELECT created_by, 'webhook.removed', id, 'incoming webhooks removed: rooms are end-to-end encrypted; use a bot', CURRENT_TIMESTAMP
FROM room_webhooks WHERE revoked_at IS NULL;
DROP TABLE room_webhooks;
`

const pushSubscriptionsSchema = `
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    p256dh VARCHAR(255) NOT NULL,
    auth_secret VARCHAR(128) NOT NULL,
    user_agent VARCHAR(255) NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL DEFAULT 0,
    UNIQUE (endpoint)
);
CREATE INDEX IF NOT EXISTS idx_push_subs_user ON push_subscriptions(tenant_id, user_id);
`

const attachmentsQuotaSchema = `
CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_attachments_quota ON attachments(tenant_id, uploader_id, message_id);
CREATE TABLE IF NOT EXISTS attachment_upload_reservations (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    uploader_id VARCHAR(64) NOT NULL,
    reserved_bytes BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachment_reservations_quota ON attachment_upload_reservations(tenant_id, uploader_id, expires_at);
`

func nativeAgentsSchema(timestamp string) string {
	return `
DROP TABLE IF EXISTS agents;
CREATE TABLE agents (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL UNIQUE,
    username VARCHAR(64) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    owner_user_id VARCHAR(64) NOT NULL,
    token_hash VARCHAR(64) NOT NULL DEFAULT '',
    token_state VARCHAR(16) NOT NULL,
    last_used_at ` + timestamp + `,
    created_by VARCHAR(255) NOT NULL,
    created_at ` + timestamp + ` NOT NULL
);
CREATE INDEX idx_agents_token_hash ON agents(token_hash);
CREATE INDEX idx_agents_owner_user_id ON agents(owner_user_id);
`
}

func agentsSchema(timestamp string) string {
	return `
CREATE TABLE agents (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    mas_user_id VARCHAR(64) NOT NULL UNIQUE,
    device_id VARCHAR(32) NOT NULL UNIQUE,
    owner_subject VARCHAR(255) NOT NULL,
    session_id VARCHAR(64) NOT NULL DEFAULT '',
    token_state VARCHAR(16) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at ` + timestamp + ` NOT NULL
);
`
}

// The custom MLS messaging stack was retired for Matrix; its tables, audit rows and backup
// settings go. Child tables first so foreign keys never block a drop.
const dropMessaging = `
DROP TABLE IF EXISTS messaging_welcomes;
DROP TABLE IF EXISTS messaging_events;
DROP TABLE IF EXISTS messaging_epoch_devices;
DROP TABLE IF EXISTS messaging_members;
DROP TABLE IF EXISTS messaging_rooms;
DROP TABLE IF EXISTS messaging_key_packages;
DROP TABLE IF EXISTS messaging_recovery_auth;
DROP TABLE IF EXISTS messaging_reset_receipts;
DROP TABLE IF EXISTS messaging_devices;
DROP TABLE IF EXISTS messaging_identities;
DROP INDEX IF EXISTS audit_action_resource_created;
DELETE FROM audit_records WHERE action LIKE 'messaging.%';
DELETE FROM server_settings WHERE key IN ('messages_backup_interval_sec', 'messages_backup_last_attempt', 'messages_kyrecovery_last_deposit');
`

const kyIdentityProvider = `
UPDATE users SET sso_provider = 'kyidentity' WHERE sso_provider = 'kysignon';
UPDATE directory_sync_state SET provider = 'kyidentity' WHERE provider = 'kysignon';
UPDATE directory_sync_events SET provider = 'kyidentity' WHERE provider = 'kysignon';
`

const messagingDeviceResume = `ALTER TABLE messaging_devices ADD COLUMN resume_token_hash TEXT NOT NULL DEFAULT '';`

const (
	suspendedAt = `ALTER TABLE messaging_devices ADD COLUMN suspended_at BIGINT NOT NULL DEFAULT 0;
UPDATE messaging_devices SET suspended_at = `
	suspendedWhere = ` WHERE status = 'approved' AND token_hash IS NULL;`
)

// ErrNewerSchema is a database already migrated past this build's newest migration.
var ErrNewerSchema = errors.New("database schema is newer than this build")

// Run executes all pending migrations for the specified database driver.
func Run(ctx context.Context, db *sql.DB, driver string) error {
	switch strings.ToLower(driver) {
	case "postgres", "postgresql":
		driver = "postgres"
	case "sqlite":
		driver = "sqlite"
	default:
		return fmt.Errorf("unsupported migration driver %q", driver)
	}

	// Create schema_migrations table
	initTableQuery := `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at DATETIME NOT NULL
);`
	if driver == "postgres" {
		initTableQuery = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL
);`
	}

	// On PostgreSQL every replica may start at once: one session-level advisory lock, held on
	// one connection for the whole run, makes the others wait and then re-read the applied set.
	var q interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
		QueryRowContext(context.Context, string, ...any) *sql.Row
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	} = db
	if driver == "postgres" {
		conn, err := db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("migration connection: %w", err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('kymessages:migrate'))`); err != nil {
			return fmt.Errorf("migration lock: %w", err)
		}
		defer func() {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('kymessages:migrate'))`)
		}()
		q = conn
	}

	if _, err := q.ExecContext(ctx, initTableQuery); err != nil {
		return fmt.Errorf("failed to init schema_migrations: %w", err)
	}

	// A database migrated by a newer build (an image rollback, or a restored capsule from one)
	// has a schema this binary does not know; running against it would corrupt it quietly.
	var applied, known int
	if err := q.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&applied); err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}
	for _, m := range registry {
		known = max(known, m.Version)
	}
	if applied > known {
		return fmt.Errorf("%w: database is at schema version %d, this build knows up to %d; run the newer build or restore an older backup", ErrNewerSchema, applied, known)
	}

	checkQuery := "SELECT COUNT(1) FROM schema_migrations WHERE version = ?"
	if driver == "postgres" {
		checkQuery = "SELECT COUNT(1) FROM schema_migrations WHERE version = $1"
	}
	for _, m := range registry {
		var exists int
		if err := q.QueryRowContext(ctx, checkQuery, m.Version).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check migration version %d: %w", m.Version, err)
		}

		if exists > 0 {
			continue
		}

		ddl := m.SQLite
		if driver == "postgres" {
			ddl = m.Postgres
		}

		tx, err := q.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin migration tx for v%d: %w", m.Version, err)
		}

		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed executing migration v%d (%s): %w", m.Version, m.Name, err)
		}

		recordQuery := "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)"
		if driver == "postgres" {
			recordQuery = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)"
		}

		if _, err := tx.ExecContext(ctx, recordQuery, m.Version, m.Name, time.Now().UTC()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to record migration v%d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration v%d: %w", m.Version, err)
		}
	}

	return nil
}

// Pairings live 90 seconds, so dropping pending rows on upgrade loses nothing. The anonymous
// verify route no longer accepts the guessable 6-digit code; only the 24-byte QR secret.
const pairingSecretOnlySQLite = `
DROP TABLE IF EXISTS device_pairings;
CREATE TABLE device_pairings (
    secret TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    push_token TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    authenticated_at DATETIME NOT NULL
);
CREATE INDEX idx_pairings_expires ON device_pairings(expires_at);
`

const pairingSecretOnlyPostgres = `
DROP TABLE IF EXISTS device_pairings;
CREATE TABLE device_pairings (
    secret VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    device_name VARCHAR(255) NOT NULL DEFAULT '',
    platform VARCHAR(32) NOT NULL DEFAULT '',
    push_token TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_pairings_expires ON device_pairings(expires_at);
`

const directorySyncStateSchema = `
CREATE TABLE directory_sync_state (
    provider VARCHAR(32) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    synced_at BIGINT NOT NULL,
    PRIMARY KEY (provider, subject)
);
`

const directorySyncRevision = `
DELETE FROM directory_sync_state;
ALTER TABLE directory_sync_state RENAME COLUMN synced_at TO revision;
CREATE TABLE directory_sync_events (
    provider VARCHAR(32) NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    PRIMARY KEY (provider, event_id)
);
`

const threadAutoPurge = `
ALTER TABLE messaging_rooms ADD COLUMN purge_days BIGINT NOT NULL DEFAULT 90 CHECK(purge_days IN (0, 1, 7, 30, 90));
UPDATE messaging_rooms SET purge_days = retention_days;
ALTER TABLE messaging_rooms DROP COLUMN retention_days;
ALTER TABLE messaging_rooms RENAME COLUMN purge_days TO retention_days;
DROP INDEX messaging_events_expiry;
DROP INDEX messaging_events_room_expiry;
ALTER TABLE messaging_events DROP COLUMN expires_at;
`

const threadAutoPurgeTail = `
DELETE FROM messaging_events WHERE payload = '';
CREATE INDEX messaging_events_room_created ON messaging_events(room_id, created_at);
CREATE INDEX audit_action_resource_created ON audit_records(action, resource, created_at);
`

// Events the old sweep blanked (empty payload) go with their audit rows, matched by the
// "sequence=N" in the details; the old floor and byte count already exclude them.
const threadAutoPurgeSQLite = threadAutoPurge + `
DELETE FROM audit_records WHERE action = 'messaging.event_accepted' AND EXISTS (
    SELECT 1 FROM messaging_events e WHERE e.room_id = audit_records.resource AND e.payload = ''
    AND e.sequence = CAST(substr(audit_records.details, instr(audit_records.details, ' sequence=') + 10) AS INTEGER));
` + threadAutoPurgeTail

const threadAutoPurgePostgres = threadAutoPurge + `
DELETE FROM audit_records WHERE action = 'messaging.event_accepted' AND EXISTS (
    SELECT 1 FROM messaging_events e WHERE e.room_id = audit_records.resource AND e.payload = ''
    AND e.sequence = CAST(substring(audit_records.details from ' sequence=([0-9]+)') AS BIGINT));
` + threadAutoPurgeTail
