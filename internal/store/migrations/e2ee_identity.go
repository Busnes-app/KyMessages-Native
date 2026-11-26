package migrations

// E3 of docs/superpowers/specs/2026-11-22-e2ee-design.md: each user's hybrid master key and
// X-Wing backup key (public halves and their signatures), the recovery-key wraps of their
// private seeds (ciphertext the server cannot open), the user's synced pin set (ciphertext
// under a master-derived key), the master-signed device list, each device's master-key
// cross-signature, the key backup of sealed Megolm sessions (keyed by sender key too), and
// short-lived QR pairing sessions. No private key is stored.
const e2eeIdentitySchema = `
CREATE TABLE IF NOT EXISTS e2ee_master_keys (
	user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	tenant_id VARCHAR(64) NOT NULL,
	version BIGINT NOT NULL,
	master_key TEXT NOT NULL,
	self_signature TEXT NOT NULL,
	backup_key TEXT NOT NULL,
	backup_signature TEXT NOT NULL,
	recovery_master TEXT NOT NULL,
	recovery_backup TEXT NOT NULL,
	pins_counter BIGINT NOT NULL DEFAULT 0,
	pins TEXT NOT NULL DEFAULT '',
	device_list TEXT NOT NULL DEFAULT '',
	device_list_epoch BIGINT NOT NULL DEFAULT 0,
	device_list_signature TEXT NOT NULL DEFAULT '',
	updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_e2ee_master_keys_tenant ON e2ee_master_keys(tenant_id, user_id);
ALTER TABLE e2ee_devices ADD COLUMN master_signature TEXT NOT NULL DEFAULT '';
ALTER TABLE e2ee_devices ADD COLUMN master_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS e2ee_key_backup (
	user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	tenant_id VARCHAR(64) NOT NULL,
	version BIGINT NOT NULL,
	room_id VARCHAR(128) NOT NULL,
	sender_key VARCHAR(64) NOT NULL,
	session_id VARCHAR(128) NOT NULL,
	first_index BIGINT NOT NULL,
	sealed TEXT NOT NULL,
	updated_at BIGINT NOT NULL,
	PRIMARY KEY (user_id, version, room_id, sender_key, session_id)
);
CREATE TABLE IF NOT EXISTS e2ee_pairings (
	id VARCHAR(32) PRIMARY KEY,
	user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	tenant_id VARCHAR(64) NOT NULL,
	initiator_device VARCHAR(64) NOT NULL,
	master_version BIGINT NOT NULL,
	new_device VARCHAR(64) NOT NULL DEFAULT '',
	ephemeral_key TEXT NOT NULL DEFAULT '',
	sealed TEXT NOT NULL DEFAULT '',
	expires_at BIGINT NOT NULL
);
-- One pairing at a time per user and org.
CREATE UNIQUE INDEX IF NOT EXISTS idx_e2ee_pairings_user ON e2ee_pairings(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_e2ee_pairings_expires ON e2ee_pairings(expires_at);
`
