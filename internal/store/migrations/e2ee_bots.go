package migrations

// e2eeBotsSchema holds, per bot, the device list its owner's master key signed (E4 of
// docs/superpowers/specs/2026-11-22-e2ee-design.md): device IDs with their keys, the owner and
// master key version that signed it, and the epoch, which only rises. No private key is stored.
const e2eeBotsSchema = `
CREATE TABLE IF NOT EXISTS e2ee_bot_devices (
	bot_user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	tenant_id VARCHAR(64) NOT NULL,
	owner_user_id VARCHAR(64) NOT NULL,
	owner_version BIGINT NOT NULL,
	epoch BIGINT NOT NULL,
	devices TEXT NOT NULL,
	signature TEXT NOT NULL,
	updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_e2ee_bot_devices_tenant ON e2ee_bot_devices(tenant_id, bot_user_id);
`
